%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_qifs_SUITE).

-moduledoc """
QPACK interop test suite driven by qpackers/qifs reference data.

For each reference encoder (nghttp3 primary, ls-qpack and proxygen as
secondary), decodes every `.out.<capacity>.<blocked>.<ack>` file and
compares the resulting field sections to the source `.qif`. A mismatch
for the primary encoder is treated as a library bug; a mismatch for a
secondary encoder is still a failure but logged with the file path so
the reviewer can triage.

Note on the offline interop format: the reference encoders assume the
decoder's dynamic table starts at the configured maximum and do NOT
emit an initial Set Dynamic Table Capacity instruction. This suite
seeds the decoder with a synthetic instruction before replaying the
file, which matches the qifs harness convention.

See: https://github.com/qpackers/qifs
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

-define(QPACK_VERSION_DIR, "qpack-06").

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, primary},
        {group, secondary}
    ].

groups() ->
    [
        {primary, [parallel], [
            decode_nghttp3
        ]},
        {secondary, [parallel], [
            decode_ls_qpack,
            decode_proxygen
        ]}
    ].

init_per_suite(Config) ->
    DataDir = resolve_data_dir(),
    case filelib:is_dir(DataDir) of
        true -> ok;
        false ->
            ct:fail(
                "qifs test data not found at ~s. "
                "Initialise submodules with: git submodule update --init",
                [DataDir]
            )
    end,
    ct:pal("Using qifs data directory: ~s", [DataDir]),
    [{qifs_dir, DataDir} | Config].

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% TEST CASES
%%%-----------------------------------------------------------------------------

decode_nghttp3(Config) ->
    run_encoder(Config, "nghttp3", primary).

decode_ls_qpack(Config) ->
    run_encoder(Config, "ls-qpack", secondary).

decode_proxygen(Config) ->
    run_encoder(Config, "proxygen", secondary).

%%%-----------------------------------------------------------------------------
%%% RUNNER
%%%-----------------------------------------------------------------------------

-spec run_encoder(ct_suite:ct_config(), string(), primary | secondary) -> ok.
run_encoder(Config, Encoder, Tier) ->
    DataDir = proplists:get_value(qifs_dir, Config),
    EncoderDir =
        filename:join([DataDir, "encoded", ?QPACK_VERSION_DIR, Encoder]),
    OutFiles = filelib:wildcard(filename:join(EncoderDir, "*.out.*.*.*")),
    case OutFiles of
        [] ->
            ct:fail(
                "No .out.*.*.* files found for encoder ~s in ~s",
                [Encoder, EncoderDir]
            );
        _ -> ok
    end,
    ct:pal("[~s] comparing ~p output files", [Encoder, length(OutFiles)]),
    {Pass, Fail} = lists:foldl(
        fun(File, {P, F}) ->
            case run_file(DataDir, File, Tier) of
                ok -> {P + 1, F};
                skipped -> {P, F};
                {error, Reason} ->
                    ct:pal("[~s] FAIL ~s: ~p", [Encoder, filename:basename(File), Reason]),
                    {P, F + 1}
            end
        end,
        {0, 0},
        OutFiles
    ),
    ct:pal("[~s] pass=~p fail=~p", [Encoder, Pass, Fail]),
    case Fail of
        0 -> ok;
        _ -> ct:fail("~s: ~p of ~p files failed", [Encoder, Fail, Pass + Fail])
    end.

-spec run_file(file:filename(), file:filename(), primary | secondary) ->
    ok | skipped | {error, term()}.
run_file(DataDir, OutFile, _Tier) ->
    {QifName, Cap, Blocked, _Ack} = parse_out_filename(OutFile),
    QifFile = filename:join([DataDir, "qifs", QifName ++ ".qif"]),
    case filelib:is_regular(QifFile) of
        false ->
            ct:pal("no matching qif for ~s (looked for ~s)", [OutFile, QifFile]),
            skipped;
        true ->
            compare_file(OutFile, QifFile, Cap, Blocked)
    end.

-spec compare_file(file:filename(), file:filename(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
compare_file(OutFile, QifFile, Cap, Blocked) ->
    {ok, OutBin} = file:read_file(OutFile),
    {ok, QifBin} = file:read_file(QifFile),
    {ok, Expected} = nhttp_qpack_interop:parse_qif(QifBin),
    case decode_interop_file(OutBin, Cap, Blocked) of
        {ok, Actual} when length(Actual) =/= length(Expected) ->
            {error, {section_count_mismatch,
                #{expected => length(Expected), got => length(Actual)}}};
        {ok, Actual} ->
            case compare_sections(Expected, Actual) of
                ok -> ok;
                {error, Reason} -> {error, Reason}
            end;
        {error, _} = Err ->
            Err
    end.

-spec compare_sections([list()], [list()]) -> ok | {error, term()}.
compare_sections([], []) ->
    ok;
compare_sections([E | Es], [A | As]) when E =:= A ->
    compare_sections(Es, As);
compare_sections([E | _], [A | _]) ->
    {error, {section_mismatch, #{expected => E, got => A}}}.

%%%-----------------------------------------------------------------------------
%%% INTEROP DECODE
%%%-----------------------------------------------------------------------------

-spec decode_interop_file(binary(), non_neg_integer(), non_neg_integer()) ->
    {ok, [[{binary(), binary()}]]} | {error, term()}.
decode_interop_file(Bin, Cap, Blocked) ->
    {ok, Dec0} = nhttp_qpack:new_decoder(#{
        max_table_capacity => Cap,
        max_blocked_streams => Blocked
    }),
    Dec1 =
        case Cap > 0 of
            true ->
                Prologue = iolist_to_binary(
                    nhttp_qpack_encoder_instruction:encode_set_capacity(Cap)
                ),
                case nhttp_qpack:feed_encoder_stream(Dec0, Prologue) of
                    {ok, D, _} -> D;
                    Err -> throw({seed_capacity_failed, Err})
                end;
            false ->
                Dec0
        end,
    replay_loop(Bin, Dec1, #{}, #{}, 0).

-spec replay_loop(binary(), term(), map(), map(), non_neg_integer()) ->
    {ok, list()} | {error, term()}.
replay_loop(<<>>, _Dec, SectionsByIdx, Blocked, NextIdx) ->
    case maps:size(Blocked) of
        0 ->
            Ordered = [
                maps:get(I, SectionsByIdx)
             || I <- lists:seq(0, NextIdx - 1)
            ],
            {ok, Ordered};
        _ ->
            {error, {still_blocked, maps:keys(Blocked)}}
    end;
replay_loop(
    <<0:64, L:32, D:L/binary, Rest/binary>>, Dec, Sections, Blocked, NextIdx
) ->
    case nhttp_qpack:feed_encoder_stream(Dec, D) of
        {ok, Dec1, Unblocked} ->
            {NewSections, NewBlocked} = absorb_unblocked(Unblocked, Sections, Blocked),
            replay_loop(Rest, Dec1, NewSections, NewBlocked, NextIdx);
        {error, _} = Err ->
            {error, {encoder_stream, Err}}
    end;
replay_loop(
    <<Sid:64, L:32, D:L/binary, Rest/binary>>, Dec, Sections, Blocked, NextIdx
) ->
    case nhttp_qpack:decode_field_section(Dec, Sid, D) of
        {ok, Dec1, _DecStream, Fields} ->
            replay_loop(Rest, Dec1, Sections#{NextIdx => Fields}, Blocked, NextIdx + 1);
        {blocked, Dec1} ->
            replay_loop(Rest, Dec1, Sections, Blocked#{Sid => NextIdx}, NextIdx + 1);
        {error, _} = Err ->
            {error, {field_section, Sid, Err}}
    end.

-spec absorb_unblocked([{nhttp_lib:stream_id(), iodata(), list()}], map(), map()) ->
    {map(), map()}.
absorb_unblocked([], Sections, Blocked) ->
    {Sections, Blocked};
absorb_unblocked([{Sid, _DecStream, Fields} | Rest], Sections, Blocked) ->
    case maps:take(Sid, Blocked) of
        {Idx, NewBlocked} ->
            absorb_unblocked(Rest, Sections#{Idx => Fields}, NewBlocked);
        error ->
            absorb_unblocked(Rest, Sections, Blocked)
    end.

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec parse_out_filename(file:filename()) ->
    {string(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
parse_out_filename(Path) ->
    Base = filename:basename(Path),
    [QifName, _Out, CapStr, BlockedStr, AckStr] =
        re:split(Base, "\\.", [{return, list}, {parts, 5}]),
    QifName2 = case _Out of "out" -> QifName end,
    {QifName2, list_to_integer(CapStr), list_to_integer(BlockedStr), list_to_integer(AckStr)}.

-spec resolve_data_dir() -> file:filename().
resolve_data_dir() ->
    filename:join([get_project_root(), "test", "fixtures", "qifs"]).

-spec get_project_root() -> file:filename().
get_project_root() ->
    SuiteDir = filename:dirname(code:which(?MODULE)),
    find_project_root(SuiteDir).

-spec find_project_root(file:filename()) -> file:filename().
find_project_root(Dir) ->
    RebarConfig = filename:join(Dir, "rebar.config"),
    case filelib:is_file(RebarConfig) of
        true -> Dir;
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir -> Dir;
                _ -> find_project_root(Parent)
            end
    end.
