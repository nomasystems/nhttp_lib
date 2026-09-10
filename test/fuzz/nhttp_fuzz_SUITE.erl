%%%-----------------------------------------------------------------------------
-module(nhttp_fuzz_SUITE).

-moduledoc """
Fuzz harness for the five wire-facing parsers.

The `oracle`, `corpus`, `mutation` and `structured` groups run in CI. They use
a fixed seed, so a failure reproduces from the seed that the report prints.

The `campaign` group is not in `all/0`. `make fuzz` selects it by name for a
long run, and it writes one corpus file per target and finding class.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

-define(CI_SEED, 20260819).
-define(CI_ITERATIONS, 2000).

-define(CAMPAIGN_ITERATIONS, 50000).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------
all() ->
    [
        {group, oracle},
        {group, corpus},
        {group, mutation},
        {group, structured}
    ].

groups() ->
    [
        {oracle, [parallel], [
            oracle_reports_a_crash,
            oracle_reports_a_zero_more,
            oracle_reports_a_negative_more,
            oracle_reports_more_above_the_bound,
            oracle_reports_bytes_consumed_past_the_input,
            oracle_reports_an_undeclared_return,
            oracle_reports_a_rest_that_grew,
            oracle_reports_a_rest_that_is_not_a_suffix,
            oracle_reports_a_value_outside_the_union,
            oracle_accepts_a_declared_return,
            generator_is_deterministic
        ]},
        {corpus, [parallel], [
            corpus_covers_every_target,
            corpus_h1,
            corpus_h2_frame,
            corpus_h3_frame,
            corpus_hpack,
            corpus_qpack,
            corpus_ws_frame
        ]},
        {mutation, [parallel], [
            mutate_h1,
            mutate_h2_frame,
            mutate_h3_frame,
            mutate_hpack,
            mutate_qpack,
            mutate_ws_frame
        ]},
        {structured, [parallel], [
            structured_h1,
            structured_h2_frame,
            structured_h3_frame,
            structured_hpack,
            structured_qpack,
            structured_ws_frame
        ]},
        {campaign, [], [campaign]}
    ].

%%%-----------------------------------------------------------------------------
%%% ORACLE TESTS
%%%
%%% An oracle that accepts any return value proves nothing, so the oracle is
%%% itself under test. Each case drives it with a return that a parser must
%%% never produce, and asserts the finding.
%%%-----------------------------------------------------------------------------
oracle_reports_a_crash(_Config) ->
    Fun = fun() -> degenerate([]) end,
    ?assertMatch(
        {error, {crash, error, badarg, _}},
        nhttp_fuzz_target:consumed_result(Fun, 10, infinity, fun erlang:is_map/1)
    ).

oracle_reports_a_zero_more(_Config) ->
    Fun = fun() -> {more, 0} end,
    ?assertEqual(
        {error, {non_positive_more, 0}},
        nhttp_fuzz_target:consumed_result(Fun, 10, infinity, fun erlang:is_map/1)
    ).

oracle_reports_a_negative_more(_Config) ->
    ?assertEqual({error, {non_positive_more, -1}}, nhttp_fuzz_target:check_more(-1, infinity)).

oracle_reports_more_above_the_bound(_Config) ->
    ?assertEqual({error, {more_exceeds_bound, 99, 10}}, nhttp_fuzz_target:check_more(99, 10)),
    ?assertEqual({ok, incomplete}, nhttp_fuzz_target:check_more(10, 10)).

oracle_reports_bytes_consumed_past_the_input(_Config) ->
    Fun = fun() -> {ok, #{}, 11} end,
    ?assertEqual(
        {error, {bytes_consumed_out_of_range, 11, 10}},
        nhttp_fuzz_target:consumed_result(Fun, 10, infinity, fun erlang:is_map/1)
    ).

oracle_reports_an_undeclared_return(_Config) ->
    Fun = fun() -> not_a_result end,
    ?assertEqual(
        {error, {undeclared_return, not_a_result}},
        nhttp_fuzz_target:consumed_result(Fun, 10, infinity, fun erlang:is_map/1)
    ).

oracle_reports_a_rest_that_grew(_Config) ->
    ?assertEqual(
        {error, {rest_not_shorter, 3, 3}}, nhttp_fuzz_target:check_rest(<<"abc">>, <<"abc">>)
    ).

oracle_reports_a_rest_that_is_not_a_suffix(_Config) ->
    ?assertEqual(
        {error, {rest_not_a_suffix, 2, 3}}, nhttp_fuzz_target:check_rest(<<"abc">>, <<"xy">>)
    ).

oracle_reports_a_value_outside_the_union(_Config) ->
    Fun = fun() -> {ok, {not_a_frame, 1}, <<"a">>} end,
    ?assertEqual(
        {error, {bad_value_shape, {not_a_frame, 1}}},
        nhttp_fuzz_target:rest_result(Fun, <<"abc">>, infinity, fun erlang:is_map/1)
    ).

oracle_accepts_a_declared_return(_Config) ->
    Fun = fun() -> {ok, #{}, 4} end,
    ?assertEqual(
        {ok, parsed}, nhttp_fuzz_target:consumed_result(Fun, 10, infinity, fun erlang:is_map/1)
    ),
    ?assertEqual({ok, parsed}, nhttp_fuzz_target:check_rest(<<"abcde">>, <<"de">>)),
    ?assertEqual({ok, incomplete}, nhttp_fuzz_target:check_more(1, infinity)).

generator_is_deterministic(_Config) ->
    Draw = fun() ->
        S0 = nhttp_fuzz_gen:new(?CI_SEED),
        {A, S1} = nhttp_fuzz_gen:structured(ws_frame, S0),
        {B, S2} = nhttp_fuzz_gen:mutate(<<"seed">>, [<<"other">>], S1),
        {C, _S3} = nhttp_fuzz_gen:random_bytes(16, S2),
        {A, B, C}
    end,
    ?assertEqual(Draw(), Draw()).

%%%-----------------------------------------------------------------------------
%%% CORPUS REPLAY
%%%-----------------------------------------------------------------------------
corpus_covers_every_target(_Config) ->
    lists:foreach(fun assert_corpus_shape/1, nhttp_fuzz_target:all()).

corpus_h1(_Config) -> replay(h1).
corpus_h2_frame(_Config) -> replay(h2_frame).
corpus_h3_frame(_Config) -> replay(h3_frame).
corpus_hpack(_Config) -> replay(hpack).
corpus_qpack(_Config) -> replay(qpack).
corpus_ws_frame(_Config) -> replay(ws_frame).

%%%-----------------------------------------------------------------------------
%%% SEEDED MUTATION
%%%-----------------------------------------------------------------------------
mutate_h1(_Config) -> mutation_run(h1).
mutate_h2_frame(_Config) -> mutation_run(h2_frame).
mutate_h3_frame(_Config) -> mutation_run(h3_frame).
mutate_hpack(_Config) -> mutation_run(hpack).
mutate_qpack(_Config) -> mutation_run(qpack).
mutate_ws_frame(_Config) -> mutation_run(ws_frame).

%%%-----------------------------------------------------------------------------
%%% SEEDED STRUCTURE AWARE GENERATION
%%%-----------------------------------------------------------------------------
structured_h1(_Config) -> structured_run(h1).
structured_h2_frame(_Config) -> structured_run(h2_frame).
structured_h3_frame(_Config) -> structured_run(h3_frame).
structured_hpack(_Config) -> structured_run(hpack).
structured_qpack(_Config) -> structured_run(qpack).
structured_ws_frame(_Config) -> structured_run(ws_frame).

%%%-----------------------------------------------------------------------------
%%% CAMPAIGN
%%%-----------------------------------------------------------------------------
campaign(_Config) ->
    Iterations = env_int("NHTTP_FUZZ_ITERATIONS", ?CAMPAIGN_ITERATIONS),
    Seed = env_int("NHTTP_FUZZ_SEED", ?CI_SEED),
    ct:pal("campaign seed=~p iterations=~p per target per source", [Seed, Iterations]),
    Reports = lists:flatmap(
        fun(Target) ->
            Corpus = seeds(Target),
            {MutationReports, MutationTally} =
                drive(Target, mutation_inputs(Corpus, Iterations, Seed)),
            {StructuredReports, StructuredTally} =
                drive(Target, structured_inputs(Target, Iterations, Seed)),
            ct:pal(
                "~p mutation=~0p structured=~0p", [Target, MutationTally, StructuredTally]
            ),
            MutationReports ++ StructuredReports
        end,
        nhttp_fuzz_target:all()
    ),
    Written = [record_crash(R, Seed) || R <- distinct(Reports)],
    lists:foreach(fun(Path) -> ct:pal("wrote ~s", [Path]) end, Written),
    fail_on(Reports, Seed).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------
-spec assert_corpus_shape(nhttp_fuzz_target:target()) -> ok.
assert_corpus_shape(Target) ->
    Seeds = nhttp_fuzz_target:load_corpus(Target),
    ?assertNotEqual([], Seeds),
    Inputs = [Input || {_File, Input} <- Seeds],
    ?assert(lists:member(<<>>, Inputs)),
    ?assert(lists:any(fun(I) -> byte_size(I) =:= 1 end, Inputs)),
    ok.

-spec replay(nhttp_fuzz_target:target()) -> ok.
replay(Target) ->
    Seeds = nhttp_fuzz_target:load_corpus(Target),
    ?assertNotEqual([], Seeds),
    Inputs = [{list_to_binary(filename:basename(F)), I} || {F, I} <- Seeds],
    {Reports, Tally} = drive(Target, Inputs),
    ct:pal("~p corpus ~p seeds ~0p", [Target, length(Inputs), Tally]),
    fail_on(Reports, corpus).

-spec mutation_run(nhttp_fuzz_target:target()) -> ok.
mutation_run(Target) ->
    Inputs = mutation_inputs(seeds(Target), ?CI_ITERATIONS, ?CI_SEED),
    {Reports, Tally} = drive(Target, Inputs),
    ct:pal("~p mutation ~0p", [Target, Tally]),
    ok = fail_on(Reports, ?CI_SEED),
    assert_reaches_every_outcome(Target, Tally).

-spec structured_run(nhttp_fuzz_target:target()) -> ok.
structured_run(Target) ->
    Inputs = structured_inputs(Target, ?CI_ITERATIONS, ?CI_SEED),
    {Reports, Tally} = drive(Target, Inputs),
    ct:pal("~p structured ~0p", [Target, Tally]),
    ok = fail_on(Reports, ?CI_SEED),
    assert_reaches_every_outcome(Target, Tally).

-doc """
A generator that never gets past the first octet exercises nothing, so a run
must reach every shape its target declares. This guards the harness against
silent decay as the parsers change.

`incomplete` belongs to a parser that reads a prefix of a stream and asks for
more octets. `nhttp_hpack:decode/3` reads one whole field block, which
RFC 9113 Section 4.3 calls a discrete unit, so it declares no `{more, _}` and
answers a truncated block with an error that ends the connection.
""".
-spec assert_reaches_every_outcome(nhttp_fuzz_target:target(), map()) -> ok.
assert_reaches_every_outcome(Target, Tally) ->
    lists:foreach(
        fun(Outcome) ->
            ?assert(maps:get(Outcome, Tally, 0) > 0, {Target, Outcome, Tally})
        end,
        declared_outcomes(Target)
    ).

-spec declared_outcomes(nhttp_fuzz_target:target()) -> [nhttp_fuzz_target:outcome(), ...].
declared_outcomes(hpack) -> [parsed, refused];
declared_outcomes(h1) -> [parsed, incomplete, refused];
declared_outcomes(h2_frame) -> [parsed, incomplete, refused];
declared_outcomes(h3_frame) -> [parsed, incomplete, refused];
declared_outcomes(qpack) -> [parsed, incomplete, refused];
declared_outcomes(ws_frame) -> [parsed, incomplete, refused].

-spec seeds(nhttp_fuzz_target:target()) -> [binary()].
seeds(Target) ->
    [Input || {_File, Input} <- nhttp_fuzz_target:load_corpus(Target)].

-spec mutation_inputs([binary()], pos_integer(), integer()) -> [{binary(), binary()}].
mutation_inputs([], _Iterations, _Seed) ->
    [];
mutation_inputs(Corpus, Iterations, Seed) ->
    {Inputs, _State} = lists:foldl(
        fun(I, {Acc, S0}) ->
            Base = lists:nth((I rem length(Corpus)) + 1, Corpus),
            {Mutated, S1} = nhttp_fuzz_gen:mutate(Base, Corpus, S0),
            {[{<<"mutation">>, Mutated} | Acc], S1}
        end,
        {[], nhttp_fuzz_gen:new(Seed)},
        lists:seq(0, Iterations - 1)
    ),
    Inputs.

-spec structured_inputs(nhttp_fuzz_target:target(), pos_integer(), integer()) ->
    [{binary(), binary()}].
structured_inputs(Target, Iterations, Seed) ->
    {Inputs, _State} = lists:foldl(
        fun(_I, {Acc, S0}) ->
            {Input, S1} = nhttp_fuzz_gen:structured(Target, S0),
            {[{<<"structured">>, Input} | Acc], S1}
        end,
        {[], nhttp_fuzz_gen:new(Seed)},
        lists:seq(1, Iterations)
    ),
    Inputs.

-spec drive(nhttp_fuzz_target:target(), [{binary(), binary()}]) -> {[map()], map()}.
drive(Target, Inputs) ->
    lists:foldl(
        fun({Origin, Input}, {Reports, Tally}) ->
            case nhttp_fuzz_target:check(Target, Input) of
                {ok, Outcome} ->
                    {Reports, maps:update_with(Outcome, fun(N) -> N + 1 end, 1, Tally)};
                {error, Finding} ->
                    Report = #{
                        target => Target, origin => Origin, input => Input, finding => Finding
                    },
                    {[Report | Reports], Tally}
            end
        end,
        {[], #{}},
        Inputs
    ).

-spec fail_on([map()], term()) -> ok.
fail_on([], _Seed) ->
    ok;
fail_on(Reports, Seed) ->
    lists:foreach(
        fun(#{target := T, origin := O, input := I, finding := F}) ->
            ct:pal(
                "finding~n  target:  ~p~n  origin:  ~s~n  input:   ~s~n  finding: ~p",
                [T, O, iolist_to_binary(nhttp_fuzz_target:format_hex(I)), F]
            )
        end,
        Reports
    ),
    ct:fail({fuzz_findings, length(Reports), {seed, Seed}}).

-doc """
One seed per behaviour, not one per run. A campaign that finds a systemic
defect reports every hit but keeps a single corpus file for each target and
finding class.
""".
-spec distinct([map()]) -> [map()].
distinct(Reports) ->
    Keyed = [{{maps:get(target, R), element(1, maps:get(finding, R))}, R} || R <- Reports],
    maps:values(maps:from_list(lists:reverse(Keyed))).

-spec record_crash(map(), integer()) -> file:filename().
record_crash(#{target := Target, origin := Origin, input := Input, finding := Finding}, Seed) ->
    Comment = io_lib:format("~s finding from seed ~p: ~0p", [Origin, Seed, element(1, Finding)]),
    nhttp_fuzz_target:write_crash(Target, Input, Comment).

-spec env_int(string(), integer()) -> integer().
env_int(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        "" -> Default;
        Value -> list_to_integer(string:trim(Value))
    end.

-doc """
The BEAM shape of CVE-2026-46527: a degenerate input reaches a code path that
assumes a non-empty structure. The C++ defect calls `front()` on an empty
vector, and this raises `badarg` on the caller's process.
""".
-spec degenerate([term()]) -> term().
degenerate(List) ->
    hd(List).
