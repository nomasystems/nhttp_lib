%%%-----------------------------------------------------------------------------
-module(nhttp_hpack_interop_SUITE).

-moduledoc """
HPACK Interoperability Test Suite.

Tests nhttp_hpack against the http2jp/hpack-test-case test vectors
(vendored as a git submodule at test/fixtures/hpack_test_data).

Each *_decode case iterates every story file emitted by a given reference
encoder and asserts that our decoder reproduces the exact header list
recorded alongside the wire bytes. Covers C (nghttp2), Go, Python,
Haskell and Swift implementations plus two nghttp2 variants that
exercise dynamic table size updates.

See: https://github.com/http2jp/hpack-test-case
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, cross_encoder_decode},
        {group, roundtrip},
        {group, static_coverage},
        {group, decoder_coverage},
        {group, error_coverage}
    ].

groups() ->
    [
        {cross_encoder_decode, [parallel], [
            decode_nghttp2,
            decode_nghttp2_change_table_size,
            decode_nghttp2_16384_4096,
            decode_go_hpack,
            decode_python_hpack,
            decode_node_http2_hpack,
            decode_haskell_http2_linear_huffman,
            decode_swift_nio_hpack_huffman
        ]},
        {roundtrip, [parallel], [
            roundtrip_all_stories,
            roundtrip_with_huffman
        ]},
        {static_coverage, [parallel], [
            static_table_all_entries,
            static_table_indexed_lookup
        ]},
        {decoder_coverage, [parallel], [
            decode_all_literal_types,
            decode_dynamic_table_update,
            decode_large_header
        ]},
        {error_coverage, [parallel], [
            decode_invalid_index,
            decode_incomplete_block,
            decode_table_size_exceeded
        ]}
    ].

init_per_suite(Config) ->
    DataDir = resolve_data_dir(),
    case filelib:is_dir(DataDir) of
        true ->
            ok;
        false ->
            ct:fail(
                "HPACK test data not found at ~s. "
                "Initialise submodules with: git submodule update --init",
                [DataDir]
            )
    end,
    ct:pal("Using HPACK data directory: ~s", [DataDir]),
    [{hpack_data_dir, DataDir} | Config].

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% CROSS-ENCODER DECODE TESTS
%%% Decode wire data from each reference encoder and verify headers match.
%%%-----------------------------------------------------------------------------

decode_nghttp2(Config) ->
    decode_encoder_dir(Config, "nghttp2", 4096).

decode_nghttp2_change_table_size(Config) ->
    decode_encoder_dir(Config, "nghttp2-change-table-size", 4096).

decode_nghttp2_16384_4096(Config) ->
    decode_encoder_dir(Config, "nghttp2-16384-4096", 16384).

decode_go_hpack(Config) ->
    decode_encoder_dir(Config, "go-hpack", 4096).

decode_python_hpack(Config) ->
    decode_encoder_dir(Config, "python-hpack", 4096).

decode_node_http2_hpack(Config) ->
    decode_encoder_dir(Config, "node-http2-hpack", 4096).

decode_haskell_http2_linear_huffman(Config) ->
    decode_encoder_dir(Config, "haskell-http2-linear-huffman", 4096).

decode_swift_nio_hpack_huffman(Config) ->
    decode_encoder_dir(Config, "swift-nio-hpack-huffman", 4096).

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP TESTS
%%% Encode headers from raw-data, then decode and verify.
%%%-----------------------------------------------------------------------------

roundtrip_all_stories(Config) ->
    DataDir = proplists:get_value(hpack_data_dir, Config),
    StoryFiles = story_files(DataDir, "raw-data"),
    lists:foreach(
        fun(File) -> run_roundtrip_story_file(File, #{huffman => false}) end,
        StoryFiles
    ).

roundtrip_with_huffman(Config) ->
    DataDir = proplists:get_value(hpack_data_dir, Config),
    StoryFiles = lists:sublist(story_files(DataDir, "raw-data"), 10),
    lists:foreach(
        fun(File) -> run_roundtrip_story_file(File, #{huffman => true}) end,
        StoryFiles
    ).

%%%-----------------------------------------------------------------------------
%%% STATIC TABLE COVERAGE
%%% Exercise all 61 static table entries.
%%%-----------------------------------------------------------------------------

static_table_all_entries(_Config) ->
    AllStaticHeaders = [
        {<<":authority">>, <<>>},
        {<<":method">>, <<"GET">>},
        {<<":method">>, <<"POST">>},
        {<<":path">>, <<"/">>},
        {<<":path">>, <<"/index.html">>},
        {<<":scheme">>, <<"http">>},
        {<<":scheme">>, <<"https">>},
        {<<":status">>, <<"200">>},
        {<<":status">>, <<"204">>},
        {<<":status">>, <<"206">>},
        {<<":status">>, <<"304">>},
        {<<":status">>, <<"400">>},
        {<<":status">>, <<"404">>},
        {<<":status">>, <<"500">>},
        {<<"accept-charset">>, <<>>},
        {<<"accept-encoding">>, <<"gzip, deflate">>},
        {<<"accept-language">>, <<>>},
        {<<"accept-ranges">>, <<>>},
        {<<"accept">>, <<>>},
        {<<"access-control-allow-origin">>, <<>>},
        {<<"age">>, <<>>},
        {<<"allow">>, <<>>},
        {<<"authorization">>, <<>>},
        {<<"cache-control">>, <<>>},
        {<<"content-disposition">>, <<>>},
        {<<"content-encoding">>, <<>>},
        {<<"content-language">>, <<>>},
        {<<"content-length">>, <<>>},
        {<<"content-location">>, <<>>},
        {<<"content-range">>, <<>>},
        {<<"content-type">>, <<>>},
        {<<"cookie">>, <<>>},
        {<<"date">>, <<>>},
        {<<"etag">>, <<>>},
        {<<"expect">>, <<>>},
        {<<"expires">>, <<>>},
        {<<"from">>, <<>>},
        {<<"host">>, <<>>},
        {<<"if-match">>, <<>>},
        {<<"if-modified-since">>, <<>>},
        {<<"if-none-match">>, <<>>},
        {<<"if-range">>, <<>>},
        {<<"if-unmodified-since">>, <<>>},
        {<<"last-modified">>, <<>>},
        {<<"link">>, <<>>},
        {<<"location">>, <<>>},
        {<<"max-forwards">>, <<>>},
        {<<"proxy-authenticate">>, <<>>},
        {<<"proxy-authorization">>, <<>>},
        {<<"range">>, <<>>},
        {<<"referer">>, <<>>},
        {<<"refresh">>, <<>>},
        {<<"retry-after">>, <<>>},
        {<<"server">>, <<>>},
        {<<"set-cookie">>, <<>>},
        {<<"strict-transport-security">>, <<>>},
        {<<"transfer-encoding">>, <<>>},
        {<<"user-agent">>, <<>>},
        {<<"vary">>, <<>>},
        {<<"via">>, <<>>},
        {<<"www-authenticate">>, <<>>}
    ],
    lists:foreach(
        fun(Header) ->
            {ok, State} = nhttp_hpack:new(),
            {ok, Encoded, _} = nhttp_hpack:encode([Header], State),
            {ok, [Decoded], _} = nhttp_hpack:decode(iolist_to_binary(Encoded), State),
            ?assertEqual(Header, Decoded)
        end,
        AllStaticHeaders
    ).

static_table_indexed_lookup(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    {ok, [{<<":method">>, <<"GET">>}], _} = nhttp_hpack:decode(<<16#82>>, State),
    {ok, [{<<":method">>, <<"POST">>}], _} = nhttp_hpack:decode(<<16#83>>, State),
    {ok, [{<<":path">>, <<"/">>}], _} = nhttp_hpack:decode(<<16#84>>, State),
    {ok, [{<<":path">>, <<"/index.html">>}], _} = nhttp_hpack:decode(<<16#85>>, State),
    {ok, [{<<":scheme">>, <<"http">>}], _} = nhttp_hpack:decode(<<16#86>>, State),
    {ok, [{<<":scheme">>, <<"https">>}], _} = nhttp_hpack:decode(<<16#87>>, State),
    {ok, [{<<":status">>, <<"200">>}], _} = nhttp_hpack:decode(<<16#88>>, State),
    {ok, [{<<"accept-encoding">>, <<"gzip, deflate">>}], _} = nhttp_hpack:decode(<<16#90>>, State),
    ok.

%%%-----------------------------------------------------------------------------
%%% DECODER COVERAGE
%%% Test all decoder paths.
%%%-----------------------------------------------------------------------------

decode_all_literal_types(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    LiteralIndexingNew = <<16#40, 3, "foo", 3, "bar">>,
    {ok, [{<<"foo">>, <<"bar">>}], State1} = nhttp_hpack:decode(LiteralIndexingNew, State),
    ?assertNot(nhttp_hpack:is_empty(State1)),

    LiteralNoIndexNew = <<16#00, 3, "baz", 3, "qux">>,
    {ok, [{<<"baz">>, <<"qux">>}], State2} = nhttp_hpack:decode(LiteralNoIndexNew, State),
    ?assert(nhttp_hpack:is_empty(State2)),

    LiteralNeverIndexNew = <<16#10, 8, "password", 6, "secret">>,
    {ok, [{<<"password">>, <<"secret">>}], State3} = nhttp_hpack:decode(
        LiteralNeverIndexNew, State
    ),
    ?assert(nhttp_hpack:is_empty(State3)),

    LiteralIndexingIdxName = <<16#44, 5, "/test">>,
    {ok, [{<<":path">>, <<"/test">>}], State4} = nhttp_hpack:decode(LiteralIndexingIdxName, State),
    ?assertNot(nhttp_hpack:is_empty(State4)),

    LiteralNoIndexIdxName = <<16#04, 5, "/page">>,
    {ok, [{<<":path">>, <<"/page">>}], _} = nhttp_hpack:decode(LiteralNoIndexIdxName, State),

    LiteralNeverIdxName7 = <<16#17, 3, "wss">>,
    {ok, [{<<":scheme">>, <<"wss">>}], _} = nhttp_hpack:decode(LiteralNeverIdxName7, State),

    LiteralNeverIdxName23 = <<16#1F, 16#08, 6, "Bearer">>,
    {ok, [{<<"authorization">>, <<"Bearer">>}], _} = nhttp_hpack:decode(
        LiteralNeverIdxName23, State
    ),

    ok.

decode_dynamic_table_update(_Config) ->
    {ok, State0} = nhttp_hpack:new(4096),
    SizeUpdateZero = <<16#20>>,
    {ok, [], State1} = nhttp_hpack:decode(SizeUpdateZero, State0),
    ?assertEqual(0, nhttp_hpack:table_size(State1)),

    SizeUpdate100 = <<16#3F, 16#45>>,
    {ok, [], State2} = nhttp_hpack:decode(SizeUpdate100, State0),
    ?assertEqual(0, nhttp_hpack:table_size(State2)),

    ok.

decode_large_header(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    LargeValue = binary:copy(<<"x">>, 200),
    LargeHeader = <<16#40, 3, "big", 16#7F, 16#49, LargeValue/binary>>,
    {ok, [{<<"big">>, LargeValue}], _} = nhttp_hpack:decode(LargeHeader, State),

    Headers = [{<<"x-large">>, LargeValue}],
    {ok, Encoded, _} = nhttp_hpack:encode(Headers, State, #{huffman => true}),
    {ok, Headers, _} = nhttp_hpack:decode(iolist_to_binary(Encoded), State),

    ok.

%%%-----------------------------------------------------------------------------
%%% ERROR COVERAGE
%%% Test error handling paths.
%%%-----------------------------------------------------------------------------

decode_invalid_index(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    InvalidIndex0 = <<16#80>>,
    {error, invalid_table_index} = nhttp_hpack:decode(InvalidIndex0, State),

    InvalidIndex100 = <<16#FF, 16#E5, 16#00>>,
    {error, invalid_table_index} = nhttp_hpack:decode(InvalidIndex100, State),

    ok.

decode_incomplete_block(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    Incomplete1 = <<16#40, 3, "fo">>,
    {error, incomplete_header_block} = nhttp_hpack:decode(Incomplete1, State),

    Incomplete2 = <<16#7F>>,
    {error, incomplete_header_block} = nhttp_hpack:decode(Incomplete2, State),

    ok.

decode_table_size_exceeded(_Config) ->
    {ok, State} = nhttp_hpack:new(100),
    TooLarge = <<16#3F, 16#A9, 16#01>>,
    {error, dynamic_table_size_exceeded} = nhttp_hpack:decode(TooLarge, State),

    ok.

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec resolve_data_dir() -> file:filename().
resolve_data_dir() ->
    filename:join([get_project_root(), "test", "fixtures", "hpack_test_data"]).

-spec get_project_root() -> file:filename().
get_project_root() ->
    SuiteDir = filename:dirname(code:which(?MODULE)),
    find_project_root(SuiteDir).

-spec find_project_root(file:filename()) -> file:filename().
find_project_root(Dir) ->
    RebarConfig = filename:join(Dir, "rebar.config"),
    case filelib:is_file(RebarConfig) of
        true ->
            Dir;
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir -> Dir;
                _ -> find_project_root(Parent)
            end
    end.

-spec story_files(file:filename(), string()) -> [file:filename()].
story_files(DataDir, SubDir) ->
    Dir = filename:join(DataDir, SubDir),
    Files = filelib:wildcard(filename:join(Dir, "story_*.json")),
    case Files of
        [] -> ct:fail("No story_*.json files found in ~s", [Dir]);
        _ -> Files
    end.

-spec decode_encoder_dir(ct_suite:ct_config(), string(), pos_integer()) -> ok.
decode_encoder_dir(Config, SubDir, MaxTableSize) ->
    DataDir = proplists:get_value(hpack_data_dir, Config),
    Files = story_files(DataDir, SubDir),
    ct:pal("[~s] decoding ~p stories", [SubDir, length(Files)]),
    lists:foreach(
        fun(File) -> run_decode_story_file(File, MaxTableSize) end,
        Files
    ).

-spec run_decode_story_file(file:filename(), pos_integer()) -> ok.
run_decode_story_file(Path, MaxTableSize) ->
    {ok, Bin} = file:read_file(Path),
    Json = json:decode(Bin),
    Cases = maps:get(<<"cases">>, Json),
    {ok, State} = nhttp_hpack:new(MaxTableSize),
    run_decode_cases(Cases, State, filename:basename(Path)).

-spec run_decode_cases([map()], nhttp_hpack:state(), string()) -> ok.
run_decode_cases([], _State, _File) ->
    ok;
run_decode_cases([Case | Rest], State, File) ->
    Wire = hex_to_binary(maps:get(<<"wire">>, Case)),
    ExpectedHeaders = parse_headers(maps:get(<<"headers">>, Case)),
    SeqNo = maps:get(<<"seqno">>, Case),
    case nhttp_hpack:decode(Wire, State) of
        {ok, DecodedHeaders, NewState} ->
            ?assertEqual(
                ExpectedHeaders,
                DecodedHeaders,
                #{file => File, seqno => SeqNo}
            ),
            run_decode_cases(Rest, NewState, File);
        {error, Reason} ->
            ct:fail("Decode failed for ~s seqno ~p: ~p", [File, SeqNo, Reason])
    end.

-spec run_roundtrip_story_file(file:filename(), nhttp_hpack:encode_opts()) -> ok.
run_roundtrip_story_file(Path, Opts) ->
    {ok, Bin} = file:read_file(Path),
    Json = json:decode(Bin),
    Cases = maps:get(<<"cases">>, Json),
    {ok, EncState} = nhttp_hpack:new(),
    {ok, DecState} = nhttp_hpack:new(),
    run_roundtrip_cases(Cases, EncState, DecState, Opts, filename:basename(Path)).

-spec run_roundtrip_cases(
    [map()],
    nhttp_hpack:state(),
    nhttp_hpack:state(),
    nhttp_hpack:encode_opts(),
    string()
) -> ok.
run_roundtrip_cases([], _EncState, _DecState, _Opts, _File) ->
    ok;
run_roundtrip_cases([Case | Rest], EncState, DecState, Opts, File) ->
    Headers = parse_headers(maps:get(<<"headers">>, Case)),
    SeqNo = maps:get(<<"seqno">>, Case, -1),
    {ok, Encoded, NewEncState} = nhttp_hpack:encode(Headers, EncState, Opts),
    case nhttp_hpack:decode(iolist_to_binary(Encoded), DecState) of
        {ok, DecodedHeaders, NewDecState} ->
            ?assertEqual(
                Headers,
                DecodedHeaders,
                #{file => File, seqno => SeqNo}
            ),
            run_roundtrip_cases(Rest, NewEncState, NewDecState, Opts, File);
        {error, Reason} ->
            ct:fail("Roundtrip decode failed for ~s seqno ~p: ~p", [File, SeqNo, Reason])
    end.

-spec parse_headers([map()]) -> nhttp_hpack:headers().
parse_headers(HeaderList) ->
    lists:map(
        fun(HeaderObj) ->
            [{Name, Value}] = maps:to_list(HeaderObj),
            {Name, Value}
        end,
        HeaderList
    ).

-spec hex_to_binary(binary()) -> binary().
hex_to_binary(HexString) ->
    hex_to_binary(HexString, <<>>).

-spec hex_to_binary(binary(), binary()) -> binary().
hex_to_binary(<<>>, Acc) ->
    Acc;
hex_to_binary(<<H1, H2, Rest/binary>>, Acc) ->
    Byte = hex_char(H1) * 16 + hex_char(H2),
    hex_to_binary(Rest, <<Acc/binary, Byte>>).

-spec hex_char(char()) -> 0..15.
hex_char(C) when C >= $0, C =< $9 -> C - $0;
hex_char(C) when C >= $a, C =< $f -> C - $a + 10;
hex_char(C) when C >= $A, C =< $F -> C - $A + 10.
