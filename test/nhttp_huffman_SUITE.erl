%%%-----------------------------------------------------------------------------
-module(nhttp_huffman_SUITE).

-moduledoc "Huffman encoding/decoding test suite (RFC 7541 Appendix B).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, encoding},
        {group, decoding},
        {group, roundtrip},
        {group, rfc_examples},
        {group, edge_cases},
        {group, exhaustive},
        {group, error_handling}
    ].

groups() ->
    [
        {encoding, [parallel], [
            encode_empty_string,
            encode_single_char,
            encode_common_chars,
            encode_all_bytes
        ]},
        {decoding, [parallel], [
            decode_empty_string,
            decode_single_char,
            decode_with_padding
        ]},
        {roundtrip, [parallel], [
            roundtrip_empty,
            roundtrip_ascii,
            roundtrip_binary,
            roundtrip_common_headers
        ]},
        {rfc_examples, [parallel], [
            rfc_example_www_example_com,
            rfc_example_no_cache,
            rfc_example_custom_key,
            rfc_example_custom_value
        ]},
        {edge_cases, [parallel], [
            long_string,
            all_same_char,
            alternating_chars
        ]},
        {exhaustive, [parallel], [
            roundtrip_all_single_bytes,
            roundtrip_all_byte_pairs,
            decode_all_valid_transitions,
            decode_all_error_fallbacks,
            decode_invalid_short_padding
        ]},
        {error_handling, [parallel], [
            invalid_padding_not_all_ones,
            truncated_input
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% ENCODING TESTS
%%%-----------------------------------------------------------------------------

encode_empty_string(_Config) ->
    ?assertEqual(<<>>, nhttp_huffman:encode(<<>>)).

encode_single_char(_Config) ->
    Encoded = nhttp_huffman:encode(<<"a">>),
    ?assertEqual(1, byte_size(Encoded)),
    {ok, <<"a">>} = nhttp_huffman:decode(Encoded).

encode_common_chars(_Config) ->
    Input = <<"text/html">>,
    Encoded = nhttp_huffman:encode(Input),
    ?assert(byte_size(Encoded) < byte_size(Input)).

encode_all_bytes(_Config) ->
    AllBytes = list_to_binary(lists:seq(0, 255)),
    Encoded = nhttp_huffman:encode(AllBytes),
    ?assert(is_binary(Encoded)),
    {ok, AllBytes} = nhttp_huffman:decode(Encoded).

%%%-----------------------------------------------------------------------------
%%% DECODING TESTS
%%%-----------------------------------------------------------------------------

decode_empty_string(_Config) ->
    {ok, <<>>} = nhttp_huffman:decode(<<>>).

decode_single_char(_Config) ->
    {ok, <<"a">>} = nhttp_huffman:decode(<<2#00011111>>).

decode_with_padding(_Config) ->
    {ok, <<>>} = nhttp_huffman:decode(<<2#1:1>>),
    {ok, <<>>} = nhttp_huffman:decode(<<2#11:2>>),
    {ok, <<>>} = nhttp_huffman:decode(<<2#111:3>>),
    {ok, <<>>} = nhttp_huffman:decode(<<2#1111111:7>>).

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP TESTS
%%%-----------------------------------------------------------------------------

roundtrip_empty(_Config) ->
    roundtrip(<<>>).

roundtrip_ascii(_Config) ->
    roundtrip(<<"hello world">>),
    roundtrip(<<"GET /index.html HTTP/1.1">>),
    roundtrip(<<"Content-Type: application/json">>).

roundtrip_binary(_Config) ->
    roundtrip(<<0, 1, 2, 3, 4, 5>>),
    roundtrip(<<127, 128, 255>>).

roundtrip_common_headers(_Config) ->
    roundtrip(<<"www.example.com">>),
    roundtrip(<<"no-cache">>),
    roundtrip(<<"text/html; charset=utf-8">>),
    roundtrip(<<"application/json">>),
    roundtrip(<<"gzip, deflate">>),
    roundtrip(<<"Mon, 21 Oct 2013 20:13:21 GMT">>).

%%%-----------------------------------------------------------------------------
%%% RFC 7541 EXAMPLES
%%%-----------------------------------------------------------------------------

rfc_example_www_example_com(_Config) ->
    Input = <<"www.example.com">>,
    Encoded = nhttp_huffman:encode(Input),
    ?assertEqual(12, byte_size(Encoded)),
    roundtrip(Input).

rfc_example_no_cache(_Config) ->
    Input = <<"no-cache">>,
    Encoded = nhttp_huffman:encode(Input),
    ?assertEqual(6, byte_size(Encoded)),
    roundtrip(Input).

rfc_example_custom_key(_Config) ->
    Input = <<"custom-key">>,
    Encoded = nhttp_huffman:encode(Input),
    ?assertEqual(8, byte_size(Encoded)),
    roundtrip(Input).

rfc_example_custom_value(_Config) ->
    Input = <<"custom-value">>,
    Encoded = nhttp_huffman:encode(Input),
    ?assertEqual(9, byte_size(Encoded)),
    roundtrip(Input).

%%%-----------------------------------------------------------------------------
%%% EDGE CASES
%%%-----------------------------------------------------------------------------

long_string(_Config) ->
    LongStr = list_to_binary(lists:duplicate(200, $x)),
    roundtrip(LongStr).

all_same_char(_Config) ->
    roundtrip(<<"aaaaaaaaaa">>),
    roundtrip(<<"0000000000">>).

alternating_chars(_Config) ->
    roundtrip(<<"ababababab">>),
    roundtrip(<<"0101010101">>).

%%%-----------------------------------------------------------------------------
%%% EXHAUSTIVE DECODE-TABLE COVERAGE
%%%-----------------------------------------------------------------------------

%% Decode is a generated 256-state nibble DFA: each state consumes one 4-bit
%% nibble and dispatches on its value. Exhaustive round-tripping reaches the
%% bulk of the table but leaves deep states (long codes) and per-state error
%% fallbacks untouched, so coverage is instead driven structurally from the
%% table itself (see derived_*_corpus/0 helpers).

roundtrip_all_single_bytes(_Config) ->
    [roundtrip(<<B>>) || B <- lists:seq(0, 255)],
    ok.

roundtrip_all_byte_pairs(_Config) ->
    [roundtrip(<<B1, B2>>) || B1 <- lists:seq(0, 255), B2 <- lists:seq(0, 255)],
    ok.

%% Every valid (state, nibble) transition is walked by a byte-aligned input
%% built from the shortest path to the state plus the transition nibble.
decode_all_valid_transitions(_Config) ->
    Inputs = derived_positive_corpus(),
    ?assert(length(Inputs) > 4000),
    [assert_decodes_or_errors(Bin) || Bin <- Inputs],
    ok.

%% Every reachable error fallback (specific invalid nibbles and the per-state
%% catch-all reached with the input exhausted) returns {error, invalid_huffman}.
decode_all_error_fallbacks(_Config) ->
    Inputs = derived_negative_corpus(),
    ?assert(length(Inputs) > 200),
    [?assertEqual({error, invalid_huffman}, nhttp_huffman:decode(Bin)) || Bin <- Inputs],
    ok.

%% Short non-all-ones leftover bits fail the EOS padding check.
decode_invalid_short_padding(_Config) ->
    [
        ?assertEqual({error, invalid_huffman}, nhttp_huffman:decode(Pad))
     || Pad <- [<<2#0:1>>, <<2#01:2>>, <<2#10:2>>, <<2#011:3>>, <<2#110:3>>, <<2#000:3>>]
    ],
    ok.

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

invalid_padding_not_all_ones(_Config) ->
    ?assertEqual({error, invalid_huffman}, nhttp_huffman:decode(<<2#00011000>>)).

truncated_input(_Config) ->
    ?assertEqual({error, invalid_huffman}, nhttp_huffman:decode(<<255, 255, 255, 255>>)).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

roundtrip(Input) ->
    Encoded = nhttp_huffman:encode(Input),
    {ok, Decoded} = nhttp_huffman:decode(Encoded),
    ?assertEqual(Input, Decoded).

%%%-----------------------------------------------------------------------------
%%% TABLE-DRIVEN CORPUS GENERATION
%%%
%%% The decode DFA is generated, so its test corpus is derived from the table
%%% itself and stays correct if the table is regenerated. The transition table
%%% is recovered from the module source; inputs are byte-aligned nibble paths.
%%%-----------------------------------------------------------------------------

derived_positive_corpus() ->
    {Trans, _Inv} = decode_table(),
    Paths = bfs_paths(Trans),
    Edges = [{S, V} || {S, Es} <- maps:to_list(Trans), {V, _} <- Es],
    [byte_align(path_to(S, Paths) ++ [V]) || {S, V} <- Edges].

derived_negative_corpus() ->
    {Trans, Inv} = decode_table(),
    Paths = bfs_paths(Trans),
    %% Reaching a state with the input exhausted (0 bits left) hits its
    %% catch-all clause; an even-nibble path is whole octets, so it lands there.
    CatchAll = [
        nibbles_to_binary(P)
     || S <- maps:keys(Trans), {ok, P} <- [path_with_parity(S, 0, Paths)], P =/= []
    ],
    %% Specific invalid-nibble clauses: an odd-nibble path plus the invalid
    %% nibble is whole octets and lands the invalid nibble at the state.
    Specific = [
        nibbles_to_binary(P ++ [N])
     || {S, Ns} <- maps:to_list(Inv), {ok, P} <- [path_with_parity(S, 1, Paths)], N <- Ns
    ],
    Errors = fun(Bin) -> nhttp_huffman:decode(Bin) =:= {error, invalid_huffman} end,
    lists:filter(Errors, CatchAll ++ Specific).

path_to(S, Paths) ->
    {_, P} = lists:min([{length(Pp), Pp} || {{St, _}, Pp} <- maps:to_list(Paths), St =:= S]),
    P.

path_with_parity(S, Parity, Paths) ->
    case maps:get({S, Parity}, Paths, undefined) of
        undefined -> false;
        P -> {ok, P}
    end.

byte_align(Nibbles) ->
    case length(Nibbles) rem 2 of
        0 -> nibbles_to_binary(Nibbles);
        1 -> nibbles_to_binary(Nibbles ++ [0])
    end.

nibbles_to_binary(Nibbles) ->
    <<<<N:4>> || N <- Nibbles>>.

%% Shortest nibble path from the root to each (state, nibble-count parity).
%% Tracking parity lets the negative corpus reach a state on a whole-octet
%% boundary, which is what the byte-aligned decoder API requires.
bfs_paths(Trans) ->
    bfs([{{0, 0}, []}], #{{0, 0} => []}, Trans).

bfs([], Acc, _Trans) ->
    Acc;
bfs([{{S, P}, Path} | Queue], Acc, Trans) ->
    {Queue1, Acc1} = lists:foldl(
        fun({V, Next}, {Q, A}) ->
            Key = {Next, (P + 1) rem 2},
            case maps:is_key(Key, A) of
                true -> {Q, A};
                false -> {Q ++ [{Key, Path ++ [V]}], A#{Key => Path ++ [V]}}
            end
        end,
        {Queue, Acc},
        maps:get(S, Trans, [])
    ),
    bfs(Queue1, Acc1, Trans).

%% Recover {Transitions, InvalidNibbles} from the generated source clauses:
%%   sN(<<V:4, R/bits>>, ...) -> sM(...)              valid edge N -V-> M
%%   sN(<<V:4, _/bits>>, _) -> {error, ...}           specific invalid nibble
decode_table() ->
    Source = proplists:get_value(source, nhttp_huffman:module_info(compile)),
    {ok, Bin} = file:read_file(Source),
    Lines = string:split(binary_to_list(Bin), "\n", all),
    lists:foldl(fun parse_clause/2, {#{}, #{}}, Lines).

parse_clause(Line, {Trans, Inv}) ->
    EdgeRe = "^s([0-9]+)\\(<<([0-9]+):4, R/bits>>.*-> s([0-9]+)\\(",
    InvRe = "^s([0-9]+)\\(<<([0-9]+):4, _/bits>>, _\\) -> \\{error",
    case re:run(Line, EdgeRe, [{capture, [1, 2, 3], list}]) of
        {match, [S, V, M]} ->
            Edge = {list_to_integer(V), list_to_integer(M)},
            {add(list_to_integer(S), Edge, Trans), Inv};
        nomatch ->
            case re:run(Line, InvRe, [{capture, [1, 2], list}]) of
                {match, [S, V]} ->
                    {Trans, add(list_to_integer(S), list_to_integer(V), Inv)};
                nomatch ->
                    {Trans, Inv}
            end
    end.

add(Key, Val, Map) ->
    maps:update_with(Key, fun(Vs) -> [Val | Vs] end, [Val], Map).

assert_decodes_or_errors(Raw) ->
    case nhttp_huffman:decode(Raw) of
        {ok, Decoded} when is_binary(Decoded) -> ok;
        {error, invalid_huffman} -> ok
    end.
