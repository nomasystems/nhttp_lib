%%%-----------------------------------------------------------------------------
-module(nhttp_str_SUITE).

-moduledoc "Shared string literal codec test suite (RFC 7541 Section 5.2).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, plain},
        {group, huffman},
        {group, roundtrip},
        {group, error_handling}
    ].

groups() ->
    [
        {plain, [parallel], [
            plain_empty,
            plain_short,
            plain_long
        ]},
        {huffman, [parallel], [
            huffman_short,
            huffman_known_value
        ]},
        {roundtrip, [parallel], [
            roundtrip_plain,
            roundtrip_huffman,
            roundtrip_with_trailing_data
        ]},
        {error_handling, [parallel], [
            decode_empty,
            decode_incomplete_length,
            decode_incomplete_data,
            decode_invalid_huffman
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
%%% PLAIN STRING TESTS
%%%-----------------------------------------------------------------------------

plain_empty(_Config) ->
    Encoded = iolist_to_binary(nhttp_str:encode(<<>>, false)),
    ?assertEqual({ok, <<>>, <<>>}, nhttp_str:decode(Encoded)).

plain_short(_Config) ->
    Encoded = iolist_to_binary(nhttp_str:encode(<<"hello">>, false)),
    ?assertEqual({ok, <<"hello">>, <<>>}, nhttp_str:decode(Encoded)).

plain_long(_Config) ->
    LongStr = binary:copy(<<"x">>, 200),
    Encoded = iolist_to_binary(nhttp_str:encode(LongStr, false)),
    ?assert(byte_size(Encoded) > 200),
    ?assertEqual({ok, LongStr, <<>>}, nhttp_str:decode(Encoded)).

%%%-----------------------------------------------------------------------------
%%% HUFFMAN STRING TESTS
%%%-----------------------------------------------------------------------------

huffman_short(_Config) ->
    Encoded = iolist_to_binary(nhttp_str:encode(<<"hello">>, true)),
    {ok, <<"hello">>, <<>>} = nhttp_str:decode(Encoded),
    <<1:1, _/bits>> = Encoded.

huffman_known_value(_Config) ->
    Input = <<"www.example.com">>,
    Encoded = iolist_to_binary(nhttp_str:encode(Input, true)),
    <<1:1, _/bits>> = Encoded,
    ?assertEqual(13, byte_size(Encoded)),
    ?assertEqual({ok, Input, <<>>}, nhttp_str:decode(Encoded)).

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP TESTS
%%%-----------------------------------------------------------------------------

roundtrip_plain(_Config) ->
    Strings = [<<>>, <<"a">>, <<"hello">>, binary:copy(<<"x">>, 200)],
    lists:foreach(fun roundtrip_plain_string/1, Strings).

roundtrip_huffman(_Config) ->
    Strings = [<<>>, <<"a">>, <<"hello">>, binary:copy(<<"x">>, 200)],
    lists:foreach(fun roundtrip_huffman_string/1, Strings).

roundtrip_with_trailing_data(_Config) ->
    Trailing = <<16#DE, 16#AD, 16#BE, 16#EF>>,
    PlainEnc = iolist_to_binary(nhttp_str:encode(<<"test">>, false)),
    PlainInput = <<PlainEnc/binary, Trailing/binary>>,
    ?assertEqual({ok, <<"test">>, Trailing}, nhttp_str:decode(PlainInput)),
    HuffEnc = iolist_to_binary(nhttp_str:encode(<<"test">>, true)),
    HuffInput = <<HuffEnc/binary, Trailing/binary>>,
    ?assertEqual({ok, <<"test">>, Trailing}, nhttp_str:decode(HuffInput)).

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

decode_empty(_Config) ->
    ?assertEqual({error, incomplete}, nhttp_str:decode(<<>>)).

decode_incomplete_length(_Config) ->
    ?assertEqual({error, incomplete}, nhttp_str:decode(<<16#FF>>)).

decode_incomplete_data(_Config) ->
    ?assertEqual({error, incomplete}, nhttp_str:decode(<<0:1, 10:7, "abc">>)).

decode_invalid_huffman(_Config) ->
    ?assertEqual(
        {error, invalid_huffman},
        nhttp_str:decode(<<1:1, 4:7, 0, 0, 0, 0>>)
    ).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

roundtrip_plain_string(Str) ->
    Encoded = iolist_to_binary(nhttp_str:encode(Str, false)),
    {ok, Str, <<>>} = nhttp_str:decode(Encoded).

roundtrip_huffman_string(Str) ->
    Encoded = iolist_to_binary(nhttp_str:encode(Str, true)),
    {ok, Str, <<>>} = nhttp_str:decode(Encoded).
