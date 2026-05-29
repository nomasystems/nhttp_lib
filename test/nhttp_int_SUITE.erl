%%%-----------------------------------------------------------------------------
-module(nhttp_int_SUITE).

-moduledoc "Shared prefixed integer codec test suite (RFC 7541 Section 5.1).".

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
        {group, error_handling}
    ].

groups() ->
    [
        {encoding, [parallel], [
            encode_5bit_small,
            encode_5bit_large,
            encode_5bit_boundary,
            encode_all_prefix_sizes,
            encode_zero
        ]},
        {decoding, [parallel], [
            decode_5bit_small,
            decode_5bit_large,
            decode_all_prefix_sizes,
            decode_with_extra_bits
        ]},
        {roundtrip, [parallel], [
            roundtrip_all_prefix_sizes,
            roundtrip_large_values
        ]},
        {error_handling, [parallel], [
            decode_incomplete_empty,
            decode_incomplete_multi_byte,
            decode_overflow
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

encode_5bit_small(_Config) ->
    Prefix = 2#010,
    Result = nhttp_int:enc5(10, Prefix),
    ?assertEqual(<<Prefix:3, 10:5>>, Result).

encode_5bit_large(_Config) ->
    Prefix = 2#010,
    Result = nhttp_int:enc5(1337, Prefix),
    ?assertEqual(<<Prefix:3, 31:5, 154, 10>>, Result).

encode_5bit_boundary(_Config) ->
    Prefix = 2#010,
    Result = nhttp_int:enc5(31, Prefix),
    ?assertEqual(<<Prefix:3, 31:5, 0>>, Result).

encode_all_prefix_sizes(_Config) ->
    ?assertEqual(<<2#10101:5, 5:3>>, nhttp_int:enc3(5, 2#10101)),
    ?assertEqual(<<2#1010:4, 5:4>>, nhttp_int:enc4(5, 2#1010)),
    ?assertEqual(<<2#010:3, 5:5>>, nhttp_int:enc5(5, 2#010)),
    ?assertEqual(<<2#01:2, 5:6>>, nhttp_int:enc6(5, 2#01)),
    ?assertEqual(<<0:1, 5:7>>, nhttp_int:enc7(5, 0)),
    ?assertEqual(<<5>>, nhttp_int:enc8(5)).

encode_zero(_Config) ->
    ?assertEqual(<<0>>, nhttp_int:enc3(0, 0)),
    ?assertEqual(<<0>>, nhttp_int:enc4(0, 0)),
    ?assertEqual(<<0>>, nhttp_int:enc5(0, 0)),
    ?assertEqual(<<0>>, nhttp_int:enc6(0, 0)),
    ?assertEqual(<<0>>, nhttp_int:enc7(0, 0)),
    ?assertEqual(<<0>>, nhttp_int:enc8(0)).

%%%-----------------------------------------------------------------------------
%%% DECODING TESTS
%%%-----------------------------------------------------------------------------

decode_5bit_small(_Config) ->
    ?assertEqual({ok, 10, <<>>}, nhttp_int:dec5(<<10:5>>)).

decode_5bit_large(_Config) ->
    ?assertEqual({ok, 1337, <<>>}, nhttp_int:dec5(<<31:5, 154, 10>>)).

decode_all_prefix_sizes(_Config) ->
    ?assertEqual({ok, 5, <<>>}, nhttp_int:dec3(<<5:3>>)),
    ?assertEqual({ok, 5, <<>>}, nhttp_int:dec4(<<5:4>>)),
    ?assertEqual({ok, 5, <<>>}, nhttp_int:dec5(<<5:5>>)),
    ?assertEqual({ok, 5, <<>>}, nhttp_int:dec6(<<5:6>>)),
    ?assertEqual({ok, 5, <<>>}, nhttp_int:dec7(<<5:7>>)),
    ?assertEqual({ok, 5, <<>>}, nhttp_int:dec8(<<5>>)).

decode_with_extra_bits(_Config) ->
    ?assertEqual({ok, 10, <<1:3>>}, nhttp_int:dec5(<<10:5, 1:3>>)),
    ?assertEqual({ok, 1337, <<16#AB>>}, nhttp_int:dec5(<<31:5, 154, 10, 16#AB>>)),
    ?assertEqual({ok, 42, <<16#CD>>}, nhttp_int:dec8(<<42, 16#CD>>)).

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP TESTS
%%%-----------------------------------------------------------------------------

roundtrip_all_prefix_sizes(_Config) ->
    lists:foreach(fun roundtrip_3/1, [0, 1, 6, 7, 8, 100, 1000, 65535]),
    lists:foreach(fun roundtrip_4/1, [0, 1, 14, 15, 16, 100, 1000, 65535]),
    lists:foreach(fun roundtrip_5/1, [0, 1, 30, 31, 32, 100, 1000, 65535]),
    lists:foreach(fun roundtrip_6/1, [0, 1, 62, 63, 64, 100, 1000, 65535]),
    lists:foreach(fun roundtrip_7/1, [0, 1, 126, 127, 128, 100, 1000, 65535]),
    lists:foreach(fun roundtrip_8/1, [0, 1, 254, 255, 256, 100, 1000, 65535]).

roundtrip_large_values(_Config) ->
    Values = [16#FFFF, 16#FFFFFF, 16#7FFFFFFE, 16#7FFFFFFF],
    lists:foreach(fun roundtrip_5/1, Values),
    lists:foreach(fun roundtrip_8/1, Values).

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

decode_incomplete_empty(_Config) ->
    ?assertEqual({error, incomplete}, nhttp_int:dec3(<<>>)),
    ?assertEqual({error, incomplete}, nhttp_int:dec4(<<>>)),
    ?assertEqual({error, incomplete}, nhttp_int:dec5(<<>>)),
    ?assertEqual({error, incomplete}, nhttp_int:dec6(<<>>)),
    ?assertEqual({error, incomplete}, nhttp_int:dec7(<<>>)),
    ?assertEqual({error, incomplete}, nhttp_int:dec8(<<>>)).

decode_incomplete_multi_byte(_Config) ->
    ?assertEqual({error, incomplete}, nhttp_int:dec5(<<31:5>>)),
    ?assertEqual({error, incomplete}, nhttp_int:dec5(<<31:5, 16#80>>)),
    ?assertEqual({error, incomplete}, nhttp_int:dec8(<<255>>)),
    ?assertEqual({error, incomplete}, nhttp_int:dec8(<<255, 16#80>>)).

decode_overflow(_Config) ->
    ?assertEqual(
        {error, overflow},
        nhttp_int:dec5(<<31:5, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#7F>>)
    ),
    ?assertEqual(
        {error, overflow},
        nhttp_int:dec8(<<255, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#7F>>)
    ).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

roundtrip_3(Value) ->
    Prefix = 2#10101,
    Bin = nhttp_int:enc3(Value, Prefix),
    <<_:5, IntBits/bits>> = Bin,
    ?assertEqual({ok, Value, <<>>}, nhttp_int:dec3(IntBits)).

roundtrip_4(Value) ->
    Prefix = 2#1010,
    Bin = nhttp_int:enc4(Value, Prefix),
    <<_:4, IntBits/bits>> = Bin,
    ?assertEqual({ok, Value, <<>>}, nhttp_int:dec4(IntBits)).

roundtrip_5(Value) ->
    Prefix = 2#010,
    Bin = nhttp_int:enc5(Value, Prefix),
    <<_:3, IntBits/bits>> = Bin,
    ?assertEqual({ok, Value, <<>>}, nhttp_int:dec5(IntBits)).

roundtrip_6(Value) ->
    Prefix = 2#01,
    Bin = nhttp_int:enc6(Value, Prefix),
    <<_:2, IntBits/bits>> = Bin,
    ?assertEqual({ok, Value, <<>>}, nhttp_int:dec6(IntBits)).

roundtrip_7(Value) ->
    Prefix = 1,
    Bin = nhttp_int:enc7(Value, Prefix),
    <<_:1, IntBits/bits>> = Bin,
    ?assertEqual({ok, Value, <<>>}, nhttp_int:dec7(IntBits)).

roundtrip_8(Value) ->
    Bin = nhttp_int:enc8(Value),
    ?assertEqual({ok, Value, <<>>}, nhttp_int:dec8(Bin)).
