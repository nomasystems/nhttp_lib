%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_decoder_instruction_SUITE).

-moduledoc "QPACK decoder instruction encode/decode test suite.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_ack},
        {group, stream_cancellation},
        {group, insert_count_increment},
        {group, error_handling},
        {group, multiple_instructions}
    ].

groups() ->
    [
        {section_ack, [parallel], [
            section_ack_small,
            section_ack_large,
            section_ack_roundtrip
        ]},
        {stream_cancellation, [parallel], [
            stream_cancellation_small,
            stream_cancellation_large,
            stream_cancellation_roundtrip
        ]},
        {insert_count_increment, [parallel], [
            increment_small,
            increment_large,
            increment_roundtrip
        ]},
        {error_handling, [parallel], [
            decode_empty,
            decode_truncated
        ]},
        {multiple_instructions, [parallel], [
            decode_multiple
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
%%% SECTION ACK TESTS
%%%-----------------------------------------------------------------------------

section_ack_small(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_section_ack(0)
    ),
    ?assertMatch(<<1:1, _:7, _/binary>>, Encoded),
    ?assertEqual(
        {ok, {section_ack, 0}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

section_ack_large(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_section_ack(1000)
    ),
    ?assert(byte_size(Encoded) > 1),
    ?assertEqual(
        {ok, {section_ack, 1000}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

section_ack_roundtrip(_Config) ->
    StreamId = 42,
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_section_ack(StreamId)
    ),
    ?assertEqual(
        {ok, {section_ack, StreamId}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

%%%-----------------------------------------------------------------------------
%%% STREAM CANCELLATION TESTS
%%%-----------------------------------------------------------------------------

stream_cancellation_small(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_stream_cancellation(1)
    ),
    ?assertMatch(<<0:1, 1:1, _:6, _/binary>>, Encoded),
    ?assertEqual(
        {ok, {stream_cancellation, 1}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

stream_cancellation_large(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_stream_cancellation(500)
    ),
    ?assert(byte_size(Encoded) > 1),
    ?assertEqual(
        {ok, {stream_cancellation, 500}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

stream_cancellation_roundtrip(_Config) ->
    StreamId = 17,
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_stream_cancellation(
            StreamId
        )
    ),
    ?assertEqual(
        {ok, {stream_cancellation, StreamId}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

%%%-----------------------------------------------------------------------------
%%% INSERT COUNT INCREMENT TESTS
%%%-----------------------------------------------------------------------------

increment_small(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_insert_count_increment(1)
    ),
    ?assertMatch(<<0:1, 0:1, _:6, _/binary>>, Encoded),
    ?assertEqual(
        {ok, {insert_count_increment, 1}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

increment_large(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_insert_count_increment(
            200
        )
    ),
    ?assert(byte_size(Encoded) > 1),
    ?assertEqual(
        {ok, {insert_count_increment, 200}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

increment_roundtrip(_Config) ->
    Increment = 55,
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_insert_count_increment(
            Increment
        )
    ),
    ?assertEqual(
        {ok, {insert_count_increment, Increment}, <<>>},
        nhttp_qpack_decoder_instruction:decode(Encoded)
    ).

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

decode_empty(_Config) ->
    ?assertEqual(
        {error, incomplete},
        nhttp_qpack_decoder_instruction:decode(<<>>)
    ).

decode_truncated(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_section_ack(1000)
    ),
    Truncated = binary:part(Encoded, 0, 1),
    ?assertEqual(
        {error, incomplete},
        nhttp_qpack_decoder_instruction:decode(Truncated)
    ).

%%%-----------------------------------------------------------------------------
%%% MULTIPLE INSTRUCTIONS TESTS
%%%-----------------------------------------------------------------------------

decode_multiple(_Config) ->
    Ack = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_section_ack(5)
    ),
    Cancel = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_stream_cancellation(10)
    ),
    Inc = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_insert_count_increment(3)
    ),
    Combined = <<Ack/binary, Cancel/binary, Inc/binary>>,

    {ok, Instr1, Rest1} =
        nhttp_qpack_decoder_instruction:decode(Combined),
    ?assertEqual({section_ack, 5}, Instr1),

    {ok, Instr2, Rest2} =
        nhttp_qpack_decoder_instruction:decode(Rest1),
    ?assertEqual({stream_cancellation, 10}, Instr2),

    {ok, Instr3, Rest3} =
        nhttp_qpack_decoder_instruction:decode(Rest2),
    ?assertEqual({insert_count_increment, 3}, Instr3),

    ?assertEqual(<<>>, Rest3).
