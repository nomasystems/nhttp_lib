%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_encoder_instruction_SUITE).

-moduledoc "QPACK encoder instruction encode/decode test suite (RFC 9204).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, set_capacity},
        {group, insert_name_ref},
        {group, insert_literal_name},
        {group, duplicate},
        {group, error_handling},
        {group, multiple_instructions}
    ].

groups() ->
    [
        {set_capacity, [parallel], [
            set_capacity_small,
            set_capacity_large,
            set_capacity_roundtrip
        ]},
        {insert_name_ref, [parallel], [
            insert_name_ref_static,
            insert_name_ref_dynamic,
            insert_name_ref_huffman,
            insert_name_ref_roundtrip
        ]},
        {insert_literal_name, [parallel], [
            insert_literal_name_plain,
            insert_literal_name_huffman,
            insert_literal_name_roundtrip
        ]},
        {duplicate, [parallel], [
            duplicate_small,
            duplicate_large,
            duplicate_roundtrip
        ]},
        {error_handling, [parallel], [
            decode_empty,
            decode_truncated_set_capacity,
            decode_truncated_name_ref
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
%%% SET CAPACITY TESTS
%%%-----------------------------------------------------------------------------

set_capacity_small(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(0)
    ),
    ?assertEqual(
        {ok, {set_capacity, 0}, <<>>},
        nhttp_qpack_encoder_instruction:decode(Encoded)
    ).

set_capacity_large(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(4096)
    ),
    ?assertEqual(
        {ok, {set_capacity, 4096}, <<>>},
        nhttp_qpack_encoder_instruction:decode(Encoded)
    ).

set_capacity_roundtrip(_Config) ->
    Values = [0, 1, 31, 32, 255, 1024, 4096, 16384],
    lists:foreach(
        fun(Cap) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_encoder_instruction:encode_set_capacity(Cap)
            ),
            ?assertEqual(
                {ok, {set_capacity, Cap}, <<>>},
                nhttp_qpack_encoder_instruction:decode(Encoded)
            )
        end,
        Values
    ).

%%%-----------------------------------------------------------------------------
%%% INSERT NAME REF TESTS
%%%-----------------------------------------------------------------------------

insert_name_ref_static(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_name_ref(
            static, 17, <<"GET">>, false
        )
    ),
    ?assertEqual(
        {ok, {insert_name_ref, static, 17, <<"GET">>}, <<>>},
        nhttp_qpack_encoder_instruction:decode(Encoded)
    ).

insert_name_ref_dynamic(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_name_ref(
            dynamic, 0, <<"test">>, false
        )
    ),
    ?assertEqual(
        {ok, {insert_name_ref, dynamic, 0, <<"test">>}, <<>>},
        nhttp_qpack_encoder_instruction:decode(Encoded)
    ).

insert_name_ref_huffman(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_name_ref(
            static, 17, <<"GET">>, true
        )
    ),
    {ok, {insert_name_ref, static, 17, Value}, <<>>} =
        nhttp_qpack_encoder_instruction:decode(Encoded),
    ?assertEqual(<<"GET">>, Value).

insert_name_ref_roundtrip(_Config) ->
    Cases = [
        {static, 0, <<"/">>},
        {static, 17, <<"GET">>},
        {static, 23, <<"https">>},
        {dynamic, 0, <<"test">>},
        {dynamic, 5, <<"hello world">>},
        {dynamic, 100, <<>>}
    ],
    lists:foreach(
        fun({Table, Index, Val}) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_encoder_instruction:encode_insert_name_ref(
                    Table, Index, Val, false
                )
            ),
            ?assertEqual(
                {ok, {insert_name_ref, Table, Index, Val}, <<>>},
                nhttp_qpack_encoder_instruction:decode(Encoded)
            )
        end,
        Cases
    ).

%%%-----------------------------------------------------------------------------
%%% INSERT LITERAL NAME TESTS
%%%-----------------------------------------------------------------------------

insert_literal_name_plain(_Config) ->
    Name = <<"x-custom-header">>,
    Value = <<"custom-value">>,
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            Name, Value, false
        )
    ),
    ?assertEqual(
        {ok, {insert_literal_name, Name, Value}, <<>>},
        nhttp_qpack_encoder_instruction:decode(Encoded)
    ).

insert_literal_name_huffman(_Config) ->
    Name = <<"x-custom-header">>,
    Value = <<"custom-value">>,
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            Name, Value, true
        )
    ),
    {ok, {insert_literal_name, DecName, DecValue}, <<>>} =
        nhttp_qpack_encoder_instruction:decode(Encoded),
    ?assertEqual(Name, DecName),
    ?assertEqual(Value, DecValue).

insert_literal_name_roundtrip(_Config) ->
    Cases = [
        {<<"content-type">>, <<"text/html">>},
        {<<"x-request-id">>, <<"abc-123">>},
        {<<"server">>, <<"erlang">>},
        {<<"empty">>, <<>>},
        {<<"a">>, <<"b">>}
    ],
    lists:foreach(
        fun({Name, Value}) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_encoder_instruction:encode_insert_literal_name(
                    Name, Value, false
                )
            ),
            ?assertEqual(
                {ok, {insert_literal_name, Name, Value}, <<>>},
                nhttp_qpack_encoder_instruction:decode(Encoded)
            )
        end,
        Cases
    ).

%%%-----------------------------------------------------------------------------
%%% DUPLICATE TESTS
%%%-----------------------------------------------------------------------------

duplicate_small(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_duplicate(0)
    ),
    ?assertEqual(
        {ok, {duplicate, 0}, <<>>},
        nhttp_qpack_encoder_instruction:decode(Encoded)
    ).

duplicate_large(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_duplicate(100)
    ),
    ?assertEqual(
        {ok, {duplicate, 100}, <<>>},
        nhttp_qpack_encoder_instruction:decode(Encoded)
    ).

duplicate_roundtrip(_Config) ->
    Indices = [0, 1, 4, 30, 31, 100, 255, 1000],
    lists:foreach(
        fun(Index) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_encoder_instruction:encode_duplicate(Index)
            ),
            ?assertEqual(
                {ok, {duplicate, Index}, <<>>},
                nhttp_qpack_encoder_instruction:decode(Encoded)
            )
        end,
        Indices
    ).

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

decode_empty(_Config) ->
    ?assertEqual(
        {error, incomplete},
        nhttp_qpack_encoder_instruction:decode(<<>>)
    ).

decode_truncated_set_capacity(_Config) ->
    Truncated = <<2#00111111:8>>,
    ?assertEqual(
        {error, incomplete},
        nhttp_qpack_encoder_instruction:decode(Truncated)
    ).

decode_truncated_name_ref(_Config) ->
    Full = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_name_ref(
            static, 17, <<"GET">>, false
        )
    ),
    Truncated = binary:part(Full, 0, 1),
    ?assertEqual(
        {error, incomplete},
        nhttp_qpack_encoder_instruction:decode(Truncated)
    ).

%%%-----------------------------------------------------------------------------
%%% MULTIPLE INSTRUCTIONS TESTS
%%%-----------------------------------------------------------------------------

decode_multiple(_Config) ->
    I1 = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(4096)
    ),
    I2 = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_name_ref(
            static, 17, <<"GET">>, false
        )
    ),
    I3 = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_duplicate(5)
    ),
    Combined = <<I1/binary, I2/binary, I3/binary>>,

    {ok, Dec1, Rest1} =
        nhttp_qpack_encoder_instruction:decode(Combined),
    ?assertEqual({set_capacity, 4096}, Dec1),

    {ok, Dec2, Rest2} =
        nhttp_qpack_encoder_instruction:decode(Rest1),
    ?assertEqual({insert_name_ref, static, 17, <<"GET">>}, Dec2),

    {ok, Dec3, Rest3} =
        nhttp_qpack_encoder_instruction:decode(Rest2),
    ?assertEqual({duplicate, 5}, Dec3),
    ?assertEqual(<<>>, Rest3).
