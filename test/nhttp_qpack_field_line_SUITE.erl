%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_field_line_SUITE).

-moduledoc "QPACK field line encode/decode test suite (RFC 9204).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, prefix},
        {group, indexed},
        {group, literal_name_ref},
        {group, literal_post_base},
        {group, literal},
        {group, error_handling},
        {group, trailing_data}
    ].

groups() ->
    [
        {prefix, [parallel], [
            prefix_ric_zero,
            prefix_ric_base_equal,
            prefix_base_greater,
            prefix_base_less,
            prefix_roundtrip,
            prefix_invalid_ric
        ]},
        {indexed, [parallel], [
            indexed_static,
            indexed_dynamic,
            indexed_roundtrip,
            indexed_post_base,
            indexed_post_base_roundtrip
        ]},
        {literal_name_ref, [parallel], [
            literal_name_ref_static,
            literal_name_ref_dynamic,
            literal_name_ref_never_indexed,
            literal_name_ref_huffman,
            literal_name_ref_roundtrip
        ]},
        {literal_post_base, [parallel], [
            literal_post_base_name_ref,
            literal_post_base_never_indexed,
            literal_post_base_roundtrip
        ]},
        {literal, [parallel], [
            literal_plain,
            literal_huffman,
            literal_never_indexed,
            literal_roundtrip
        ]},
        {error_handling, [parallel], [
            decode_empty,
            decode_truncated_indexed,
            decode_prefix_empty
        ]},
        {trailing_data, [parallel], [
            representation_trailing_data
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
%%% PREFIX TESTS
%%%-----------------------------------------------------------------------------

prefix_ric_zero(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(0, 0, 128)
    ),
    {ok, Prefix, <<>>} =
        nhttp_qpack_field_line:decode_prefix(Encoded, 128, 0),
    ?assertEqual(0, maps:get(required_insert_count, Prefix)),
    ?assertEqual(0, maps:get(base, Prefix)).

prefix_ric_base_equal(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(5, 5, 128)
    ),
    {ok, Prefix, <<>>} =
        nhttp_qpack_field_line:decode_prefix(Encoded, 128, 10),
    ?assertEqual(5, maps:get(required_insert_count, Prefix)),
    ?assertEqual(5, maps:get(base, Prefix)).

prefix_base_greater(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(5, 8, 128)
    ),
    {ok, Prefix, <<>>} =
        nhttp_qpack_field_line:decode_prefix(Encoded, 128, 10),
    ?assertEqual(5, maps:get(required_insert_count, Prefix)),
    ?assertEqual(8, maps:get(base, Prefix)).

prefix_base_less(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(5, 3, 128)
    ),
    {ok, Prefix, <<>>} =
        nhttp_qpack_field_line:decode_prefix(Encoded, 128, 10),
    ?assertEqual(5, maps:get(required_insert_count, Prefix)),
    ?assertEqual(3, maps:get(base, Prefix)).

prefix_roundtrip(_Config) ->
    Cases = [
        {0, 0, 128, 0},
        {1, 1, 128, 1},
        {10, 10, 128, 20},
        {10, 15, 128, 20},
        {10, 5, 128, 20}
    ],
    lists:foreach(
        fun({RIC, Base, MaxEntries, TotalInserts}) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_field_line:encode_prefix(
                    RIC, Base, MaxEntries
                )
            ),
            {ok, Prefix, <<>>} =
                nhttp_qpack_field_line:decode_prefix(
                    Encoded, MaxEntries, TotalInserts
                ),
            ?assertEqual(
                RIC,
                maps:get(required_insert_count, Prefix)
            ),
            ?assertEqual(Base, maps:get(base, Prefix))
        end,
        Cases
    ).

prefix_invalid_ric(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(3, 3, 128)
    ),
    ?assertEqual(
        {error, invalid_required_insert_count},
        nhttp_qpack_field_line:decode_prefix(Encoded, 1, 0)
    ).

%%%-----------------------------------------------------------------------------
%%% INDEXED TESTS
%%%-----------------------------------------------------------------------------

indexed_static(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed, static, 17}, false
        )
    ),
    ?assertEqual(
        {ok, {indexed, static, 17}, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

indexed_dynamic(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed, dynamic, 3}, false
        )
    ),
    ?assertEqual(
        {ok, {indexed, dynamic, 3}, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

indexed_roundtrip(_Config) ->
    Cases = [
        {indexed, static, 0},
        {indexed, static, 1},
        {indexed, static, 62},
        {indexed, static, 63},
        {indexed, static, 100},
        {indexed, dynamic, 0},
        {indexed, dynamic, 1},
        {indexed, dynamic, 62},
        {indexed, dynamic, 63},
        {indexed, dynamic, 200}
    ],
    lists:foreach(
        fun(Rep) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_field_line:encode_representation(
                    Rep, false
                )
            ),
            ?assertEqual(
                {ok, Rep, <<>>},
                nhttp_qpack_field_line:decode_representation(
                    Encoded
                )
            )
        end,
        Cases
    ).

indexed_post_base(_Config) ->
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed_post_base, 2}, false
        )
    ),
    ?assertEqual(
        {ok, {indexed_post_base, 2}, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

indexed_post_base_roundtrip(_Config) ->
    Indices = [0, 1, 14, 15, 16, 100, 255],
    lists:foreach(
        fun(Index) ->
            Rep = {indexed_post_base, Index},
            Encoded = iolist_to_binary(
                nhttp_qpack_field_line:encode_representation(
                    Rep, false
                )
            ),
            ?assertEqual(
                {ok, Rep, <<>>},
                nhttp_qpack_field_line:decode_representation(
                    Encoded
                )
            )
        end,
        Indices
    ).

%%%-----------------------------------------------------------------------------
%%% LITERAL NAME REF TESTS
%%%-----------------------------------------------------------------------------

literal_name_ref_static(_Config) ->
    Rep = {literal_name_ref, static, 17, <<"GET">>, false},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, false
        )
    ),
    ?assertEqual(
        {ok, Rep, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

literal_name_ref_dynamic(_Config) ->
    Rep = {literal_name_ref, dynamic, 0, <<"test">>, false},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, false
        )
    ),
    ?assertEqual(
        {ok, Rep, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

literal_name_ref_never_indexed(_Config) ->
    Rep = {literal_name_ref, static, 17, <<"GET">>, true},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, false
        )
    ),
    ?assertEqual(
        {ok, Rep, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

literal_name_ref_huffman(_Config) ->
    Rep = {literal_name_ref, static, 17, <<"GET">>, false},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, true
        )
    ),
    {ok, Decoded, <<>>} =
        nhttp_qpack_field_line:decode_representation(Encoded),
    ?assertEqual(Rep, Decoded).

literal_name_ref_roundtrip(_Config) ->
    Cases = [
        {literal_name_ref, static, 0, <<"/">>, false},
        {literal_name_ref, static, 17, <<"GET">>, false},
        {literal_name_ref, static, 23, <<"https">>, true},
        {literal_name_ref, dynamic, 0, <<"test">>, false},
        {literal_name_ref, dynamic, 5, <<"hello">>, true},
        {literal_name_ref, dynamic, 100, <<>>, false}
    ],
    lists:foreach(
        fun(Rep) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_field_line:encode_representation(
                    Rep, false
                )
            ),
            ?assertEqual(
                {ok, Rep, <<>>},
                nhttp_qpack_field_line:decode_representation(
                    Encoded
                )
            )
        end,
        Cases
    ).

%%%-----------------------------------------------------------------------------
%%% LITERAL POST BASE TESTS
%%%-----------------------------------------------------------------------------

literal_post_base_name_ref(_Config) ->
    Rep = {literal_post_base_name_ref, 0, <<"val">>, false},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, false
        )
    ),
    ?assertEqual(
        {ok, Rep, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

literal_post_base_never_indexed(_Config) ->
    Rep = {literal_post_base_name_ref, 0, <<"val">>, true},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, false
        )
    ),
    ?assertEqual(
        {ok, Rep, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

literal_post_base_roundtrip(_Config) ->
    Cases = [
        {literal_post_base_name_ref, 0, <<"a">>, false},
        {literal_post_base_name_ref, 1, <<"test">>, false},
        {literal_post_base_name_ref, 6, <<"value">>, true},
        {literal_post_base_name_ref, 7, <<>>, false},
        {literal_post_base_name_ref, 50, <<"data">>, true}
    ],
    lists:foreach(
        fun(Rep) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_field_line:encode_representation(
                    Rep, false
                )
            ),
            ?assertEqual(
                {ok, Rep, <<>>},
                nhttp_qpack_field_line:decode_representation(
                    Encoded
                )
            )
        end,
        Cases
    ).

%%%-----------------------------------------------------------------------------
%%% LITERAL TESTS
%%%-----------------------------------------------------------------------------

literal_plain(_Config) ->
    Rep = {literal, <<"custom-header">>, <<"custom-value">>, false},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, false
        )
    ),
    ?assertEqual(
        {ok, Rep, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

literal_huffman(_Config) ->
    Rep = {literal, <<"custom-header">>, <<"custom-value">>, false},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, true
        )
    ),
    {ok, Decoded, <<>>} =
        nhttp_qpack_field_line:decode_representation(Encoded),
    ?assertEqual(Rep, Decoded).

literal_never_indexed(_Config) ->
    Rep = {literal, <<"custom-header">>, <<"custom-value">>, true},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, false
        )
    ),
    ?assertEqual(
        {ok, Rep, <<>>},
        nhttp_qpack_field_line:decode_representation(Encoded)
    ).

literal_roundtrip(_Config) ->
    Cases = [
        {literal, <<"a">>, <<"b">>, false},
        {literal, <<"content-type">>, <<"text/html">>, false},
        {literal, <<"x-id">>, <<"abc-123">>, true},
        {literal, <<"server">>, <<"erlang">>, false},
        {literal, <<"empty">>, <<>>, false}
    ],
    lists:foreach(
        fun(Rep) ->
            Encoded = iolist_to_binary(
                nhttp_qpack_field_line:encode_representation(
                    Rep, false
                )
            ),
            ?assertEqual(
                {ok, Rep, <<>>},
                nhttp_qpack_field_line:decode_representation(
                    Encoded
                )
            )
        end,
        Cases
    ).

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

decode_empty(_Config) ->
    ?assertEqual(
        {error, incomplete},
        nhttp_qpack_field_line:decode_representation(<<>>)
    ).

decode_truncated_indexed(_Config) ->
    Truncated = <<2#11111111:8>>,
    ?assertEqual(
        {error, incomplete},
        nhttp_qpack_field_line:decode_representation(Truncated)
    ).

decode_prefix_empty(_Config) ->
    ?assertEqual(
        {error, incomplete},
        nhttp_qpack_field_line:decode_prefix(<<>>, 128, 0)
    ).

%%%-----------------------------------------------------------------------------
%%% TRAILING DATA TESTS
%%%-----------------------------------------------------------------------------

representation_trailing_data(_Config) ->
    Trailing = <<16#DE, 16#AD, 16#BE, 16#EF>>,
    Rep = {indexed, static, 17},
    Encoded = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            Rep, false
        )
    ),
    Combined = <<Encoded/binary, Trailing/binary>>,
    {ok, Decoded, Rest} =
        nhttp_qpack_field_line:decode_representation(Combined),
    ?assertEqual(Rep, Decoded),
    ?assertEqual(Trailing, Rest).
