%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_SUITE).

-moduledoc """
QPACK integration test suite (RFC 9204).

Tests the full encode/decode roundtrip through the public nhttp_qpack
API, exercising static-only encoding, dynamic table insertion,
blocked stream handling, acknowledgment flow, and error paths.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

-define(TABLE_CAPACITY, 4096).
-define(TABLE_CONFIG, #{max_table_capacity => ?TABLE_CAPACITY, max_blocked_streams => 10}).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, static_only},
        {group, dynamic_table},
        {group, blocked_streams},
        {group, acknowledgment},
        {group, sequential},
        {group, reconcile},
        {group, error_paths},
        {group, decoder_coverage},
        {group, encode_lowercase},
        {group, field_validity}
    ].

groups() ->
    [
        {static_only, [parallel], [
            static_method_path,
            static_status_200,
            static_multiple_headers,
            static_literal_name
        ]},
        {dynamic_table, [parallel], [
            dynamic_insert_and_reference,
            dynamic_custom_headers,
            dynamic_eviction
        ]},
        {blocked_streams, [parallel], [
            blocked_then_unblocked,
            blocked_stream_limit
        ]},
        {acknowledgment, [parallel], [
            section_ack_updates_krc,
            stream_cancellation,
            insert_count_increment
        ]},
        {sequential, [], [
            multiple_field_sections,
            encoder_decoder_full_flow
        ]},
        {reconcile, [], [
            reconcile_dormant_until_peer,
            reconcile_peer_zero_stays_dormant,
            reconcile_min_capacity,
            reconcile_peer_blocked_zero,
            reconcile_then_steady_state_nonblocking
        ]},
        {error_paths, [parallel], [
            empty_field_section,
            decode_invalid_data
        ]},
        {decoder_coverage, [], [
            decoder_encoder_stream_instructions,
            decoder_duplicate_instruction,
            decoder_dynamic_name_ref,
            decoder_literal_name_ref_fields,
            decoder_post_base_fields,
            decoder_empty_encoder_stream
        ]},
        {encode_lowercase, [parallel], [
            mixed_case_name_encodes_as_lowercase,
            mixed_case_name_hits_the_static_entry,
            mixed_case_name_round_trips_lowercase,
            mixed_case_name_enters_the_table_lowercase,
            mixed_case_name_lowercases_the_insert_instruction
        ]},
        {field_validity, [parallel], [
            literal_uppercase_name_is_invalid_field,
            literal_name_with_interior_colon_is_invalid_field,
            literal_empty_name_is_invalid_field,
            literal_value_with_cr_is_invalid_field,
            literal_value_edge_whitespace_is_invalid_field,
            literal_name_ref_value_is_validated,
            literal_pseudo_header_name_is_accepted,
            encoder_stream_literal_name_is_validated,
            encoder_stream_name_ref_value_is_validated,
            refused_insert_leaves_the_dynamic_table_unchanged
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
%%% STATIC-ONLY TESTS
%%%-----------------------------------------------------------------------------

static_method_path(_Config) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{}),
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>}
    ],
    {ok, _Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    ?assertEqual(<<>>, iolist_to_binary(EncStream)),
    FieldBin = iolist_to_binary(FieldData),
    {ok, _Dec1, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec, 0, FieldBin),
    ?assertEqual(Headers, Decoded).

static_status_200(_Config) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{}),
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    Headers = [{<<":status">>, <<"200">>}],
    {ok, _Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    ?assertEqual(<<>>, iolist_to_binary(EncStream)),
    FieldBin = iolist_to_binary(FieldData),
    {ok, _Dec1, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec, 0, FieldBin),
    ?assertEqual(Headers, Decoded).

static_multiple_headers(_Config) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{}),
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":status">>, <<"200">>}
    ],
    {ok, _Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    ?assertEqual(<<>>, iolist_to_binary(EncStream)),
    FieldBin = iolist_to_binary(FieldData),
    {ok, _Dec1, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec, 0, FieldBin),
    ?assertEqual(Headers, Decoded).

static_literal_name(_Config) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{}),
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/custom/path">>}
    ],
    {ok, _Enc1, _EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    FieldBin = iolist_to_binary(FieldData),
    {ok, _Dec1, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec, 0, FieldBin),
    ?assertEqual(Headers, Decoded).

%%%-----------------------------------------------------------------------------
%%% DYNAMIC TABLE TESTS
%%%-----------------------------------------------------------------------------

dynamic_insert_and_reference(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Enc} = nhttp_qpack:new_encoder(Config),
    {ok, Dec} = nhttp_qpack:new_decoder(Config),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<"x-custom">>, <<"value1">>}
    ],
    {ok, Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    EncStreamBin = iolist_to_binary(EncStream),
    ?assert(byte_size(EncStreamBin) > 0),
    {ok, Dec1, []} =
        nhttp_qpack:feed_encoder_stream(Dec, EncStreamBin),
    FieldBin = iolist_to_binary(FieldData),
    {ok, Dec2, DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, 0, FieldBin),
    ?assertEqual(Headers, Decoded),
    DecStreamBin = iolist_to_binary(DecStream),
    case byte_size(DecStreamBin) > 0 of
        true ->
            {ok, _Enc2} =
                nhttp_qpack:feed_decoder_stream(Enc1, DecStreamBin);
        false ->
            ok
    end,
    _ = Dec2.

dynamic_custom_headers(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Enc} = nhttp_qpack:new_encoder(Config),
    {ok, Dec} = nhttp_qpack:new_decoder(Config),
    Headers = [
        {<<"x-foo">>, <<"bar">>},
        {<<"x-baz">>, <<"qux">>},
        {<<"x-hello">>, <<"world">>}
    ],
    {ok, _Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    EncStreamBin = iolist_to_binary(EncStream),
    {ok, Dec1, []} =
        nhttp_qpack:feed_encoder_stream(Dec, EncStreamBin),
    FieldBin = iolist_to_binary(FieldData),
    {ok, _Dec2, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, 0, FieldBin),
    ?assertEqual(Headers, Decoded).

dynamic_eviction(_Config) ->
    Config = #{max_table_capacity => 128, max_blocked_streams => 10},
    {ok, Enc} = nhttp_qpack:new_encoder(Config),
    {ok, Dec} = nhttp_qpack:new_decoder(Config),
    Headers1 = [{<<"x-key1">>, <<"val1">>}],
    {ok, Enc1, EncStream1, FieldData1} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers1),
    EncStreamBin1 = iolist_to_binary(EncStream1),
    {ok, Dec1, []} =
        nhttp_qpack:feed_encoder_stream(Dec, EncStreamBin1),
    FieldBin1 = iolist_to_binary(FieldData1),
    {ok, Dec2, DecStream1, Decoded1} =
        nhttp_qpack:decode_field_section(Dec1, 0, FieldBin1),
    ?assertEqual(Headers1, Decoded1),
    DecStreamBin1 = iolist_to_binary(DecStream1),
    {ok, Enc2} =
        case byte_size(DecStreamBin1) of
            0 -> {ok, Enc1};
            _ -> nhttp_qpack:feed_decoder_stream(Enc1, DecStreamBin1)
        end,
    Headers2 = [
        {<<"x-key2">>, <<"value-that-is-longer-to-force-eviction">>}
    ],
    {ok, _Enc3, EncStream2, FieldData2} =
        nhttp_qpack:encode_field_section(Enc2, 4, Headers2),
    EncStreamBin2 = iolist_to_binary(EncStream2),
    {ok, Dec3, _Unblocked} =
        nhttp_qpack:feed_encoder_stream(Dec2, EncStreamBin2),
    FieldBin2 = iolist_to_binary(FieldData2),
    {ok, _Dec4, _DecStream2, Decoded2} =
        nhttp_qpack:decode_field_section(Dec3, 4, FieldBin2),
    ?assertEqual(Headers2, Decoded2).

%%%-----------------------------------------------------------------------------
%%% BLOCKED STREAM TESTS
%%%-----------------------------------------------------------------------------

blocked_then_unblocked(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Enc} = nhttp_qpack:new_encoder(Config),
    {ok, Dec} = nhttp_qpack:new_decoder(Config),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<"x-request-id">>, <<"abc123">>}
    ],
    {ok, _Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    FieldBin = iolist_to_binary(FieldData),
    EncStreamBin = iolist_to_binary(EncStream),
    case nhttp_qpack:decode_field_section(Dec, 0, FieldBin) of
        {blocked, Dec1} ->
            {ok, Dec2, Unblocked} =
                nhttp_qpack:feed_encoder_stream(
                    Dec1, EncStreamBin
                ),
            ?assertEqual(1, length(Unblocked)),
            [{0, _DecStream, DecodedHeaders}] = Unblocked,
            ?assertEqual(Headers, DecodedHeaders),
            _ = Dec2;
        {ok, _Dec1, _DecStream, Decoded} ->
            ?assertEqual(Headers, Decoded)
    end.

blocked_stream_limit(_Config) ->
    Config = #{
        max_table_capacity => 4096,
        max_blocked_streams => 1
    },
    {ok, Enc} = nhttp_qpack:new_encoder(Config),
    {ok, Dec} = nhttp_qpack:new_decoder(
        Config#{max_blocked_streams => 1}
    ),
    Headers1 = [{<<"x-a">>, <<"1">>}],
    Headers2 = [{<<"x-b">>, <<"2">>}],
    {ok, Enc1, EncStream1, FieldData1} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers1),
    {ok, _Enc2, EncStream2, FieldData2} =
        nhttp_qpack:encode_field_section(Enc1, 4, Headers2),
    FieldBin1 = iolist_to_binary(FieldData1),
    FieldBin2 = iolist_to_binary(FieldData2),
    EncStreamBin1 = iolist_to_binary(EncStream1),
    EncStreamBin2 = iolist_to_binary(EncStream2),
    HasDynamic1 = byte_size(EncStreamBin1) > 0,
    HasDynamic2 = byte_size(EncStreamBin2) > 0,
    case {HasDynamic1, HasDynamic2} of
        {true, true} ->
            {blocked, Dec1} =
                nhttp_qpack:decode_field_section(Dec, 0, FieldBin1),
            ?assertMatch(
                {error, blocked_stream_limit},
                nhttp_qpack:decode_field_section(
                    Dec1, 4, FieldBin2
                )
            );
        _ ->
            ok
    end.

%%%-----------------------------------------------------------------------------
%%% ACKNOWLEDGMENT TESTS
%%%-----------------------------------------------------------------------------

section_ack_updates_krc(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Enc0} = nhttp_qpack:new_encoder(Config),
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    H1 = [{<<"x-token">>, <<"secret">>}],
    {ok, Enc1, EncStream1, FD1} =
        nhttp_qpack:encode_field_section(Enc0, 0, H1),
    EncBin1 = iolist_to_binary(EncStream1),
    {ok, Dec1, []} =
        nhttp_qpack:feed_encoder_stream(Dec0, EncBin1),
    FDBin1 = iolist_to_binary(FD1),
    {ok, Dec2, DecStream1, Decoded1} =
        nhttp_qpack:decode_field_section(Dec1, 0, FDBin1),
    ?assertEqual(H1, Decoded1),
    DecBin1 = iolist_to_binary(DecStream1),
    {ok, Enc2} =
        case byte_size(DecBin1) of
            0 -> {ok, Enc1};
            _ -> nhttp_qpack:feed_decoder_stream(Enc1, DecBin1)
        end,
    H2 = [{<<"x-token">>, <<"secret">>}],
    {ok, _Enc3, _EncStream2, FD2} =
        nhttp_qpack:encode_field_section(Enc2, 4, H2),
    FDBin2 = iolist_to_binary(FD2),
    {ok, _Dec3, _DecStream2, Decoded2} =
        nhttp_qpack:decode_field_section(Dec2, 4, FDBin2),
    ?assertEqual(H2, Decoded2).

stream_cancellation(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Enc0} = nhttp_qpack:new_encoder(Config),
    Headers = [{<<"x-cancel">>, <<"test">>}],
    {ok, Enc1, _EncStream, _FD} =
        nhttp_qpack:encode_field_section(Enc0, 0, Headers),
    CancelData = iolist_to_binary(
        nhttp_qpack_decoder_instruction:encode_stream_cancellation(0)
    ),
    {ok, _Enc2} = nhttp_qpack:feed_decoder_stream(Enc1, CancelData).

insert_count_increment(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Enc0} = nhttp_qpack:new_encoder(Config),
    Headers = [{<<"x-inc">>, <<"test">>}],
    {ok, Enc1, EncStream, _FD} =
        nhttp_qpack:encode_field_section(Enc0, 0, Headers),
    EncBin = iolist_to_binary(EncStream),
    case byte_size(EncBin) > 0 of
        true ->
            ICIData = iolist_to_binary(
                nhttp_qpack_decoder_instruction:encode_insert_count_increment(1)
            ),
            {ok, _Enc2} =
                nhttp_qpack:feed_decoder_stream(Enc1, ICIData);
        false ->
            ok
    end.

%%%-----------------------------------------------------------------------------
%%% SEQUENTIAL TESTS
%%%-----------------------------------------------------------------------------

multiple_field_sections(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 100},
    {ok, Enc0} = nhttp_qpack:new_encoder(Config),
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    Requests = [
        [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
        [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/api">>}],
        [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/index.html">>}],
        [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}]
    ],
    encode_decode_sequence(Requests, Enc0, Dec0, 0).

encoder_decoder_full_flow(_Config) ->
    Config = #{
        max_table_capacity => 4096,
        max_blocked_streams => 100,
        huffman => true
    },
    {ok, Enc0} = nhttp_qpack:new_encoder(Config),
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    H1 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    {Enc1, Dec1} = roundtrip_with_streams(Enc0, Dec0, 0, H1),
    H2 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/style.css">>},
        {<<":authority">>, <<"example.com">>}
    ],
    {Enc2, Dec2} = roundtrip_with_streams(Enc1, Dec1, 4, H2),
    H3 = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/api/data">>},
        {<<":authority">>, <<"example.com">>},
        {<<"content-type">>, <<"application/json">>}
    ],
    {_Enc3, _Dec3} = roundtrip_with_streams(Enc2, Dec2, 8, H3).

%%%-----------------------------------------------------------------------------
%%% RECONCILE TESTS (RFC 9204 Section 3.2.3 peer-limit negotiation)
%%%-----------------------------------------------------------------------------

dormant_encoder() ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{
        max_table_capacity => 0,
        configured_max_capacity => 4096,
        max_blocked_streams => 0,
        configured_max_blocked => 16
    }),
    Enc.

reconcile_dormant_until_peer(_Config) ->
    Enc0 = dormant_encoder(),
    Headers = [{<<":method">>, <<"GET">>}, {<<"x-custom">>, <<"value1">>}],
    {ok, _Enc1, EncStream0, FieldData0} =
        nhttp_qpack:encode_field_section(Enc0, 0, Headers),
    ?assertEqual(<<>>, iolist_to_binary(EncStream0)),
    {ok, DecZero} = nhttp_qpack:new_decoder(#{}),
    {ok, _, _, Decoded0} =
        nhttp_qpack:decode_field_section(DecZero, 0, iolist_to_binary(FieldData0)),
    ?assertEqual(Headers, Decoded0),

    Enc1 = nhttp_qpack:reconcile_peer_limits(4096, 16, Enc0),
    {ok, Dec0} = nhttp_qpack:new_decoder(#{max_table_capacity => 4096, max_blocked_streams => 16}),
    {ok, _Enc2, EncStream1, FieldData1} =
        nhttp_qpack:encode_field_section(Enc1, 0, Headers),
    EncBin1 = iolist_to_binary(EncStream1),
    ?assert(byte_size(EncBin1) > 0),
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, EncBin1),
    {ok, _Dec2, _DecStream, Decoded1} =
        nhttp_qpack:decode_field_section(Dec1, 0, iolist_to_binary(FieldData1)),
    ?assertEqual(Headers, Decoded1).

reconcile_peer_zero_stays_dormant(_Config) ->
    Enc0 = dormant_encoder(),
    Enc1 = nhttp_qpack:reconcile_peer_limits(0, 0, Enc0),
    Headers = [{<<"x-custom">>, <<"value1">>}],
    {ok, _Enc2, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc1, 0, Headers),
    ?assertEqual(<<>>, iolist_to_binary(EncStream)),
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    {ok, _, _, Decoded} =
        nhttp_qpack:decode_field_section(Dec, 0, iolist_to_binary(FieldData)),
    ?assertEqual(Headers, Decoded).

reconcile_min_capacity(_Config) ->
    Enc0 = dormant_encoder(),
    Enc1 = nhttp_qpack:reconcile_peer_limits(128, 10, Enc0),
    {ok, Dec0} = nhttp_qpack:new_decoder(#{max_table_capacity => 128, max_blocked_streams => 10}),
    Headers = [{<<"x-k">>, <<"v">>}],
    {ok, _Enc2, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc1, 0, Headers),
    EncBin = iolist_to_binary(EncStream),
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, EncBin),
    {ok, _Dec2, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, 0, iolist_to_binary(FieldData)),
    ?assertEqual(Headers, Decoded).

reconcile_peer_blocked_zero(_Config) ->
    Enc0 = dormant_encoder(),
    Enc1 = nhttp_qpack:reconcile_peer_limits(4096, 0, Enc0),
    Headers = [{<<"x-custom">>, <<"value1">>}],
    {ok, _Enc2, _EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc1, 0, Headers),
    {ok, Dec} = nhttp_qpack:new_decoder(#{max_table_capacity => 4096, max_blocked_streams => 0}),
    {ok, _Dec1, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec, 0, iolist_to_binary(FieldData)),
    ?assertEqual(Headers, Decoded).

reconcile_then_steady_state_nonblocking(_Config) ->
    Enc0 = nhttp_qpack:reconcile_peer_limits(4096, 16, dormant_encoder()),
    {ok, Dec0} = nhttp_qpack:new_decoder(#{max_table_capacity => 4096, max_blocked_streams => 16}),
    Headers = [{<<"x-rep">>, <<"shared-value">>}],
    {ok, Enc1, EncStream1, FieldData1} =
        nhttp_qpack:encode_field_section(Enc0, 0, Headers),
    EncBin1 = iolist_to_binary(EncStream1),
    ?assert(byte_size(EncBin1) > 0),
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, EncBin1),
    {ok, Dec2, DecStream1, Decoded1} =
        nhttp_qpack:decode_field_section(Dec1, 0, iolist_to_binary(FieldData1)),
    ?assertEqual(Headers, Decoded1),
    DecBin1 = iolist_to_binary(DecStream1),
    ?assert(byte_size(DecBin1) > 0),
    {ok, Enc2} = nhttp_qpack:feed_decoder_stream(Enc1, DecBin1),

    {ok, _Enc3, EncStream2, FieldData2} =
        nhttp_qpack:encode_field_section(Enc2, 4, Headers),
    ?assertEqual(<<>>, iolist_to_binary(EncStream2)),
    {ok, _Dec3, _DecStream2, Decoded2} =
        nhttp_qpack:decode_field_section(Dec2, 4, iolist_to_binary(FieldData2)),
    ?assertEqual(Headers, Decoded2).

%%%-----------------------------------------------------------------------------
%%% ERROR PATH TESTS
%%%-----------------------------------------------------------------------------

empty_field_section(_Config) ->
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    ?assertMatch(
        {error, _},
        nhttp_qpack:decode_field_section(Dec, 0, <<>>)
    ).

decode_invalid_data(_Config) ->
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    Garbage = crypto:strong_rand_bytes(32),
    Result = nhttp_qpack:decode_field_section(Dec, 0, Garbage),
    case Result of
        {error, _} -> ok;
        {ok, _, _, _} -> ok;
        {blocked, _} -> ok
    end.

%%%-----------------------------------------------------------------------------
%%% DECODER COVERAGE TESTS
%%%-----------------------------------------------------------------------------

decoder_encoder_stream_instructions(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    CapInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(4096)
    ),
    InsertInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"x-test">>, <<"hello">>, false
        )
    ),
    EncData = <<CapInstr/binary, InsertInstr/binary>>,
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, EncData),
    Prefix = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(1, 1, 128)
    ),
    Rep = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed, dynamic, 0}, false
        )
    ),
    FieldBin = <<Prefix/binary, Rep/binary>>,
    {ok, _Dec2, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, 0, FieldBin),
    ?assertEqual([{<<"x-test">>, <<"hello">>}], Decoded).

decoder_duplicate_instruction(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    CapInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(4096)
    ),
    InsertInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"x-dup">>, <<"orig">>, false
        )
    ),
    DupInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_duplicate(0)
    ),
    EncData = <<CapInstr/binary, InsertInstr/binary, DupInstr/binary>>,
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, EncData),
    Prefix = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(2, 2, 128)
    ),
    Rep = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed, dynamic, 0}, false
        )
    ),
    FieldBin = <<Prefix/binary, Rep/binary>>,
    {ok, _Dec2, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, 0, FieldBin),
    ?assertEqual([{<<"x-dup">>, <<"orig">>}], Decoded).

decoder_dynamic_name_ref(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    CapInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(4096)
    ),
    Insert1 = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"x-name">>, <<"val1">>, false
        )
    ),
    Insert2 = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_name_ref(
            dynamic, 0, <<"val2">>, false
        )
    ),
    EncData = <<CapInstr/binary, Insert1/binary, Insert2/binary>>,
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, EncData),
    Prefix = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(2, 2, 128)
    ),
    Rep = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed, dynamic, 0}, false
        )
    ),
    FieldBin = <<Prefix/binary, Rep/binary>>,
    {ok, _Dec2, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, 0, FieldBin),
    ?assertEqual([{<<"x-name">>, <<"val2">>}], Decoded).

decoder_literal_name_ref_fields(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    CapInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(4096)
    ),
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, CapInstr),
    Prefix = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(0, 0, 128)
    ),
    Rep1 = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {literal_name_ref, static, 1, <<"/foo">>, false}, false
        )
    ),
    Rep2 = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {literal, <<"x-custom">>, <<"bar">>, false}, false
        )
    ),
    FieldBin = <<Prefix/binary, Rep1/binary, Rep2/binary>>,
    {ok, _Dec2, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, 0, FieldBin),
    ?assertEqual(
        [{<<":path">>, <<"/foo">>}, {<<"x-custom">>, <<"bar">>}],
        Decoded
    ).

decoder_post_base_fields(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    CapInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(4096)
    ),
    Insert1 = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"x-post">>, <<"base1">>, false
        )
    ),
    Insert2 = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"x-post2">>, <<"base2">>, false
        )
    ),
    EncData = <<CapInstr/binary, Insert1/binary, Insert2/binary>>,
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, EncData),
    Prefix = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(2, 1, 128)
    ),
    Rep1 = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed, dynamic, 0}, false
        )
    ),
    Rep2 = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed_post_base, 0}, false
        )
    ),
    FieldBin = <<Prefix/binary, Rep1/binary, Rep2/binary>>,
    {ok, _Dec2, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, 0, FieldBin),
    ?assertEqual(
        [{<<"x-post">>, <<"base1">>}, {<<"x-post2">>, <<"base2">>}],
        Decoded
    ).

decoder_empty_encoder_stream(_Config) ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 10},
    {ok, Dec0} = nhttp_qpack:new_decoder(Config),
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, <<>>),
    _ = Dec1.

%%%-----------------------------------------------------------------------------
%%% FIELD VALIDITY TESTS (RFC 9113 SECTION 8.2.1, RFC 9114 SECTION 4.1.2)
%%%
%%% The decoder reports a field that breaks the rule apart from a
%%% decompression failure, because RFC 9114 Section 4.1.2 makes the first a
%%% stream error and RFC 9204 Section 2.2 makes the second a connection error.
%%%-----------------------------------------------------------------------------

literal_uppercase_name_is_invalid_field(_Config) ->
    ?assertEqual(
        {error, {invalid_field, uppercase_field_name, <<"X-Bad">>}},
        decode_literal(<<"X-Bad">>, <<"v">>)
    ).

literal_name_with_interior_colon_is_invalid_field(_Config) ->
    ?assertEqual(
        {error, {invalid_field, invalid_field_name_char, <<"x:bad">>}},
        decode_literal(<<"x:bad">>, <<"v">>)
    ).

literal_empty_name_is_invalid_field(_Config) ->
    ?assertEqual(
        {error, {invalid_field, empty_field_name, <<>>}},
        decode_literal(<<>>, <<"v">>)
    ).

literal_value_with_cr_is_invalid_field(_Config) ->
    ?assertEqual(
        {error, {invalid_field, invalid_field_value_char, <<"x-bad">>}},
        decode_literal(<<"x-bad">>, <<"a\rb">>)
    ).

literal_value_edge_whitespace_is_invalid_field(_Config) ->
    ?assertEqual(
        {error, {invalid_field, field_value_edge_whitespace, <<"x-bad">>}},
        decode_literal(<<"x-bad">>, <<" v">>)
    ),
    ?assertEqual(
        {error, {invalid_field, field_value_edge_whitespace, <<"x-bad">>}},
        decode_literal(<<"x-bad">>, <<"v\t">>)
    ).

%% The name comes from the static table, which holds lowercase names, but the
%% value comes from the wire and is read.
literal_name_ref_value_is_validated(_Config) ->
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    Section = field_section([{literal_name_ref, static, 0, <<"a\nb">>, false}]),
    ?assertMatch(
        {error, {invalid_field, invalid_field_value_char, _}},
        nhttp_qpack:decode_field_section(Dec, 0, Section)
    ).

literal_pseudo_header_name_is_accepted(_Config) ->
    ?assertMatch(
        {ok, _Dec, _DecStream, [{<<":method">>, <<"GET">>}]},
        decode_literal(<<":method">>, <<"GET">>)
    ).

encoder_stream_literal_name_is_validated(_Config) ->
    {ok, Dec} = nhttp_qpack:new_decoder(?TABLE_CONFIG),
    Data = encoder_stream([
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"X-Bad">>, <<"v">>, false
        )
    ]),
    ?assertEqual(
        {error, {invalid_field, uppercase_field_name, <<"X-Bad">>}},
        nhttp_qpack:feed_encoder_stream(Dec, Data)
    ).

encoder_stream_name_ref_value_is_validated(_Config) ->
    {ok, Dec} = nhttp_qpack:new_decoder(?TABLE_CONFIG),
    Data = encoder_stream([
        nhttp_qpack_encoder_instruction:encode_insert_name_ref(
            static, 0, <<"a\rb">>, false
        )
    ]),
    ?assertMatch(
        {error, {invalid_field, invalid_field_value_char, _}},
        nhttp_qpack:feed_encoder_stream(Dec, Data)
    ).

%% A refused insert must not advance the insert count. A field section that
%% requires the second entry stays blocked, which it cannot do if the entry
%% had landed.
refused_insert_leaves_the_dynamic_table_unchanged(_Config) ->
    {ok, Dec0} = nhttp_qpack:new_decoder(?TABLE_CONFIG),
    Good = encoder_stream([
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"x-good">>, <<"1">>, false
        )
    ]),
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, Good),
    Bad = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"X-Bad">>, <<"2">>, false
        )
    ),
    ?assertEqual(
        {error, {invalid_field, uppercase_field_name, <<"X-Bad">>}},
        nhttp_qpack:feed_encoder_stream(Dec1, Bad)
    ),
    OneEntry = field_section([{indexed, dynamic, 0}], 1, 1),
    ?assertMatch(
        {ok, _Dec, _DecStream, [{<<"x-good">>, <<"1">>}]},
        nhttp_qpack:decode_field_section(Dec1, 0, OneEntry)
    ),
    TwoEntries = field_section([{indexed, dynamic, 0}], 2, 2),
    ?assertMatch({blocked, _Dec}, nhttp_qpack:decode_field_section(Dec1, 4, TwoEntries)).

%%%-----------------------------------------------------------------------------
%%% ENCODE LOWERCASE TESTS (RFC 9114 Section 4.2)
%%%-----------------------------------------------------------------------------

mixed_case_name_encodes_as_lowercase(_Config) ->
    Value = <<"text/html">>,
    ?assertEqual(
        encode_fresh([{<<"content-type">>, Value}]),
        encode_fresh([{<<"Content-Type">>, Value}])
    ),
    ?assertEqual(
        encode_fresh([{<<"x-custom-field">>, Value}]),
        encode_fresh([{<<"X-Custom-Field">>, Value}])
    ).

%% Static entry 31 is `accept-encoding: gzip, deflate, br'. The whole section
%% is a two octet prefix and one indexed representation, so the length answers
%% whether the mixed case name reached the entry or took a literal.
mixed_case_name_hits_the_static_entry(_Config) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{}),
    Header = {<<"Accept-Encoding">>, <<"gzip, deflate, br">>},
    {ok, _Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, [Header]),
    ?assertEqual(<<>>, iolist_to_binary(EncStream)),
    ?assertEqual(<<0, 0, 2#11:2, 31:6>>, iolist_to_binary(FieldData)).

mixed_case_name_round_trips_lowercase(_Config) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{}),
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    Headers = [{<<"X-Request-Id">>, <<"abc">>}, {<<"Content-Type">>, <<"text/html">>}],
    {ok, _Enc1, _EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    {ok, _Dec1, _DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec, 0, iolist_to_binary(FieldData)),
    ?assertEqual(
        [{<<"x-request-id">>, <<"abc">>}, {<<"content-type">>, <<"text/html">>}],
        Decoded
    ).

%% The decoder holds the entry the insert instruction named. It resolves the
%% index of the second section to that entry, so the lowercase name it returns
%% is the name the encoder put in both tables.
mixed_case_name_enters_the_table_lowercase(_Config) ->
    {ok, Enc0} = nhttp_qpack:new_encoder(?TABLE_CONFIG),
    {ok, Dec0} = nhttp_qpack:new_decoder(?TABLE_CONFIG),
    {ok, Enc1, EncStream1, FD1} =
        nhttp_qpack:encode_field_section(Enc0, 0, [{<<"X-Custom">>, <<"v">>}]),
    {ok, Dec1, []} = nhttp_qpack:feed_encoder_stream(Dec0, iolist_to_binary(EncStream1)),
    {ok, Dec2, DecStream1, Decoded1} =
        nhttp_qpack:decode_field_section(Dec1, 0, iolist_to_binary(FD1)),
    ?assertEqual([{<<"x-custom">>, <<"v">>}], Decoded1),
    {ok, Enc2} = nhttp_qpack:feed_decoder_stream(Enc1, iolist_to_binary(DecStream1)),
    {ok, _Enc3, EncStream2, FD2} =
        nhttp_qpack:encode_field_section(Enc2, 4, [{<<"x-custom">>, <<"v">>}]),
    ?assertEqual(<<>>, iolist_to_binary(EncStream2)),
    {ok, _Dec3, _DecStream2, Decoded2} =
        nhttp_qpack:decode_field_section(Dec2, 4, iolist_to_binary(FD2)),
    ?assertEqual([{<<"x-custom">>, <<"v">>}], Decoded2).

mixed_case_name_lowercases_the_insert_instruction(_Config) ->
    {ok, Enc} = nhttp_qpack:new_encoder(?TABLE_CONFIG),
    {ok, _Enc1, EncStream, _FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, [{<<"X-Custom">>, <<"v">>}]),
    Bin = iolist_to_binary(EncStream),
    {ok, {set_capacity, ?TABLE_CAPACITY}, Rest} =
        nhttp_qpack_encoder_instruction:decode(Bin),
    ?assertEqual(
        {ok, {insert_literal_name, <<"x-custom">>, <<"v">>}, <<>>},
        nhttp_qpack_encoder_instruction:decode(Rest)
    ).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec encode_fresh([{binary(), binary()}]) -> binary().
encode_fresh(Headers) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{}),
    {ok, _Enc1, _EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    iolist_to_binary(FieldData).

-spec decode_literal(binary(), binary()) -> term().
decode_literal(Name, Value) ->
    {ok, Dec} = nhttp_qpack:new_decoder(#{}),
    Section = field_section([{literal, Name, Value, false}]),
    nhttp_qpack:decode_field_section(Dec, 0, Section).

-spec field_section([nhttp_qpack_field_line:representation()]) -> binary().
field_section(Reps) ->
    field_section(Reps, 0, 0).

-spec field_section(
    [nhttp_qpack_field_line:representation()], non_neg_integer(), non_neg_integer()
) -> binary().
field_section(Reps, RequiredInsertCount, Base) ->
    Prefix = nhttp_qpack_field_line:encode_prefix(
        RequiredInsertCount, Base, ?TABLE_CAPACITY div 32
    ),
    Encoded = [nhttp_qpack_field_line:encode_representation(Rep, false) || Rep <- Reps],
    iolist_to_binary([Prefix, Encoded]).

-spec encoder_stream([iodata()]) -> binary().
encoder_stream(Instructions) ->
    iolist_to_binary([
        nhttp_qpack_encoder_instruction:encode_set_capacity(?TABLE_CAPACITY)
        | Instructions
    ]).

-spec encode_decode_sequence(
    [[{binary(), binary()}]],
    nhttp_qpack:encoder(),
    nhttp_qpack:decoder(),
    non_neg_integer()
) -> ok.
encode_decode_sequence([], _Enc, _Dec, _StreamId) ->
    ok;
encode_decode_sequence(
    [Headers | Rest], Enc, Dec, StreamId
) ->
    {ok, Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, StreamId, Headers),
    EncBin = iolist_to_binary(EncStream),
    {ok, Dec1, Unblocked} =
        case byte_size(EncBin) of
            0 -> {ok, Dec, []};
            _ -> nhttp_qpack:feed_encoder_stream(Dec, EncBin)
        end,
    Dec2 = process_unblocked(Dec1, Unblocked),
    FieldBin = iolist_to_binary(FieldData),
    {ok, Dec3, DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec2, StreamId, FieldBin),
    ?assertEqual(Headers, Decoded),
    DecBin = iolist_to_binary(DecStream),
    Enc2 =
        case byte_size(DecBin) of
            0 ->
                Enc1;
            _ ->
                {ok, E} = nhttp_qpack:feed_decoder_stream(Enc1, DecBin),
                E
        end,
    encode_decode_sequence(Rest, Enc2, Dec3, StreamId + 4).

-spec process_unblocked(
    nhttp_qpack:decoder(),
    [{non_neg_integer(), iodata(), [{binary(), binary()}]}]
) -> nhttp_qpack:decoder().
process_unblocked(Dec, []) ->
    Dec;
process_unblocked(Dec, _Unblocked) ->
    Dec.

-spec roundtrip_with_streams(
    nhttp_qpack:encoder(),
    nhttp_qpack:decoder(),
    non_neg_integer(),
    [{binary(), binary()}]
) -> {nhttp_qpack:encoder(), nhttp_qpack:decoder()}.
roundtrip_with_streams(Enc0, Dec0, StreamId, Headers) ->
    {ok, Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc0, StreamId, Headers),
    EncBin = iolist_to_binary(EncStream),
    {ok, Dec1, _Unblocked} =
        case byte_size(EncBin) of
            0 -> {ok, Dec0, []};
            _ -> nhttp_qpack:feed_encoder_stream(Dec0, EncBin)
        end,
    FieldBin = iolist_to_binary(FieldData),
    {ok, Dec2, DecStream, Decoded} =
        nhttp_qpack:decode_field_section(Dec1, StreamId, FieldBin),
    ?assertEqual(Headers, Decoded),
    DecBin = iolist_to_binary(DecStream),
    Enc2 =
        case byte_size(DecBin) of
            0 ->
                Enc1;
            _ ->
                {ok, E} = nhttp_qpack:feed_decoder_stream(Enc1, DecBin),
                E
        end,
    {Enc2, Dec2}.
