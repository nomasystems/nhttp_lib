%%%-----------------------------------------------------------------------------
-module(nhttp_hpack_SUITE).

-moduledoc "HPACK encoding/decoding test suite (RFC 7541).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, state},
        {group, roundtrip},
        {group, rfc_examples},
        {group, rfc_byte_exact},
        {group, static_table},
        {group, dynamic_table},
        {group, integer_encoding},
        {group, error_handling},
        {group, encode_lowercase},
        {group, coverage_edge_cases},
        {group, index_maps}
    ].

groups() ->
    [
        {state, [parallel], [
            new_default,
            new_with_size,
            is_empty_initial,
            table_size_initial
        ]},
        {roundtrip, [parallel], [
            roundtrip_simple_request,
            roundtrip_simple_response,
            roundtrip_with_huffman,
            roundtrip_custom_headers,
            roundtrip_pseudo_headers
        ]},
        {rfc_examples, [parallel], [
            rfc_c3_first_request,
            rfc_c3_second_request,
            rfc_c3_third_request,
            rfc_c5_first_response,
            rfc_c5_second_response,
            rfc_c5_third_response
        ]},
        {rfc_byte_exact, [parallel], [
            decode_rfc_c2_1,
            decode_rfc_c2_2,
            decode_rfc_c2_3,
            decode_rfc_c2_4,
            decode_rfc_c4_1,
            decode_rfc_c4_2,
            decode_rfc_c4_3,
            encode_rfc_c3_sequence,
            encode_rfc_c4_sequence
        ]},
        {static_table, [parallel], [
            static_indexed_method_get,
            static_indexed_path_root,
            static_indexed_scheme_https,
            static_indexed_status_200
        ]},
        {dynamic_table, [parallel], [
            dynamic_insertion,
            dynamic_eviction,
            dynamic_size_update
        ]},
        {integer_encoding, [parallel], [
            int_small_values,
            int_boundary_values,
            int_large_values
        ]},
        {error_handling, [parallel], [
            error_invalid_index,
            error_incomplete_block,
            error_header_list_too_large,
            decode_with_unlimited_max_list_size
        ]},
        {encode_lowercase, [parallel], [
            mixed_case_name_encodes_as_lowercase,
            mixed_case_name_hits_the_static_entry,
            mixed_case_name_round_trips_lowercase,
            mixed_case_name_enters_the_table_lowercase,
            mixed_case_name_hits_the_static_name_entry
        ]},
        {coverage_edge_cases, [parallel], [
            table_size_update_encoding,
            table_size_update_decoding,
            error_integer_overflow,
            error_incomplete_integer,
            error_uppercase_header_name,
            error_invalid_huffman,
            error_dynamic_table_size_exceeded,
            dynamic_name_only_match,
            large_string_encoding,
            static_table_name_only_match,
            static_table_additional_entries,
            eviction_edge_case,
            large_huffman_string,
            table_size_update_nonzero,
            entry_too_large_for_table,
            multiple_size_updates,
            dynamic_table_decode_reference,
            error_invalid_dynamic_index,
            stale_entry_handling,
            static_table_name_matches,
            server_header_encoding,
            transfer_encoding_header,
            incomplete_string_error,
            incomplete_indexed_name_error
        ]},
        {index_maps, [], [
            encoder_state_is_bounded,
            evicted_key_is_absent,
            rebound_key_survives_eviction,
            allocation_per_request_is_flat
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
%%% STATE TESTS
%%%-----------------------------------------------------------------------------

new_default(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual(0, nhttp_hpack:table_size(State)),
    ?assert(nhttp_hpack:is_empty(State)).

new_with_size(_Config) ->
    {ok, State} = nhttp_hpack:new(8192),
    ?assertEqual(0, nhttp_hpack:table_size(State)),
    ?assert(nhttp_hpack:is_empty(State)).

is_empty_initial(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    ?assert(nhttp_hpack:is_empty(State)).

table_size_initial(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual(0, nhttp_hpack:table_size(State)).

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP TESTS
%%%-----------------------------------------------------------------------------

roundtrip_simple_request(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>}
    ],
    roundtrip(Headers).

roundtrip_simple_response(_Config) ->
    Headers = [
        {<<":status">>, <<"200">>},
        {<<"content-type">>, <<"text/html">>},
        {<<"content-length">>, <<"1234">>}
    ],
    roundtrip(Headers).

roundtrip_with_huffman(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/api/v1/users">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"api.example.com">>}
    ],
    roundtrip_huffman(Headers).

roundtrip_custom_headers(_Config) ->
    Headers = [
        {<<"x-custom-header">>, <<"custom-value">>},
        {<<"x-request-id">>, <<"12345">>}
    ],
    roundtrip(Headers).

roundtrip_pseudo_headers(_Config) ->
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":path">>, <<"/index.html">>},
        {<<":scheme">>, <<"http">>},
        {<<":authority">>, <<"www.example.com">>}
    ],
    roundtrip(Headers).

%%%-----------------------------------------------------------------------------
%%% RFC 7541 APPENDIX C EXAMPLES
%%%-----------------------------------------------------------------------------

rfc_c3_first_request(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"http">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"www.example.com">>}
    ],
    {ok, EncState} = nhttp_hpack:new(),
    {ok, DecState} = nhttp_hpack:new(),
    {ok, Encoded, _EncState2} = nhttp_hpack:encode(Headers, EncState),
    {ok, Decoded, _DecState2} = nhttp_hpack:decode(iolist_to_binary(Encoded), DecState),
    ?assertEqual(Headers, Decoded).

rfc_c3_second_request(_Config) ->
    Headers1 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"http">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"www.example.com">>}
    ],
    Headers2 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"http">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"www.example.com">>},
        {<<"cache-control">>, <<"no-cache">>}
    ],
    {ok, EncState0} = nhttp_hpack:new(),
    {ok, DecState0} = nhttp_hpack:new(),
    {ok, Encoded1, EncState1} = nhttp_hpack:encode(Headers1, EncState0),
    {ok, _, DecState1} = nhttp_hpack:decode(iolist_to_binary(Encoded1), DecState0),
    {ok, Encoded2, _EncState2} = nhttp_hpack:encode(Headers2, EncState1),
    {ok, Decoded2, _DecState2} = nhttp_hpack:decode(iolist_to_binary(Encoded2), DecState1),
    ?assertEqual(Headers2, Decoded2).

rfc_c3_third_request(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/index.html">>},
        {<<":authority">>, <<"www.example.com">>},
        {<<"custom-key">>, <<"custom-value">>}
    ],
    roundtrip(Headers).

rfc_c5_first_response(_Config) ->
    Headers = [
        {<<":status">>, <<"302">>},
        {<<"cache-control">>, <<"private">>},
        {<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
        {<<"location">>, <<"https://www.example.com">>}
    ],
    roundtrip(Headers).

rfc_c5_second_response(_Config) ->
    Headers = [
        {<<":status">>, <<"307">>},
        {<<"cache-control">>, <<"private">>},
        {<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
        {<<"location">>, <<"https://www.example.com">>}
    ],
    roundtrip(Headers).

rfc_c5_third_response(_Config) ->
    Headers = [
        {<<":status">>, <<"200">>},
        {<<"cache-control">>, <<"private">>},
        {<<"date">>, <<"Mon, 21 Oct 2013 20:13:22 GMT">>},
        {<<"location">>, <<"https://www.example.com">>},
        {<<"content-encoding">>, <<"gzip">>},
        {<<"set-cookie">>, <<"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU">>}
    ],
    roundtrip(Headers).

%%%-----------------------------------------------------------------------------
%%% RFC 7541 BYTE-EXACT DECODING TESTS (Interoperability)
%%%
%%% These tests decode the exact byte sequences from RFC 7541 Appendix C.
%%% This ensures we can decode headers from any compliant HPACK implementation.
%%%-----------------------------------------------------------------------------

decode_rfc_c2_1(_Config) ->
    Encoded = <<16#40, 16#0a, "custom-key", 16#0d, "custom-header">>,
    Expected = [{<<"custom-key">>, <<"custom-header">>}],
    {ok, State} = nhttp_hpack:new(),
    {ok, Decoded, _} = nhttp_hpack:decode(Encoded, State),
    ?assertEqual(Expected, Decoded).

decode_rfc_c2_2(_Config) ->
    Encoded = <<16#04, 16#0c, "/sample/path">>,
    Expected = [{<<":path">>, <<"/sample/path">>}],
    {ok, State} = nhttp_hpack:new(),
    {ok, Decoded, _} = nhttp_hpack:decode(Encoded, State),
    ?assertEqual(Expected, Decoded).

decode_rfc_c2_3(_Config) ->
    Encoded = <<16#10, 16#08, "password", 16#06, "secret">>,
    Expected = [{<<"password">>, <<"secret">>}],
    {ok, State} = nhttp_hpack:new(),
    {ok, Decoded, _} = nhttp_hpack:decode(Encoded, State),
    ?assertEqual(Expected, Decoded).

decode_rfc_c2_4(_Config) ->
    Encoded = <<16#82>>,
    Expected = [{<<":method">>, <<"GET">>}],
    {ok, State} = nhttp_hpack:new(),
    {ok, Decoded, _} = nhttp_hpack:decode(Encoded, State),
    ?assertEqual(Expected, Decoded).

decode_rfc_c4_1(_Config) ->
    Encoded =
        <<16#82, 16#86, 16#84, 16#41, 16#8c, 16#f1, 16#e3, 16#c2, 16#e5, 16#f2, 16#3a, 16#6b, 16#a0,
            16#ab, 16#90, 16#f4, 16#ff>>,
    Expected = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"http">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"www.example.com">>}
    ],
    {ok, State} = nhttp_hpack:new(),
    {ok, Decoded, _} = nhttp_hpack:decode(Encoded, State),
    ?assertEqual(Expected, Decoded).

decode_rfc_c4_2(_Config) ->
    FirstReq =
        <<16#82, 16#86, 16#84, 16#41, 16#8c, 16#f1, 16#e3, 16#c2, 16#e5, 16#f2, 16#3a, 16#6b, 16#a0,
            16#ab, 16#90, 16#f4, 16#ff>>,
    {ok, State0} = nhttp_hpack:new(),
    {ok, _, State1} = nhttp_hpack:decode(FirstReq, State0),
    SecondReq =
        <<16#82, 16#86, 16#84, 16#be, 16#58, 16#86, 16#a8, 16#eb, 16#10, 16#64, 16#9c, 16#bf>>,
    Expected = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"http">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"www.example.com">>},
        {<<"cache-control">>, <<"no-cache">>}
    ],
    {ok, Decoded, _} = nhttp_hpack:decode(SecondReq, State1),
    ?assertEqual(Expected, Decoded).

decode_rfc_c4_3(_Config) ->
    FirstReq =
        <<16#82, 16#86, 16#84, 16#41, 16#8c, 16#f1, 16#e3, 16#c2, 16#e5, 16#f2, 16#3a, 16#6b, 16#a0,
            16#ab, 16#90, 16#f4, 16#ff>>,
    SecondReq =
        <<16#82, 16#86, 16#84, 16#be, 16#58, 16#86, 16#a8, 16#eb, 16#10, 16#64, 16#9c, 16#bf>>,
    {ok, State0} = nhttp_hpack:new(),
    {ok, _, State1} = nhttp_hpack:decode(FirstReq, State0),
    {ok, _, State2} = nhttp_hpack:decode(SecondReq, State1),
    ThirdReq =
        <<16#82, 16#87, 16#85, 16#bf, 16#40, 16#88, 16#25, 16#a8, 16#49, 16#e9, 16#5b, 16#a9, 16#7d,
            16#7f, 16#89, 16#25, 16#a8, 16#49, 16#e9, 16#5b, 16#b8, 16#e8, 16#b4, 16#bf>>,
    Expected = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/index.html">>},
        {<<":authority">>, <<"www.example.com">>},
        {<<"custom-key">>, <<"custom-value">>}
    ],
    {ok, Decoded, _} = nhttp_hpack:decode(ThirdReq, State2),
    ?assertEqual(Expected, Decoded).

encode_rfc_c3_sequence(_Config) ->
    Expected = [
        <<16#82, 16#86, 16#84, 16#41, 16#0f, "www.example.com">>,
        <<16#82, 16#86, 16#84, 16#be, 16#58, 16#08, "no-cache">>,
        <<16#82, 16#87, 16#85, 16#bf, 16#40, 16#0a, "custom-key", 16#0c, "custom-value">>
    ],
    encode_sequence(#{huffman => false}, Expected).

encode_rfc_c4_sequence(_Config) ->
    Expected = [
        <<16#82, 16#86, 16#84, 16#41, 16#8c, 16#f1, 16#e3, 16#c2, 16#e5, 16#f2, 16#3a, 16#6b, 16#a0,
            16#ab, 16#90, 16#f4, 16#ff>>,
        <<16#82, 16#86, 16#84, 16#be, 16#58, 16#86, 16#a8, 16#eb, 16#10, 16#64, 16#9c, 16#bf>>,
        <<16#82, 16#87, 16#85, 16#bf, 16#40, 16#88, 16#25, 16#a8, 16#49, 16#e9, 16#5b, 16#a9, 16#7d,
            16#7f, 16#89, 16#25, 16#a8, 16#49, 16#e9, 16#5b, 16#b8, 16#e8, 16#b4, 16#bf>>
    ],
    encode_sequence(#{huffman => true}, Expected).

%% RFC 7541 C.3 and C.4 share one request sequence. The second and the third
%% request reuse `:authority' from the dynamic table, so an encoder that only
%% consults the static table never reaches the expected octets.
encode_sequence(Opts, Expected) ->
    Requests = [
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"http">>},
            {<<":path">>, <<"/">>},
            {<<":authority">>, <<"www.example.com">>}
        ],
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"http">>},
            {<<":path">>, <<"/">>},
            {<<":authority">>, <<"www.example.com">>},
            {<<"cache-control">>, <<"no-cache">>}
        ],
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/index.html">>},
            {<<":authority">>, <<"www.example.com">>},
            {<<"custom-key">>, <<"custom-value">>}
        ]
    ],
    {ok, State0} = nhttp_hpack:new(),
    lists:foldl(
        fun({Headers, Want}, State) ->
            {ok, Encoded, State2} = nhttp_hpack:encode(Headers, State, Opts),
            ?assertEqual(Want, iolist_to_binary(Encoded)),
            State2
        end,
        State0,
        lists:zip(Requests, Expected)
    ).

%%%-----------------------------------------------------------------------------
%%% STATIC TABLE TESTS
%%%-----------------------------------------------------------------------------

static_indexed_method_get(_Config) ->
    Headers = [{<<":method">>, <<"GET">>}],
    {ok, EncState} = nhttp_hpack:new(),
    {ok, Encoded, _} = nhttp_hpack:encode(Headers, EncState),
    EncodedBin = iolist_to_binary(Encoded),
    ?assertEqual(<<16#82>>, EncodedBin).

static_indexed_path_root(_Config) ->
    Headers = [{<<":path">>, <<"/">>}],
    {ok, EncState} = nhttp_hpack:new(),
    {ok, Encoded, _} = nhttp_hpack:encode(Headers, EncState),
    EncodedBin = iolist_to_binary(Encoded),
    ?assertEqual(<<16#84>>, EncodedBin).

static_indexed_scheme_https(_Config) ->
    Headers = [{<<":scheme">>, <<"https">>}],
    {ok, EncState} = nhttp_hpack:new(),
    {ok, Encoded, _} = nhttp_hpack:encode(Headers, EncState),
    EncodedBin = iolist_to_binary(Encoded),
    ?assertEqual(<<16#87>>, EncodedBin).

static_indexed_status_200(_Config) ->
    Headers = [{<<":status">>, <<"200">>}],
    {ok, EncState} = nhttp_hpack:new(),
    {ok, Encoded, _} = nhttp_hpack:encode(Headers, EncState),
    EncodedBin = iolist_to_binary(Encoded),
    ?assertEqual(<<16#88>>, EncodedBin).

%%%-----------------------------------------------------------------------------
%%% DYNAMIC TABLE TESTS
%%%-----------------------------------------------------------------------------

dynamic_insertion(_Config) ->
    Headers = [{<<"custom-key">>, <<"custom-value">>}],
    {ok, State0} = nhttp_hpack:new(),
    ?assert(nhttp_hpack:is_empty(State0)),
    {ok, _, State1} = nhttp_hpack:encode(Headers, State0),
    ?assertNot(nhttp_hpack:is_empty(State1)),
    ?assertEqual(54, nhttp_hpack:table_size(State1)).

dynamic_eviction(_Config) ->
    {ok, State0} = nhttp_hpack:new(64),
    Headers1 = [{<<"key1">>, <<"value1">>}],
    Headers2 = [{<<"key2">>, <<"value2">>}],
    {ok, _, State1} = nhttp_hpack:encode(Headers1, State0),
    ?assertEqual(42, nhttp_hpack:table_size(State1)),
    {ok, _, State2} = nhttp_hpack:encode(Headers2, State1),
    ?assertEqual(42, nhttp_hpack:table_size(State2)).

dynamic_size_update(_Config) ->
    {ok, State0} = nhttp_hpack:new(4096),
    Headers = [{<<"key">>, <<"value">>}],
    {ok, _, State1} = nhttp_hpack:encode(Headers, State0),
    ?assertEqual(40, nhttp_hpack:table_size(State1)),
    {ok, State2} = nhttp_hpack:set_max_table_size(0, State1),
    {ok, Encoded, State3} = nhttp_hpack:encode([], State2),
    ?assertNotEqual([], Encoded),
    ?assertEqual(0, nhttp_hpack:table_size(State3)).

%%%-----------------------------------------------------------------------------
%%% INTEGER ENCODING TESTS
%%%-----------------------------------------------------------------------------

int_small_values(_Config) ->
    test_int_roundtrip(0),
    test_int_roundtrip(1),
    test_int_roundtrip(10).

int_boundary_values(_Config) ->
    test_int_roundtrip(30),
    test_int_roundtrip(31),
    test_int_roundtrip(32),
    test_int_roundtrip(126),
    test_int_roundtrip(127),
    test_int_roundtrip(128).

int_large_values(_Config) ->
    test_int_roundtrip(1000),
    test_int_roundtrip(10000),
    test_int_roundtrip(100000).

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

error_invalid_index(_Config) ->
    InvalidData = <<16#80>>,
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual({error, invalid_table_index}, nhttp_hpack:decode(InvalidData, State)).

error_incomplete_block(_Config) ->
    IncompleteData = <<16#40, 5, "hello">>,
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual({error, incomplete_header_block}, nhttp_hpack:decode(IncompleteData, State)).

error_header_list_too_large(_Config) ->
    Headers = [
        {<<"aaaaa">>, <<"bbbbb">>},
        {<<"ccccc">>, <<"ddddd">>},
        {<<"eeeee">>, <<"fffff">>}
    ],
    {ok, EncState} = nhttp_hpack:new(),
    {ok, Block, _} = nhttp_hpack:encode(Headers, EncState),
    BlockBin = iolist_to_binary(Block),
    {ok, DecState} = nhttp_hpack:new(),
    ?assertEqual(
        {error, header_list_too_large},
        nhttp_hpack:decode(BlockBin, DecState, #{max_list_size => 100})
    ).

decode_with_unlimited_max_list_size(_Config) ->
    Headers = [{<<"a">>, <<"b">>}, {<<"c">>, <<"d">>}],
    {ok, EncState} = nhttp_hpack:new(),
    {ok, Block, _} = nhttp_hpack:encode(Headers, EncState),
    BlockBin = iolist_to_binary(Block),
    {ok, DecState} = nhttp_hpack:new(),
    {ok, Decoded2, _} = nhttp_hpack:decode(BlockBin, DecState),
    {ok, Decoded3a, _} = nhttp_hpack:decode(BlockBin, DecState, #{}),
    {ok, Decoded3b, _} = nhttp_hpack:decode(BlockBin, DecState, #{max_list_size => infinity}),
    ?assertEqual(Decoded2, Decoded3a),
    ?assertEqual(Decoded2, Decoded3b).

%%%-----------------------------------------------------------------------------
%%% COVERAGE EDGE CASES
%%%-----------------------------------------------------------------------------

table_size_update_encoding(_Config) ->
    SizeUpdate256 = <<2#00111111, 225, 1>>,
    Data = <<SizeUpdate256/binary, 16#82>>,
    {ok, State0} = nhttp_hpack:new(4096),
    {ok, Decoded, _State1} = nhttp_hpack:decode(Data, State0),
    ?assertEqual([{<<":method">>, <<"GET">>}], Decoded).

table_size_update_decoding(_Config) ->
    {ok, Enc0} = nhttp_hpack:new(4096),
    {ok, Dec0} = nhttp_hpack:new(4096),
    Headers1 = [{<<"x-key">>, <<"x-value">>}],
    {ok, Encoded1, Enc1} = nhttp_hpack:encode(Headers1, Enc0),
    {ok, _, Dec1} = nhttp_hpack:decode(iolist_to_binary(Encoded1), Dec0),
    {ok, Enc2} = nhttp_hpack:set_max_table_size(128, Enc1),
    {ok, Dec2} = nhttp_hpack:set_max_table_size(128, Dec1),
    {ok, Encoded2, _Enc3} = nhttp_hpack:encode(Headers1, Enc2),
    {ok, Decoded, _Dec3} = nhttp_hpack:decode(iolist_to_binary(Encoded2), Dec2),
    ?assertEqual(Headers1, Decoded).

error_integer_overflow(_Config) ->
    Overflow = <<
        16#FF,
        16#FF,
        16#FF,
        16#FF,
        16#FF,
        16#FF,
        16#7F
    >>,
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual({error, integer_overflow}, nhttp_hpack:decode(Overflow, State)).

error_incomplete_integer(_Config) ->
    Incomplete = <<16#FF, 16#80>>,
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual({error, incomplete_header_block}, nhttp_hpack:decode(Incomplete, State)).

error_uppercase_header_name(_Config) ->
    InvalidName = <<16#40, 7, "X-Upper", 5, "value">>,
    {ok, State} = nhttp_hpack:new(),
    ?assertMatch({invalid_field, uppercase_header_name, _}, nhttp_hpack:decode(InvalidName, State)).

error_invalid_huffman(_Config) ->
    InvalidHuffman = <<16#40, 16#82, 16#00, 16#00, 16#01, "v">>,
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual({error, invalid_huffman}, nhttp_hpack:decode(InvalidHuffman, State)).

error_dynamic_table_size_exceeded(_Config) ->
    SizeUpdate = <<2#001:3, 2#11111:5, 16#C0, 16#3F>>,
    {ok, State} = nhttp_hpack:new(4096),
    ?assertEqual({error, dynamic_table_size_exceeded}, nhttp_hpack:decode(SizeUpdate, State)).

dynamic_name_only_match(_Config) ->
    {ok, Enc0} = nhttp_hpack:new(),
    {ok, Dec0} = nhttp_hpack:new(),
    Headers1 = [{<<"x-custom">>, <<"value1">>}],
    {ok, Encoded1, Enc1} = nhttp_hpack:encode(Headers1, Enc0),
    {ok, _, Dec1} = nhttp_hpack:decode(iolist_to_binary(Encoded1), Dec0),
    Headers2 = [{<<"x-custom">>, <<"different-value">>}],
    {ok, Encoded2, _Enc2} = nhttp_hpack:encode(Headers2, Enc1),
    {ok, Decoded2, _Dec2} = nhttp_hpack:decode(iolist_to_binary(Encoded2), Dec1),
    ?assertEqual(Headers2, Decoded2).

large_string_encoding(_Config) ->
    LargeValue = list_to_binary(lists:duplicate(200, $x)),
    Headers = [{<<"x-large">>, LargeValue}],
    {ok, Enc0} = nhttp_hpack:new(),
    {ok, Dec0} = nhttp_hpack:new(),
    {ok, Encoded, _Enc1} = nhttp_hpack:encode(Headers, Enc0),
    {ok, Decoded, _Dec1} = nhttp_hpack:decode(iolist_to_binary(Encoded), Dec0),
    ?assertEqual(Headers, Decoded).

static_table_name_only_match(_Config) ->
    Headers = [
        {<<":authority">>, <<"custom.example.com">>},
        {<<":status">>, <<"201">>},
        {<<"content-type">>, <<"application/json">>},
        {<<"cache-control">>, <<"max-age=3600">>}
    ],
    roundtrip(Headers).

static_table_additional_entries(_Config) ->
    Headers1 = [
        {<<"accept-charset">>, <<>>},
        {<<"accept-language">>, <<>>},
        {<<"accept-ranges">>, <<>>},
        {<<"accept">>, <<>>}
    ],
    roundtrip(Headers1),
    Headers2 = [
        {<<"age">>, <<>>},
        {<<"allow">>, <<>>},
        {<<"authorization">>, <<>>},
        {<<"content-disposition">>, <<>>}
    ],
    roundtrip(Headers2),
    Headers3 = [
        {<<"content-language">>, <<>>},
        {<<"content-location">>, <<>>},
        {<<"content-range">>, <<>>},
        {<<"cookie">>, <<>>}
    ],
    roundtrip(Headers3),
    Headers4 = [
        {<<"date">>, <<>>},
        {<<"etag">>, <<>>},
        {<<"expect">>, <<>>},
        {<<"expires">>, <<>>}
    ],
    roundtrip(Headers4),
    Headers5 = [
        {<<"from">>, <<>>},
        {<<"host">>, <<>>},
        {<<"if-match">>, <<>>},
        {<<"if-modified-since">>, <<>>}
    ],
    roundtrip(Headers5),
    Headers6 = [
        {<<"if-none-match">>, <<>>},
        {<<"if-range">>, <<>>},
        {<<"if-unmodified-since">>, <<>>},
        {<<"last-modified">>, <<>>}
    ],
    roundtrip(Headers6),
    Headers7 = [
        {<<"link">>, <<>>},
        {<<"location">>, <<>>},
        {<<"max-forwards">>, <<>>},
        {<<"proxy-authenticate">>, <<>>}
    ],
    roundtrip(Headers7),
    Headers8 = [
        {<<"proxy-authorization">>, <<>>},
        {<<"range">>, <<>>},
        {<<"referer">>, <<>>},
        {<<"refresh">>, <<>>}
    ],
    roundtrip(Headers8),
    Headers9 = [
        {<<"retry-after">>, <<>>},
        {<<"server">>, <<>>},
        {<<"set-cookie">>, <<>>},
        {<<"strict-transport-security">>, <<>>}
    ],
    roundtrip(Headers9),
    Headers10 = [
        {<<"transfer-encoding">>, <<>>},
        {<<"user-agent">>, <<>>},
        {<<"vary">>, <<>>},
        {<<"via">>, <<>>},
        {<<"www-authenticate">>, <<>>}
    ],
    roundtrip(Headers10).

eviction_edge_case(_Config) ->
    {ok, State0} = nhttp_hpack:new(72),
    Headers1 = [{<<"aa">>, <<"bb">>}],
    {ok, _, State1} = nhttp_hpack:encode(Headers1, State0),
    ?assertEqual(36, nhttp_hpack:table_size(State1)),
    Headers2 = [{<<"cc">>, <<"dd">>}],
    {ok, _, State2} = nhttp_hpack:encode(Headers2, State1),
    ?assertEqual(72, nhttp_hpack:table_size(State2)),
    Headers3 = [{<<"ee">>, <<"ff">>}],
    {ok, _, State3} = nhttp_hpack:encode(Headers3, State2),
    ?assertEqual(72, nhttp_hpack:table_size(State3)).

large_huffman_string(_Config) ->
    LargeValue = list_to_binary(lists:duplicate(200, $a)),
    Headers = [{<<"x-large">>, LargeValue}],
    {ok, Enc0} = nhttp_hpack:new(),
    {ok, Dec0} = nhttp_hpack:new(),
    {ok, Encoded, _Enc1} = nhttp_hpack:encode(Headers, Enc0, #{huffman => true}),
    {ok, Decoded, _Dec1} = nhttp_hpack:decode(iolist_to_binary(Encoded), Dec0),
    ?assertEqual(Headers, Decoded).

table_size_update_nonzero(_Config) ->
    SizeUpdate = <<2#00111111, 97>>,
    {ok, State0} = nhttp_hpack:new(4096),
    {ok, [], State1} = nhttp_hpack:decode(SizeUpdate, State0),
    Headers = [{<<":method">>, <<"GET">>}],
    {ok, Enc0} = nhttp_hpack:new(128),
    {ok, Encoded, _} = nhttp_hpack:encode(Headers, Enc0),
    {ok, Decoded, _} = nhttp_hpack:decode(iolist_to_binary(Encoded), State1),
    ?assertEqual(Headers, Decoded).

entry_too_large_for_table(_Config) ->
    {ok, State0} = nhttp_hpack:new(40),
    Headers = [{<<"0123456789">>, <<"0123456789">>}],
    {ok, _, State1} = nhttp_hpack:encode(Headers, State0),
    ?assertEqual(0, nhttp_hpack:table_size(State1)).

multiple_size_updates(_Config) ->
    SizeUpdate64 = <<2#00111111, 33>>,
    Data = <<SizeUpdate64/binary, SizeUpdate64/binary, 16#82>>,
    {ok, State0} = nhttp_hpack:new(4096),
    {ok, Decoded, _} = nhttp_hpack:decode(Data, State0),
    ?assertEqual([{<<":method">>, <<"GET">>}], Decoded).

dynamic_table_decode_reference(_Config) ->
    AddEntry = <<16#40, 5, "x-key", 5, "value">>,
    {ok, State0} = nhttp_hpack:new(),
    {ok, _, State1} = nhttp_hpack:decode(AddEntry, State0),
    RefEntry = <<16#BE>>,
    {ok, Decoded, _} = nhttp_hpack:decode(RefEntry, State1),
    ?assertEqual([{<<"x-key">>, <<"value">>}], Decoded).

error_invalid_dynamic_index(_Config) ->
    InvalidRef = <<16#BE>>,
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual({error, invalid_table_index}, nhttp_hpack:decode(InvalidRef, State)).

stale_entry_handling(_Config) ->
    {ok, Enc0} = nhttp_hpack:new(50),
    {ok, Dec0} = nhttp_hpack:new(50),
    Headers1 = [{<<"key">>, <<"v1">>}],
    {ok, Encoded1, Enc1} = nhttp_hpack:encode(Headers1, Enc0),
    {ok, _, Dec1} = nhttp_hpack:decode(iolist_to_binary(Encoded1), Dec0),
    Headers2 = [{<<"new">>, <<"v2">>}],
    {ok, Encoded2, Enc2} = nhttp_hpack:encode(Headers2, Enc1),
    {ok, _, Dec2} = nhttp_hpack:decode(iolist_to_binary(Encoded2), Dec1),
    Headers3 = [{<<"key">>, <<"v3">>}],
    {ok, Encoded3, _} = nhttp_hpack:encode(Headers3, Enc2),
    {ok, Decoded3, _} = nhttp_hpack:decode(iolist_to_binary(Encoded3), Dec2),
    ?assertEqual(Headers3, Decoded3).

server_header_encoding(_Config) ->
    Headers = [{<<"server">>, <<"nginx">>}],
    roundtrip(Headers),
    Headers2 = [{<<"server">>, <<>>}],
    roundtrip(Headers2).

transfer_encoding_header(_Config) ->
    Headers = [{<<"transfer-encoding">>, <<"chunked">>}],
    roundtrip(Headers),
    Headers2 = [{<<"transfer-encoding">>, <<>>}],
    roundtrip(Headers2).

incomplete_string_error(_Config) ->
    IncompleteData = <<16#40, 10, "hello">>,
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual({error, incomplete_header_block}, nhttp_hpack:decode(IncompleteData, State)).

incomplete_indexed_name_error(_Config) ->
    IncompleteData = <<16#41>>,
    {ok, State} = nhttp_hpack:new(),
    ?assertEqual({error, incomplete_header_block}, nhttp_hpack:decode(IncompleteData, State)).

static_table_name_matches(_Config) ->
    Headers1 = [
        {<<":scheme">>, <<"wss">>},
        {<<"accept-charset">>, <<"utf-8">>},
        {<<"accept-ranges">>, <<"bytes">>},
        {<<"accept">>, <<"application/json">>}
    ],
    roundtrip(Headers1),
    Headers2 = [
        {<<"access-control-allow-origin">>, <<"*">>},
        {<<"age">>, <<"3600">>},
        {<<"allow">>, <<"GET, POST">>},
        {<<"authorization">>, <<"Bearer token">>}
    ],
    roundtrip(Headers2),
    Headers3 = [
        {<<"content-disposition">>, <<"attachment">>},
        {<<"content-language">>, <<"en-US">>},
        {<<"content-location">>, <<"/resource">>},
        {<<"content-range">>, <<"bytes 0-100/200">>}
    ],
    roundtrip(Headers3),
    Headers4 = [
        {<<"etag">>, <<"\"abc123\"">>},
        {<<"expect">>, <<"100-continue">>},
        {<<"expires">>, <<"Thu, 01 Jan 2030">>},
        {<<"from">>, <<"user@example.com">>}
    ],
    roundtrip(Headers4),
    Headers5 = [
        {<<"if-match">>, <<"\"xyz\"">>},
        {<<"if-modified-since">>, <<"Mon, 01 Jan 2024">>},
        {<<"if-none-match">>, <<"\"etag\"">>},
        {<<"if-range">>, <<"\"range\"">>}
    ],
    roundtrip(Headers5),
    Headers6 = [
        {<<"if-unmodified-since">>, <<"Tue, 02 Jan 2024">>},
        {<<"last-modified">>, <<"Wed, 03 Jan 2024">>},
        {<<"link">>, <<"</next>; rel=next">>},
        {<<"max-forwards">>, <<"10">>}
    ],
    roundtrip(Headers6),
    Headers7 = [
        {<<"proxy-authenticate">>, <<"Basic">>},
        {<<"proxy-authorization">>, <<"Basic xyz">>},
        {<<"range">>, <<"bytes=0-100">>},
        {<<"referer">>, <<"https://example.com">>}
    ],
    roundtrip(Headers7),
    Headers8 = [
        {<<"refresh">>, <<"5">>},
        {<<"retry-after">>, <<"120">>},
        {<<"strict-transport-security">>, <<"max-age=31536000">>},
        {<<"vary">>, <<"Accept-Encoding">>}
    ],
    roundtrip(Headers8),
    Headers9 = [
        {<<"via">>, <<"1.1 proxy">>},
        {<<"www-authenticate">>, <<"Bearer">>}
    ],
    roundtrip(Headers9).

%%%-----------------------------------------------------------------------------
%%% ENCODE LOWERCASE TESTS (RFC 9113 Section 8.2)
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

mixed_case_name_hits_the_static_entry(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    Header = {<<"Accept-Encoding">>, <<"gzip, deflate">>},
    {ok, Encoded, State2} = nhttp_hpack:encode([Header], State),
    ?assertEqual(<<2#1:1, 16:7>>, iolist_to_binary(Encoded)),
    ?assertEqual(0, nhttp_hpack:table_size(State2)).

mixed_case_name_hits_the_static_name_entry(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    Header = {<<"Accept-Encoding">>, <<"br">>},
    {ok, Encoded, _State2} = nhttp_hpack:encode([Header], State),
    ?assertEqual(
        <<2#01:2, 16:6, 0:1, 2:7, "br">>,
        iolist_to_binary(Encoded)
    ).

mixed_case_name_round_trips_lowercase(_Config) ->
    {ok, EncState} = nhttp_hpack:new(),
    {ok, DecState} = nhttp_hpack:new(),
    Headers = [{<<"X-Request-Id">>, <<"abc">>}, {<<"Content-Type">>, <<"text/html">>}],
    {ok, Encoded, _EncState2} = nhttp_hpack:encode(Headers, EncState),
    {ok, Decoded, _DecState2} = nhttp_hpack:decode(iolist_to_binary(Encoded), DecState),
    ?assertEqual(
        [{<<"x-request-id">>, <<"abc">>}, {<<"content-type">>, <<"text/html">>}],
        Decoded
    ).

%% The second encode reaches the entry the first one inserted only when the
%% table holds the lowercase name, so the one byte answers what the table holds.
mixed_case_name_enters_the_table_lowercase(_Config) ->
    {ok, State} = nhttp_hpack:new(),
    {ok, _Encoded, State2} = nhttp_hpack:encode([{<<"X-Custom">>, <<"v">>}], State),
    ?assert(nhttp_hpack:table_size(State2) > 0),
    {ok, Again, _State3} = nhttp_hpack:encode([{<<"x-custom">>, <<"v">>}], State2),
    ?assertEqual(<<2#1:1, 62:7>>, iolist_to_binary(Again)).

%%%-----------------------------------------------------------------------------
%%% INDEX MAP TESTS
%%%-----------------------------------------------------------------------------

encoder_state_is_bounded(_Config) ->
    {ok, State0} = nhttp_hpack:new(),
    State1 = encode_apns_requests(1, 999, State0),
    {Words1, State2} = max_state_words(1000, 1063, State1),
    State3 = encode_apns_requests(1064, 9999, State2),
    {Words2, State4} = max_state_words(10000, 10063, State3),
    State5 = encode_apns_requests(10064, 99999, State4),
    {Words3, _State6} = max_state_words(100000, 100063, State5),
    ct:log("state words at 1000, 10000, 100000 requests: ~p", [[Words1, Words2, Words3]]),
    Tolerance = erts_debug:flat_size(apns_request(1)),
    ?assert(lists:max([Words1, Words2, Words3]) - lists:min([Words1, Words2, Words3]) =< Tolerance).

evicted_key_is_absent(_Config) ->
    {ok, State0} = nhttp_hpack:new(72),
    {ok, _, State1} = nhttp_hpack:encode([{<<"aa">>, <<"bb">>}, {<<"cc">>, <<"dd">>}], State0),
    ?assertEqual(72, nhttp_hpack:table_size(State1)),
    {ok, _, State2} = nhttp_hpack:encode([{<<"ee">>, <<"ff">>}], State1),
    ?assertEqual(72, nhttp_hpack:table_size(State2)),
    ?assertNot(maps:is_key({<<"aa">>, <<"bb">>}, hpack_field(full_index, State2))),
    ?assertNot(maps:is_key(<<"aa">>, hpack_field(name_index, State2))),
    {ok, Encoded, _State3} = nhttp_hpack:encode([{<<"aa">>, <<"bb">>}], State2),
    ?assertMatch(<<2#01:2, 0:6, _/binary>>, iolist_to_binary(Encoded)).

rebound_key_survives_eviction(_Config) ->
    rebound_name_survives_eviction(),
    rebound_field_survives_eviction().

rebound_name_survives_eviction() ->
    {ok, State0} = nhttp_hpack:new(72),
    {ok, _, State1} = nhttp_hpack:encode([{<<"aa">>, <<"bb">>}, {<<"aa">>, <<"cc">>}], State0),
    ?assertEqual(#{<<"aa">> => 1}, hpack_field(name_index, State1)),
    {ok, _, State2} = nhttp_hpack:encode([{<<"ee">>, <<"ff">>}], State1),
    ?assertEqual(#{<<"aa">> => 1, <<"ee">> => 2}, hpack_field(name_index, State2)),
    ?assertEqual(
        #{{<<"aa">>, <<"cc">>} => 1, {<<"ee">>, <<"ff">>} => 2},
        hpack_field(full_index, State2)
    ),
    {ok, Encoded, _State3} = nhttp_hpack:encode([{<<"aa">>, <<"dd">>}], State2),
    ?assertMatch(<<2#01:2, 63:6, 0, _/binary>>, iolist_to_binary(Encoded)).

rebound_field_survives_eviction() ->
    {ok, State0} = nhttp_hpack:new(72),
    Literal = <<2#01:2, 0:6, 2, "aa", 2, "bb">>,
    {ok, _, State1} = nhttp_hpack:decode(<<Literal/binary, Literal/binary>>, State0),
    ?assertEqual(#{{<<"aa">>, <<"bb">>} => 1}, hpack_field(full_index, State1)),
    {ok, _, State2} = nhttp_hpack:decode(<<2#01:2, 0:6, 2, "cc", 2, "dd">>, State1),
    ?assertEqual(
        #{{<<"aa">>, <<"bb">>} => 1, {<<"cc">>, <<"dd">>} => 2},
        hpack_field(full_index, State2)
    ),
    ?assertEqual(#{<<"aa">> => 1, <<"cc">> => 2}, hpack_field(name_index, State2)).

allocation_per_request_is_flat(_Config) ->
    {ok, State0} = nhttp_hpack:new(),
    {State1, Words1} = allocated_words(fun() -> encode_apns_requests(1, 10000, State0) end),
    {_State2, Words2} = allocated_words(fun() -> encode_apns_requests(10001, 20000, State1) end),
    ct:log("words allocated: first window ~p, second window ~p", [Words1, Words2]),
    ?assert(abs(Words2 - Words1) * 100 =< Words1).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

encode_fresh(Headers) ->
    {ok, State} = nhttp_hpack:new(),
    {ok, Encoded, _State2} = nhttp_hpack:encode(Headers, State),
    iolist_to_binary(Encoded).

roundtrip(Headers) ->
    {ok, EncState} = nhttp_hpack:new(),
    {ok, DecState} = nhttp_hpack:new(),
    {ok, Encoded, _EncState2} = nhttp_hpack:encode(Headers, EncState),
    EncodedBin = iolist_to_binary(Encoded),
    {ok, Decoded, _DecState2} = nhttp_hpack:decode(EncodedBin, DecState),
    ?assertEqual(Headers, Decoded).

roundtrip_huffman(Headers) ->
    {ok, EncState} = nhttp_hpack:new(),
    {ok, DecState} = nhttp_hpack:new(),
    {ok, Encoded, _EncState2} = nhttp_hpack:encode(Headers, EncState, #{huffman => true}),
    EncodedBin = iolist_to_binary(Encoded),
    {ok, Decoded, _DecState2} = nhttp_hpack:decode(EncodedBin, DecState),
    ?assertEqual(Headers, Decoded).

test_int_roundtrip(Value) ->
    LongValue = list_to_binary(lists:duplicate(Value, $x)),
    Headers = [{<<"x">>, LongValue}],
    roundtrip(Headers).

hpack_field(Field, State) ->
    element(maps:get(Field, record_positions(hpack)), State).

record_positions(Record) ->
    Beam = filename:join([code:lib_dir(nhttp_lib), "ebin", "nhttp_hpack.beam"]),
    {ok, {nhttp_hpack, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
        beam_lib:chunks(Beam, [abstract_code]),
    [Fields] = [Fs || {attribute, _, record, {R, Fs}} <- Forms, R =:= Record],
    Names = [record_field_name(Field) || Field <- Fields],
    maps:from_list(lists:zip(Names, lists:seq(2, length(Names) + 1))).

record_field_name({typed_record_field, Field, _Type}) -> record_field_name(Field);
record_field_name({record_field, _, {atom, _, Name}}) -> Name;
record_field_name({record_field, _, {atom, _, Name}, _Default}) -> Name.

apns_request(N) ->
    Token = binary:encode_hex(<<N:256>>, lowercase),
    <<A:8/binary, B:4/binary, C:4/binary, D:4/binary, E:12/binary>> =
        binary:encode_hex(<<N:128>>, lowercase),
    Id = <<A/binary, "-", B/binary, "-", C/binary, "-", D/binary, "-", E/binary>>,
    Jwt = binary:copy(<<"x">>, 184),
    [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"api.push.apple.com">>},
        {<<":path">>, <<"/3/device/", Token/binary>>},
        {<<"apns-id">>, Id},
        {<<"apns-topic">>, <<"com.example.app">>},
        {<<"apns-push-type">>, <<"alert">>},
        {<<"apns-priority">>, <<"10">>},
        {<<"apns-expiration">>, <<"0">>},
        {<<"authorization">>, <<"bearer ", Jwt/binary>>},
        {<<"content-type">>, <<"application/json">>},
        {<<"content-length">>, <<"134">>}
    ].

encode_apns_requests(From, To, State) when From > To ->
    State;
encode_apns_requests(From, To, State) ->
    {ok, _, State1} = nhttp_hpack:encode(apns_request(From), State),
    encode_apns_requests(From + 1, To, State1).

max_state_words(From, To, State) ->
    max_state_words(From, To, State, 0).

max_state_words(From, To, State, Max) when From > To ->
    {Max, State};
max_state_words(From, To, State, Max) ->
    {ok, _, State1} = nhttp_hpack:encode(apns_request(From), State),
    max_state_words(From + 1, To, State1, max(Max, erts_debug:flat_size(State1))).

allocated_words(Fun) ->
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        receive
            go -> ok
        end,
        true = erlang:garbage_collect(),
        Result = Fun(),
        true = erlang:garbage_collect(),
        Parent ! {result, self(), Result}
    end),
    Session = trace:session_create(hpack_allocation, self(), []),
    1 = trace:process(Session, Pid, true, [garbage_collection]),
    Pid ! go,
    Result =
        receive
            {result, Pid, R} -> R
        end,
    receive
        {'DOWN', Ref, process, Pid, normal} -> ok
    end,
    true = trace:session_destroy(Session),
    {Result, sum_gc_allocations(Pid, undefined, 0)}.

sum_gc_allocations(Pid, PrevEnd, Sum) ->
    receive
        {trace, Pid, Start, Info} when Start =:= gc_minor_start; Start =:= gc_major_start ->
            sum_gc_allocations(Pid, PrevEnd, Sum + allocated_since(PrevEnd, Info));
        {trace, Pid, End, Info} when End =:= gc_minor_end; End =:= gc_major_end ->
            {heap_size, Live} = lists:keyfind(heap_size, 1, Info),
            sum_gc_allocations(Pid, Live, Sum)
    after 0 ->
        Sum
    end.

allocated_since(undefined, _Info) ->
    0;
allocated_since(PrevEnd, Info) ->
    {heap_size, Used} = lists:keyfind(heap_size, 1, Info),
    {mbuf_size, Mbuf} = lists:keyfind(mbuf_size, 1, Info),
    Used + Mbuf - PrevEnd.
