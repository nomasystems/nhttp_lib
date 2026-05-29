%%%-----------------------------------------------------------------------------
-module(nhttp_h3_frame_SUITE).

-moduledoc "HTTP/3 frame encoding/decoding test suite (RFC 9114 Section 7).".

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
        {group, settings},
        {group, forbidden_frames},
        {group, unknown_frames},
        {group, error_handling}
    ].

groups() ->
    [
        {encoding, [parallel], [
            encode_data,
            encode_headers,
            encode_cancel_push,
            encode_settings_empty,
            encode_settings_with_values,
            encode_push_promise,
            encode_goaway,
            encode_max_push_id
        ]},
        {decoding, [parallel], [
            decode_data,
            decode_headers,
            decode_cancel_push,
            decode_settings_empty,
            decode_settings_with_values,
            decode_push_promise,
            decode_goaway,
            decode_max_push_id
        ]},
        {roundtrip, [parallel], [
            roundtrip_data,
            roundtrip_data_empty,
            roundtrip_headers,
            roundtrip_cancel_push,
            roundtrip_settings,
            roundtrip_push_promise,
            roundtrip_goaway,
            roundtrip_goaway_large_id,
            roundtrip_max_push_id
        ]},
        {settings, [parallel], [
            settings_qpack_max_table_capacity,
            settings_qpack_blocked_streams,
            settings_max_field_section_size,
            settings_enable_connect_protocol,
            settings_multiple,
            settings_unknown_ignored,
            settings_infinity_omitted
        ]},
        {forbidden_frames, [parallel], [
            forbidden_priority_frame,
            forbidden_ping_frame,
            forbidden_window_update_frame,
            forbidden_continuation_frame
        ]},
        {unknown_frames, [parallel], [
            unknown_frame_ignored,
            grease_frame_ignored,
            unknown_frame_preserves_type_and_payload
        ]},
        {error_handling, [parallel], [
            decode_incomplete_type,
            decode_incomplete_length,
            decode_incomplete_payload,
            decode_forbidden_h2_settings,
            decode_invalid_cancel_push_trailing,
            decode_invalid_goaway_trailing,
            decode_invalid_max_push_id_trailing
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

encode_data(_Config) ->
    {ok, IoData} = nhttp_h3_frame:data(<<"hello">>),
    Bin = iolist_to_binary(IoData),
    ?assertEqual(<<0, 5, "hello">>, Bin).

encode_headers(_Config) ->
    {ok, IoData} = nhttp_h3_frame:headers(<<1, 2, 3>>),
    Bin = iolist_to_binary(IoData),
    ?assertEqual(<<1, 3, 1, 2, 3>>, Bin).

encode_cancel_push(_Config) ->
    {ok, IoData} = nhttp_h3_frame:cancel_push(5),
    Bin = iolist_to_binary(IoData),
    ?assertEqual(<<3, 1, 5>>, Bin).

encode_settings_empty(_Config) ->
    {ok, IoData} = nhttp_h3_frame:settings(#{}),
    Bin = iolist_to_binary(IoData),
    ?assertEqual(<<4, 0>>, Bin).

encode_settings_with_values(_Config) ->
    {ok, IoData} = nhttp_h3_frame:settings(#{qpack_max_table_capacity => 4096}),
    Bin = iolist_to_binary(IoData),
    {ok, 4, Rest0} = nquic_varint:decode(Bin),
    {ok, Len, Rest1} = nquic_varint:decode(Rest0),
    ?assertEqual(Len, byte_size(Rest1)),
    {ok, 1, Rest2} = nquic_varint:decode(Rest1),
    {ok, 4096, <<>>} = nquic_varint:decode(Rest2).

encode_push_promise(_Config) ->
    {ok, IoData} = nhttp_h3_frame:push_promise(7, <<10, 20>>),
    Bin = iolist_to_binary(IoData),
    {ok, 5, Rest0} = nquic_varint:decode(Bin),
    {ok, Len, Rest1} = nquic_varint:decode(Rest0),
    ?assertEqual(Len, byte_size(Rest1)),
    {ok, 7, FieldSection} = nquic_varint:decode(Rest1),
    ?assertEqual(<<10, 20>>, FieldSection).

encode_goaway(_Config) ->
    {ok, IoData} = nhttp_h3_frame:goaway(100),
    Bin = iolist_to_binary(IoData),
    {ok, 7, Rest0} = nquic_varint:decode(Bin),
    {ok, Len, Rest1} = nquic_varint:decode(Rest0),
    ?assertEqual(Len, byte_size(Rest1)),
    {ok, 100, <<>>} = nquic_varint:decode(Rest1).

encode_max_push_id(_Config) ->
    {ok, IoData} = nhttp_h3_frame:max_push_id(15),
    Bin = iolist_to_binary(IoData),
    {ok, 16#0D, Rest0} = nquic_varint:decode(Bin),
    {ok, Len, Rest1} = nquic_varint:decode(Rest0),
    ?assertEqual(Len, byte_size(Rest1)),
    {ok, 15, <<>>} = nquic_varint:decode(Rest1).

%%%-----------------------------------------------------------------------------
%%% DECODING TESTS
%%%-----------------------------------------------------------------------------

decode_data(_Config) ->
    ?assertEqual({ok, {data, <<"hello">>}, <<>>}, nhttp_h3_frame:decode(<<0, 5, "hello">>)).

decode_headers(_Config) ->
    ?assertEqual({ok, {headers, <<1, 2, 3>>}, <<>>}, nhttp_h3_frame:decode(<<1, 3, 1, 2, 3>>)).

decode_cancel_push(_Config) ->
    ?assertEqual({ok, {cancel_push, 5}, <<>>}, nhttp_h3_frame:decode(<<3, 1, 5>>)).

decode_settings_empty(_Config) ->
    ?assertEqual({ok, {settings, #{}}, <<>>}, nhttp_h3_frame:decode(<<4, 0>>)).

decode_settings_with_values(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:settings(#{qpack_max_table_capacity => 4096}),
    Bin = iolist_to_binary(Encoded),
    {ok, {settings, Settings}, _} = nhttp_h3_frame:decode(Bin),
    ?assertEqual(4096, maps:get(qpack_max_table_capacity, Settings)).

decode_push_promise(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:push_promise(3, <<"field_section">>),
    Bin = iolist_to_binary(Encoded),
    {ok, {push_promise, 3, <<"field_section">>}, _} = nhttp_h3_frame:decode(Bin).

decode_goaway(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:goaway(42),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {goaway, 42}, <<>>}, nhttp_h3_frame:decode(Bin)).

decode_max_push_id(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:max_push_id(99),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {max_push_id, 99}, <<>>}, nhttp_h3_frame:decode(Bin)).

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP TESTS
%%%-----------------------------------------------------------------------------

roundtrip_data(_Config) ->
    Payload = <<"The quick brown fox">>,
    {ok, Encoded} = nhttp_h3_frame:data(Payload),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {data, Payload}, <<>>}, nhttp_h3_frame:decode(Bin)).

roundtrip_data_empty(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:data(<<>>),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {data, <<>>}, <<>>}, nhttp_h3_frame:decode(Bin)).

roundtrip_headers(_Config) ->
    FieldSection = crypto:strong_rand_bytes(100),
    {ok, Encoded} = nhttp_h3_frame:headers(FieldSection),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {headers, FieldSection}, <<>>}, nhttp_h3_frame:decode(Bin)).

roundtrip_cancel_push(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:cancel_push(42),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {cancel_push, 42}, <<>>}, nhttp_h3_frame:decode(Bin)).

roundtrip_settings(_Config) ->
    Settings = #{
        qpack_max_table_capacity => 4096,
        qpack_blocked_streams => 100,
        max_field_section_size => 8192,
        enable_connect_protocol => true
    },
    {ok, Encoded} = nhttp_h3_frame:settings(Settings),
    Bin = iolist_to_binary(Encoded),
    {ok, {settings, Decoded}, _} = nhttp_h3_frame:decode(Bin),
    ?assertEqual(Settings, Decoded).

roundtrip_push_promise(_Config) ->
    FieldSection = <<"encoded_headers">>,
    {ok, Encoded} = nhttp_h3_frame:push_promise(7, FieldSection),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual(
        {ok, {push_promise, 7, FieldSection}, <<>>},
        nhttp_h3_frame:decode(Bin)
    ).

roundtrip_goaway(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:goaway(0),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {goaway, 0}, <<>>}, nhttp_h3_frame:decode(Bin)).

roundtrip_goaway_large_id(_Config) ->
    Id = 16#FFFFFFFF,
    {ok, Encoded} = nhttp_h3_frame:goaway(Id),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {goaway, Id}, <<>>}, nhttp_h3_frame:decode(Bin)).

roundtrip_max_push_id(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:max_push_id(1000),
    Bin = iolist_to_binary(Encoded),
    ?assertEqual({ok, {max_push_id, 1000}, <<>>}, nhttp_h3_frame:decode(Bin)).

%%%-----------------------------------------------------------------------------
%%% SETTINGS TESTS
%%%-----------------------------------------------------------------------------

settings_qpack_max_table_capacity(_Config) ->
    roundtrip_setting(#{qpack_max_table_capacity => 0}),
    roundtrip_setting(#{qpack_max_table_capacity => 4096}).

settings_qpack_blocked_streams(_Config) ->
    roundtrip_setting(#{qpack_blocked_streams => 0}),
    roundtrip_setting(#{qpack_blocked_streams => 100}).

settings_max_field_section_size(_Config) ->
    roundtrip_setting(#{max_field_section_size => 8192}).

settings_enable_connect_protocol(_Config) ->
    roundtrip_setting(#{enable_connect_protocol => true}),
    roundtrip_setting(#{enable_connect_protocol => false}).

settings_multiple(_Config) ->
    Settings = #{
        qpack_max_table_capacity => 4096,
        qpack_blocked_streams => 50,
        max_field_section_size => 16384,
        enable_connect_protocol => true
    },
    roundtrip_setting(Settings).

settings_unknown_ignored(_Config) ->
    TypeBin = nquic_varint:encode(4),
    UnknownId = nquic_varint:encode(16#FF),
    UnknownVal = nquic_varint:encode(42),
    Payload = iolist_to_binary([UnknownId, UnknownVal]),
    LenBin = nquic_varint:encode(byte_size(Payload)),
    Bin = iolist_to_binary([TypeBin, LenBin, Payload]),
    ?assertMatch({ok, {settings, #{}}, _}, nhttp_h3_frame:decode(Bin)).

settings_infinity_omitted(_Config) ->
    {ok, Encoded} = nhttp_h3_frame:settings(#{max_field_section_size => infinity}),
    Bin = iolist_to_binary(Encoded),
    {ok, {settings, Settings}, _} = nhttp_h3_frame:decode(Bin),
    ?assertEqual(false, maps:is_key(max_field_section_size, Settings)).

%%%-----------------------------------------------------------------------------
%%% FORBIDDEN FRAME TESTS (RFC 9114 Section 7.2.8)
%%%-----------------------------------------------------------------------------

forbidden_priority_frame(_Config) ->
    Bin = make_raw_frame(16#02, <<>>),
    ?assertEqual({error, h3_frame_unexpected}, nhttp_h3_frame:decode(Bin)).

forbidden_ping_frame(_Config) ->
    Bin = make_raw_frame(16#06, <<0, 0, 0, 0, 0, 0, 0, 0>>),
    ?assertEqual({error, h3_frame_unexpected}, nhttp_h3_frame:decode(Bin)).

forbidden_window_update_frame(_Config) ->
    Bin = make_raw_frame(16#08, <<0, 0, 0, 1>>),
    ?assertEqual({error, h3_frame_unexpected}, nhttp_h3_frame:decode(Bin)).

forbidden_continuation_frame(_Config) ->
    Bin = make_raw_frame(16#09, <<"headers">>),
    ?assertEqual({error, h3_frame_unexpected}, nhttp_h3_frame:decode(Bin)).

%%%-----------------------------------------------------------------------------
%%% UNKNOWN FRAME TESTS (RFC 9114 Section 9)
%%%-----------------------------------------------------------------------------

unknown_frame_ignored(_Config) ->
    Bin = make_raw_frame(16#FF, <<"some payload">>),
    {ok, {unknown, 16#FF, <<"some payload">>}, _} = nhttp_h3_frame:decode(Bin).

grease_frame_ignored(_Config) ->
    GreaseType = 16#1F * 3 + 16#21,
    Bin = make_raw_frame(GreaseType, <<"grease">>),
    {ok, {unknown, GreaseType, <<"grease">>}, _} = nhttp_h3_frame:decode(Bin).

unknown_frame_preserves_type_and_payload(_Config) ->
    Payload = crypto:strong_rand_bytes(50),
    Type = 16#1234,
    Bin = make_raw_frame(Type, Payload),
    {ok, {unknown, Type, Payload}, _} = nhttp_h3_frame:decode(Bin).

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

decode_incomplete_type(_Config) ->
    ?assertEqual({more, 1}, nhttp_h3_frame:decode(<<>>)).

decode_incomplete_length(_Config) ->
    ?assertEqual({more, 1}, nhttp_h3_frame:decode(<<0>>)).

decode_incomplete_payload(_Config) ->
    ?assertEqual({more, 1}, nhttp_h3_frame:decode(<<0, 5, "hi">>)).

decode_forbidden_h2_settings(_Config) ->
    lists:foreach(
        fun(ForbiddenId) ->
            TypeBin = nquic_varint:encode(4),
            Id = nquic_varint:encode(ForbiddenId),
            Val = nquic_varint:encode(100),
            Payload = iolist_to_binary([Id, Val]),
            LenBin = nquic_varint:encode(byte_size(Payload)),
            Bin = iolist_to_binary([TypeBin, LenBin, Payload]),
            ?assertEqual({error, h3_settings_error}, nhttp_h3_frame:decode(Bin))
        end,
        [16#02, 16#03, 16#04, 16#05]
    ).

decode_invalid_cancel_push_trailing(_Config) ->
    TypeBin = nquic_varint:encode(3),
    PushIdBin = nquic_varint:encode(5),
    Payload = <<PushIdBin/binary, 16#FF>>,
    LenBin = nquic_varint:encode(byte_size(Payload)),
    Bin = iolist_to_binary([TypeBin, LenBin, Payload]),
    ?assertEqual({error, h3_frame_error}, nhttp_h3_frame:decode(Bin)).

decode_invalid_goaway_trailing(_Config) ->
    TypeBin = nquic_varint:encode(7),
    IdBin = nquic_varint:encode(42),
    Payload = <<IdBin/binary, 16#FF>>,
    LenBin = nquic_varint:encode(byte_size(Payload)),
    Bin = iolist_to_binary([TypeBin, LenBin, Payload]),
    ?assertEqual({error, h3_frame_error}, nhttp_h3_frame:decode(Bin)).

decode_invalid_max_push_id_trailing(_Config) ->
    TypeBin = nquic_varint:encode(16#0D),
    PushIdBin = nquic_varint:encode(10),
    Payload = <<PushIdBin/binary, 16#FF>>,
    LenBin = nquic_varint:encode(byte_size(Payload)),
    Bin = iolist_to_binary([TypeBin, LenBin, Payload]),
    ?assertEqual({error, h3_frame_error}, nhttp_h3_frame:decode(Bin)).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

make_raw_frame(Type, Payload) ->
    TypeBin = nquic_varint:encode(Type),
    LenBin = nquic_varint:encode(byte_size(Payload)),
    iolist_to_binary([TypeBin, LenBin, Payload]).

roundtrip_setting(Settings) ->
    {ok, Encoded} = nhttp_h3_frame:settings(Settings),
    Bin = iolist_to_binary(Encoded),
    {ok, {settings, Decoded}, _} = nhttp_h3_frame:decode(Bin),
    ?assertEqual(Settings, Decoded).
