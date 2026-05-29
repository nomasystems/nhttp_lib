%%%-----------------------------------------------------------------------------
-module(nhttp_h3_rfc9114_frames_SUITE).

-moduledoc """
RFC 9114 Frame-Level Compliance Test Suite.

Hand-written wire vectors for every HTTP/3 frame type defined in
RFC 9114 Section 7.2 plus QUIC variable-length integer edge cases from
RFC 9000 Section 16. Each test cites the specific requirement it covers.

Run with: rebar3 ct --suite=test/compliance/nhttp_h3_rfc9114_frames_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_7_2_1_data},
        {group, section_7_2_2_headers},
        {group, section_7_2_3_cancel_push},
        {group, section_7_2_4_settings},
        {group, section_7_2_5_push_promise},
        {group, section_7_2_6_goaway},
        {group, section_7_2_7_max_push_id},
        {group, section_7_2_8_forbidden_h2},
        {group, section_9_extensibility},
        {group, rfc9000_16_varint}
    ].

groups() ->
    [
        {section_7_2_1_data, [parallel], [
            data_empty_payload,
            data_non_empty_payload
        ]},
        {section_7_2_2_headers, [parallel], [
            headers_empty_payload,
            headers_non_empty_payload
        ]},
        {section_7_2_3_cancel_push, [parallel], [
            cancel_push_single_varint,
            cancel_push_large_varint
        ]},
        {section_7_2_4_settings, [parallel], [
            settings_empty_payload,
            settings_single_entry,
            settings_multiple_entries,
            settings_unknown_identifier_ignored,
            settings_h2_enable_push_forbidden,
            settings_h2_max_concurrent_streams_forbidden,
            settings_h2_initial_window_size_forbidden,
            settings_h2_max_frame_size_forbidden
        ]},
        {section_7_2_5_push_promise, [parallel], [
            push_promise_minimal,
            push_promise_with_field_section
        ]},
        {section_7_2_6_goaway, [parallel], [
            goaway_zero_id,
            goaway_large_id,
            goaway_trailing_bytes_is_frame_error
        ]},
        {section_7_2_7_max_push_id, [parallel], [
            max_push_id_zero,
            max_push_id_large
        ]},
        {section_7_2_8_forbidden_h2, [parallel], [
            priority_frame_is_unexpected,
            ping_frame_is_unexpected,
            window_update_frame_is_unexpected,
            continuation_frame_is_unexpected
        ]},
        {section_9_extensibility, [parallel], [
            unknown_frame_type_reported_as_unknown,
            grease_frame_reported_as_unknown
        ]},
        {rfc9000_16_varint, [parallel], [
            varint_1_byte_boundary,
            varint_2_byte_boundary,
            varint_4_byte_boundary,
            varint_8_byte_boundary,
            varint_incomplete_returns_more
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

%%%-----------------------------------------------------------------------------
%%% §7.2.1 DATA
%%%-----------------------------------------------------------------------------

data_empty_payload(_Config) ->
    Frame = build_frame(16#00, <<>>),
    {ok, {data, <<>>}, <<>>} = nhttp_h3_frame:decode(Frame),
    ok.

data_non_empty_payload(_Config) ->
    Payload = <<"hello world">>,
    Frame = build_frame(16#00, Payload),
    {ok, {data, Payload}, _} = nhttp_h3_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% §7.2.2 HEADERS
%%%-----------------------------------------------------------------------------

headers_empty_payload(_Config) ->
    Frame = build_frame(16#01, <<>>),
    {ok, {headers, <<>>}, _} = nhttp_h3_frame:decode(Frame),
    ok.

headers_non_empty_payload(_Config) ->
    Payload = <<0, 0, 16#82>>,
    Frame = build_frame(16#01, Payload),
    {ok, {headers, Payload}, _} = nhttp_h3_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% §7.2.3 CANCEL_PUSH
%%%-----------------------------------------------------------------------------

cancel_push_single_varint(_Config) ->
    {ok, Frame} = nhttp_h3_frame:cancel_push(7),
    {ok, {cancel_push, 7}, _} = nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

cancel_push_large_varint(_Config) ->
    LargeId = 1 bsl 40,
    {ok, Frame} = nhttp_h3_frame:cancel_push(LargeId),
    {ok, {cancel_push, LargeId}, _} = nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

%%%-----------------------------------------------------------------------------
%%% §7.2.4 SETTINGS
%%%-----------------------------------------------------------------------------

settings_empty_payload(_Config) ->
    {ok, Frame} = nhttp_h3_frame:settings(#{}),
    {ok, {settings, #{}}, _} = nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

settings_single_entry(_Config) ->
    {ok, Frame} = nhttp_h3_frame:settings(#{qpack_max_table_capacity => 4096}),
    {ok, {settings, Settings}, _} = nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ?assertEqual(4096, maps:get(qpack_max_table_capacity, Settings)),
    ok.

settings_multiple_entries(_Config) ->
    {ok, Frame} = nhttp_h3_frame:settings(#{
        qpack_max_table_capacity => 4096,
        qpack_blocked_streams => 100,
        max_field_section_size => 65536
    }),
    {ok, {settings, Settings}, _} = nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ?assertEqual(4096, maps:get(qpack_max_table_capacity, Settings)),
    ?assertEqual(100, maps:get(qpack_blocked_streams, Settings)),
    ?assertEqual(65536, maps:get(max_field_section_size, Settings)),
    ok.

settings_unknown_identifier_ignored(_Config) ->
    IdBin = nquic_varint:encode(16#FF),
    ValBin = nquic_varint:encode(42),
    Payload = iolist_to_binary([IdBin, ValBin]),
    Frame = build_frame(16#04, Payload),
    {ok, {settings, Settings}, _} = nhttp_h3_frame:decode(Frame),
    ?assertEqual(#{}, Settings),
    ok.

settings_h2_enable_push_forbidden(_Config) ->
    assert_forbidden_setting(16#02).

settings_h2_max_concurrent_streams_forbidden(_Config) ->
    assert_forbidden_setting(16#03).

settings_h2_initial_window_size_forbidden(_Config) ->
    assert_forbidden_setting(16#04).

settings_h2_max_frame_size_forbidden(_Config) ->
    assert_forbidden_setting(16#05).

%%%-----------------------------------------------------------------------------
%%% §7.2.5 PUSH_PROMISE
%%%-----------------------------------------------------------------------------

push_promise_minimal(_Config) ->
    {ok, Frame} = nhttp_h3_frame:push_promise(0, <<>>),
    {ok, {push_promise, 0, <<>>}, _} =
        nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

push_promise_with_field_section(_Config) ->
    Fields = <<0, 0, 16#82>>,
    {ok, Frame} = nhttp_h3_frame:push_promise(7, Fields),
    {ok, {push_promise, 7, Fields}, _} =
        nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

%%%-----------------------------------------------------------------------------
%%% §7.2.6 GOAWAY
%%%-----------------------------------------------------------------------------

goaway_zero_id(_Config) ->
    {ok, Frame} = nhttp_h3_frame:goaway(0),
    {ok, {goaway, 0}, _} = nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

goaway_large_id(_Config) ->
    LargeId = 1 bsl 40,
    {ok, Frame} = nhttp_h3_frame:goaway(LargeId),
    {ok, {goaway, LargeId}, _} = nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

goaway_trailing_bytes_is_frame_error(_Config) ->
    IdBin = nquic_varint:encode(7),
    Payload = iolist_to_binary([IdBin, <<"garbage">>]),
    Frame = build_frame(16#07, Payload),
    {error, h3_frame_error} = nhttp_h3_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% §7.2.7 MAX_PUSH_ID
%%%-----------------------------------------------------------------------------

max_push_id_zero(_Config) ->
    {ok, Frame} = nhttp_h3_frame:max_push_id(0),
    {ok, {max_push_id, 0}, _} = nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

max_push_id_large(_Config) ->
    LargeId = 1 bsl 32,
    {ok, Frame} = nhttp_h3_frame:max_push_id(LargeId),
    {ok, {max_push_id, LargeId}, _} =
        nhttp_h3_frame:decode(iolist_to_binary(Frame)),
    ok.

%%%-----------------------------------------------------------------------------
%%% §7.2.8 Forbidden H2 frame types
%%%-----------------------------------------------------------------------------

priority_frame_is_unexpected(_Config) ->
    assert_forbidden_h2_frame(16#02).

ping_frame_is_unexpected(_Config) ->
    assert_forbidden_h2_frame(16#06).

window_update_frame_is_unexpected(_Config) ->
    assert_forbidden_h2_frame(16#08).

continuation_frame_is_unexpected(_Config) ->
    assert_forbidden_h2_frame(16#09).

%%%-----------------------------------------------------------------------------
%%% §9 Extensibility
%%%-----------------------------------------------------------------------------

unknown_frame_type_reported_as_unknown(_Config) ->
    Frame = build_frame(16#7F, <<"payload">>),
    {ok, {unknown, 16#7F, <<"payload">>}, _} = nhttp_h3_frame:decode(Frame),
    ok.

grease_frame_reported_as_unknown(_Config) ->
    GreaseType = 16#1F * 3 + 16#21,
    Frame = build_frame(GreaseType, <<>>),
    {ok, {unknown, GreaseType, <<>>}, _} = nhttp_h3_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% RFC 9000 §16 - Variable-Length Integer Encoding
%%%-----------------------------------------------------------------------------

varint_1_byte_boundary(_Config) ->
    <<0>> = nquic_varint:encode(0),
    {ok, 0, <<>>} = nquic_varint:decode(<<0>>),
    <<63>> = nquic_varint:encode(63),
    {ok, 63, <<>>} = nquic_varint:decode(<<63>>),
    ok.

varint_2_byte_boundary(_Config) ->
    Bin64 = nquic_varint:encode(64),
    ?assertEqual(<<16#40, 64>>, Bin64),
    {ok, 64, <<>>} = nquic_varint:decode(Bin64),
    Bin = nquic_varint:encode(16383),
    {ok, 16383, <<>>} = nquic_varint:decode(Bin),
    ok.

varint_4_byte_boundary(_Config) ->
    Bin = nquic_varint:encode(16384),
    {ok, 16384, <<>>} = nquic_varint:decode(Bin),
    Max30 = (1 bsl 30) - 1,
    BinMax = nquic_varint:encode(Max30),
    {ok, Max30, <<>>} = nquic_varint:decode(BinMax),
    ok.

varint_8_byte_boundary(_Config) ->
    Val = 1 bsl 30,
    Bin = nquic_varint:encode(Val),
    {ok, Val, <<>>} = nquic_varint:decode(Bin),
    Max62 = (1 bsl 62) - 1,
    BinMax = nquic_varint:encode(Max62),
    {ok, Max62, <<>>} = nquic_varint:decode(BinMax),
    ok.

varint_incomplete_returns_more(_Config) ->
    {error, incomplete_binary} = nquic_varint:decode(<<16#40>>),
    {error, incomplete_binary} = nquic_varint:decode(<<16#80, 0>>),
    ok.

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec build_frame(non_neg_integer(), binary()) -> binary().
build_frame(Type, Payload) ->
    TypeBin = nquic_varint:encode(Type),
    LenBin = nquic_varint:encode(byte_size(Payload)),
    iolist_to_binary([TypeBin, LenBin, Payload]).

-spec assert_forbidden_h2_frame(non_neg_integer()) -> ok.
assert_forbidden_h2_frame(Type) ->
    Frame = build_frame(Type, <<>>),
    {error, h3_frame_unexpected} = nhttp_h3_frame:decode(Frame),
    ok.

-spec assert_forbidden_setting(non_neg_integer()) -> ok.
assert_forbidden_setting(SettingId) ->
    IdBin = nquic_varint:encode(SettingId),
    ValBin = nquic_varint:encode(1),
    Payload = iolist_to_binary([IdBin, ValBin]),
    Frame = build_frame(16#04, Payload),
    {error, h3_settings_error} = nhttp_h3_frame:decode(Frame),
    ok.
