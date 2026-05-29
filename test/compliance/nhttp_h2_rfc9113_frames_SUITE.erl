%%%-----------------------------------------------------------------------------
-module(nhttp_h2_rfc9113_frames_SUITE).

-moduledoc """
RFC 9113 Frame-Level Compliance Test Suite.

Hand-written wire vectors for every frame type defined in RFC 9113 Section 6,
covering good frames, boundary cases and malformed payloads. Each test case
cites the specific RFC requirement.

Run with: rebar3 ct --suite=test/compliance/nhttp_h2_rfc9113_frames_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_4_frame_format},
        {group, section_6_1_data},
        {group, section_6_2_headers},
        {group, section_6_3_priority},
        {group, section_6_4_rst_stream},
        {group, section_6_5_settings},
        {group, section_6_6_push_promise},
        {group, section_6_7_ping},
        {group, section_6_8_goaway},
        {group, section_6_9_window_update},
        {group, section_6_10_continuation},
        {group, section_7_error_codes}
    ].

groups() ->
    [
        {section_4_frame_format, [parallel], [
            incomplete_header_yields_more,
            frame_exceeding_max_size_is_frame_size_error,
            reserved_bit_ignored_on_decode,
            undefined_flag_bits_ignored
        ]},
        {section_6_1_data, [parallel], [
            data_on_stream_zero_is_protocol_error,
            data_padding_equals_length_is_protocol_error,
            data_padding_exceeds_length_is_protocol_error,
            data_good_with_padding,
            data_empty_payload_with_end_stream
        ]},
        {section_6_2_headers, [parallel], [
            headers_on_stream_zero_is_protocol_error,
            headers_with_priority_self_dependency_is_protocol_error,
            headers_with_priority_length_below_five_is_frame_size_error,
            headers_padding_exceeds_payload_is_protocol_error,
            headers_good_no_flags,
            headers_good_with_priority
        ]},
        {section_6_3_priority, [parallel], [
            priority_on_stream_zero_is_protocol_error,
            priority_wrong_length_is_stream_error,
            priority_self_dependency_is_stream_error,
            priority_good
        ]},
        {section_6_4_rst_stream, [parallel], [
            rst_stream_on_stream_zero_is_protocol_error,
            rst_stream_wrong_length_is_frame_size_error,
            rst_stream_good
        ]},
        {section_6_5_settings, [parallel], [
            settings_on_non_zero_stream_is_protocol_error,
            settings_ack_with_payload_is_frame_size_error,
            settings_length_not_multiple_of_six_is_frame_size_error,
            settings_enable_push_non_boolean_is_protocol_error,
            settings_initial_window_size_overflow_is_flow_control_error,
            settings_max_frame_size_below_min_is_protocol_error,
            settings_max_frame_size_above_max_is_protocol_error,
            settings_unknown_identifier_ignored,
            settings_ack_good,
            settings_multiple_params_good
        ]},
        {section_6_6_push_promise, [parallel], [
            push_promise_on_stream_zero_is_protocol_error,
            push_promise_length_below_four_is_frame_size_error,
            push_promise_padding_exceeds_payload_is_protocol_error,
            push_promise_good
        ]},
        {section_6_7_ping, [parallel], [
            ping_on_non_zero_stream_is_protocol_error,
            ping_wrong_length_is_frame_size_error,
            ping_good,
            ping_ack_good
        ]},
        {section_6_8_goaway, [parallel], [
            goaway_on_non_zero_stream_is_protocol_error,
            goaway_length_below_eight_is_frame_size_error,
            goaway_good,
            goaway_with_debug_data
        ]},
        {section_6_9_window_update, [parallel], [
            window_update_wrong_length_is_frame_size_error,
            connection_window_update_zero_is_protocol_error,
            stream_window_update_zero_is_stream_error,
            window_update_connection_good,
            window_update_stream_good
        ]},
        {section_6_10_continuation, [parallel], [
            continuation_on_stream_zero_is_protocol_error,
            continuation_good
        ]},
        {section_7_error_codes, [parallel], [
            known_error_codes_roundtrip,
            unknown_error_code_decodes_as_internal_error
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
%%% Section 4 - Frame Format
%%%-----------------------------------------------------------------------------

incomplete_header_yields_more(_Config) ->
    {more, _} = nhttp_h2_frame:decode(<<0, 0, 0, 0>>),
    ok.

frame_exceeding_max_size_is_frame_size_error(_Config) ->
    Frame = <<16385:24, 16#00:8, 0:8, 0:1, 1:31, 0:(16385 * 8)>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

reserved_bit_ignored_on_decode(_Config) ->
    Frame = <<8:24, 16#06:8, 0:8, 1:1, 0:31, 0, 0, 0, 0, 0, 0, 0, 0>>,
    {ok, {ping, <<0:64>>}, 17} = nhttp_h2_frame:decode(Frame),
    ok.

undefined_flag_bits_ignored(_Config) ->
    Frame = <<8:24, 16#06:8, 2:8, 0:32, 0, 0, 0, 0, 0, 0, 0, 0>>,
    {ok, {ping, <<0:64>>}, 17} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.1 - DATA
%%%-----------------------------------------------------------------------------

data_on_stream_zero_is_protocol_error(_Config) ->
    Frame = <<0:24, 16#00:8, 0:8, 0:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

data_padding_equals_length_is_protocol_error(_Config) ->
    Frame = <<1:24, 16#00:8, 16#08:8, 0:1, 1:31, 1:8>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

data_padding_exceeds_length_is_protocol_error(_Config) ->
    Frame = <<2:24, 16#00:8, 16#08:8, 0:1, 1:31, 5:8, "x">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

data_good_with_padding(_Config) ->
    Frame = <<5:24, 16#00:8, 16#08:8, 0:1, 1:31, 2:8, "ab", 0, 0>>,
    {ok, {data, 1, nofin, <<"ab">>}, 14} = nhttp_h2_frame:decode(Frame),
    ok.

data_empty_payload_with_end_stream(_Config) ->
    Frame = <<0:24, 16#00:8, 16#01:8, 0:1, 3:31>>,
    {ok, {data, 3, fin, <<>>}, 9} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.2 - HEADERS
%%%-----------------------------------------------------------------------------

headers_on_stream_zero_is_protocol_error(_Config) ->
    Frame = <<0:24, 16#01:8, 16#04:8, 0:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

headers_with_priority_self_dependency_is_protocol_error(_Config) ->
    Frame = <<5:24, 16#01:8, 16#24:8, 0:1, 1:31, 0:1, 1:31, 0:8>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

headers_with_priority_length_below_five_is_frame_size_error(_Config) ->
    Frame = <<4:24, 16#01:8, 16#20:8, 0:1, 1:31, 0:32>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

headers_padding_exceeds_payload_is_protocol_error(_Config) ->
    Frame = <<2:24, 16#01:8, 16#08:8, 0:1, 1:31, 5:8, "x">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

headers_good_no_flags(_Config) ->
    Frame = <<1:24, 16#01:8, 0:8, 0:1, 1:31, 16#82>>,
    {ok, {headers, 1, nofin, nofin, <<16#82>>}, 10} = nhttp_h2_frame:decode(Frame),
    ok.

headers_good_with_priority(_Config) ->
    Frame = <<6:24, 16#01:8, 16#24:8, 0:1, 1:31, 0:1, 0:31, 0:8, 16#82>>,
    {ok, {headers, 1, nofin, fin, #{}, <<16#82>>}, 15} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.3 - PRIORITY
%%%-----------------------------------------------------------------------------

priority_on_stream_zero_is_protocol_error(_Config) ->
    Frame = <<5:24, 16#02:8, 0:8, 0:32, 0:40>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

priority_wrong_length_is_stream_error(_Config) ->
    Frame = <<4:24, 16#02:8, 0:8, 0:1, 1:31, 0:32>>,
    {error, {stream_error, 1, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

priority_self_dependency_is_stream_error(_Config) ->
    Frame = <<5:24, 16#02:8, 0:8, 0:1, 7:31, 0:1, 7:31, 0:8>>,
    {error, {stream_error, 7, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

priority_good(_Config) ->
    Frame = <<5:24, 16#02:8, 0:8, 0:1, 1:31, 1:1, 3:31, 14:8>>,
    {ok, {priority, 1, #{exclusive := true, stream_dependency := 3, weight := 15}}, 14} =
        nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.4 - RST_STREAM
%%%-----------------------------------------------------------------------------

rst_stream_on_stream_zero_is_protocol_error(_Config) ->
    Frame = <<4:24, 16#03:8, 0:8, 0:32, 0:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

rst_stream_wrong_length_is_frame_size_error(_Config) ->
    Frame = <<3:24, 16#03:8, 0:8, 0:1, 1:31, 0:24>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

rst_stream_good(_Config) ->
    Frame = <<4:24, 16#03:8, 0:8, 0:1, 1:31, 8:32>>,
    {ok, {rst_stream, 1, cancel}, 13} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.5 - SETTINGS
%%%-----------------------------------------------------------------------------

settings_on_non_zero_stream_is_protocol_error(_Config) ->
    Frame = <<0:24, 16#04:8, 0:8, 0:1, 1:31>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

settings_ack_with_payload_is_frame_size_error(_Config) ->
    Frame = <<6:24, 16#04:8, 16#01:8, 0:32, 0:48>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

settings_length_not_multiple_of_six_is_frame_size_error(_Config) ->
    Frame = <<5:24, 16#04:8, 0:8, 0:32, 0:40>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

settings_enable_push_non_boolean_is_protocol_error(_Config) ->
    Frame = <<6:24, 16#04:8, 0:8, 0:32, 16#0002:16, 2:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

settings_initial_window_size_overflow_is_flow_control_error(_Config) ->
    Frame = <<6:24, 16#04:8, 0:8, 0:32, 16#0004:16, 16#80000000:32>>,
    {error, {connection_error, flow_control_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

settings_max_frame_size_below_min_is_protocol_error(_Config) ->
    Frame = <<6:24, 16#04:8, 0:8, 0:32, 16#0005:16, 1024:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

settings_max_frame_size_above_max_is_protocol_error(_Config) ->
    Frame = <<6:24, 16#04:8, 0:8, 0:32, 16#0005:16, 16#1000000:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

settings_unknown_identifier_ignored(_Config) ->
    Frame = <<6:24, 16#04:8, 0:8, 0:32, 16#00FF:16, 42:32>>,
    {ok, {settings, Settings}, 15} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(#{}, Settings),
    ok.

settings_ack_good(_Config) ->
    Frame = <<0:24, 16#04:8, 16#01:8, 0:32>>,
    {ok, settings_ack, 9} = nhttp_h2_frame:decode(Frame),
    ok.

settings_multiple_params_good(_Config) ->
    Frame =
        <<18:24, 16#04:8, 0:8, 0:32,
            16#0001:16, 4096:32,
            16#0003:16, 100:32,
            16#0005:16, 16384:32>>,
    {ok, {settings, Settings}, 27} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(4096, maps:get(header_table_size, Settings)),
    ?assertEqual(100, maps:get(max_concurrent_streams, Settings)),
    ?assertEqual(16384, maps:get(max_frame_size, Settings)),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.6 - PUSH_PROMISE
%%%-----------------------------------------------------------------------------

push_promise_on_stream_zero_is_protocol_error(_Config) ->
    Frame = <<4:24, 16#05:8, 16#04:8, 0:32, 0:1, 2:31>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

push_promise_length_below_four_is_frame_size_error(_Config) ->
    Frame = <<3:24, 16#05:8, 16#04:8, 0:1, 1:31, 0:24>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

push_promise_padding_exceeds_payload_is_protocol_error(_Config) ->
    Frame = <<5:24, 16#05:8, 16#0C:8, 0:1, 1:31, 10:8, 0:1, 2:31>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

push_promise_good(_Config) ->
    Frame = <<5:24, 16#05:8, 16#04:8, 0:1, 1:31, 0:1, 2:31, 16#82>>,
    {ok, {push_promise, 1, fin, 2, <<16#82>>}, 14} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.7 - PING
%%%-----------------------------------------------------------------------------

ping_on_non_zero_stream_is_protocol_error(_Config) ->
    Frame = <<8:24, 16#06:8, 0:8, 0:1, 1:31, 0, 0, 0, 0, 0, 0, 0, 0>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

ping_wrong_length_is_frame_size_error(_Config) ->
    Frame = <<7:24, 16#06:8, 0:8, 0:32, 0, 0, 0, 0, 0, 0, 0>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

ping_good(_Config) ->
    Frame = <<8:24, 16#06:8, 0:8, 0:32, 1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, {ping, <<1, 2, 3, 4, 5, 6, 7, 8>>}, 17} = nhttp_h2_frame:decode(Frame),
    ok.

ping_ack_good(_Config) ->
    Frame = <<8:24, 16#06:8, 16#01:8, 0:32, 1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, {ping_ack, <<1, 2, 3, 4, 5, 6, 7, 8>>}, 17} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.8 - GOAWAY
%%%-----------------------------------------------------------------------------

goaway_on_non_zero_stream_is_protocol_error(_Config) ->
    Frame = <<8:24, 16#07:8, 0:8, 0:1, 1:31, 0:32, 0:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

goaway_length_below_eight_is_frame_size_error(_Config) ->
    Frame = <<4:24, 16#07:8, 0:8, 0:32, 0:32>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

goaway_good(_Config) ->
    Frame = <<8:24, 16#07:8, 0:8, 0:32, 0:1, 7:31, 0:32>>,
    {ok, {goaway, 7, no_error, <<>>}, 17} = nhttp_h2_frame:decode(Frame),
    ok.

goaway_with_debug_data(_Config) ->
    Debug = <<"shutdown">>,
    Len = 8 + byte_size(Debug),
    Expected = 9 + Len,
    Frame = <<Len:24, 16#07:8, 0:8, 0:32, 0:1, 0:31, 0:32, Debug/binary>>,
    {ok, {goaway, 0, no_error, Debug}, Expected} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.9 - WINDOW_UPDATE
%%%-----------------------------------------------------------------------------

window_update_wrong_length_is_frame_size_error(_Config) ->
    Frame = <<5:24, 16#08:8, 0:8, 0:32, 0:1, 10:31, 0:8>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

connection_window_update_zero_is_protocol_error(_Config) ->
    Frame = <<4:24, 16#08:8, 0:8, 0:32, 0:1, 0:31>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

stream_window_update_zero_is_stream_error(_Config) ->
    Frame = <<4:24, 16#08:8, 0:8, 0:1, 3:31, 0:1, 0:31>>,
    {error, {stream_error, 3, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

window_update_connection_good(_Config) ->
    Frame = <<4:24, 16#08:8, 0:8, 0:32, 0:1, 65535:31>>,
    {ok, {window_update, 65535}, 13} = nhttp_h2_frame:decode(Frame),
    ok.

window_update_stream_good(_Config) ->
    Frame = <<4:24, 16#08:8, 0:8, 0:1, 1:31, 0:1, 4096:31>>,
    {ok, {window_update, 1, 4096}, 13} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6.10 - CONTINUATION
%%%-----------------------------------------------------------------------------

continuation_on_stream_zero_is_protocol_error(_Config) ->
    Frame = <<0:24, 16#09:8, 16#04:8, 0:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    ok.

continuation_good(_Config) ->
    Frame = <<1:24, 16#09:8, 16#04:8, 0:1, 1:31, 16#82>>,
    {ok, {continuation, 1, fin, <<16#82>>}, 10} = nhttp_h2_frame:decode(Frame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 7 - Error Codes
%%%-----------------------------------------------------------------------------

known_error_codes_roundtrip(_Config) ->
    Codes = [
        no_error, protocol_error, internal_error, flow_control_error,
        settings_timeout, stream_closed, frame_size_error, refused_stream,
        cancel, compression_error, connect_error, enhance_your_calm,
        inadequate_security, http_1_1_required
    ],
    lists:foreach(
        fun(Code) ->
            {ok, Frame} = nhttp_h2_frame:rst_stream(1, Code),
            {ok, {rst_stream, 1, Code}, _} = nhttp_h2_frame:decode(iolist_to_binary(Frame))
        end,
        Codes
    ).

unknown_error_code_decodes_as_internal_error(_Config) ->
    Frame = <<4:24, 16#03:8, 0:8, 0:1, 1:31, 16#FF:32>>,
    {ok, {rst_stream, 1, internal_error}, 13} = nhttp_h2_frame:decode(Frame),
    ok.
