%%%-----------------------------------------------------------------------------
-module(nhttp_props_SUITE).

-moduledoc """
Property-based test suite using triq.

This suite runs all property tests defined in:
- nhttp_h2_frame_props
- nhttp_hpack_props
- nhttp_h1_props
- nhttp_h2_props
- nhttp_qpack_props
- nhttp_h3_frame_props
- nhttp_h3_props
- nhttp_ws_props
- nhttp_cookie_props
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, frame_props},
        {group, hpack_props},
        {group, h1_props},
        {group, h2_props},
        {group, qpack_props},
        {group, h3_frame_props},
        {group, h3_props},
        {group, ws_props},
        {group, cookie_props},
        {group, msg_props},
        {group, compress_props}
    ].

groups() ->
    [
        {frame_props, [parallel], [
            frame_data_roundtrip,
            frame_headers_roundtrip,
            frame_headers_priority_roundtrip,
            frame_priority_roundtrip,
            frame_rst_stream_roundtrip,
            frame_settings_roundtrip,
            frame_push_promise_roundtrip,
            frame_ping_roundtrip,
            frame_goaway_roundtrip,
            frame_window_update_conn_roundtrip,
            frame_window_update_stream_roundtrip,
            frame_continuation_roundtrip,
            frame_split_at,
            frame_decode_all,
            frame_bytes_consumed_correct,
            frame_incomplete_returns_more,
            frame_preface_roundtrip,
            frame_random_binary_no_crash,
            frame_bad_length_no_crash,
            frame_corrupted_payload_no_crash,
            frame_oversized_no_crash
        ]},
        {hpack_props, [parallel], [
            hpack_roundtrip,
            hpack_roundtrip_huffman,
            hpack_roundtrip_sequential,
            hpack_table_size_bounded,
            hpack_table_size_update,
            hpack_empty_after_zero_size,
            hpack_huffman_roundtrip,
            hpack_huffman_compression,
            hpack_random_binary_no_crash,
            hpack_huffman_random_no_crash,
            hpack_malformed_index_no_crash,
            hpack_bounded_after_error
        ]},
        {h1_props, [parallel], [
            h1_request_roundtrip,
            h1_response_roundtrip,
            h1_chunked_roundtrip,
            h1_split_at,
            h1_random_request_no_crash,
            h1_random_response_no_crash,
            h1_malformed_request_line_no_crash,
            h1_oversized_headers_no_crash,
            h1_chunked_extensions_and_trailers,
            h1_chunked_roundtrip_with_trailers,
            h1_reject_header_name_injection,
            h1_reject_header_value_bare_controls,
            h1_no_smuggling
        ]},
        {h2_props, [parallel], [
            h2_headers_roundtrip,
            h2_data_roundtrip,
            h2_request_response_roundtrip,
            h2_stream_state_machine,
            h2_stream_id_increment,
            h2_flow_control_window,
            h2_flow_control_consumes,
            h2_settings_roundtrip,
            h2_settings_update_peer,
            h2_continuation_sequence
        ]},
        {qpack_props, [parallel], [
            qpack_roundtrip_static,
            qpack_roundtrip_dynamic,
            qpack_sequential_roundtrip,
            qpack_interop_roundtrip,
            qpack_decode_no_crash,
            qpack_encoder_stream_no_crash,
            qpack_field_section_before_encoder_stream,
            qpack_multi_stream_acknowledgement
        ]},
        {h3_frame_props, [parallel], [
            h3_frame_data_roundtrip,
            h3_frame_headers_roundtrip,
            h3_frame_cancel_push_roundtrip,
            h3_frame_settings_roundtrip,
            h3_frame_push_promise_roundtrip,
            h3_frame_goaway_roundtrip,
            h3_frame_max_push_id_roundtrip,
            h3_frame_decode_returns_tail,
            h3_frame_incomplete_returns_more,
            h3_frame_random_binary_no_crash
        ]},
        {h3_props, [parallel], [
            h3_headers_roundtrip,
            h3_settings_roundtrip,
            h3_request_stream_no_crash,
            h3_uni_stream_no_crash
        ]},
        {ws_props, [parallel], [
            ws_unmasked_roundtrip,
            ws_masked_roundtrip,
            ws_unmasked_trailing_bytes,
            ws_decode_never_crashes,
            ws_decode_unmasked_never_crashes,
            ws_text_invalid_utf8_rejected,
            ws_close_code_rejected,
            ws_close_code_accepted,
            ws_fragmentation_reassembly,
            ws_continuation_without_start_rejected,
            ws_new_message_mid_fragmentation_rejected,
            ws_max_message_size_cumulative
        ]},
        {cookie_props, [parallel], [
            cookie_roundtrip,
            cookie_set_cookie_roundtrip,
            cookie_decode_never_crashes,
            cookie_decode_set_cookie_never_crashes
        ]},
        {msg_props, [parallel], [
            msg_validate_request_pseudo_shape_no_crash,
            msg_validate_request_pseudo_shape_valid_roundtrip
        ]},
        {compress_props, [parallel], [
            compress_roundtrip_gzip,
            compress_roundtrip_deflate,
            compress_decompress_max_output_gzip,
            compress_decompress_within_max_output_gzip,
            compress_decompress_truncated_no_crash,
            compress_decompress_random_binary_no_crash
        ]}
    ].

init_per_suite(Config) ->
    ct_property_test:init_per_suite(Config).

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
%%% FRAME PROPERTY TESTS
%%%-----------------------------------------------------------------------------

frame_data_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_data_roundtrip, Config).

frame_headers_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_headers_roundtrip, Config).

frame_headers_priority_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_headers_priority_roundtrip, Config).

frame_priority_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_priority_roundtrip, Config).

frame_rst_stream_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_rst_stream_roundtrip, Config).

frame_settings_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_settings_roundtrip, Config).

frame_push_promise_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_push_promise_roundtrip, Config).

frame_ping_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_ping_roundtrip, Config).

frame_goaway_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_goaway_roundtrip, Config).

frame_window_update_conn_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_window_update_conn_roundtrip, Config).

frame_window_update_stream_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_window_update_stream_roundtrip, Config).

frame_continuation_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_continuation_roundtrip, Config).

frame_split_at(Config) ->
    run_property(nhttp_h2_frame_props, prop_split_at, Config).

frame_decode_all(Config) ->
    run_property(nhttp_h2_frame_props, prop_decode_all, Config).

frame_bytes_consumed_correct(Config) ->
    run_property(nhttp_h2_frame_props, prop_bytes_consumed_correct, Config).

frame_incomplete_returns_more(Config) ->
    run_property(nhttp_h2_frame_props, prop_incomplete_returns_more, Config).

frame_preface_roundtrip(Config) ->
    run_property(nhttp_h2_frame_props, prop_preface_roundtrip, Config).

frame_random_binary_no_crash(Config) ->
    run_property(nhttp_h2_frame_props, prop_random_binary_no_crash, Config).

frame_bad_length_no_crash(Config) ->
    run_property(nhttp_h2_frame_props, prop_frame_bad_length_no_crash, Config).

frame_corrupted_payload_no_crash(Config) ->
    run_property(nhttp_h2_frame_props, prop_frame_corrupted_payload_no_crash, Config).

frame_oversized_no_crash(Config) ->
    run_property(nhttp_h2_frame_props, prop_oversized_frame_no_crash, Config).

%%%-----------------------------------------------------------------------------
%%% HPACK PROPERTY TESTS
%%%-----------------------------------------------------------------------------

hpack_roundtrip(Config) ->
    run_property(nhttp_hpack_props, prop_roundtrip, Config).

hpack_roundtrip_huffman(Config) ->
    run_property(nhttp_hpack_props, prop_roundtrip_huffman, Config).

hpack_roundtrip_sequential(Config) ->
    run_property(nhttp_hpack_props, prop_roundtrip_sequential, Config).

hpack_table_size_bounded(Config) ->
    run_property(nhttp_hpack_props, prop_table_size_bounded, Config).

hpack_table_size_update(Config) ->
    run_property(nhttp_hpack_props, prop_table_size_update, Config).

hpack_empty_after_zero_size(Config) ->
    run_property(nhttp_hpack_props, prop_empty_after_zero_size, Config).

hpack_huffman_roundtrip(Config) ->
    run_property(nhttp_hpack_props, prop_huffman_roundtrip, Config).

hpack_huffman_compression(Config) ->
    run_property(nhttp_hpack_props, prop_huffman_compression, Config).

hpack_random_binary_no_crash(Config) ->
    run_property(nhttp_hpack_props, prop_random_binary_no_crash, Config).

hpack_huffman_random_no_crash(Config) ->
    run_property(nhttp_hpack_props, prop_huffman_random_no_crash, Config).

hpack_malformed_index_no_crash(Config) ->
    run_property(nhttp_hpack_props, prop_malformed_index_no_crash, Config).

hpack_bounded_after_error(Config) ->
    run_property(nhttp_hpack_props, prop_hpack_bounded_after_error, Config).

%%%-----------------------------------------------------------------------------
%%% HTTP/1.1 PROPERTY TESTS
%%%-----------------------------------------------------------------------------

h1_request_roundtrip(Config) ->
    run_property(nhttp_h1_props, prop_request_roundtrip, Config).

h1_response_roundtrip(Config) ->
    run_property(nhttp_h1_props, prop_response_roundtrip, Config).

h1_chunked_roundtrip(Config) ->
    run_property(nhttp_h1_props, prop_chunked_roundtrip, Config).

h1_split_at(Config) ->
    run_property(nhttp_h1_props, prop_split_at, Config).

h1_random_request_no_crash(Config) ->
    run_property(nhttp_h1_props, prop_random_request_no_crash, Config).

h1_random_response_no_crash(Config) ->
    run_property(nhttp_h1_props, prop_random_response_no_crash, Config).

h1_malformed_request_line_no_crash(Config) ->
    run_property(nhttp_h1_props, prop_malformed_request_line_no_crash, Config).

h1_oversized_headers_no_crash(Config) ->
    run_property(nhttp_h1_props, prop_oversized_headers_no_crash, Config).

h1_chunked_extensions_and_trailers(Config) ->
    run_property(nhttp_h1_props, prop_chunked_extensions_and_trailers, Config).

h1_chunked_roundtrip_with_trailers(Config) ->
    run_property(nhttp_h1_props, prop_chunked_roundtrip_with_trailers, Config).

h1_reject_header_name_injection(Config) ->
    run_property(nhttp_h1_props, prop_reject_header_name_injection, Config).

h1_reject_header_value_bare_controls(Config) ->
    run_property(nhttp_h1_props, prop_reject_header_value_bare_controls, Config).

h1_no_smuggling(Config) ->
    run_property(nhttp_h1_props, prop_no_smuggling, Config).

%%%-----------------------------------------------------------------------------
%%% HTTP/2 PROPERTY TESTS
%%%-----------------------------------------------------------------------------

h2_headers_roundtrip(Config) ->
    run_property(nhttp_h2_props, prop_headers_roundtrip, Config).

h2_data_roundtrip(Config) ->
    run_property(nhttp_h2_props, prop_data_roundtrip, Config).

h2_request_response_roundtrip(Config) ->
    run_property(nhttp_h2_props, prop_request_response_roundtrip, Config).

h2_stream_state_machine(Config) ->
    run_property(nhttp_h2_props, prop_stream_state_machine, Config).

h2_stream_id_increment(Config) ->
    run_property(nhttp_h2_props, prop_stream_id_increment, Config).

h2_flow_control_window(Config) ->
    run_property(nhttp_h2_props, prop_flow_control_window, Config).

h2_flow_control_consumes(Config) ->
    run_property(nhttp_h2_props, prop_flow_control_consumes, Config).

h2_settings_roundtrip(Config) ->
    run_property(nhttp_h2_props, prop_settings_roundtrip, Config).

h2_settings_update_peer(Config) ->
    run_property(nhttp_h2_props, prop_settings_update_peer, Config).

h2_continuation_sequence(Config) ->
    run_property(nhttp_h2_props, prop_continuation_sequence, Config).

%%%-----------------------------------------------------------------------------
%%% QPACK PROPERTY TESTS
%%%-----------------------------------------------------------------------------

qpack_roundtrip_static(Config) ->
    run_property(nhttp_qpack_props, prop_roundtrip_static, Config).

qpack_roundtrip_dynamic(Config) ->
    run_property(nhttp_qpack_props, prop_roundtrip_dynamic, Config).

qpack_sequential_roundtrip(Config) ->
    run_property(nhttp_qpack_props, prop_sequential_roundtrip, Config).

qpack_interop_roundtrip(Config) ->
    run_property(nhttp_qpack_props, prop_interop_roundtrip, Config).

qpack_decode_no_crash(Config) ->
    run_property(nhttp_qpack_props, prop_decode_no_crash, Config).

qpack_encoder_stream_no_crash(Config) ->
    run_property(nhttp_qpack_props, prop_encoder_stream_no_crash, Config).

qpack_field_section_before_encoder_stream(Config) ->
    run_property(nhttp_qpack_props, prop_field_section_before_encoder_stream, Config).

qpack_multi_stream_acknowledgement(Config) ->
    run_property(nhttp_qpack_props, prop_multi_stream_acknowledgement, Config).

%%%-----------------------------------------------------------------------------
%%% H3 FRAME PROPERTY TESTS
%%%-----------------------------------------------------------------------------

h3_frame_data_roundtrip(Config) ->
    run_property(nhttp_h3_frame_props, prop_data_roundtrip, Config).

h3_frame_headers_roundtrip(Config) ->
    run_property(nhttp_h3_frame_props, prop_headers_roundtrip, Config).

h3_frame_cancel_push_roundtrip(Config) ->
    run_property(nhttp_h3_frame_props, prop_cancel_push_roundtrip, Config).

h3_frame_settings_roundtrip(Config) ->
    run_property(nhttp_h3_frame_props, prop_settings_roundtrip, Config).

h3_frame_push_promise_roundtrip(Config) ->
    run_property(nhttp_h3_frame_props, prop_push_promise_roundtrip, Config).

h3_frame_goaway_roundtrip(Config) ->
    run_property(nhttp_h3_frame_props, prop_goaway_roundtrip, Config).

h3_frame_max_push_id_roundtrip(Config) ->
    run_property(nhttp_h3_frame_props, prop_max_push_id_roundtrip, Config).

h3_frame_decode_returns_tail(Config) ->
    run_property(nhttp_h3_frame_props, prop_decode_returns_tail, Config).

h3_frame_incomplete_returns_more(Config) ->
    run_property(nhttp_h3_frame_props, prop_incomplete_returns_more, Config).

h3_frame_random_binary_no_crash(Config) ->
    run_property(nhttp_h3_frame_props, prop_random_binary_no_crash, Config).

%%%-----------------------------------------------------------------------------
%%% H3 CONNECTION PROPERTY TESTS
%%%-----------------------------------------------------------------------------

h3_headers_roundtrip(Config) ->
    run_property(nhttp_h3_props, prop_headers_roundtrip, Config).

h3_settings_roundtrip(Config) ->
    run_property(nhttp_h3_props, prop_settings_roundtrip, Config).

h3_request_stream_no_crash(Config) ->
    run_property(nhttp_h3_props, prop_request_stream_no_crash, Config).

h3_uni_stream_no_crash(Config) ->
    run_property(nhttp_h3_props, prop_uni_stream_no_crash, Config).

%%%-----------------------------------------------------------------------------
%%% WEBSOCKET PROPERTY TESTS
%%%-----------------------------------------------------------------------------

ws_unmasked_roundtrip(Config) ->
    run_property(nhttp_ws_props, prop_unmasked_roundtrip, Config).

ws_masked_roundtrip(Config) ->
    run_property(nhttp_ws_props, prop_masked_roundtrip, Config).

ws_unmasked_trailing_bytes(Config) ->
    run_property(nhttp_ws_props, prop_unmasked_trailing_bytes, Config).

ws_decode_never_crashes(Config) ->
    run_property(nhttp_ws_props, prop_decode_never_crashes, Config).

ws_decode_unmasked_never_crashes(Config) ->
    run_property(nhttp_ws_props, prop_decode_unmasked_never_crashes, Config).

ws_text_invalid_utf8_rejected(Config) ->
    run_property(nhttp_ws_props, prop_text_invalid_utf8_rejected, Config).

ws_close_code_rejected(Config) ->
    run_property(nhttp_ws_props, prop_close_code_rejected, Config).

ws_close_code_accepted(Config) ->
    run_property(nhttp_ws_props, prop_close_code_accepted, Config).

ws_fragmentation_reassembly(Config) ->
    run_property(nhttp_ws_props, prop_ws_fragmentation_reassembly, Config).

ws_continuation_without_start_rejected(Config) ->
    run_property(nhttp_ws_props, prop_ws_continuation_without_start_rejected, Config).

ws_new_message_mid_fragmentation_rejected(Config) ->
    run_property(nhttp_ws_props, prop_ws_new_message_mid_fragmentation_rejected, Config).

ws_max_message_size_cumulative(Config) ->
    run_property(nhttp_ws_props, prop_ws_max_message_size_cumulative, Config).

%%%-----------------------------------------------------------------------------
%%% COOKIE PROPERTY TESTS
%%%-----------------------------------------------------------------------------

cookie_roundtrip(Config) ->
    run_property(nhttp_cookie_props, prop_cookie_roundtrip, Config).

cookie_set_cookie_roundtrip(Config) ->
    run_property(nhttp_cookie_props, prop_set_cookie_roundtrip, Config).

cookie_decode_never_crashes(Config) ->
    run_property(nhttp_cookie_props, prop_decode_cookie_never_crashes, Config).

cookie_decode_set_cookie_never_crashes(Config) ->
    run_property(nhttp_cookie_props, prop_decode_set_cookie_never_crashes, Config).

%%%-----------------------------------------------------------------------------
%%% NHTTP_MSG PROPERTY TESTS
%%%-----------------------------------------------------------------------------

msg_validate_request_pseudo_shape_no_crash(Config) ->
    run_property(nhttp_msg_props, prop_validate_request_pseudo_shape_no_crash, Config).

msg_validate_request_pseudo_shape_valid_roundtrip(Config) ->
    run_property(nhttp_msg_props, prop_validate_request_pseudo_shape_valid_roundtrip, Config).

%%%-----------------------------------------------------------------------------
%%% NHTTP_COMPRESS PROPERTY TESTS
%%%-----------------------------------------------------------------------------

compress_roundtrip_gzip(Config) ->
    run_property(nhttp_compress_props, prop_compress_roundtrip_gzip, Config).

compress_roundtrip_deflate(Config) ->
    run_property(nhttp_compress_props, prop_compress_roundtrip_deflate, Config).

compress_decompress_max_output_gzip(Config) ->
    run_property(nhttp_compress_props, prop_decompress_max_output_gzip, Config).

compress_decompress_within_max_output_gzip(Config) ->
    run_property(nhttp_compress_props, prop_decompress_within_max_output_gzip, Config).

compress_decompress_truncated_no_crash(Config) ->
    run_property(nhttp_compress_props, prop_decompress_truncated_no_crash, Config).

compress_decompress_random_binary_no_crash(Config) ->
    run_property(nhttp_compress_props, prop_decompress_random_binary_no_crash, Config).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec run_property(module(), atom(), list()) -> ok.
run_property(Module, Property, Config) ->
    ct_property_test:quickcheck(Module:Property(), Config).
