%%%-----------------------------------------------------------------------------
-module(nhttp_h2_rfc9113_SUITE).

-moduledoc """
RFC 9113 Compliance Test Suite.

Tests compliance with RFC 9113 (HTTP/2) at the connection and stream
state machine level. Frame-level wire compliance lives in
`nhttp_h2_rfc9113_frames_SUITE`.

Each test case cites the specific RFC requirement it exercises in the
form `RFC9113-N.N-K: <paraphrased rule>`.

Run with: rebar3 ct --suite=test/compliance/nhttp_h2_rfc9113_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_3_starting},
        {group, section_4_frames},
        {group, section_5_streams},
        {group, section_6_settings_and_flow_control},
        {group, section_8_http_semantics},
        {group, section_10_denial_of_service}
    ].

groups() ->
    [
        {section_3_starting, [parallel], [
            server_accepts_valid_preface,
            server_rejects_invalid_preface,
            server_accepts_preface_delivered_in_two_reads,
            server_rejects_a_preface_prefix_that_cannot_complete,
            client_preface_contains_magic_and_settings,
            server_preface_is_settings_only,
            server_rejects_a_second_preface,
            client_rejects_a_preface_from_the_server,
            server_requires_settings_after_the_magic,
            server_rejects_settings_ack_as_first_frame,
            client_requires_settings_as_first_server_frame
        ]},
        {section_4_frames, [parallel], [
            interleaved_frame_during_continuation_is_connection_error,
            unknown_frame_type_discarded,
            send_data_frames_stay_under_peer_max_frame_size
        ]},
        {section_5_streams, [parallel], [
            data_on_idle_stream_is_connection_error,
            client_data_on_idle_stream_is_connection_error,
            data_after_rst_stream_is_discarded_and_credited,
            headers_on_half_closed_remote_is_stream_error,
            rst_stream_on_idle_stream_is_connection_error,
            window_update_on_idle_stream_is_connection_error,
            server_rejects_even_client_stream_id,
            server_rejects_non_increasing_stream_id,
            client_rejects_odd_server_stream_id,
            max_concurrent_streams_triggers_refused_stream,
            client_rejects_window_update_on_idle_stream,
            client_refuses_stream_id_above_maximum,
            data_after_peer_rst_stream_is_stream_closed,
            data_on_closed_stream_is_stream_closed,
            client_data_after_peer_rst_stream_is_stream_closed,
            second_data_after_reject_is_discarded,
            late_response_after_cancel_is_discarded,
            late_response_updates_the_hpack_decoder,
            server_data_after_local_rst_stream_is_discarded_and_credited,
            headers_after_local_rst_stream_is_discarded,
            continuation_after_local_rst_stream_is_discarded,
            empty_data_after_local_rst_stream_emits_nothing,
            data_after_refused_stream_is_discarded,
            refused_headers_keep_the_hpack_decoder,
            refused_stream_advances_last_peer_stream_id,
            data_after_codec_rst_stream_is_discarded,
            local_reset_memory_evicts_the_oldest_reset
        ]},
        {section_6_settings_and_flow_control, [parallel], [
            settings_ack_sent_in_response,
            settings_initial_window_size_updates_streams,
            settings_initial_window_size_reaches_idle_stream,
            settings_initial_window_size_shrink_retains_negative_window,
            settings_initial_window_size_growth_drains_queued_data,
            settings_initial_window_size_overflow_is_connection_error,
            settings_initial_window_size_emits_no_window_update_event,
            zero_length_end_stream_data_is_sent_at_zero_window,
            settings_header_table_size_propagates_to_hpack,
            ping_ack_echoes_payload,
            connection_window_overflow_is_connection_error,
            stream_window_overflow_is_stream_error,
            padded_data_credits_its_padding,
            padded_data_counts_against_the_window,
            padded_data_credit_matches_every_pad_length,
            discarded_data_counts_against_the_window,
            data_on_half_closed_remote_credits_the_connection,
            data_over_stream_window_credits_the_connection,
            content_length_mismatch_credits_the_connection,
            goaway_transitions_to_closing,
            peer_without_max_concurrent_streams_has_no_limit,
            peer_settings_report_rfc_initial_values
        ]},
        {section_8_http_semantics, [parallel], [
            request_missing_method_is_stream_error,
            request_missing_scheme_is_stream_error,
            request_missing_path_is_stream_error,
            request_empty_path_is_stream_error,
            request_duplicate_pseudo_header_is_stream_error,
            request_pseudo_after_regular_is_stream_error,
            request_unknown_pseudo_is_stream_error,
            response_missing_status_is_stream_error,
            response_non_digit_status_is_stream_error,
            response_status_not_three_digits_is_stream_error,
            response_status_outside_class_range_is_stream_error,
            response_three_digit_status_accepted,
            connection_header_forbidden,
            keep_alive_header_forbidden,
            proxy_connection_header_forbidden,
            transfer_encoding_header_forbidden,
            upgrade_header_forbidden,
            te_trailers_allowed,
            te_non_trailers_forbidden,
            sender_lowercases_field_names,
            uppercase_header_name_is_stream_error,
            invalid_field_name_char_is_stream_error,
            interior_colon_in_field_name_is_stream_error,
            pseudo_header_name_is_accepted,
            invalid_field_value_char_is_stream_error,
            field_value_edge_whitespace_is_stream_error,
            invalid_field_keeps_the_dynamic_table_in_step,
            invalid_field_value_in_response_is_stream_error,
            invalid_field_value_in_trailers_is_stream_error,
            trailers_with_pseudo_header_is_stream_error,
            trailers_deliver_after_fin,
            content_length_mismatch_is_stream_error,
            content_length_exceeded_is_stream_error
        ]},
        {section_10_denial_of_service, [parallel], [
            max_concurrent_streams_does_not_bound_stream_turnover,
            stream_turnover_is_tracked_on_the_connection,
            reset_allowance_is_connection_error_enhance_your_calm,
            empty_continuation_flood_is_connection_error_enhance_your_calm,
            continuation_allowance_scales_with_max_header_list_size
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
%%% Section 3 - Starting HTTP/2
%%%-----------------------------------------------------------------------------

server_accepts_valid_preface(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    ok.

server_rejects_invalid_preface(_Config) ->
    Conn0 = nhttp_h2:new(server),
    Bogus = <<"PRI * HTTP/1.1\r\n\r\nSM\r\n\r\n">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn0, Bogus),
    ok.

server_accepts_preface_delivered_in_two_reads(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {ok, Preface} = nhttp_h2_frame:preface(),
    <<Head:10/binary, Tail/binary>> = iolist_to_binary(Preface),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, Head),
    {ok, [], _Conn2} = nhttp_h2:recv(Conn1, Tail),
    ok.

server_rejects_a_preface_prefix_that_cannot_complete(_Config) ->
    Conn0 = nhttp_h2:new(server),
    Head = <<"PRI * HTTP/1.1">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn0, Head),
    ok.

client_preface_contains_magic_and_settings(_Config) ->
    Conn = nhttp_h2:new(client),
    PrefaceData = nhttp_h2:preface(Conn),
    Preface = iolist_to_binary(PrefaceData),
    Magic = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
    ?assertEqual(Magic, binary:part(Preface, 0, 24)),
    <<_:24/binary, SettingsFrame/binary>> = Preface,
    {ok, {settings, _}, _} = nhttp_h2_frame:decode(SettingsFrame),
    ok.

server_preface_is_settings_only(_Config) ->
    Conn = nhttp_h2:new(server),
    PrefaceData = nhttp_h2:preface(Conn),
    Preface = iolist_to_binary(PrefaceData),
    {ok, {settings, _}, _} = nhttp_h2_frame:decode(Preface),
    ok.

%% RFC9113-3.4-1: the magic opens the client preface once. A second copy is
%% an invalid preface, a connection error.
server_rejects_a_second_preface(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {ok, [{settings, #{}}], Conn1, _Ack} =
        nhttp_h2:recv(Conn0, <<(literal_magic())/binary, (literal_settings())/binary>>),
    {error, {connection_error, _, _}} = nhttp_h2:recv(Conn1, literal_magic()),
    ok.

%% RFC9113-3.4-2: the server preface is a SETTINGS frame and carries no
%% magic. The magic from a server is an invalid preface, at the start of the
%% connection and after it.
client_rejects_a_preface_from_the_server(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {error, {connection_error, _, _}} = nhttp_h2:recv(Conn0, literal_magic()),
    {ok, [{settings, #{}}], Conn1, _Ack} = nhttp_h2:recv(Conn0, literal_settings()),
    {error, {connection_error, _, _}} = nhttp_h2:recv(Conn1, literal_magic()),
    ok.

%% RFC9113-3.4-3: the magic MUST be followed by a SETTINGS frame. Any other
%% frame is an invalid preface, a PROTOCOL_ERROR connection error.
server_requires_settings_after_the_magic(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, <<(literal_magic())/binary, (literal_ping())/binary>>),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, literal_magic()),
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn1, literal_ping()),
    ok.

%% RFC9113-3.4-4: a SETTINGS frame with ACK acknowledges the SETTINGS of this
%% endpoint and cannot open the peer preface.
server_rejects_settings_ack_as_first_frame(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, <<(literal_magic())/binary, (literal_settings_ack())/binary>>),
    ok.

%% RFC9113-3.4-5: the SETTINGS frame MUST be the first frame the server
%% sends. A PING first is an invalid preface.
client_requires_settings_as_first_server_frame(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn0, literal_ping()),
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn0, literal_settings_ack()),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 4 - HTTP Frames
%%%-----------------------------------------------------------------------------

interleaved_frame_during_continuation_is_connection_error(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, HeaderBlock),
    {ok, Ping} = nhttp_h2_frame:ping(<<0:64>>),
    Buf = iolist_to_binary([HeadersFrame, Ping]),
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn0, Buf),
    ok.

unknown_frame_type_discarded(_Config) ->
    Conn0 = server_with_preface(),
    UnknownFrame = <<0:24, 16#FA:8, 0:8, 0:32>>,
    {ok, [], _Conn1} = nhttp_h2:recv(Conn0, UnknownFrame),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 5 - Streams and Multiplexing
%%%-----------------------------------------------------------------------------

data_on_idle_stream_is_connection_error(_Config) ->
    Conn0 = server_with_preface(),
    {ok, DataFrame} = nhttp_h2_frame:data(1, fin, <<"hello">>),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(DataFrame)),
    ok.

%% A stream id at or above the next one the client opens, or an even one,
%% names a stream that never existed.
client_data_on_idle_stream_is_connection_error(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), fin),
    {ok, Even} = nhttp_h2_frame:data(2, fin, <<"x">>),
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn2, iolist_to_binary(Even)),
    {ok, Next} = nhttp_h2_frame:data(StreamId + 2, fin, <<"x">>),
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn2, iolist_to_binary(Next)),
    ok.

%% RFC 9113 Section 5.1: DATA that the peer sent before it saw our
%% RST_STREAM is discarded, and Section 6.9 still counts it against the
%% connection window. The codec returns that credit, answers with no
%% RST_STREAM, and the connection stays up.
data_after_rst_stream_is_discarded_and_credited(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), fin),
    {ok, Conn3, _} = nhttp_h2:send_rst_stream(Conn2, StreamId, cancel),
    Late = <<10:24, 16#00:8, 16#08:8, 0:1, StreamId:31, 3:8, "late!!", 0, 0, 0>>,
    {ok, [], _Conn4, Out} = nhttp_h2:recv(Conn3, Late),
    ?assertEqual({ok, [{window_update, 10}], 13}, nhttp_h2_frame:decode_all(iolist_to_binary(Out))),
    ok.

headers_on_half_closed_remote_is_stream_error(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [{request, 1, _, fin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    TrailerBlock = encode_headers([{<<"x-trailer">>, <<"1">>}]),
    {ok, TrailerFrame} = nhttp_h2_frame:headers(1, fin, fin, TrailerBlock),
    Result = nhttp_h2:recv(Conn1, iolist_to_binary(TrailerFrame)),
    {ok, [], _Conn2, RstData} = Result,
    {ok, {rst_stream, 1, stream_closed}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstData)),
    ok.

rst_stream_on_idle_stream_is_connection_error(_Config) ->
    Conn0 = server_with_preface(),
    {ok, RstFrame} = nhttp_h2_frame:rst_stream(1, cancel),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(RstFrame)),
    ok.

window_update_on_idle_stream_is_connection_error(_Config) ->
    Conn0 = server_with_preface(),
    {ok, Wu} = nhttp_h2_frame:window_update(1, 100),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(Wu)),
    ok.

client_rejects_window_update_on_idle_stream(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, WuEven} = nhttp_h2_frame:window_update(2, 100),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(WuEven)),
    {ok, WuUnopened} = nhttp_h2_frame:window_update(1, 100),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(WuUnopened)),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), fin),
    RespBlock = encode_headers([{<<":status">>, <<"204">>}]),
    {ok, Resp} = nhttp_h2_frame:headers(StreamId, fin, fin, RespBlock),
    {ok, [{response, StreamId, _, fin}], Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Resp)),
    {ok, WuClosed} = nhttp_h2_frame:window_update(StreamId, 100),
    {ok, [], _Conn4} = nhttp_h2:recv(Conn3, iolist_to_binary(WuClosed)),
    {ok, WuNext} = nhttp_h2_frame:window_update(StreamId + 2, 100),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn3, iolist_to_binary(WuNext)),
    ok.

client_refuses_stream_id_above_maximum(_Config) ->
    Conn0 = nhttp_h2:new(client),
    Index = maps:get(next_stream_id, record_positions(nhttp_h2, h2_conn)),
    LastId = 16#7fffffff,
    Conn1 = setelement(Index, Conn0, LastId),
    {ok, LastId, Conn2} = nhttp_h2:open_stream(Conn1),
    ?assertEqual(LastId + 2, element(Index, Conn2)),
    {error, stream_ids_exhausted} = nhttp_h2:open_stream(Conn2),
    ok.

server_rejects_even_client_stream_id(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(2, fin, fin, HeaderBlock),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ok.

server_rejects_non_increasing_stream_id(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, F3} = nhttp_h2_frame:headers(3, fin, fin, HeaderBlock),
    {ok, _Events, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(F3)),
    {ok, F1} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn1, iolist_to_binary(F1)),
    ok.

client_rejects_odd_server_stream_id(_Config) ->
    Conn0 = client_with_server_preface(),
    HeaderBlock = encode_headers([{<<":status">>, <<"200">>}]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(3, fin, fin, HeaderBlock),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ok.

max_concurrent_streams_triggers_refused_stream(_Config) ->
    Conn0 = server_with_preface_settings(#{max_concurrent_streams => 1}),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, F1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(F1)),
    {ok, F3} = nhttp_h2_frame:headers(3, fin, fin, HeaderBlock),
    Result = nhttp_h2:recv(Conn1, iolist_to_binary(F3)),
    ?assertMatch({ok, [{stream_refused, 3}], _, _}, Result),
    {ok, [{stream_refused, 3}], _Conn2, OutData} = Result,
    {ok, {rst_stream, 3, refused_stream}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

%% RFC 9113 Section 5.1: the peer reset the stream, so it knows the stream
%% is closed. DATA after its own RST_STREAM is a STREAM_CLOSED stream
%% error, and the octets still count against the connection window.
%% Mirrors h2spec 5.1/8.
data_after_peer_rst_stream_is_stream_closed(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, encode_headers(minimal_request_headers())),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, Rst} = nhttp_h2_frame:rst_stream(1, cancel),
    {ok, [{stream_reset, 1, cancel}], Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(Rst)),
    {ok, D} = nhttp_h2_frame:data(1, nofin, <<"late">>),
    {ok, [], _Conn3, Out} = nhttp_h2:recv(Conn2, iolist_to_binary(D)),
    ?assertEqual(
        {ok, [{rst_stream, 1, stream_closed}, {window_update, 4}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out))
    ),
    ok.

%% RFC 9113 Section 5.1: both sides sent END_STREAM, so the stream is
%% closed and the peer knows it. DATA on it is a STREAM_CLOSED stream
%% error. Mirrors h2spec 5.1/11.
data_on_closed_stream_is_stream_closed(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, fin, fin, encode_headers(minimal_request_headers())),
    {ok, [{request, 1, _, fin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, 1, [{<<":status">>, <<"204">>}], fin),
    {ok, D} = nhttp_h2_frame:data(1, nofin, <<"late">>),
    {ok, [], _Conn3, Out} = nhttp_h2:recv(Conn2, iolist_to_binary(D)),
    ?assertEqual(
        {ok, [{rst_stream, 1, stream_closed}, {window_update, 4}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out))
    ),
    ok.

%% The client role twin of data_after_peer_rst_stream_is_stream_closed.
client_data_after_peer_rst_stream_is_stream_closed(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), fin),
    {ok, Rst} = nhttp_h2_frame:rst_stream(StreamId, cancel),
    {ok, [{stream_reset, StreamId, cancel}], Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Rst)),
    {ok, D} = nhttp_h2_frame:data(StreamId, nofin, <<"late">>),
    {ok, [], _Conn4, Out} = nhttp_h2:recv(Conn3, iolist_to_binary(D)),
    ?assertEqual(
        {ok, [{rst_stream, StreamId, stream_closed}, {window_update, 4}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out))
    ),
    ok.

%% A stream that the codec reset with STREAM_CLOSED is a stream this
%% endpoint reset. The next DATA frame on it is discarded and credited,
%% so one bad stream costs one RST_STREAM, never one per frame.
second_data_after_reject_is_discarded(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, fin, fin, encode_headers(minimal_request_headers())),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, D1} = nhttp_h2_frame:data(1, nofin, <<"extra">>),
    {ok, [], Conn2, Out1} = nhttp_h2:recv(Conn1, iolist_to_binary(D1)),
    ?assertEqual(
        {ok, [{rst_stream, 1, stream_closed}, {window_update, 5}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out1))
    ),
    {ok, D2} = nhttp_h2_frame:data(1, nofin, <<"more">>),
    {ok, [], _Conn3, Out2} = nhttp_h2:recv(Conn2, iolist_to_binary(D2)),
    ?assertEqual(
        {ok, [{window_update, 4}], 13},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out2))
    ),
    ok.

%% RFC 9113 Section 5.1: after this endpoint sends RST_STREAM, frames the
%% peer sent before it saw the reset are processed for their side effects
%% and discarded. A whole late response to a cancelled request, HEADERS,
%% padded DATA and trailers, costs the connection nothing but the
%% WINDOW_UPDATE credit for each DATA frame.
late_response_after_cancel_is_discarded(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), fin),
    {ok, Conn3, _} = nhttp_h2:send_rst_stream(Conn2, StreamId, cancel),
    {ok, Enc0} = nhttp_hpack:new(),
    {RespBlock, Enc1} = encode_headers([{<<":status">>, <<"200">>}], Enc0),
    {ok, Resp} = nhttp_h2_frame:headers(StreamId, nofin, fin, RespBlock),
    D1 = <<8:24, 16#00:8, 16#08:8, 0:1, StreamId:31, 3:8, "aaaa", 0:24>>,
    D2 = <<6:24, 16#00:8, 16#08:8, 0:1, StreamId:31, 0:8, "bbbbb">>,
    D3 = <<14:24, 16#00:8, 16#08:8, 0:1, StreamId:31, 7:8, "cccccc", 0:56>>,
    {TrailerBlock, _Enc2} = encode_headers([{<<"x-trailer">>, <<"1">>}], Enc1),
    {ok, Trailers} = nhttp_h2_frame:headers(StreamId, fin, fin, TrailerBlock),
    {ok, [], _Conn4, Out} = nhttp_h2:recv(Conn3, iolist_to_binary([Resp, D1, D2, D3, Trailers])),
    ?assertEqual(
        {ok, [{window_update, 8}, {window_update, 6}, {window_update, 14}], 39},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out))
    ),
    ok.

%% A discarded field section still updates the HPACK decoder (RFC 9113
%% Section 4.3), so a later response that references the entry it inserted
%% decodes.
late_response_updates_the_hpack_decoder(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, Cancelled, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, Cancelled, minimal_request_headers(), fin),
    {ok, Conn3, _} = nhttp_h2:send_rst_stream(Conn2, Cancelled, cancel),
    {ok, Live, Conn4} = nhttp_h2:open_stream(Conn3),
    {ok, Conn5, _} = nhttp_h2:send_headers(Conn4, Live, minimal_request_headers(), fin),
    Response = [{<<":status">>, <<"200">>}, {<<"x-custom">>, <<"v">>}],
    {ok, Enc0} = nhttp_hpack:new(),
    {LateBlock, Enc1} = encode_headers(Response, Enc0),
    {LiveBlock, _Enc2} = encode_headers(Response, Enc1),
    ?assertEqual(<<16#88, 16#BE>>, LiveBlock),
    {ok, LateResp} = nhttp_h2_frame:headers(Cancelled, fin, fin, LateBlock),
    {ok, LiveResp} = nhttp_h2_frame:headers(Live, fin, fin, LiveBlock),
    {ok, [{response, Live, Resp, fin}], _Conn6} =
        nhttp_h2:recv(Conn5, iolist_to_binary([LateResp, LiveResp])),
    ?assertEqual(<<"v">>, nhttp_headers:get(<<"x-custom">>, maps:get(headers, Resp))),
    ok.

%% The server side of the local reset: DATA after our RST_STREAM is
%% discarded and the full flow length, padding included, is credited on
%% the connection.
server_data_after_local_rst_stream_is_discarded_and_credited(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, encode_headers(minimal_request_headers())),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, Conn2, _} = nhttp_h2:send_rst_stream(Conn1, 1, cancel),
    Padded = <<6:24, 16#00:8, 16#08:8, 0:1, 1:31, 3:8, "ab", 0:24>>,
    {ok, [], _Conn3, Out} = nhttp_h2:recv(Conn2, Padded),
    ?assertEqual({ok, [{window_update, 6}], 13}, nhttp_h2_frame:decode_all(iolist_to_binary(Out))),
    ok.

%% HEADERS after our RST_STREAM is decoded for the HPACK side effects and
%% dropped: no event, no frame, no error.
headers_after_local_rst_stream_is_discarded(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, encode_headers(minimal_request_headers())),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, Conn2, _} = nhttp_h2:send_rst_stream(Conn1, 1, cancel),
    {ok, Trailers} = nhttp_h2_frame:headers(1, fin, fin, encode_headers([{<<"x-trailer">>, <<"1">>}])),
    {ok, [], _Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Trailers)),
    ok.

%% A field section split over HEADERS and CONTINUATION on a stream we reset
%% is dropped once complete, and the entry that buffered it leaves the
%% stream map.
continuation_after_local_rst_stream_is_discarded(_Config) ->
    Conn0 = server_with_preface(),
    ReqBlock = encode_headers(minimal_request_headers()),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, ReqBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, Conn2, _} = nhttp_h2:send_rst_stream(Conn1, 1, cancel),
    TrailerBlock = encode_headers([{<<"x-trailer">>, <<"1">>}, {<<"x-other">>, <<"2">>}]),
    Split = byte_size(TrailerBlock) div 2,
    <<Part1:Split/binary, Part2/binary>> = TrailerBlock,
    {ok, Head} = nhttp_h2_frame:headers(1, fin, nofin, Part1),
    {ok, Cont} = nhttp_h2_frame:continuation(1, fin, Part2),
    {ok, [], Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary([Head, Cont])),
    StreamsIndex = maps:get(streams, record_positions(nhttp_h2, h2_conn)),
    ?assertNot(maps:is_key(1, element(StreamsIndex, Conn3))),
    {ok, H3} = nhttp_h2_frame:headers(3, fin, fin, ReqBlock),
    {ok, [{request, 3, _, fin}], _Conn4} = nhttp_h2:recv(Conn3, iolist_to_binary(H3)),
    ok.

%% An empty DATA frame after our RST_STREAM owes no credit, so recv/2
%% returns nothing to write.
empty_data_after_local_rst_stream_emits_nothing(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, encode_headers(minimal_request_headers())),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, Conn2, _} = nhttp_h2:send_rst_stream(Conn1, 1, cancel),
    {ok, Empty} = nhttp_h2_frame:data(1, fin, <<>>),
    {ok, [], _Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Empty)),
    ok.

%% A refused stream is a stream this endpoint reset. A client that
%% pipelines HEADERS and DATA always has DATA in flight for it, and that
%% DATA is discarded and credited, not answered with an error.
data_after_refused_stream_is_discarded(_Config) ->
    Conn0 = server_with_preface_settings(#{max_concurrent_streams => 1}),
    ReqBlock = encode_headers(minimal_request_headers()),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, ReqBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, H3} = nhttp_h2_frame:headers(3, nofin, fin, ReqBlock),
    {ok, [{stream_refused, 3}], Conn2, _} = nhttp_h2:recv(Conn1, iolist_to_binary(H3)),
    {ok, D} = nhttp_h2_frame:data(3, fin, <<"body">>),
    {ok, [], _Conn3, Out} = nhttp_h2:recv(Conn2, iolist_to_binary(D)),
    ?assertEqual({ok, [{window_update, 4}], 13}, nhttp_h2_frame:decode_all(iolist_to_binary(Out))),
    ok.

%% RFC 9113 Section 4.3: a refused field section still updates the HPACK
%% decoder. The next accepted field section that references the entry it
%% inserted decodes.
refused_headers_keep_the_hpack_decoder(_Config) ->
    Conn0 = server_with_preface_settings(#{max_concurrent_streams => 1}),
    {ok, Enc0} = nhttp_hpack:new(),
    {Block1, Enc1} = encode_headers(minimal_request_headers(), Enc0),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, Block1),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    Custom = minimal_request_headers() ++ [{<<"x-custom">>, <<"v">>}],
    {Block3, Enc2} = encode_headers(Custom, Enc1),
    {ok, H3} = nhttp_h2_frame:headers(3, fin, fin, Block3),
    {ok, [{stream_refused, 3}], Conn2, _} = nhttp_h2:recv(Conn1, iolist_to_binary(H3)),
    {ok, Rst} = nhttp_h2_frame:rst_stream(1, cancel),
    {ok, [{stream_reset, 1, cancel}], Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Rst)),
    {Block5, _Enc3} = encode_headers(Custom, Enc2),
    ?assertEqual(16#BE, binary:last(Block5)),
    {ok, H5} = nhttp_h2_frame:headers(5, fin, fin, Block5),
    {ok, [{request, 5, Request, fin}], _Conn4} = nhttp_h2:recv(Conn3, iolist_to_binary(H5)),
    ?assertEqual(<<"v">>, nhttp_headers:get(<<"x-custom">>, maps:get(headers, Request))),
    ok.

%% RFC 9113 Section 5.1.1: a refused stream was opened. The peer cannot
%% open a lower stream id behind it.
refused_stream_advances_last_peer_stream_id(_Config) ->
    Conn0 = server_with_preface_settings(#{max_concurrent_streams => 1}),
    ReqBlock = encode_headers(minimal_request_headers()),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, ReqBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, H5} = nhttp_h2_frame:headers(5, fin, fin, ReqBlock),
    {ok, [{stream_refused, 5}], Conn2, _} = nhttp_h2:recv(Conn1, iolist_to_binary(H5)),
    {ok, H3} = nhttp_h2_frame:headers(3, fin, fin, ReqBlock),
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn2, iolist_to_binary(H3)),
    ok.

%% A stream that the codec reset for a stream window overflow is a stream
%% this endpoint reset. More DATA on it is discarded and credited.
data_after_codec_rst_stream_is_discarded(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, encode_headers(minimal_request_headers())),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, Conn2, _} = nhttp_h2:send_window_update(Conn1, connection, 100000),
    {ok, Full} = nhttp_h2_frame:data(1, nofin, binary:copy(<<"x">>, 16384)),
    {ok, Events, Conn3, Out1} = nhttp_h2:recv(Conn2, iolist_to_binary([Full, Full, Full, Full])),
    ?assertEqual(3, length(Events)),
    ?assertEqual(
        {ok, [{rst_stream, 1, flow_control_error}, {window_update, 16384}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out1))
    ),
    {ok, More} = nhttp_h2_frame:data(1, fin, <<"more">>),
    {ok, [], _Conn4, Out2} = nhttp_h2:recv(Conn3, iolist_to_binary(More)),
    ?assertEqual({ok, [{window_update, 4}], 13}, nhttp_h2_frame:decode_all(iolist_to_binary(Out2))),
    ok.

%% The codec remembers the last 1024 streams it reset, in reset order. The
%% oldest reset leaves first, whatever its id. The DATA on stream 1 goes
%% first: the STREAM_CLOSED answer on stream 3 records a reset of its own,
%% and that one evicts stream 1.
local_reset_memory_evicts_the_oldest_reset(_Config) ->
    Conn0 = server_with_preface(),
    ReqBlock = encode_headers(minimal_request_headers()),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, ReqBlock),
    {ok, H3} = nhttp_h2_frame:headers(3, nofin, fin, ReqBlock),
    {ok, [{request, 1, _, nofin}, {request, 3, _, nofin}], Conn1} =
        nhttp_h2:recv(Conn0, iolist_to_binary([H1, H3])),
    {ok, Conn2, _} = nhttp_h2:send_rst_stream(Conn1, 3, cancel),
    {ok, Conn3, _} = nhttp_h2:send_rst_stream(Conn2, 1, cancel),
    Conn4 = lists:foldl(
        fun(StreamId, Conn) ->
            {ok, Next, _} = nhttp_h2:send_rst_stream(Conn, StreamId, cancel),
            Next
        end,
        Conn3,
        lists:seq(5, 5 + 2 * 1022, 2)
    ),
    {ok, D1} = nhttp_h2_frame:data(1, nofin, <<"y">>),
    {ok, [], Conn5, Out1} = nhttp_h2:recv(Conn4, iolist_to_binary(D1)),
    ?assertEqual({ok, [{window_update, 1}], 13}, nhttp_h2_frame:decode_all(iolist_to_binary(Out1))),
    {ok, D3} = nhttp_h2_frame:data(3, nofin, <<"x">>),
    {ok, [], _Conn6, Out3} = nhttp_h2:recv(Conn5, iolist_to_binary(D3)),
    ?assertEqual(
        {ok, [{rst_stream, 3, stream_closed}, {window_update, 1}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out3))
    ),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 6 - SETTINGS and Flow Control
%%%-----------------------------------------------------------------------------

settings_ack_sent_in_response(_Config) ->
    Conn0 = server_with_preface(),
    {ok, SettingsFrame} = nhttp_h2_frame:settings(#{max_concurrent_streams => 50}),
    {ok, [{settings, _}], _Conn1, OutData} =
        nhttp_h2:recv(Conn0, iolist_to_binary(SettingsFrame)),
    {ok, settings_ack, _} = nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

settings_initial_window_size_updates_streams(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, F1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(F1)),
    ?assertEqual({ok, 65535}, nhttp_h2:stream_send_window(Conn1, 1)),
    {ok, S} = nhttp_h2_frame:settings(#{initial_window_size => 131070}),
    {ok, [{settings, #{initial_window_size := 131070}}], Conn2, _OutData} =
        nhttp_h2:recv(Conn1, iolist_to_binary(S)),
    ?assertEqual({ok, 131070}, nhttp_h2:stream_send_window(Conn2, 1)),
    ok.

settings_initial_window_size_reaches_idle_stream(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    ?assertEqual({ok, 65535}, nhttp_h2:stream_send_window(Conn1, StreamId)),
    {ok, S} = nhttp_h2_frame:settings(#{initial_window_size => 100000, max_frame_size => 131072}),
    {ok, [{settings, _}], Conn2, _} = nhttp_h2:recv(Conn1, iolist_to_binary(S)),
    ?assertEqual({ok, 100000}, nhttp_h2:stream_send_window(Conn2, StreamId)),
    {ok, Wu} = nhttp_h2_frame:window_update(100000),
    {ok, [{window_update, 0, 100000}], Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Wu)),
    {ok, Conn4, _} = nhttp_h2:send_headers(Conn3, StreamId, minimal_request_headers(), nofin),
    Body = binary:copy(<<$a>>, 100000),
    {ok, Conn5, Frame} = nhttp_h2:send_data(Conn4, StreamId, Body, fin),
    ?assertEqual(100000 + 9, iolist_size(Frame)),
    ?assertEqual({ok, 0}, nhttp_h2:stream_send_window(Conn5, StreamId)),
    ?assertEqual(65535, nhttp_h2:connection_send_window(Conn5)),
    ok.

settings_initial_window_size_growth_drains_queued_data(_Config) ->
    Conn0 = client_with_server_preface(#{send_queue => true}),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), nofin),
    {ok, Wu} = nhttp_h2_frame:window_update(100000),
    {ok, [{window_update, 0, 100000}], Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Wu)),
    Body = binary:copy(<<$a>>, 70000),
    {queued, Conn4, _Frames, 4465} = nhttp_h2:send_data(Conn3, StreamId, Body, fin),
    ?assertEqual({ok, 0}, nhttp_h2:stream_send_window(Conn4, StreamId)),
    {ok, S} = nhttp_h2_frame:settings(#{initial_window_size => 131070}),
    {ok, Events, Conn5, OutData} = nhttp_h2:recv(Conn4, iolist_to_binary(S)),
    ?assertMatch(
        [{settings, #{initial_window_size := 131070}}, {data_sent, StreamId, 4465, fin}], Events
    ),
    Bin = iolist_to_binary(OutData),
    {ok, settings_ack, Consumed} = nhttp_h2_frame:decode(Bin),
    <<_:Consumed/binary, Rest/binary>> = Bin,
    {ok, {data, StreamId, fin, Payload}, _} = nhttp_h2_frame:decode(Rest),
    ?assertEqual(4465, byte_size(Payload)),
    ?assertEqual({ok, 131070 - 70000}, nhttp_h2:stream_send_window(Conn5, StreamId)),
    ?assertEqual(165535 - 70000, nhttp_h2:connection_send_window(Conn5)),
    ?assertEqual(0, nhttp_h2:send_buffer_bytes(Conn5)),
    ok.

settings_initial_window_size_shrink_retains_negative_window(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), nofin),
    {ok, Conn3, _} = nhttp_h2:send_data(Conn2, StreamId, binary:copy(<<0>>, 16384), nofin),
    ?assertEqual({ok, 65535 - 16384}, nhttp_h2:stream_send_window(Conn3, StreamId)),
    {ok, S} = nhttp_h2_frame:settings(#{initial_window_size => 1}),
    {ok, [{settings, _}], Conn4, _} = nhttp_h2:recv(Conn3, iolist_to_binary(S)),
    ?assertEqual({ok, 1 - 16384}, nhttp_h2:stream_send_window(Conn4, StreamId)),
    {partial, Conn4, [], <<"x">>, nofin, -16383} = nhttp_h2:send_data(Conn4, StreamId, <<"x">>, nofin),
    {ok, Wu} = nhttp_h2_frame:window_update(StreamId, 16384),
    {ok, [{window_update, StreamId, 16384}], Conn5} = nhttp_h2:recv(Conn4, iolist_to_binary(Wu)),
    ?assertEqual({ok, 1}, nhttp_h2:stream_send_window(Conn5, StreamId)),
    {ok, _Conn6, Frame} = nhttp_h2:send_data(Conn5, StreamId, <<"x">>, nofin),
    {ok, {data, StreamId, nofin, <<"x">>}, _} = nhttp_h2_frame:decode(iolist_to_binary(Frame)),
    ok.

settings_initial_window_size_overflow_is_connection_error(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, S1} = nhttp_h2_frame:settings(#{initial_window_size => 1000}),
    {ok, [{settings, _}], Conn1, _} = nhttp_h2:recv(Conn0, iolist_to_binary(S1)),
    {ok, StreamId, Conn2} = nhttp_h2:open_stream(Conn1),
    {ok, Conn3, _} = nhttp_h2:send_headers(Conn2, StreamId, minimal_request_headers(), nofin),
    {ok, Wu} = nhttp_h2_frame:window_update(StreamId, 16#7fffffff - 1000),
    {ok, [{window_update, StreamId, _}], Conn4} = nhttp_h2:recv(Conn3, iolist_to_binary(Wu)),
    {ok, S2} = nhttp_h2_frame:settings(#{initial_window_size => 16#7fffffff}),
    {error, {connection_error, flow_control_error, _}} =
        nhttp_h2:recv(Conn4, iolist_to_binary(S2)),
    ok.

settings_initial_window_size_emits_no_window_update_event(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, S1} = nhttp_h2_frame:settings(#{max_concurrent_streams => 1000}),
    {ok, [{settings, _}], Conn1, _} = nhttp_h2:recv(Conn0, iolist_to_binary(S1)),
    Conn2 = open_streams_with_headers(Conn1, 1000),
    ?assertEqual(1000, maps:get(active, nhttp_h2:stream_stats(Conn2))),
    {ok, S2} = nhttp_h2_frame:settings(#{initial_window_size => 131070}),
    {ok, Events, Conn3, _} = nhttp_h2:recv(Conn2, iolist_to_binary(S2)),
    ?assertMatch([{settings, #{initial_window_size := 131070}}], Events),
    ?assertEqual({ok, 131070}, nhttp_h2:stream_send_window(Conn3, 1)),
    ?assertEqual({ok, 131070}, nhttp_h2:stream_send_window(Conn3, 1999)),
    ok.

zero_length_end_stream_data_is_sent_at_zero_window(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), nofin),
    Conn3 = send_chunks(Conn2, StreamId, [16384, 16384, 16384, 16383]),
    {ok, Conn4, Frame} = nhttp_h2:send_data(Conn3, StreamId, <<>>, fin),
    {ok, {data, StreamId, fin, <<>>}, _} = nhttp_h2_frame:decode(iolist_to_binary(Frame)),
    ?assertEqual(0, nhttp_h2:connection_send_window(Conn3)),
    ?assertEqual(0, nhttp_h2:connection_send_window(Conn4)),
    ?assertEqual({ok, 0}, nhttp_h2:stream_send_window(Conn4, StreamId)),
    {error, {stream_closed, StreamId}} = nhttp_h2:send_data(Conn4, StreamId, <<"x">>, nofin),
    RespBlock = encode_headers([{<<":status">>, <<"204">>}]),
    {ok, Resp} = nhttp_h2_frame:headers(StreamId, fin, fin, RespBlock),
    {ok, [{response, StreamId, #{status := 204}, fin}], _Conn5} =
        nhttp_h2:recv(Conn4, iolist_to_binary(Resp)),
    ok.

open_streams_with_headers(Conn, 0) ->
    Conn;
open_streams_with_headers(Conn0, N) ->
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), nofin),
    open_streams_with_headers(Conn2, N - 1).

send_chunks(Conn, _StreamId, []) ->
    Conn;
send_chunks(Conn0, StreamId, [Size | Sizes]) ->
    {ok, Conn1, _} = nhttp_h2:send_data(Conn0, StreamId, binary:copy(<<0>>, Size), nofin),
    send_chunks(Conn1, StreamId, Sizes).

settings_header_table_size_propagates_to_hpack(_Config) ->
    Conn0 = server_with_preface(),
    {ok, S} = nhttp_h2_frame:settings(#{header_table_size => 0}),
    {ok, [{settings, #{header_table_size := 0}}], _Conn1, _Ack} =
        nhttp_h2:recv(Conn0, iolist_to_binary(S)),
    ok.

ping_ack_echoes_payload(_Config) ->
    Conn0 = server_with_preface(),
    Payload = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, PingFrame} = nhttp_h2_frame:ping(Payload),
    {ok, [{ping, Payload}], _Conn1, OutData} =
        nhttp_h2:recv(Conn0, iolist_to_binary(PingFrame)),
    {ok, {ping_ack, Payload}, _} = nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

connection_window_overflow_is_connection_error(_Config) ->
    Conn0 = server_with_preface(),
    {ok, Wu} = nhttp_h2_frame:window_update(16#7fffffff),
    {error, {connection_error, flow_control_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(Wu)),
    ok.

stream_window_overflow_is_stream_error(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, F1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(F1)),
    MaxW = 16#7fffffff,
    {ok, Wu} = nhttp_h2_frame:window_update(1, MaxW),
    Result = nhttp_h2:recv(Conn1, iolist_to_binary(Wu)),
    {ok, _Events, _Conn2, OutData} = Result,
    {ok, {rst_stream, 1, flow_control_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

%% RFC 9113 Section 6.1: the Pad Length field and the padding count
%% against flow control. No caller ever sees the padding, so the codec
%% returns its credit in the same recv/2 call: on the connection always,
%% and on the stream while the peer can still send on it.
padded_data_credits_its_padding(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, H3} = nhttp_h2_frame:headers(3, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary([H1, H3])),
    Open = <<8:24, 16#00:8, 16#08:8, 0:1, 1:31, 5:8, "ab", 0, 0, 0, 0, 0>>,
    {ok, [{data, 1, <<"ab">>, nofin}], Conn2, OpenOut} = nhttp_h2:recv(Conn1, Open),
    ?assertEqual(
        {ok, [{window_update, 6}, {window_update, 1, 6}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(OpenOut))
    ),
    Last = <<4:24, 16#00:8, 16#09:8, 0:1, 3:31, 2:8, "c", 0, 0>>,
    {ok, [{data, 3, <<"c">>, fin}], _Conn3, LastOut} = nhttp_h2:recv(Conn2, Last),
    ?assertEqual(
        {ok, [{window_update, 3}], 13},
        nhttp_h2_frame:decode_all(iolist_to_binary(LastOut))
    ),
    ok.

%% RFC 9113 Sections 6.1 and 6.9: a padded DATA frame whose payload,
%% padding included, exceeds the connection window is a FLOW_CONTROL_ERROR,
%% even when its data alone would fit.
padded_data_counts_against_the_window(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, encode_headers(minimal_request_headers())),
    {ok, Full} = nhttp_h2_frame:data(1, nofin, binary:copy(<<"x">>, 16384)),
    {ok, Events, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary([H1, Full, Full, Full])),
    ?assertEqual(3, length([D || {data, 1, _, nofin} = D <- Events])),
    OverByPadding =
        <<16384:24, 16#00:8, 16#08:8, 0:1, 1:31, 1:8, (binary:copy(<<"y">>, 16382))/binary, 0>>,
    {error, {connection_error, flow_control_error, _}} = nhttp_h2:recv(Conn1, OverByPadding),
    ok.

%% Every Pad Length from 0 to 255: the codec reports the data alone and
%% returns exactly the Pad Length field plus the padding, so a PADDED
%% frame with a Pad Length of 0 still returns its one octet.
padded_data_credit_matches_every_pad_length(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, encode_headers(minimal_request_headers())),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    lists:foreach(
        fun(PadLength) ->
            Len = 1 + 1 + PadLength,
            Frame = <<Len:24, 16#00:8, 16#08:8, 0:1, 1:31, PadLength:8, "d", 0:(PadLength * 8)>>,
            {ok, [{data, 1, <<"d">>, nofin}], _Conn, Out} = nhttp_h2:recv(Conn1, Frame),
            ?assertEqual(
                {ok, [{window_update, PadLength + 1}, {window_update, 1, PadLength + 1}], 26},
                nhttp_h2_frame:decode_all(iolist_to_binary(Out))
            )
        end,
        lists:seq(0, 255)
    ),
    ok.

%% RFC 9113 Section 6.9: discarded DATA still counts against the
%% connection window. DATA on a reset stream that exceeds what is left of
%% the window is a FLOW_CONTROL_ERROR, not a frame to ignore.
discarded_data_counts_against_the_window(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, Open, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, Open, minimal_request_headers(), fin),
    {ok, Reset, Conn3} = nhttp_h2:open_stream(Conn2),
    {ok, Conn4, _} = nhttp_h2:send_headers(Conn3, Reset, minimal_request_headers(), fin),
    {ok, Conn5, _} = nhttp_h2:send_rst_stream(Conn4, Reset, cancel),
    {ok, Resp} = nhttp_h2_frame:headers(Open, nofin, fin, encode_headers([{<<":status">>, <<"200">>}])),
    {ok, Full} = nhttp_h2_frame:data(Open, nofin, binary:copy(<<"x">>, 16384)),
    {ok, _, Conn6} = nhttp_h2:recv(Conn5, iolist_to_binary([Resp, Full, Full, Full])),
    {ok, Late} = nhttp_h2_frame:data(Reset, fin, binary:copy(<<"y">>, 16384)),
    {error, {connection_error, flow_control_error, _}} =
        nhttp_h2:recv(Conn6, iolist_to_binary(Late)),
    ok.

%% DATA after the peer's END_STREAM is a STREAM_CLOSED stream error
%% (Section 5.1), and its octets still count against the connection
%% window (Section 6.9): the RST_STREAM goes out with the credit.
data_on_half_closed_remote_credits_the_connection(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, fin, fin, encode_headers(minimal_request_headers())),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, D} = nhttp_h2_frame:data(1, nofin, <<"extra">>),
    {ok, [], _Conn2, Out} = nhttp_h2:recv(Conn1, iolist_to_binary(D)),
    ?assertEqual(
        {ok, [{rst_stream, 1, stream_closed}, {window_update, 5}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out))
    ),
    ok.

%% DATA that exceeds the stream window but fits the connection window is
%% a FLOW_CONTROL_ERROR stream error (Section 6.9). The connection window
%% was charged, so the RST_STREAM goes out with the credit.
data_over_stream_window_credits_the_connection(_Config) ->
    Conn0 = server_with_preface(),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, encode_headers(minimal_request_headers())),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, Conn2, _} = nhttp_h2:send_window_update(Conn1, connection, 100000),
    {ok, Full} = nhttp_h2_frame:data(1, nofin, binary:copy(<<"x">>, 16384)),
    {ok, Events, _Conn3, Out} = nhttp_h2:recv(Conn2, iolist_to_binary([Full, Full, Full, Full])),
    ?assertEqual(3, length(Events)),
    ?assertEqual(
        {ok, [{rst_stream, 1, flow_control_error}, {window_update, 16384}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out))
    ),
    ok.

%% A Content-Length mismatch is a PROTOCOL_ERROR stream error (Section
%% 8.1.1), and the octets of the frame that revealed it still count
%% against the connection window.
content_length_mismatch_credits_the_connection(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers() ++ [{<<"content-length">>, <<"10">>}]),
    {ok, H1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(H1)),
    {ok, D} = nhttp_h2_frame:data(1, fin, <<"short">>),
    {ok, [], _Conn2, Out} = nhttp_h2:recv(Conn1, iolist_to_binary(D)),
    ?assertEqual(
        {ok, [{rst_stream, 1, protocol_error}, {window_update, 5}], 26},
        nhttp_h2_frame:decode_all(iolist_to_binary(Out))
    ),
    ok.

goaway_transitions_to_closing(_Config) ->
    Conn0 = server_with_preface(),
    {ok, Goaway} = nhttp_h2_frame:goaway(0, no_error, <<"bye">>),
    {ok, [{goaway, 0, no_error, <<"bye">>}], _Conn1} =
        nhttp_h2:recv(Conn0, iolist_to_binary(Goaway)),
    ok.

%% RFC9113-6.5.2-1: SETTINGS_MAX_CONCURRENT_STREAMS has no limit until the
%% peer sends it. An empty SETTINGS frame leaves it unset.
peer_without_max_concurrent_streams_has_no_limit(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, [{settings, #{}}], Conn1, _Ack} = nhttp_h2:recv(Conn0, literal_settings()),
    Conn2 = open_request_streams(Conn1, 101),
    {ok, _StreamId, _Conn3} = nhttp_h2:open_stream(Conn2),
    ok.

%% RFC9113-6.5.2-2: every parameter the peer did not send holds its initial
%% value: 4096, 65535 and 16384 octets, and no limit on the concurrent
%% streams or on the field section.
peer_settings_report_rfc_initial_values(_Config) ->
    Initial = #{
        header_table_size => 4096,
        initial_window_size => 65535,
        max_frame_size => 16384,
        max_concurrent_streams => infinity,
        max_header_list_size => infinity
    },
    Conn0 = nhttp_h2:new(client),
    ?assertEqual(Initial, nhttp_h2:peer_settings(Conn0)),
    {ok, [{settings, #{}}], Conn1, _Ack} = nhttp_h2:recv(Conn0, literal_settings()),
    ?assertEqual(Initial, nhttp_h2:peer_settings(Conn1)),
    Server0 = nhttp_h2:new(server),
    {ok, [{settings, #{}}], Server1, _} =
        nhttp_h2:recv(Server0, <<(literal_magic())/binary, (literal_settings())/binary>>),
    ?assertEqual(Initial, nhttp_h2:peer_settings(Server1)),
    ok.

open_request_streams(Conn, 0) ->
    Conn;
open_request_streams(Conn0, N) ->
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, minimal_request_headers(), nofin),
    open_request_streams(Conn2, N - 1).

%%%-----------------------------------------------------------------------------
%%% Section 8 - HTTP Message Exchanges
%%%-----------------------------------------------------------------------------

request_missing_method_is_stream_error(_Config) ->
    assert_request_rejected([
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>}
    ]).

request_missing_scheme_is_stream_error(_Config) ->
    assert_request_rejected([
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>}
    ]).

request_missing_path_is_stream_error(_Config) ->
    assert_request_rejected([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>}
    ]).

request_empty_path_is_stream_error(_Config) ->
    assert_request_rejected([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<>>}
    ]).

request_duplicate_pseudo_header_is_stream_error(_Config) ->
    assert_request_rejected([
        {<<":method">>, <<"GET">>},
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>}
    ]).

request_pseudo_after_regular_is_stream_error(_Config) ->
    assert_request_rejected([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<"x-custom">>, <<"v">>},
        {<<":path">>, <<"/">>}
    ]).

request_unknown_pseudo_is_stream_error(_Config) ->
    assert_request_rejected([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":unknown">>, <<"x">>}
    ]).

response_missing_status_is_stream_error(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, _StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    HeaderBlock = encode_headers([{<<"content-type">>, <<"text/plain">>}]),
    {ok, Frame} = nhttp_h2_frame:headers(2, fin, fin, HeaderBlock),
    Result = nhttp_h2:recv(Conn1, iolist_to_binary(Frame)),
    {ok, _Events, _Conn2, OutData} = Result,
    {ok, {rst_stream, 2, protocol_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

%% RFC9113-8.3.2-1: the `:status` pseudo-header field carries the HTTP
%% status code as a string of three digits.
%% RFC9110-15.1-1: the first digit of the status code defines the class
%% of the response, and there are exactly five classes, so a valid code
%% is in the range 100 to 599.
%% RFC9113-8.1.1-1: a malformed response is a stream error of type
%% PROTOCOL_ERROR.

-spec assert_response_status_rejected(binary()) -> ok.
assert_response_status_rejected(StatusValue) ->
    Conn0 = client_with_server_preface(),
    {ok, _StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    HeaderBlock = encode_headers([{<<":status">>, StatusValue}]),
    {ok, Frame} = nhttp_h2_frame:headers(2, fin, fin, HeaderBlock),
    {ok, Events, _Conn2, OutData} = nhttp_h2:recv(Conn1, iolist_to_binary(Frame)),
    ?assertEqual([], Events),
    {ok, {rst_stream, 2, protocol_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

response_non_digit_status_is_stream_error(_Config) ->
    lists:foreach(
        fun assert_response_status_rejected/1,
        [<<"abc">>, <<"20a">>, <<"1e2">>, <<"0x1">>]
    ).

response_status_not_three_digits_is_stream_error(_Config) ->
    lists:foreach(
        fun assert_response_status_rejected/1,
        [<<>>, <<"2">>, <<"20">>, <<"2000">>, <<"+200">>, <<"-200">>, <<" 200">>, <<"200 ">>]
    ).

response_status_outside_class_range_is_stream_error(_Config) ->
    lists:foreach(
        fun assert_response_status_rejected/1,
        [<<"000">>, <<"099">>, <<"600">>, <<"999">>]
    ).

response_three_digit_status_accepted(_Config) ->
    lists:foreach(
        fun({Value, Expected}) ->
            Conn0 = client_with_server_preface(),
            {ok, _StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
            HeaderBlock = encode_headers([{<<":status">>, Value}]),
            {ok, Frame} = nhttp_h2_frame:headers(2, fin, fin, HeaderBlock),
            {ok, Events, _Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(Frame)),
            ?assertMatch([{response, 2, #{status := Expected}, fin}], Events)
        end,
        [{<<"100">>, 100}, {<<"200">>, 200}, {<<"404">>, 404}, {<<"599">>, 599}]
    ).

connection_header_forbidden(_Config) ->
    assert_request_rejected(minimal_request_headers() ++ [{<<"connection">>, <<"close">>}]).

keep_alive_header_forbidden(_Config) ->
    assert_request_rejected(minimal_request_headers() ++ [{<<"keep-alive">>, <<"timeout=5">>}]).

proxy_connection_header_forbidden(_Config) ->
    assert_request_rejected(
        minimal_request_headers() ++ [{<<"proxy-connection">>, <<"close">>}]
    ).

transfer_encoding_header_forbidden(_Config) ->
    assert_request_rejected(
        minimal_request_headers() ++ [{<<"transfer-encoding">>, <<"chunked">>}]
    ).

upgrade_header_forbidden(_Config) ->
    assert_request_rejected(minimal_request_headers() ++ [{<<"upgrade">>, <<"h2c">>}]).

te_trailers_allowed(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers() ++ [{<<"te">>, <<"trailers">>}]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [{request, 1, _, fin}], _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ok.

te_non_trailers_forbidden(_Config) ->
    assert_request_rejected(minimal_request_headers() ++ [{<<"te">>, <<"gzip">>}]).

%% RFC9113-8.2-1: field names are converted to lowercase when an HTTP/2
%% message is constructed. The rule is the sender half of
%% `uppercase_header_name_is_stream_error', so a message this library writes
%% never trips the receive check of a conformant peer.
sender_lowercases_field_names(_Config) ->
    Client = client_with_server_preface(),
    Headers = minimal_request_headers() ++ [{<<"X-Trace-Id">>, <<"abc">>}],
    {ok, _Client1, OutData} = nhttp_h2:send_headers(Client, 1, Headers, fin),
    Server = server_with_preface(),
    {ok, Events, _Server1} = nhttp_h2:recv(Server, iolist_to_binary(OutData)),
    ?assertMatch(
        [{request, 1, #{headers := [{<<"x-trace-id">>, <<"abc">>}]}, fin}],
        Events
    ).

uppercase_header_name_is_stream_error(_Config) ->
    UppercaseLiteral = <<16#40, 10, "X-Bad-Name", 3, "foo">>,
    HeaderBlock = <<
        16#82,
        16#86,
        16#84,
        16#41,
        12,
        "example.com",
        ".",
        UppercaseLiteral/binary
    >>,
    Conn0 = server_with_preface(),
    {ok, Frame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    Result = nhttp_h2:recv(Conn0, iolist_to_binary(Frame)),
    {ok, _, _Conn1, OutData} = Result,
    {ok, {rst_stream, 1, protocol_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.


%% RFC 9113 Section 8.2.1: a field name must not hold an octet in 0x00-0x20,
%% 0x41-0x5A or 0x7F-0xFF.
invalid_field_name_char_is_stream_error(_Config) ->
    lists:foreach(
        fun(Name) ->
            assert_field_block_rejected(literal_indexed(Name, <<"v">>))
        end,
        [
            <<"x", 16#20, "y">>,
            <<"x", 16#00, "y">>,
            <<"x", 16#7F, "y">>,
            <<"x", 16#FF, "y">>
        ]
    ).

%% RFC 9113 Section 8.2.1: only the single leading colon of a pseudo-header
%% field is allowed in a field name.
interior_colon_in_field_name_is_stream_error(_Config) ->
    assert_field_block_rejected(literal_indexed(<<"x:y">>, <<"v">>)).

%% RFC 9113 Section 8.3: a pseudo-header field name starts with a single colon.
%% The name rule of Section 8.2.1 must not refuse that colon.
pseudo_header_name_is_accepted(_Config) ->
    Conn0 = server_with_preface(),
    Block = <<
        (literal_plain(<<":method">>, <<"GET">>))/binary,
        (literal_plain(<<":scheme">>, <<"https">>))/binary,
        (literal_plain(<<":path">>, <<"/">>))/binary
    >>,
    {ok, Frame} = nhttp_h2_frame:headers(1, fin, fin, Block),
    {ok, [{request, 1, _, fin}], _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Frame)),
    ok.

%% RFC 9113 Section 8.2.1: a field value must not hold NUL, LF or CR at any
%% position.
invalid_field_value_char_is_stream_error(_Config) ->
    lists:foreach(
        fun(Value) ->
            assert_field_block_rejected(literal_indexed(<<"x-test">>, Value))
        end,
        [
            <<"a", 16#00, "b">>,
            <<"a", 16#0A, "b">>,
            <<"a", 16#0D, "b">>
        ]
    ).

%% RFC 9113 Section 8.2.1: a field value must not start or end with SP or HTAB.
field_value_edge_whitespace_is_stream_error(_Config) ->
    assert_field_block_rejected(literal_indexed(<<"x-test">>, <<16#20, "v">>)),
    assert_field_block_rejected(literal_indexed(<<"x-test">>, <<"v", 16#09>>)).

%% RFC 9113 Section 4.3 makes an endpoint decompress a field block even when it
%% discards the frames, so a refused field still takes its dynamic table slot.
%% The entry carries the refusal instead, so index 62 stays live and every
%% message that repeats the malformed value is refused in turn.
invalid_field_keeps_the_dynamic_table_in_step(_Config) ->
    Conn0 = server_with_preface(),
    BadBlock = request_block(literal_indexed(<<"x-bad">>, <<"a", 16#0D, "b">>)),
    {ok, BadFrame} = nhttp_h2_frame:headers(1, fin, fin, BadBlock),
    {ok, _, Conn1, BadOut} = nhttp_h2:recv(Conn0, iolist_to_binary(BadFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(BadOut)),

    %% Index 62 resolves, so the insert happened. It carries the refusal, so the
    %% malformed value never reaches the application.
    RepeatBlock = request_block(<<16#BE>>),
    {ok, RepeatFrame} = nhttp_h2_frame:headers(3, fin, fin, RepeatBlock),
    {ok, _, Conn2, RepeatOut} = nhttp_h2:recv(Conn1, iolist_to_binary(RepeatFrame)),
    {ok, {rst_stream, 3, protocol_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(RepeatOut)),

    %% Only the value of entry 62 was refused, so a field that reuses its name
    %% with a value of its own is accepted.
    ReuseBlock = request_block(<<16#7E, 1, "v">>),
    {ok, ReuseFrame} = nhttp_h2_frame:headers(5, fin, fin, ReuseBlock),
    {ok, [{request, 5, Request, fin}], _Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(ReuseFrame)),
    ?assertEqual(<<"v">>, nhttp_headers:get(<<"x-bad">>, maps:get(headers, Request))),
    ok.


%% RFC 9113 Section 8.2.1 applies to every field section. The decode precedes
%% the request, response and trailer split, so all three refuse alike.
invalid_field_value_in_response_is_stream_error(_Config) ->
    Conn0 = client_with_server_preface(),
    {ok, _StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Block = <<16#88, (literal_indexed(<<"x-test">>, <<"a", 16#0D, "b">>))/binary>>,
    {ok, Frame} = nhttp_h2_frame:headers(2, fin, fin, Block),
    {ok, _Events, _Conn2, OutData} = nhttp_h2:recv(Conn1, iolist_to_binary(Frame)),
    {ok, {rst_stream, 2, protocol_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

invalid_field_value_in_trailers_is_stream_error(_Config) ->
    Conn0 = server_with_preface(),
    {ok, ReqFrame} = nhttp_h2_frame:headers(1, nofin, fin, request_block(<<>>)),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(ReqFrame)),
    Trailers = literal_indexed(<<"x-trailer">>, <<"a", 16#0D, "b">>),
    {ok, TrailerFrame} = nhttp_h2_frame:headers(1, fin, fin, Trailers),
    {ok, _Events, _Conn2, OutData} = nhttp_h2:recv(Conn1, iolist_to_binary(TrailerFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

trailers_with_pseudo_header_is_stream_error(_Config) ->
    Conn0 = server_with_preface(),
    ReqBlock = encode_headers(minimal_request_headers()),
    {ok, ReqFrame} = nhttp_h2_frame:headers(1, nofin, fin, ReqBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(ReqFrame)),
    TrailerBlock = encode_headers([{<<":trailer">>, <<"x">>}]),
    {ok, TrailerFrame} = nhttp_h2_frame:headers(1, fin, fin, TrailerBlock),
    Result = nhttp_h2:recv(Conn1, iolist_to_binary(TrailerFrame)),
    {ok, _, _Conn2, OutData} = Result,
    {ok, {rst_stream, 1, protocol_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

trailers_deliver_after_fin(_Config) ->
    Conn0 = server_with_preface(),
    ReqBlock = encode_headers(minimal_request_headers()),
    {ok, F1} = nhttp_h2_frame:headers(1, nofin, fin, ReqBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(F1)),
    TrailerBlock = encode_headers([{<<"x-trace">>, <<"abc">>}]),
    {ok, F2} = nhttp_h2_frame:headers(1, fin, fin, TrailerBlock),
    {ok, Events, _Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(F2)),
    ?assertMatch([{trailers, 1, [{<<"x-trace">>, <<"abc">>}]}], Events),
    ok.

content_length_mismatch_is_stream_error(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(
        minimal_request_headers() ++ [{<<"content-length">>, <<"10">>}]
    ),
    {ok, F1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(F1)),
    {ok, D} = nhttp_h2_frame:data(1, fin, <<"short">>),
    Result = nhttp_h2:recv(Conn1, iolist_to_binary(D)),
    {ok, _, _Conn2, OutData} = Result,
    {ok, {rst_stream, 1, protocol_error}, _} =
        nhttp_h2_frame:decode(iolist_to_binary(OutData)),
    ok.

content_length_exceeded_is_stream_error(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(
        minimal_request_headers() ++ [{<<"content-length">>, <<"3">>}]
    ),
    {ok, F1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(F1)),
    {ok, D} = nhttp_h2_frame:data(1, nofin, <<"too-long">>),
    Result = nhttp_h2:recv(Conn1, iolist_to_binary(D)),
    case Result of
        {ok, _, _, OutData} ->
            {ok, {rst_stream, 1, ErrCode}, _} =
                nhttp_h2_frame:decode(iolist_to_binary(OutData)),
            ?assert(ErrCode =:= protocol_error orelse ErrCode =:= stream_closed);
        {error, _} ->
            ok
    end,
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 10 - Denial-of-Service Considerations
%%%-----------------------------------------------------------------------------

%% RFC9113-5.1.2-1: SETTINGS_MAX_CONCURRENT_STREAMS bounds the streams in the
%% "open" state or in either "half-closed" state. It bounds no other quantity.
%% A peer that sends HEADERS and RST_STREAM in turn holds the active count at
%% zero, so the limit never applies, and the peer drives stream turnover
%% without bound. This case is the record of that gap.
max_concurrent_streams_does_not_bound_stream_turnover(_Config) ->
    Conn0 = server_with_preface_settings(#{max_concurrent_streams => 1}),
    {ok, Conn1} = h2_reset_rounds(Conn0, 1, 200),
    ?assertEqual(
        #{active => 0, peer_opened => 200, peer_reset => 200},
        nhttp_h2:stream_stats(Conn1)
    ),
    ok.

%% RFC9113-10.5-1: an implementation tracks the use of features that a peer can
%% abuse, and sets a limit on that use. `stream_stats/1` reports the counters
%% that carry stream turnover.
stream_turnover_is_tracked_on_the_connection(_Config) ->
    Conn0 = server_with_preface_settings(#{}),
    ?assertEqual(
        #{active => 0, peer_opened => 0, peer_reset => 0}, nhttp_h2:stream_stats(Conn0)
    ),
    {ok, Conn1} = h2_reset_rounds(Conn0, 1, 3),
    ?assertEqual(
        #{active => 0, peer_opened => 3, peer_reset => 3}, nhttp_h2:stream_stats(Conn1)
    ),
    ok.

%% RFC9113-10.5-2: an endpoint can treat suspicious activity as a connection
%% error of type ENHANCE_YOUR_CALM. `max_reset_streams` sets the point at which
%% peer stream resets become suspicious.
reset_allowance_is_connection_error_enhance_your_calm(_Config) ->
    Conn0 = server_with_preface_settings(#{max_reset_streams => 10}),
    ?assertMatch(
        {refused, 21, {connection_error, enhance_your_calm, _}},
        h2_reset_rounds(Conn0, 1, 200)
    ),
    ok.

%% RFC9113-10.5-3: "Large numbers of small or empty frames can be abused to
%% cause a peer to expend time processing frame headers." An empty CONTINUATION
%% frame adds no bytes, so the byte bound of Section 10.5.1 never fires on it.
%% The frame count is the bound that does.
empty_continuation_flood_is_connection_error_enhance_your_calm(_Config) ->
    Conn0 = server_with_preface_settings(#{}),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, <<"a">>),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch(
        {refused, _, {connection_error, enhance_your_calm, _}},
        h2_empty_continuations(Conn1, 1, 500)
    ),
    ok.

%% RFC9113-10.5-4: the count bound must not contradict the byte bound of
%% Section 10.5.1. A peer that is allowed a larger field section is allowed the
%% CONTINUATION frames that carry it.
continuation_allowance_scales_with_max_header_list_size(_Config) ->
    Conn0 = server_with_preface_settings(#{max_header_list_size => 1048576}),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, <<"a">>),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch({ok, _}, h2_empty_continuations(Conn1, 1, 64)),
    ok.

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec h2_empty_continuations(nhttp_h2:conn(), nhttp_lib:stream_id(), non_neg_integer()) ->
    {ok, nhttp_h2:conn()} | {refused, pos_integer(), nhttp_h2_frame:decode_error()}.
h2_empty_continuations(Conn, StreamId, Count) ->
    h2_empty_continuations(Conn, StreamId, Count, 1).

-spec h2_empty_continuations(
    nhttp_h2:conn(), nhttp_lib:stream_id(), non_neg_integer(), pos_integer()
) -> {ok, nhttp_h2:conn()} | {refused, pos_integer(), nhttp_h2_frame:decode_error()}.
h2_empty_continuations(Conn, _StreamId, 0, _Sent) ->
    {ok, Conn};
h2_empty_continuations(Conn, StreamId, Count, Sent) ->
    {ok, ContFrame} = nhttp_h2_frame:continuation(StreamId, nofin, <<>>),
    case nhttp_h2:recv(Conn, iolist_to_binary(ContFrame)) of
        {ok, [], Conn1} -> h2_empty_continuations(Conn1, StreamId, Count - 1, Sent + 1);
        {error, Reason} -> {refused, Sent, Reason}
    end.

-spec h2_reset_rounds(nhttp_h2:conn(), nhttp_lib:stream_id(), non_neg_integer()) ->
    {ok, nhttp_h2:conn()} | {refused, pos_integer(), nhttp_h2_frame:decode_error()}.
h2_reset_rounds(Conn, _BaseId, 0) ->
    {ok, Conn};
h2_reset_rounds(Conn, BaseId, N) ->
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(BaseId, fin, fin, HeaderBlock),
    {ok, RstFrame} = nhttp_h2_frame:rst_stream(BaseId, cancel),
    Data = iolist_to_binary([HeadersFrame, RstFrame]),
    case nhttp_h2:recv(Conn, Data) of
        {ok, _, Conn1} -> h2_reset_rounds(Conn1, BaseId + 2, N - 1);
        {ok, _, Conn1, _} -> h2_reset_rounds(Conn1, BaseId + 2, N - 1);
        {error, Reason} -> {refused, (BaseId + 1) div 2, Reason}
    end.

-doc """
No emitted DATA frame exceeds SETTINGS_MAX_FRAME_SIZE, at the raised value
and again after the peer sets it back (RFC 9113 Section 4.2).
""".
send_data_frames_stay_under_peer_max_frame_size(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, S1} = nhttp_h2_frame:settings(#{max_frame_size => 32768, initial_window_size => 200000}),
    {ok, [{settings, _}], Conn2, _} = nhttp_h2:recv(Conn1, iolist_to_binary(S1)),
    {ok, Wu} = nhttp_h2_frame:window_update(200000),
    {ok, [{window_update, 0, 200000}], Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Wu)),
    {ok, Conn4, _} = nhttp_h2:send_headers(Conn3, StreamId, minimal_request_headers(), nofin),
    Wide = binary:copy(<<1>>, 70000),
    {ok, Conn5, WideFrames} = nhttp_h2:send_data(Conn4, StreamId, Wide, nofin),
    WideDecoded = decode_data_frames(iolist_to_binary(WideFrames), 32768),
    ?assertEqual([32768, 32768, 4464], [byte_size(P) || {_, _, P} <- WideDecoded]),
    ?assertEqual(Wide, iolist_to_binary([P || {_, _, P} <- WideDecoded])),
    {ok, S2} = nhttp_h2_frame:settings(#{max_frame_size => 16384}),
    {ok, [{settings, _}], Conn6, _} = nhttp_h2:recv(Conn5, iolist_to_binary(S2)),
    Narrow = binary:copy(<<2>>, 40000),
    {ok, _Conn7, NarrowFrames} = nhttp_h2:send_data(Conn6, StreamId, Narrow, fin),
    NarrowDecoded = decode_data_frames(iolist_to_binary(NarrowFrames), 16384),
    ?assertEqual([16384, 16384, 7232], [byte_size(P) || {_, _, P} <- NarrowDecoded]),
    ?assertEqual([nofin, nofin, fin], [Fin || {_, Fin, _} <- NarrowDecoded]),
    ?assertEqual(Narrow, iolist_to_binary([P || {_, _, P} <- NarrowDecoded])),
    ok.

decode_data_frames(<<>>, _MaxFrameSize) ->
    [];
decode_data_frames(Bin, MaxFrameSize) ->
    {ok, {data, StreamId, Fin, Payload}, Consumed} = nhttp_h2_frame:decode(Bin, MaxFrameSize),
    <<_:Consumed/binary, Rest/binary>> = Bin,
    [{StreamId, Fin, Payload} | decode_data_frames(Rest, MaxFrameSize)].

server_with_preface() ->
    Conn0 = nhttp_h2:new(server),
    server_with_preface(Conn0).

server_with_preface_settings(Settings) ->
    Conn0 = nhttp_h2:new(server, maps:merge(#{max_concurrent_streams => 100}, Settings)),
    server_with_preface(Conn0).

server_with_preface(Conn0) ->
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, Settings} = nhttp_h2_frame:settings(#{}),
    {ok, [{settings, #{}}], Conn1, _Ack} =
        nhttp_h2:recv(Conn0, iolist_to_binary([Preface, Settings])),
    Conn1.

client_with_server_preface() ->
    client_with_server_preface(#{}).

client_with_server_preface(Settings) ->
    Conn0 = nhttp_h2:new(client, Settings),
    {ok, S} = nhttp_h2_frame:settings(#{}),
    {ok, _, Conn1, _} = nhttp_h2:recv(Conn0, iolist_to_binary(S)),
    Conn1.

literal_magic() ->
    <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>.

literal_settings() ->
    <<0:24, 16#04:8, 16#00:8, 0:32>>.

literal_settings_ack() ->
    <<0:24, 16#04:8, 16#01:8, 0:32>>.

literal_ping() ->
    <<8:24, 16#06:8, 16#00:8, 0:32, "pingpong">>.

encode_headers(Headers) ->
    {ok, State} = nhttp_hpack:new(),
    {HeaderBlock, _} = encode_headers(Headers, State),
    HeaderBlock.

encode_headers(Headers, Enc0) ->
    {ok, HeaderBlock, Enc1} = nhttp_hpack:encode(Headers, Enc0),
    {iolist_to_binary(HeaderBlock), Enc1}.

minimal_request_headers() ->
    [{<<":method">>, <<"GET">>}, {<<":scheme">>, <<"https">>}, {<<":path">>, <<"/">>}].

record_positions(Module, Record) ->
    Beam = filename:join([code:lib_dir(nhttp_lib), "ebin", atom_to_list(Module) ++ ".beam"]),
    {ok, {Module, [{abstract_code, {raw_abstract_v1, Forms}}]}} =
        beam_lib:chunks(Beam, [abstract_code]),
    [Fields] = [Fs || {attribute, _, record, {R, Fs}} <- Forms, R =:= Record],
    Names = [record_field_name(Field) || Field <- Fields],
    maps:from_list(lists:zip(Names, lists:seq(2, length(Names) + 1))).

record_field_name({typed_record_field, Field, _Type}) -> record_field_name(Field);
record_field_name({record_field, _, {atom, _, Name}}) -> Name;
record_field_name({record_field, _, {atom, _, Name}, _Default}) -> Name.

assert_request_rejected(Headers) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(Headers),
    {ok, Frame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    Result = nhttp_h2:recv(Conn0, iolist_to_binary(Frame)),
    case Result of
        {ok, _, _Conn1, OutData} ->
            {ok, {rst_stream, 1, ErrCode}, _} =
                nhttp_h2_frame:decode(iolist_to_binary(OutData)),
            ?assertEqual(protocol_error, ErrCode),
            ok;
        {error, {connection_error, _, _}} = Err ->
            ct:fail("Expected stream error but got connection error: ~p", [Err])
    end.

%% A literal field line with incremental indexing and a new name (RFC 7541
%% Section 6.2.1). Every name and value here is short enough for the one octet
%% length prefix.
literal_indexed(Name, Value) ->
    <<16#40, (byte_size(Name)), Name/binary, (byte_size(Value)), Value/binary>>.

%% A literal field line without indexing and a new name (RFC 7541 Section
%% 6.2.2).
literal_plain(Name, Value) ->
    <<16#00, (byte_size(Name)), Name/binary, (byte_size(Value)), Value/binary>>.

%% The three static table pseudo-header fields of a minimal request, followed by
%% the field lines under test.
request_block(Fields) ->
    <<16#82, 16#86, 16#84, Fields/binary>>.

assert_field_block_rejected(Fields) ->
    Conn0 = server_with_preface(),
    {ok, Frame} = nhttp_h2_frame:headers(1, fin, fin, request_block(Fields)),
    case nhttp_h2:recv(Conn0, iolist_to_binary(Frame)) of
        {ok, _, _Conn1, OutData} ->
            {ok, {rst_stream, 1, ErrCode}, _} =
                nhttp_h2_frame:decode(iolist_to_binary(OutData)),
            ?assertEqual(protocol_error, ErrCode),
            ok;
        {error, {connection_error, _, _}} = Err ->
            ct:fail("Expected stream error but got connection error: ~p", [Err])
    end.
