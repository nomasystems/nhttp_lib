-module(nhttp_h2_SUITE).

-moduledoc """
HTTP/2 protocol layer tests.

Tests RFC 9113 compliance for:
- Connection lifecycle (preface, settings, shutdown)
- Stream state machine (Section 5.1)
- Flow control (Section 5.2)
- Header block assembly (CONTINUATION)
- Error handling
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    new_client_connection/1,
    new_server_connection/1,
    client_preface_format/1,
    server_preface_format/1,
    custom_settings/1
]).

-export([
    stream_idle_to_open/1,
    stream_open_to_half_closed_local/1,
    stream_open_to_half_closed_remote/1,
    stream_half_closed_to_closed/1,
    stream_rst_stream_closes/1
]).

-export([
    settings_exchange/1,
    settings_ack_sent/1,
    settings_updates_peer/1,
    settings_initial_window_size_update/1
]).

-export([
    connection_window_update/1,
    stream_window_update/1,
    window_overflow_error/1,
    data_consumes_window/1
]).

-export([
    headers_single_frame/1,
    headers_with_continuation/1,
    headers_decode_with_hpack/1
]).

-export([
    goaway_closes_connection/1,
    rst_stream_closes_stream/1
]).

-export([
    full_request_response_cycle/1,
    multiple_concurrent_streams/1
]).

-export([
    stream_removed_after_full_lifecycle_h2/1,
    stream_removed_after_rst_stream_h2/1
]).

-export([
    send_goaway_test/1,
    send_ping_test/1,
    send_headers_after_goaway/1,
    send_headers_on_closed_stream/1,
    send_data_on_unknown_stream/1,
    send_data_on_closed_stream/1,
    send_window_update_unknown_stream/1,
    open_stream_after_goaway_sent/1,
    open_stream_after_goaway_received/1,
    ping_ack_received/1,
    priority_frame_ignored/1,
    unknown_frame_ignored/1,
    continuation_wrong_stream/1,
    continuation_unexpected/1,
    data_on_unknown_stream/1,
    hpack_decode_error/1,
    stream_window_overflow/1,
    push_promise_rejected/1,
    push_promise_server_error/1,
    ping_received_test/1,
    settings_ack_received/1,
    headers_with_priority_test/1,
    settings_with_table_size/1,
    flow_control_blocked/1,
    continuation_partial_test/1,
    close_stream_nonexistent/1,
    stream_concurrency_limit/1,
    stream_concurrency_count_tracking/1,
    stream_concurrency_decrement_on_close/1,
    continuation_flood_protection_test/1,
    oversized_initial_headers_test/1,
    decoded_header_list_too_large_test/1
]).

-export([
    trailers_validation_test/1,
    te_header_validation_test/1,
    te_trailers_allowed_test/1,
    connection_headers_rejected_test/1,
    content_length_mismatch_test/1,
    content_length_exceeded_test/1,
    headers_on_half_closed_remote_test/1,
    second_headers_without_end_stream_test/1,
    invalid_preface_test/1,
    data_on_half_closed_local_test/1,
    uppercase_header_name_test/1,
    client_receives_even_stream_id_test/1,
    window_update_on_closed_stream_test/1,
    response_missing_status_test/1,
    duplicate_pseudo_header_test/1,
    pseudo_header_after_regular_test/1,
    empty_path_test/1,
    invalid_request_pseudo_header_test/1,
    missing_required_pseudo_headers_test/1,
    non_continuation_during_continuation_test/1,
    partial_data_for_more_test/1,
    window_update_on_half_closed_remote_test/1,
    authority_host_match_test/1,
    authority_host_mismatch_test/1,
    host_only_test/1,
    multiple_host_test/1,
    extended_connect_accepted_test/1,
    extended_connect_not_enabled_test/1,
    protocol_without_connect_test/1,
    extended_connect_missing_authority_test/1
]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, connection},
        {group, stream_states},
        {group, settings},
        {group, flow_control},
        {group, header_processing},
        {group, error_handling},
        {group, integration},
        {group, stream_cleanup},
        {group, coverage},
        {group, header_validation}
    ].

groups() ->
    [
        {connection, [parallel], [
            new_client_connection,
            new_server_connection,
            client_preface_format,
            server_preface_format,
            custom_settings
        ]},
        {stream_states, [parallel], [
            stream_idle_to_open,
            stream_open_to_half_closed_local,
            stream_open_to_half_closed_remote,
            stream_half_closed_to_closed,
            stream_rst_stream_closes
        ]},
        {settings, [parallel], [
            settings_exchange,
            settings_ack_sent,
            settings_updates_peer,
            settings_initial_window_size_update
        ]},
        {flow_control, [parallel], [
            connection_window_update,
            stream_window_update,
            window_overflow_error,
            data_consumes_window
        ]},
        {header_processing, [parallel], [
            headers_single_frame,
            headers_with_continuation,
            headers_decode_with_hpack
        ]},
        {error_handling, [parallel], [
            goaway_closes_connection,
            rst_stream_closes_stream
        ]},
        {integration, [sequence], [
            full_request_response_cycle,
            multiple_concurrent_streams
        ]},
        {stream_cleanup, [parallel], [
            stream_removed_after_full_lifecycle_h2,
            stream_removed_after_rst_stream_h2
        ]},
        {coverage, [parallel], [
            send_goaway_test,
            send_ping_test,
            send_headers_after_goaway,
            send_headers_on_closed_stream,
            send_data_on_unknown_stream,
            send_data_on_closed_stream,
            send_window_update_unknown_stream,
            open_stream_after_goaway_sent,
            open_stream_after_goaway_received,
            ping_ack_received,
            priority_frame_ignored,
            unknown_frame_ignored,
            continuation_wrong_stream,
            continuation_unexpected,
            data_on_unknown_stream,
            hpack_decode_error,
            stream_window_overflow,
            push_promise_rejected,
            push_promise_server_error,
            ping_received_test,
            settings_ack_received,
            headers_with_priority_test,
            settings_with_table_size,
            flow_control_blocked,
            continuation_partial_test,
            close_stream_nonexistent,
            stream_concurrency_limit,
            stream_concurrency_count_tracking,
            stream_concurrency_decrement_on_close,
            continuation_flood_protection_test,
            oversized_initial_headers_test,
            decoded_header_list_too_large_test
        ]},
        {header_validation, [parallel], [
            trailers_validation_test,
            te_header_validation_test,
            te_trailers_allowed_test,
            connection_headers_rejected_test,
            content_length_mismatch_test,
            content_length_exceeded_test,
            headers_on_half_closed_remote_test,
            second_headers_without_end_stream_test,
            invalid_preface_test,
            data_on_half_closed_local_test,
            uppercase_header_name_test,
            client_receives_even_stream_id_test,
            window_update_on_closed_stream_test,
            response_missing_status_test,
            duplicate_pseudo_header_test,
            pseudo_header_after_regular_test,
            empty_path_test,
            invalid_request_pseudo_header_test,
            missing_required_pseudo_headers_test,
            non_continuation_during_continuation_test,
            partial_data_for_more_test,
            window_update_on_half_closed_remote_test,
            authority_host_match_test,
            authority_host_mismatch_test,
            host_only_test,
            multiple_host_test,
            extended_connect_accepted_test,
            extended_connect_not_enabled_test,
            protocol_without_connect_test,
            extended_connect_missing_authority_test
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
%%% CONNECTION TESTS
%%%-----------------------------------------------------------------------------

new_client_connection(_Config) ->
    Conn = nhttp_h2:new(client),
    Preface = nhttp_h2:preface(Conn),
    ?assert(is_list(Preface) orelse is_binary(Preface)),
    ok.

new_server_connection(_Config) ->
    Conn = nhttp_h2:new(server),
    Preface = nhttp_h2:preface(Conn),
    ?assert(is_list(Preface) orelse is_binary(Preface)),
    ok.

client_preface_format(_Config) ->
    Conn = nhttp_h2:new(client),
    PrefaceData = nhttp_h2:preface(Conn),
    Preface = iolist_to_binary(PrefaceData),
    Magic = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
    ?assertEqual(Magic, binary:part(Preface, 0, 24)),
    <<_:24/binary, SettingsFrame/binary>> = Preface,
    {ok, {settings, _}, _} = nhttp_h2_frame:decode(SettingsFrame),
    ok.

server_preface_format(_Config) ->
    Conn = nhttp_h2:new(server),
    PrefaceData = nhttp_h2:preface(Conn),
    Preface = iolist_to_binary(PrefaceData),
    {ok, {settings, _}, _} = nhttp_h2_frame:decode(Preface),
    ok.

custom_settings(_Config) ->
    CustomSettings = #{
        max_concurrent_streams => 50,
        initial_window_size => 1048576
    },
    Conn = nhttp_h2:new(client, CustomSettings),
    PrefaceData = nhttp_h2:preface(Conn),
    Preface = iolist_to_binary(PrefaceData),
    <<_:24/binary, SettingsFrame/binary>> = Preface,
    {ok, {settings, Settings}, _} = nhttp_h2_frame:decode(SettingsFrame),
    ?assertEqual(50, maps:get(max_concurrent_streams, Settings)),
    ?assertEqual(1048576, maps:get(initial_window_size, Settings)),
    ok.

%%%-----------------------------------------------------------------------------
%%% STREAM STATE TESTS
%%%-----------------------------------------------------------------------------

stream_idle_to_open(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    ?assertEqual(1, StreamId),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _Frame} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
    {ok, _Conn3, _DataFrame} = nhttp_h2:send_data(Conn2, StreamId, <<"test">>, nofin),
    ok.

stream_open_to_half_closed_local(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
    {ok, Conn3, _} = nhttp_h2:send_data(Conn2, StreamId, <<>>, fin),
    ?assertMatch({error, _}, nhttp_h2:send_data(Conn3, StreamId, <<"more">>, nofin)),
    ok.

stream_open_to_half_closed_remote(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, DataFrame} = nhttp_h2_frame:data(1, fin, <<>>),
    {ok, [{data, 1, <<>>, fin}], Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(DataFrame)),
    {ok, _Conn3, _} = nhttp_h2:send_headers(Conn2, 1, [{<<":status">>, <<"200">>}], fin),
    ok.

stream_half_closed_to_closed(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, fin),
    RespHeaderBlock = encode_headers(minimal_response_headers()),
    {ok, RespFrame} = nhttp_h2_frame:headers(StreamId, fin, fin, RespHeaderBlock),
    {ok, [{response, StreamId, _, fin}], Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(RespFrame)),
    ?assertMatch({error, _}, nhttp_h2:send_data(Conn3, StreamId, <<"data">>, nofin)),
    ok.

stream_rst_stream_closes(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
    {ok, Conn3, RstFrame} = nhttp_h2:send_rst_stream(Conn2, StreamId, cancel),
    {ok, {rst_stream, StreamId, cancel}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ?assertMatch({error, _}, nhttp_h2:send_data(Conn3, StreamId, <<"data">>, nofin)),
    ok.

%%%-----------------------------------------------------------------------------
%%% SETTINGS TESTS
%%%-----------------------------------------------------------------------------

settings_exchange(_Config) ->
    Conn0 = nhttp_h2:new(client),
    ServerSettings = #{max_concurrent_streams => 100},
    {ok, SettingsFrame} = nhttp_h2_frame:settings(ServerSettings),
    {ok, Events, _Conn1, _AckFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(SettingsFrame)),
    ?assertMatch([{settings, #{max_concurrent_streams := 100}}], Events),
    ok.

settings_ack_sent(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, SettingsFrame} = nhttp_h2_frame:settings(#{}),
    {ok, _Events, _Conn1, AckFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(SettingsFrame)),
    {ok, settings_ack, _} = nhttp_h2_frame:decode(iolist_to_binary(AckFrame)),
    ok.

settings_updates_peer(_Config) ->
    Conn0 = nhttp_h2:new(server),
    ClientSettings = #{initial_window_size => 1048576},
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, SettingsData} = nhttp_h2_frame:settings(ClientSettings),
    PrefaceAndSettings = [Preface, SettingsData],
    {ok, Events, _Conn1, _} = nhttp_h2:recv(Conn0, iolist_to_binary(PrefaceAndSettings)),
    ?assertMatch([{settings, #{initial_window_size := 1048576}}], Events),
    ok.

settings_initial_window_size_update(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
    NewSettings = #{initial_window_size => 131072},
    {ok, SettingsFrame} = nhttp_h2_frame:settings(NewSettings),
    {ok, Events, _Conn3, _} = nhttp_h2:recv(Conn2, iolist_to_binary(SettingsFrame)),
    ?assertMatch([{settings, #{initial_window_size := 131072}} | _], Events),
    ok.

%%%-----------------------------------------------------------------------------
%%% FLOW CONTROL TESTS
%%%-----------------------------------------------------------------------------

connection_window_update(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, Conn1, Frame} = nhttp_h2:send_window_update(Conn0, connection, 1000),
    {ok, {window_update, 1000}, _} = nhttp_h2_frame:decode(iolist_to_binary(Frame)),
    ?assertNotEqual(Conn0, Conn1),
    ok.

stream_window_update(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
    {ok, Conn3, Frame} = nhttp_h2:send_window_update(Conn2, StreamId, 5000),
    {ok, {window_update, StreamId, 5000}, _} = nhttp_h2_frame:decode(iolist_to_binary(Frame)),
    ?assertNotEqual(Conn2, Conn3),
    ok.

window_overflow_error(_Config) ->
    Conn0 = nhttp_h2:new(client),
    NearMaxIncrement = 16#7fffffff - 65535 - 1000,
    {ok, Frame1} = nhttp_h2_frame:window_update(NearMaxIncrement),
    {ok, [{window_update, 0, NearMaxIncrement}], Conn1} = nhttp_h2:recv(
        Conn0, iolist_to_binary(Frame1)
    ),
    OverflowIncrement = 2000,
    {ok, Frame2} = nhttp_h2_frame:window_update(OverflowIncrement),
    {error, {connection_error, flow_control_error, _}} =
        nhttp_h2:recv(Conn1, iolist_to_binary(Frame2)),
    ok.

data_consumes_window(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
    Data = binary:copy(<<0>>, 1000),
    {ok, Conn3, _Frame} = nhttp_h2:send_data(Conn2, StreamId, Data, nofin),
    ?assertNotEqual(Conn2, Conn3),
    ok.

%%%-----------------------------------------------------------------------------
%%% HEADER PROCESSING TESTS
%%%-----------------------------------------------------------------------------

headers_single_frame(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, Events, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch([{request, 1, _, fin}], Events),
    [{request, 1, Request, fin}] = Events,
    ?assertEqual(get, maps:get(method, Request)),
    ?assertNot(maps:is_key(connect_protocol, Request)),
    ?assertNotEqual(Conn0, Conn1),
    ok.

headers_with_continuation(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"x-large-header">>, binary:copy(<<$a>>, 1000)}
    ]),
    <<First:50/binary, Rest/binary>> = HeaderBlock,
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, First),
    {ok, ContinuationFrame} = nhttp_h2_frame:continuation(1, fin, Rest),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, Events, _Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(ContinuationFrame)),
    ?assertMatch([{request, 1, _, fin}], Events),
    ok.

headers_decode_with_hpack(_Config) ->
    Conn0 = server_with_preface(),
    {ok, HpackState} = nhttp_hpack:new(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>}
    ],
    {ok, HeaderBlock, _} = nhttp_hpack:encode(Headers, HpackState),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, Events, _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    [{request, 1, Request, fin}] = Events,
    ?assertEqual(get, maps:get(method, Request)),
    ?assertEqual(<<"/">>, maps:get(path, Request)),
    ok.

%%%-----------------------------------------------------------------------------
%%% ERROR HANDLING TESTS
%%%-----------------------------------------------------------------------------

goaway_closes_connection(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, GoawayFrame} = nhttp_h2_frame:goaway(0, no_error, <<>>),
    {ok, Events, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(GoawayFrame)),
    ?assertMatch([{goaway, 0, no_error, <<>>}], Events),
    {error, connection_closing} = nhttp_h2:open_stream(Conn1),
    ok.

rst_stream_closes_stream(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, RstFrame} = nhttp_h2_frame:rst_stream(1, cancel),
    {ok, Events, Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(RstFrame)),
    ?assertMatch([{stream_reset, 1, cancel}], Events),
    ?assertMatch({error, _}, nhttp_h2:send_headers(Conn2, 1, [{<<":status">>, <<"200">>}], fin)),
    ok.

%%%-----------------------------------------------------------------------------
%%% INTEGRATION TESTS
%%%-----------------------------------------------------------------------------

full_request_response_cycle(_Config) ->
    ClientConn0 = nhttp_h2:new(client),
    ServerConn0 = nhttp_h2:new(server),

    {ok, StreamId, ClientConn1} = nhttp_h2:open_stream(ClientConn0),
    ReqHeaders = [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>}
    ],
    {ok, ClientConn2, ReqFrame} = nhttp_h2:send_headers(ClientConn1, StreamId, ReqHeaders, fin),

    {ok, ClientPrefaceData} = nhttp_h2_frame:preface(),
    ClientPreface = iolist_to_binary(ClientPrefaceData),
    {ok, ReqEvents, ServerConn1} = nhttp_h2:recv(
        ServerConn0, <<ClientPreface/binary, (iolist_to_binary(ReqFrame))/binary>>
    ),
    ?assertMatch([{request, StreamId, _, fin}], ReqEvents),

    RespHeaders = [{<<":status">>, <<"200">>}],
    {ok, ServerConn2, RespFrame} = nhttp_h2:send_headers(ServerConn1, StreamId, RespHeaders, fin),

    {ok, RespEvents, ClientConn3} = nhttp_h2:recv(ClientConn2, iolist_to_binary(RespFrame)),
    ?assertMatch([{response, StreamId, _, fin}], RespEvents),

    ?assertMatch({error, _}, nhttp_h2:send_data(ClientConn3, StreamId, <<"data">>, nofin)),
    ?assertMatch({error, _}, nhttp_h2:send_data(ServerConn2, StreamId, <<"data">>, nofin)),
    ok.

multiple_concurrent_streams(_Config) ->
    Conn0 = nhttp_h2:new(client),

    {ok, Stream1, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Stream3, Conn2} = nhttp_h2:open_stream(Conn1),
    {ok, Stream5, Conn3} = nhttp_h2:open_stream(Conn2),

    ?assertEqual(1, Stream1),
    ?assertEqual(3, Stream3),
    ?assertEqual(5, Stream5),

    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn4, _} = nhttp_h2:send_headers(Conn3, Stream1, Headers, nofin),
    {ok, Conn5, _} = nhttp_h2:send_headers(Conn4, Stream3, Headers, nofin),
    {ok, Conn6, _} = nhttp_h2:send_headers(Conn5, Stream5, Headers, nofin),

    {ok, Conn7, _} = nhttp_h2:send_data(Conn6, Stream1, <<"data1">>, nofin),
    {ok, Conn8, _} = nhttp_h2:send_data(Conn7, Stream3, <<"data3">>, nofin),
    {ok, _Conn9, _} = nhttp_h2:send_data(Conn8, Stream5, <<"data5">>, nofin),
    ok.

%%%-----------------------------------------------------------------------------
%%% ADDITIONAL COVERAGE TESTS
%%%-----------------------------------------------------------------------------

send_goaway_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, Conn2, Frame} = nhttp_h2:send_goaway(Conn1, no_error, <<"shutting down">>),
    ?assert(iolist_size(Frame) > 0),
    {ok, {goaway, 1, no_error, <<"shutting down">>}, _} = nhttp_h2_frame:decode(
        iolist_to_binary(Frame)
    ),
    {error, connection_closing} = nhttp_h2:open_stream(Conn2),
    ok.

send_ping_test(_Config) ->
    Conn0 = nhttp_h2:new(client),
    OpaqueData = crypto:strong_rand_bytes(8),
    {ok, _Conn1, Frame} = nhttp_h2:send_ping(Conn0, OpaqueData),
    ?assert(iolist_size(Frame) > 0),
    {ok, {ping, DecodedData}, _} = nhttp_h2_frame:decode(iolist_to_binary(Frame)),
    ?assertEqual(OpaqueData, DecodedData),
    ok.

send_headers_after_goaway(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    {ok, Conn2, _} = nhttp_h2:send_goaway(Conn1, no_error, <<>>),
    Headers = [{<<":method">>, <<"GET">>}],
    {error, connection_closing} = nhttp_h2:send_headers(Conn2, StreamId, Headers, fin),
    ok.

send_headers_on_closed_stream(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, fin),
    RespBlock = encode_headers([{<<":status">>, <<"200">>}]),
    {ok, RespFrame} = nhttp_h2_frame:headers(StreamId, fin, fin, RespBlock),
    {ok, _, Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(RespFrame)),
    {error, {stream_closed, StreamId}} = nhttp_h2:send_headers(Conn3, StreamId, Headers, fin),
    ok.

send_data_on_unknown_stream(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {error, {unknown_stream, 99}} = nhttp_h2:send_data(Conn0, 99, <<"data">>, fin),
    ok.

send_data_on_closed_stream(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, fin),
    {error, {stream_closed, StreamId}} = nhttp_h2:send_data(Conn2, StreamId, <<"data">>, fin),
    ok.

send_window_update_unknown_stream(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {error, {stream_error, 99, protocol_error, _}} = nhttp_h2:send_window_update(Conn0, 99, 1000),
    ok.

open_stream_after_goaway_sent(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {ok, Conn1, _} = nhttp_h2:send_goaway(Conn0, no_error, <<>>),
    {error, connection_closing} = nhttp_h2:open_stream(Conn1),
    ok.

open_stream_after_goaway_received(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, GoawayFrame} = nhttp_h2_frame:goaway(0, no_error, <<>>),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(GoawayFrame)),
    {error, connection_closing} = nhttp_h2:open_stream(Conn1),
    ok.

ping_ack_received(_Config) ->
    Conn0 = nhttp_h2:new(client),
    OpaqueData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, PingAckFrame} = nhttp_h2_frame:ping_ack(OpaqueData),
    {ok, Events, _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(PingAckFrame)),
    ?assertEqual([{ping_ack, OpaqueData}], Events),
    ok.

priority_frame_ignored(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    Priority = #{exclusive => false, stream_dependency => 0, weight => 16},
    {ok, PriorityFrame} = nhttp_h2_frame:priority(1, Priority),
    {ok, Events, _Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(PriorityFrame)),
    ?assertEqual([], Events),
    ok.

unknown_frame_ignored(_Config) ->
    Conn0 = nhttp_h2:new(client),
    UnknownFrame = <<5:24, 99:8, 0:8, 0:32, "hello">>,
    {ok, Events, _Conn1} = nhttp_h2:recv(Conn0, UnknownFrame),
    ?assertEqual([], Events),
    ok.

continuation_wrong_stream(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/some/longer/path/to/ensure/enough/bytes">>}
    ]),
    HBSize = byte_size(HeaderBlock),
    SplitAt = HBSize div 2,
    <<First:SplitAt/binary, _Rest/binary>> = HeaderBlock,
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, First),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, WrongContinuation} = nhttp_h2_frame:continuation(3, fin, <<"more">>),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn1, iolist_to_binary(WrongContinuation)),
    ok.

continuation_unexpected(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {ok, ContinuationFrame} = nhttp_h2_frame:continuation(1, fin, <<"headers">>),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(ContinuationFrame)),
    ok.

continuation_flood_protection_test(_Config) ->
    Settings = #{max_header_list_size => 200},
    Conn0 = nhttp_h2:new(server, Settings),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    First = binary:copy(<<"a">>, 100),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, First),
    {ok, [], Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(HeadersFrame)),
    Tail = binary:copy(<<"b">>, 150),
    {ok, ContFrame} = nhttp_h2_frame:continuation(1, fin, Tail),
    {error, {connection_error, enhance_your_calm, _}} =
        nhttp_h2:recv(Conn2, iolist_to_binary(ContFrame)),
    ok.

oversized_initial_headers_test(_Config) ->
    Settings = #{max_header_list_size => 100},
    Conn0 = nhttp_h2:new(server, Settings),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    Block = binary:copy(<<"x">>, 200),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, Block),
    {error, {connection_error, enhance_your_calm, _}} =
        nhttp_h2:recv(Conn1, iolist_to_binary(HeadersFrame)),
    ok.

decoded_header_list_too_large_test(_Config) ->
    Settings = #{max_header_list_size => 200},
    Conn0 = nhttp_h2:new(server, Settings),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    StaticIdx = list_to_binary(
        lists:duplicate(20, 16#82) ++
            lists:duplicate(20, 16#84)
    ),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, StaticIdx),
    {error, {connection_error, enhance_your_calm, _}} =
        nhttp_h2:recv(Conn1, iolist_to_binary(HeadersFrame)),
    ok.

data_on_unknown_stream(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {ok, DataFrame} = nhttp_h2_frame:data(1, fin, <<"body">>),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(DataFrame)),
    ok.

hpack_decode_error(_Config) ->
    Conn0 = server_with_preface(),
    InvalidHpack = <<255, 255, 255, 255>>,
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, InvalidHpack),
    {error, {connection_error, compression_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ok.

stream_window_overflow(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    NearMaxIncrement = 16#7fffffff - 65535 - 1000,
    {ok, Frame1} = nhttp_h2_frame:window_update(1, NearMaxIncrement),
    {ok, [{window_update, 1, NearMaxIncrement}], Conn2} = nhttp_h2:recv(
        Conn1, iolist_to_binary(Frame1)
    ),
    OverflowIncrement = 2000,
    {ok, Frame2} = nhttp_h2_frame:window_update(1, OverflowIncrement),
    {ok, [], Conn3, RstFrame} = nhttp_h2:recv(Conn2, iolist_to_binary(Frame2)),
    {ok, {rst_stream, 1, flow_control_error}, _} = nhttp_h2_frame:decode(
        iolist_to_binary(RstFrame)
    ),
    ?assertMatch({error, _}, nhttp_h2:send_headers(Conn3, 1, [{<<":status">>, <<"200">>}], fin)),
    ok.

push_promise_rejected(_Config) ->
    Conn0 = nhttp_h2:new(client),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, PushFrame} = nhttp_h2_frame:push_promise(1, 2, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(PushFrame)),
    {ok, {rst_stream, 2, refused_stream}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

push_promise_server_error(_Config) ->
    Conn0 = nhttp_h2:new(server),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, PushFrame} = nhttp_h2_frame:push_promise(1, 2, fin, HeaderBlock),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(PushFrame)),
    ok.

ping_received_test(_Config) ->
    Conn0 = server_with_preface(),
    PingData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, PingFrame} = nhttp_h2_frame:ping(PingData),
    {ok, Events, _Conn1, PongFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(PingFrame)),
    ?assertEqual([{ping, PingData}], Events),
    {ok, {ping_ack, PingData}, _} = nhttp_h2_frame:decode(iolist_to_binary(PongFrame)),
    ok.

settings_ack_received(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, SettingsAckFrame} = nhttp_h2_frame:settings_ack(),
    {ok, Events, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(SettingsAckFrame)),
    ?assertEqual([settings_ack], Events),
    {ok, Events2, _Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(SettingsAckFrame)),
    ?assertEqual([], Events2),
    ok.

headers_with_priority_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    Priority = #{exclusive => false, stream_dependency => 0, weight => 16},
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, Priority, HeaderBlock),
    {ok, Events, _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch([{request, 1, _, fin}], Events),
    ok.

settings_with_table_size(_Config) ->
    Conn0 = nhttp_h2:new(client),
    NewSettings = #{header_table_size => 8192},
    {ok, SettingsFrame} = nhttp_h2_frame:settings(NewSettings),
    {ok, Events, _Conn1, _} = nhttp_h2:recv(Conn0, iolist_to_binary(SettingsFrame)),
    ?assertMatch([{settings, #{header_table_size := 8192}}], Events),
    ok.

flow_control_blocked(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    Headers = [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
    LargeData = binary:copy(<<0>>, 70000),
    {partial, _Conn3, _Frame, Remaining, fin, Window} = nhttp_h2:send_data(
        Conn2, StreamId, LargeData, fin
    ),
    53616 = byte_size(Remaining),
    49151 = Window,
    ok.

continuation_partial_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"x-large-header">>, binary:copy(<<$a>>, 500)},
        {<<"x-another-header">>, binary:copy(<<$b>>, 500)}
    ]),
    HBSize = byte_size(HeaderBlock),
    Part1Size = HBSize div 3,
    Part2Size = HBSize div 3,
    <<Part1:Part1Size/binary, Part2:Part2Size/binary, Part3/binary>> = HeaderBlock,
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, Part1),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, Cont1} = nhttp_h2_frame:continuation(1, nofin, Part2),
    {ok, [], Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(Cont1)),
    {ok, Cont2} = nhttp_h2_frame:continuation(1, fin, Part3),
    {ok, Events, _Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(Cont2)),
    ?assertMatch([{request, 1, _, fin}], Events),
    ok.

close_stream_nonexistent(_Config) ->
    Conn0 = nhttp_h2:new(server),
    {ok, RstFrame} = nhttp_h2_frame:rst_stream(99, cancel),
    Result = nhttp_h2:recv(Conn0, iolist_to_binary(RstFrame)),
    ?assertMatch({error, {connection_error, protocol_error, _}}, Result),
    ok.

%%%-----------------------------------------------------------------------------
%%% TEST HELPERS
%%%-----------------------------------------------------------------------------

-doc "Create a server connection that has already received the client preface. This is needed for tests that send frames directly without the preface.".
-spec server_with_preface() -> nhttp_h2:conn().
server_with_preface() ->
    Conn0 = nhttp_h2:new(server),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    Conn1.

-doc "Encode headers using HPACK (for test data generation).".
-spec encode_headers(nhttp_lib:headers()) -> binary().
encode_headers(Headers) ->
    {ok, State} = nhttp_hpack:new(),
    {ok, HeaderBlock, _} = nhttp_hpack:encode(Headers, State),
    iolist_to_binary(HeaderBlock).

-doc "Create valid minimal GET request headers.".
-spec minimal_request_headers() -> nhttp_lib:headers().
minimal_request_headers() ->
    [{<<":method">>, <<"GET">>}, {<<":scheme">>, <<"https">>}, {<<":path">>, <<"/">>}].

-doc "Create valid minimal response headers.".
-spec minimal_response_headers() -> nhttp_lib:headers().
minimal_response_headers() ->
    [{<<":status">>, <<"200">>}].

-doc "After a full request/response cycle, the stream should be removed.".
stream_removed_after_full_lifecycle_h2(_Config) ->
    Conn0 = server_with_preface(),
    Conn1 = complete_n_h2_streams(Conn0, 1, 50),
    _Conn2 = complete_n_h2_streams(Conn1, 101, 50),
    ok.

-doc "After RST_STREAM, the stream should be removed.".
stream_removed_after_rst_stream_h2(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, Conn2, _RstFrame} = nhttp_h2:send_rst_stream(Conn1, 1, cancel),
    HeaderBlock2 = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame2} = nhttp_h2_frame:headers(3, fin, fin, HeaderBlock2),
    {ok, [{request, 3, _, fin}], _Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(HeadersFrame2)),
    ok.

-spec complete_n_h2_streams(nhttp_h2:conn(), nhttp_lib:stream_id(), non_neg_integer()) ->
    nhttp_h2:conn().
complete_n_h2_streams(Conn, _BaseId, 0) ->
    Conn;
complete_n_h2_streams(Conn, BaseId, N) ->
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(BaseId, fin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn, iolist_to_binary(HeadersFrame)),
    RespHeaders = [{<<":status">>, <<"200">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, BaseId, RespHeaders, fin),
    complete_n_h2_streams(Conn2, BaseId + 2, N - 1).

-doc "Test that streams are refused when at max_concurrent_streams limit.".
stream_concurrency_limit(_Config) ->
    Conn0 = nhttp_h2:new(server, #{max_concurrent_streams => 2}),
    PrefaceData = nhttp_h2:preface(Conn0),
    Preface = iolist_to_binary(PrefaceData),
    {ok, {settings, Settings}, _} = nhttp_h2_frame:decode(Preface),
    ?assertEqual(2, maps:get(max_concurrent_streams, Settings)),
    {ok, ClientPrefaceData} = nhttp_h2_frame:preface(),
    ClientPreface = iolist_to_binary(ClientPrefaceData),
    Conn1 = recv_ok(Conn0, ClientPreface),
    {ok, ClientSettingsData} = nhttp_h2_frame:settings(#{}),
    ClientSettings = iolist_to_binary(ClientSettingsData),
    Conn2 = recv_ok(Conn1, ClientSettings),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, Headers1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {Events1, Conn3} = recv_events(Conn2, iolist_to_binary(Headers1)),
    ?assertMatch([{request, 1, _, nofin}], Events1),
    {ok, Headers2} = nhttp_h2_frame:headers(3, nofin, fin, HeaderBlock),
    {Events2, Conn4} = recv_events(Conn3, iolist_to_binary(Headers2)),
    ?assertMatch([{request, 3, _, nofin}], Events2),
    {ok, Headers3} = nhttp_h2_frame:headers(5, nofin, fin, HeaderBlock),
    {ok, Events3, _Conn5, RstFrame} = nhttp_h2:recv(Conn4, iolist_to_binary(Headers3)),
    ?assertMatch([{stream_refused, 5}], Events3),
    RstBin = iolist_to_binary(RstFrame),
    ?assert(byte_size(RstBin) > 0),
    {ok, {rst_stream, 5, refused_stream}, _} = nhttp_h2_frame:decode(RstBin),
    ok.

-doc "Test that active_stream_count increments on new streams.".
stream_concurrency_count_tracking(_Config) ->
    Conn0 = server_with_preface(),
    {ok, ClientSettingsData} = nhttp_h2_frame:settings(#{}),
    ClientSettings = iolist_to_binary(ClientSettingsData),
    Conn1 = recv_ok(Conn0, ClientSettings),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, Headers1} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {[_], Conn2} = recv_events(Conn1, iolist_to_binary(Headers1)),
    RespHeaders = [{<<":status">>, <<"200">>}],
    {ok, Conn3, _} = nhttp_h2:send_headers(Conn2, 1, RespHeaders, fin),
    ?assertMatch({error, _}, nhttp_h2:send_data(Conn3, 1, <<"data">>, nofin)),
    ok.

-doc "Test that active_stream_count decrements on RST_STREAM.".
stream_concurrency_decrement_on_close(_Config) ->
    Conn0 = nhttp_h2:new(server, #{max_concurrent_streams => 1}),
    {ok, ClientPrefaceData} = nhttp_h2_frame:preface(),
    ClientPreface = iolist_to_binary(ClientPrefaceData),
    Conn1 = recv_ok(Conn0, ClientPreface),
    {ok, ClientSettingsData} = nhttp_h2_frame:settings(#{}),
    ClientSettings = iolist_to_binary(ClientSettingsData),
    Conn2 = recv_ok(Conn1, ClientSettings),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, Headers1} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {[_], Conn3} = recv_events(Conn2, iolist_to_binary(Headers1)),
    {ok, Headers2} = nhttp_h2_frame:headers(3, nofin, fin, HeaderBlock),
    {ok, [_], Conn4, _} = nhttp_h2:recv(Conn3, iolist_to_binary(Headers2)),
    {ok, RstFrame} = nhttp_h2_frame:rst_stream(1, cancel),
    Conn5 = recv_ok(Conn4, iolist_to_binary(RstFrame)),
    {ok, Headers3} = nhttp_h2_frame:headers(5, fin, fin, HeaderBlock),
    {Events, _Conn6} = recv_events(Conn5, iolist_to_binary(Headers3)),
    ?assertMatch([{request, 5, _, fin}], Events),
    ok.

-doc "Helper to receive data and extract connection (ignores events and output).".
-spec recv_ok(nhttp_h2:conn(), binary()) -> nhttp_h2:conn().
recv_ok(Conn, Data) ->
    case nhttp_h2:recv(Conn, Data) of
        {ok, _, NewConn} -> NewConn;
        {ok, _, NewConn, _} -> NewConn
    end.

-doc "Helper to receive data and extract events and connection (ignores output).".
-spec recv_events(nhttp_h2:conn(), binary()) -> {[nhttp_h2:event()], nhttp_h2:conn()}.
recv_events(Conn, Data) ->
    case nhttp_h2:recv(Conn, Data) of
        {ok, Events, NewConn} -> {Events, NewConn};
        {ok, Events, NewConn, _} -> {Events, NewConn}
    end.

trailers_validation_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, DataFrame} = nhttp_h2_frame:data(1, nofin, <<"body data">>),
    {ok, _, Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(DataFrame)),
    TrailerBlock = encode_headers([{<<":invalid">>, <<"value">>}, {<<"x-trailer">>, <<"val">>}]),
    {ok, TrailerFrame} = nhttp_h2_frame:headers(1, fin, fin, TrailerBlock),
    {ok, [], _Conn3, RstFrame} = nhttp_h2:recv(Conn2, iolist_to_binary(TrailerFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

te_header_validation_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"te">>, <<"gzip">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

te_trailers_allowed_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"te">>, <<"trailers">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, Events, _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch([{request, 1, _, fin}], Events),
    ok.

connection_headers_rejected_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"connection">>, <<"keep-alive">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

authority_host_match_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"example.com">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, Events, _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch([{request, 1, _, fin}], Events),
    ok.

authority_host_mismatch_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"evil.com">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

host_only_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"example.com">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, Events, _Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch([{request, 1, _, fin}], Events),
    ok.

multiple_host_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"a.example">>},
        {<<"host">>, <<"b.example">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

extended_connect_accepted_test(_Config) ->
    Conn0 = nhttp_h2:new(server, #{enable_connect_protocol => true}),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/chat">>},
        {<<":protocol">>, <<"websocket">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, Events, _Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(HeadersFrame)),
    ?assertMatch([{request, 1, #{connect_protocol := <<"websocket">>}, fin}], Events),
    [{request, 1, Request, fin}] = Events,
    ?assertEqual(connect, maps:get(method, Request)),
    ok.

extended_connect_not_enabled_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/chat">>},
        {<<":protocol">>, <<"websocket">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

protocol_without_connect_test(_Config) ->
    Conn0 = nhttp_h2:new(server, #{enable_connect_protocol => true}),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<":protocol">>, <<"websocket">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn2, RstFrame} = nhttp_h2:recv(Conn1, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

extended_connect_missing_authority_test(_Config) ->
    Conn0 = nhttp_h2:new(server, #{enable_connect_protocol => true}),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/chat">>},
        {<<":protocol">>, <<"websocket">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn2, RstFrame} = nhttp_h2:recv(Conn1, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

content_length_mismatch_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"content-length">>, <<"10">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, DataFrame} = nhttp_h2_frame:data(1, fin, <<"hello">>),
    {ok, [], _Conn2, RstFrame} = nhttp_h2:recv(Conn1, iolist_to_binary(DataFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

content_length_exceeded_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"content-length">>, <<"5">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, DataFrame} = nhttp_h2_frame:data(1, nofin, <<"helloworld">>),
    {ok, [], _Conn2, RstFrame} = nhttp_h2:recv(Conn1, iolist_to_binary(DataFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

headers_on_half_closed_remote_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [{request, 1, _, fin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    TrailerBlock = encode_headers([{<<"x-trailer">>, <<"val">>}]),
    {ok, TrailerFrame} = nhttp_h2_frame:headers(1, fin, fin, TrailerBlock),
    {ok, [], _Conn2, RstFrame} = nhttp_h2:recv(Conn1, iolist_to_binary(TrailerFrame)),
    {ok, {rst_stream, 1, stream_closed}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

second_headers_without_end_stream_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    TrailerBlock = encode_headers([{<<"x-header">>, <<"val">>}]),
    {ok, TrailerFrame} = nhttp_h2_frame:headers(1, nofin, fin, TrailerBlock),
    {ok, [], _Conn2, RstFrame} = nhttp_h2:recv(Conn1, iolist_to_binary(TrailerFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

invalid_preface_test(_Config) ->
    Conn0 = nhttp_h2:new(server),
    InvalidPreface = <<"THIS IS NOT A VALID HTTP/2 PREFACE!">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2:recv(Conn0, InvalidPreface),
    ok.

data_on_half_closed_local_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, HeaderBlock),
    {ok, [{request, 1, _, nofin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    RespHeaders = [{<<":status">>, <<"200">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, 1, RespHeaders, fin),
    {ok, DataFrame} = nhttp_h2_frame:data(1, fin, <<"body">>),
    {ok, Events, Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(DataFrame)),
    ?assertMatch([{data, 1, <<"body">>, fin}], Events),
    ?assertMatch({error, _}, nhttp_h2:send_data(Conn3, 1, <<"more">>, nofin)),
    ok.

uppercase_header_name_test(_Config) ->
    Conn0 = server_with_preface(),
    UppercaseHeaderBlock = <<16#00, 16#04, "TEST", 16#05, "value">>,
    {ok, State0} = nhttp_hpack:new(),
    {ok, PseudoBlock, _} = nhttp_hpack:encode(
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/">>}
        ],
        State0
    ),
    HeaderBlock = <<(iolist_to_binary(PseudoBlock))/binary, UppercaseHeaderBlock/binary>>,
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

client_receives_even_stream_id_test(_Config) ->
    Conn0 = nhttp_h2:new(client),
    RespHeaders = encode_headers([{<<":status">>, <<"200">>}]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, RespHeaders),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ok.

window_update_on_closed_stream_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, _, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, 1, [{<<":status">>, <<"200">>}], fin),
    {ok, WinUpdate} = nhttp_h2_frame:window_update(1, 1000),
    {ok, [], _Conn3} = nhttp_h2:recv(Conn2, iolist_to_binary(WinUpdate)),
    ok.

response_missing_status_test(_Config) ->
    Conn0 = nhttp_h2:new(client),
    {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
    ReqHeaders = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, ReqHeaders, fin),
    RespBlock = encode_headers([{<<"content-type">>, <<"text/html">>}]),
    {ok, RespFrame} = nhttp_h2_frame:headers(StreamId, fin, fin, RespBlock),
    {ok, [], _Conn3, RstFrame} = nhttp_h2:recv(Conn2, iolist_to_binary(RespFrame)),
    {ok, {rst_stream, StreamId, protocol_error}, _} = nhttp_h2_frame:decode(
        iolist_to_binary(RstFrame)
    ),
    ok.

duplicate_pseudo_header_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

pseudo_header_after_regular_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<"x-custom">>, <<"value">>},
        {<<":path">>, <<"/">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

empty_path_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<>>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

invalid_request_pseudo_header_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":status">>, <<"200">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

missing_required_pseudo_headers_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>}
    ]),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, {rst_stream, 1, protocol_error}, _} = nhttp_h2_frame:decode(iolist_to_binary(RstFrame)),
    ok.

non_continuation_during_continuation_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/verylongpath">>}
    ]),
    HBSize = byte_size(HeaderBlock),
    SplitAt = HBSize div 2,
    <<First:SplitAt/binary, _Rest/binary>> = HeaderBlock,
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, nofin, First),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, DataFrame} = nhttp_h2_frame:data(1, fin, <<"body">>),
    {error, {connection_error, protocol_error, _}} =
        nhttp_h2:recv(Conn1, iolist_to_binary(DataFrame)),
    ok.

partial_data_for_more_test(_Config) ->
    Conn0 = nhttp_h2:new(client),
    PartialFrame = <<0, 0, 10>>,
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, PartialFrame),
    ?assertNotEqual(Conn0, Conn1),
    ok.

window_update_on_half_closed_remote_test(_Config) ->
    Conn0 = server_with_preface(),
    HeaderBlock = encode_headers(minimal_request_headers()),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, HeaderBlock),
    {ok, [{request, 1, _, fin}], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    {ok, WinUpdate} = nhttp_h2_frame:window_update(1, 1000),
    {ok, [{window_update, 1, 1000}], _Conn2} = nhttp_h2:recv(Conn1, iolist_to_binary(WinUpdate)),
    ok.
