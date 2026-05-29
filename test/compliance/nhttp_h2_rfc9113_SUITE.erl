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
        {group, section_8_http_semantics}
    ].

groups() ->
    [
        {section_3_starting, [parallel], [
            server_accepts_valid_preface,
            server_rejects_invalid_preface,
            client_preface_contains_magic_and_settings,
            server_preface_is_settings_only
        ]},
        {section_4_frames, [parallel], [
            interleaved_frame_during_continuation_is_connection_error,
            unknown_frame_type_discarded
        ]},
        {section_5_streams, [parallel], [
            data_on_idle_stream_is_connection_error,
            headers_on_half_closed_remote_is_stream_error,
            rst_stream_on_idle_stream_is_connection_error,
            window_update_on_idle_stream_is_connection_error,
            server_rejects_even_client_stream_id,
            server_rejects_non_increasing_stream_id,
            client_rejects_odd_server_stream_id,
            max_concurrent_streams_triggers_refused_stream
        ]},
        {section_6_settings_and_flow_control, [parallel], [
            settings_ack_sent_in_response,
            settings_initial_window_size_updates_streams,
            settings_header_table_size_propagates_to_hpack,
            ping_ack_echoes_payload,
            connection_window_overflow_is_connection_error,
            stream_window_overflow_is_stream_error,
            goaway_transitions_to_closing
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
            connection_header_forbidden,
            keep_alive_header_forbidden,
            proxy_connection_header_forbidden,
            transfer_encoding_header_forbidden,
            upgrade_header_forbidden,
            te_trailers_allowed,
            te_non_trailers_forbidden,
            uppercase_header_name_is_stream_error,
            trailers_with_pseudo_header_is_stream_error,
            trailers_deliver_after_fin,
            content_length_mismatch_is_stream_error,
            content_length_exceeded_is_stream_error
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
    {ok, S} = nhttp_h2_frame:settings(#{initial_window_size => 131070}),
    Result = nhttp_h2:recv(Conn1, iolist_to_binary(S)),
    {ok, Events, _Conn2, _OutData} = Result,
    ?assert(lists:any(fun({window_update, 1, 65535}) -> true; (_) -> false end, Events)),
    ok.

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

goaway_transitions_to_closing(_Config) ->
    Conn0 = server_with_preface(),
    {ok, Goaway} = nhttp_h2_frame:goaway(0, no_error, <<"bye">>),
    {ok, [{goaway, 0, no_error, <<"bye">>}], _Conn1} =
        nhttp_h2:recv(Conn0, iolist_to_binary(Goaway)),
    ok.

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
%%% HELPERS
%%%-----------------------------------------------------------------------------

server_with_preface() ->
    Conn0 = nhttp_h2:new(server),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    Conn1.

server_with_preface_settings(Settings) ->
    Conn0 = nhttp_h2:new(server, maps:merge(#{max_concurrent_streams => 100}, Settings)),
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, [], Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(Preface)),
    Conn1.

client_with_server_preface() ->
    Conn0 = nhttp_h2:new(client),
    {ok, S} = nhttp_h2_frame:settings(#{}),
    {ok, _, Conn1, _} = nhttp_h2:recv(Conn0, iolist_to_binary(S)),
    Conn1.

encode_headers(Headers) ->
    {ok, State} = nhttp_hpack:new(),
    {ok, HeaderBlock, _} = nhttp_hpack:encode(Headers, State),
    iolist_to_binary(HeaderBlock).

minimal_request_headers() ->
    [{<<":method">>, <<"GET">>}, {<<":scheme">>, <<"https">>}, {<<":path">>, <<"/">>}].

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
