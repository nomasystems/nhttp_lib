%%%-----------------------------------------------------------------------------
-module(nhttp_h3_SUITE).

-moduledoc "HTTP/3 connection state machine test suite (RFC 9114).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, initialization},
        {group, settings_exchange},
        {group, stream_classification},
        {group, control_stream},
        {group, qpack_streams},
        {group, request_response},
        {group, goaway},
        {group, header_validation},
        {group, response_validation},
        {group, stream_lifecycle},
        {group, content_length},
        {group, push_client},
        {group, additional_coverage},
        {group, error_cases},
        {group, send_response}
    ].

groups() ->
    [
        {initialization, [parallel], [
            new_server,
            new_client,
            init_local_streams_server,
            init_local_streams_client
        ]},
        {settings_exchange, [parallel], [
            settings_roundtrip,
            settings_with_qpack_params,
            settings_reconciles_encoder,
            settings_forbidden_h2_setting,
            settings_must_be_first_on_control,
            settings_duplicate_rejected
        ]},
        {stream_classification, [parallel], [
            classify_control_stream,
            classify_encoder_stream,
            classify_decoder_stream,
            classify_unknown_uni_stream_type,
            classify_bidi_request_stream
        ]},
        {control_stream, [parallel], [
            control_stream_close_is_error,
            duplicate_control_stream_error,
            data_on_control_stream_error,
            headers_on_control_stream_error,
            unknown_frame_on_control_stream,
            cancel_push_on_control_stream,
            max_push_id_on_control_stream
        ]},
        {qpack_streams, [parallel], [
            encoder_stream_close_is_error,
            decoder_stream_close_is_error,
            duplicate_encoder_stream_error,
            duplicate_decoder_stream_error
        ]},
        {request_response, [parallel], [
            send_and_recv_headers,
            send_and_recv_data,
            full_request_response_flow,
            data_before_headers_error,
            trailers_support,
            send_headers_with_fin,
            unknown_frame_on_request_stream,
            multiple_trailers_error
        ]},
        {goaway, [parallel], [
            send_goaway_server,
            send_goaway_client,
            recv_goaway,
            goaway_id_must_not_increase,
            stream_opened_after_goaway,
            stream_opened_before_goaway_ok,
            stream_opened_uni_ok,
            stream_opened_goaway_in_range
        ]},
        {header_validation, [parallel], [
            request_missing_method,
            request_missing_scheme,
            request_missing_path,
            request_te_header_forbidden,
            request_connection_header_forbidden,
            request_duplicate_pseudo_header,
            request_unknown_pseudo_header,
            request_pseudo_after_regular,
            response_missing_status,
            trailers_with_pseudo_headers_error,
            request_authority_host_match,
            request_authority_host_mismatch,
            request_host_only,
            request_multiple_host,
            request_extended_connect_accepted,
            request_extended_connect_not_enabled,
            request_protocol_without_connect,
            request_extended_connect_missing_authority
        ]},
        {response_validation, [parallel], [
            response_valid_with_body,
            response_duplicate_status,
            response_invalid_pseudo_header,
            response_te_header_forbidden,
            response_connection_header_forbidden
        ]},
        {stream_lifecycle, [parallel], [
            stream_reset_event,
            send_headers_after_goaway_error,
            send_data_after_goaway_error,
            stream_removed_after_full_lifecycle,
            stream_removed_after_reset
        ]},
        {content_length, [parallel], [
            content_length_exact_match,
            content_length_mismatch_on_fin,
            content_length_exceeded_before_fin
        ]},
        {push_client, [parallel], [
            client_recv_push_promise,
            max_push_id_decrease_error,
            push_stream_to_client_ignored
        ]},
        {additional_coverage, [parallel], [
            send_data_nofin,
            partial_uni_stream_type,
            partial_uni_stream_type_fin,
            forbidden_h2_frame_on_request_stream,
            malformed_frame_on_request_stream,
            request_stream_byte_at_a_time
        ]},
        {error_cases, [parallel], [
            settings_on_request_stream_error,
            goaway_on_request_stream_error,
            max_push_id_on_request_stream_error,
            cancel_push_on_request_stream_error,
            push_promise_to_server_error,
            max_push_id_to_client_error,
            push_stream_to_server_error
        ]},
        {send_response, [parallel], [
            send_response_combined_action,
            send_response_stream_removed,
            send_response_after_goaway_error,
            send_response_decodable_frames
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
%%% INITIALIZATION TESTS
%%%-----------------------------------------------------------------------------

new_server(_Config) ->
    _Conn = nhttp_h3:new(server, #{}),
    ok.

new_client(_Config) ->
    _Conn = nhttp_h3:new(client, #{}),
    ok.

init_local_streams_server(_Config) ->
    Conn = nhttp_h3:new(server, #{}),
    {ok, Conn1, Actions} = nhttp_h3:init_local_streams(Conn, #{
        control => 3, encoder => 7, decoder => 11
    }),
    ?assertEqual(3, length(Actions)),
    [{send, 3, CtrlData}, {send, 7, _EncData}, {send, 11, _DecData}] = Actions,
    CtrlBin = iolist_to_binary(CtrlData),
    {ok, 0, Rest} = nquic_varint:decode(CtrlBin),
    {ok, {settings, _}, _} = nhttp_h3_frame:decode(Rest),
    ?assert(is_tuple(Conn1)).

init_local_streams_client(_Config) ->
    Conn = nhttp_h3:new(client, #{qpack_max_table_capacity => 4096}),
    {ok, _, Actions} = nhttp_h3:init_local_streams(Conn, #{
        control => 2, encoder => 6, decoder => 10
    }),
    ?assertEqual(3, length(Actions)),
    [{send, 2, CtrlData}, {send, 6, EncData}, {send, 10, DecData}] = Actions,
    CtrlBin = iolist_to_binary(CtrlData),
    {ok, 0, CtrlRest} = nquic_varint:decode(CtrlBin),
    {ok, {settings, Settings}, _} = nhttp_h3_frame:decode(CtrlRest),
    ?assertEqual(4096, maps:get(qpack_max_table_capacity, Settings)),
    EncBin = iolist_to_binary(EncData),
    {ok, 2, <<>>} = nquic_varint:decode(EncBin),
    DecBin = iolist_to_binary(DecData),
    {ok, 3, <<>>} = nquic_varint:decode(DecBin).

%%%-----------------------------------------------------------------------------
%%% SETTINGS EXCHANGE TESTS
%%%-----------------------------------------------------------------------------

settings_roundtrip(_Config) ->
    {ok, Server} = init_server(),
    {ok, Client} = init_client(),
    {ok, _, ServerActions} = nhttp_h3:init_local_streams(Server, #{
        control => 3, encoder => 7, decoder => 11
    }),
    [{send, 3, ServerCtrlData} | _] = ServerActions,
    ServerCtrlBin = iolist_to_binary(ServerCtrlData),
    {ok, 0, SettingsBin} = nquic_varint:decode(ServerCtrlBin),
    {ok, Events, _Client1, _} = nhttp_h3:recv(Client, 3, <<0, SettingsBin/binary>>, nofin),
    ?assertMatch([{settings, _}], Events).

settings_with_qpack_params(_Config) ->
    Settings = #{qpack_max_table_capacity => 4096, qpack_blocked_streams => 100},
    Server = nhttp_h3:new(server, Settings),
    {ok, _, ServerActions} = nhttp_h3:init_local_streams(Server, #{
        control => 3, encoder => 7, decoder => 11
    }),
    [{send, 3, CtrlData} | _] = ServerActions,
    CtrlBin = iolist_to_binary(CtrlData),
    {ok, 0, SettingsBin} = nquic_varint:decode(CtrlBin),

    {ok, Client} = init_client(),
    {ok, [{settings, PeerSettings}], _, _} =
        nhttp_h3:recv(Client, 3, <<0, SettingsBin/binary>>, nofin),
    ?assertEqual(4096, maps:get(qpack_max_table_capacity, PeerSettings)),
    ?assertEqual(100, maps:get(qpack_blocked_streams, PeerSettings)).

settings_reconciles_encoder(_Config) ->
    Client0 = nhttp_h3:new(client, #{
        qpack_max_table_capacity => 4096, qpack_blocked_streams => 16
    }),
    {ok, Client1, _} = nhttp_h3:init_local_streams(Client0, #{
        control => 2, encoder => 6, decoder => 10
    }),
    Headers = [{<<":method">>, <<"GET">>}, {<<"x-custom">>, <<"v">>}],
    {ok, _, ActionsBefore} = nhttp_h3:send_headers(Client1, 0, Headers, fin),
    ?assertEqual([], [D || {send, 6, D} <- ActionsBefore]),

    Server = nhttp_h3:new(server, #{
        qpack_max_table_capacity => 4096, qpack_blocked_streams => 16
    }),
    {ok, _, ServerActions} = nhttp_h3:init_local_streams(Server, #{
        control => 3, encoder => 7, decoder => 11
    }),
    [{send, 3, CtrlData} | _] = ServerActions,
    {ok, 0, SettingsBin} = nquic_varint:decode(iolist_to_binary(CtrlData)),
    {ok, [{settings, _}], Client2, _} =
        nhttp_h3:recv(Client1, 3, <<0, SettingsBin/binary>>, nofin),

    {ok, _, ActionsAfter} = nhttp_h3:send_headers(Client2, 4, Headers, fin),
    EncSends = [iolist_to_binary(D) || {send, 6, D} <- ActionsAfter],
    ?assert(lists:any(fun(B) -> byte_size(B) > 0 end, EncSends)).

settings_forbidden_h2_setting(_Config) ->
    {ok, Client} = init_client(),
    TypeBin = nquic_varint:encode(4),
    ForbiddenId = nquic_varint:encode(16#02),
    ForbiddenVal = nquic_varint:encode(1),
    Payload = iolist_to_binary([ForbiddenId, ForbiddenVal]),
    LenBin = nquic_varint:encode(byte_size(Payload)),
    SettingsFrame = iolist_to_binary([TypeBin, LenBin, Payload]),
    ControlData = <<0, SettingsFrame/binary>>,
    ?assertMatch(
        {error, {connection_error, h3_settings_error, _}},
        nhttp_h3:recv(Client, 3, ControlData, nofin)
    ).

settings_must_be_first_on_control(_Config) ->
    {ok, Client} = init_client(),
    {ok, GoawayFrame} = nhttp_h3_frame:goaway(0),
    GoawayBin = iolist_to_binary(GoawayFrame),
    ControlData = <<0, GoawayBin/binary>>,
    ?assertMatch(
        {error, {connection_error, h3_missing_settings, _}},
        nhttp_h3:recv(Client, 3, ControlData, nofin)
    ).

settings_duplicate_rejected(_Config) ->
    {ok, Client} = init_client(),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    ControlData = <<0, SettingsBin/binary, SettingsBin/binary>>,
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Client, 3, ControlData, nofin)
    ).

%%%-----------------------------------------------------------------------------
%%% STREAM CLASSIFICATION TESTS
%%%-----------------------------------------------------------------------------

classify_control_stream(_Config) ->
    {ok, Client} = init_client(),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    ControlData = <<0, SettingsBin/binary>>,
    {ok, [{settings, _}], Client1, _} = nhttp_h3:recv(Client, 3, ControlData, nofin),
    {ok, [], _, _} = nhttp_h3:recv(Client1, 3, <<>>, nofin).

classify_encoder_stream(_Config) ->
    {ok, Client} = init_client(),
    {ok, [], Client1, _} = nhttp_h3:recv(Client, 7, <<2>>, nofin),
    {ok, [], _, _} = nhttp_h3:recv(Client1, 7, <<>>, nofin).

classify_decoder_stream(_Config) ->
    {ok, Client} = init_client(),
    {ok, [], Client1, _} = nhttp_h3:recv(Client, 11, <<3>>, nofin),
    {ok, [], _, _} = nhttp_h3:recv(Client1, 11, <<>>, nofin).

classify_unknown_uni_stream_type(_Config) ->
    {ok, Client} = init_client(),
    GreaseType = 16#1F * 5 + 16#21,
    TypeBin = nquic_varint:encode(GreaseType),
    {ok, [], Client1, _} = nhttp_h3:recv(Client, 15, TypeBin, nofin),
    {ok, [], _, _} = nhttp_h3:recv(Client1, 15, <<"ignored data">>, nofin).

classify_bidi_request_stream(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    RequestData = encode_headers_for_test(Headers),
    {ok, [{request, 0, _, _}], _, _} = nhttp_h3:recv(Server, 0, RequestData, fin).

%%%-----------------------------------------------------------------------------
%%% CONTROL STREAM TESTS
%%%-----------------------------------------------------------------------------

control_stream_close_is_error(_Config) ->
    {ok, Client} = init_client(),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    ControlData = <<0, SettingsBin/binary>>,
    {ok, _, Client1, _} = nhttp_h3:recv(Client, 3, ControlData, nofin),
    ?assertMatch(
        {error, {connection_error, h3_closed_critical_stream, _}},
        nhttp_h3:recv(Client1, 3, <<>>, fin)
    ).

duplicate_control_stream_error(_Config) ->
    {ok, Client} = init_client(),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    {ok, _, Client1, _} = nhttp_h3:recv(Client, 3, <<0, SettingsBin/binary>>, nofin),
    ?assertMatch(
        {error, {connection_error, h3_stream_creation_error, _}},
        nhttp_h3:recv(Client1, 15, <<0>>, nofin)
    ).

data_on_control_stream_error(_Config) ->
    {ok, Client} = init_client_with_settings(),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"hello">>),
    DataBin = iolist_to_binary(DataFrame),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Client, 3, DataBin, nofin)
    ).

headers_on_control_stream_error(_Config) ->
    {ok, Client} = init_client_with_settings(),
    {ok, HeadersFrame} = nhttp_h3_frame:headers(<<"encoded">>),
    HeadersBin = iolist_to_binary(HeadersFrame),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Client, 3, HeadersBin, nofin)
    ).

unknown_frame_on_control_stream(_Config) ->
    {ok, Client} = init_client_with_settings(),
    TypeBin = nquic_varint:encode(16#FF),
    LenBin = nquic_varint:encode(0),
    UnknownFrame = iolist_to_binary([TypeBin, LenBin]),
    {ok, [], _, _} = nhttp_h3:recv(Client, 3, UnknownFrame, nofin).

cancel_push_on_control_stream(_Config) ->
    {ok, Client} = init_client_with_settings(),
    {ok, CancelPushFrame} = nhttp_h3_frame:cancel_push(42),
    CancelPushBin = iolist_to_binary(CancelPushFrame),
    {ok, Events, _, _} = nhttp_h3:recv(Client, 3, CancelPushBin, nofin),
    ?assertMatch([{cancel_push, 42}], Events).

max_push_id_on_control_stream(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, MaxPushIdFrame} = nhttp_h3_frame:max_push_id(10),
    MaxPushIdBin = iolist_to_binary(MaxPushIdFrame),
    {ok, [], _, _} = nhttp_h3:recv(Server, 2, MaxPushIdBin, nofin).

%%%-----------------------------------------------------------------------------
%%% QPACK STREAM TESTS
%%%-----------------------------------------------------------------------------

encoder_stream_close_is_error(_Config) ->
    {ok, Client} = init_client(),
    {ok, [], Client1, _} = nhttp_h3:recv(Client, 7, <<2>>, nofin),
    ?assertMatch(
        {error, {connection_error, h3_closed_critical_stream, _}},
        nhttp_h3:recv(Client1, 7, <<>>, fin)
    ).

decoder_stream_close_is_error(_Config) ->
    {ok, Client} = init_client(),
    {ok, [], Client1, _} = nhttp_h3:recv(Client, 11, <<3>>, nofin),
    ?assertMatch(
        {error, {connection_error, h3_closed_critical_stream, _}},
        nhttp_h3:recv(Client1, 11, <<>>, fin)
    ).

duplicate_encoder_stream_error(_Config) ->
    {ok, Client} = init_client(),
    {ok, [], Client1, _} = nhttp_h3:recv(Client, 7, <<2>>, nofin),
    ?assertMatch(
        {error, {connection_error, h3_stream_creation_error, _}},
        nhttp_h3:recv(Client1, 15, <<2>>, nofin)
    ).

duplicate_decoder_stream_error(_Config) ->
    {ok, Client} = init_client(),
    {ok, [], Client1, _} = nhttp_h3:recv(Client, 11, <<3>>, nofin),
    ?assertMatch(
        {error, {connection_error, h3_stream_creation_error, _}},
        nhttp_h3:recv(Client1, 15, <<3>>, nofin)
    ).

%%%-----------------------------------------------------------------------------
%%% REQUEST/RESPONSE TESTS
%%%-----------------------------------------------------------------------------

send_and_recv_headers(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    RequestData = encode_headers_for_test(Headers),
    {ok, Events, _, _} = nhttp_h3:recv(Server, 0, RequestData, fin),
    ?assertMatch([{request, 0, _, fin}], Events),
    [{request, 0, Request, fin}] = Events,
    ?assertEqual(get, maps:get(method, Request)),
    ?assertEqual(<<"/">>, maps:get(path, Request)),
    ?assertNot(maps:is_key(connect_protocol, Request)).

send_and_recv_data(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"body">>),
    DataBin = iolist_to_binary(DataFrame),
    {ok, Events, _, _} = nhttp_h3:recv(Server1, 0, DataBin, fin),
    ?assertMatch([{data, 0, <<"body">>, fin}], Events).

full_request_response_flow(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, Client} = init_client_with_peer_settings(),

    ReqHeaders = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    {ok, Client1, ClientActions} = nhttp_h3:send_headers(Client, 4, ReqHeaders, fin),
    ?assertMatch([{send_fin, 4, _}], ClientActions),

    RespHeaders = [{<<":status">>, <<"200">>}],
    {ok, Server1, ServerActions} = nhttp_h3:send_headers(Server, 4, RespHeaders, nofin),
    ?assertMatch([{send, 4, _}], ServerActions),

    {ok, Server2, DataActions} = nhttp_h3:send_data(Server1, 4, <<"hello">>, fin),
    ?assertMatch([{send_fin, 4, _}], DataActions),
    ?assert(is_tuple(Client1)),
    ?assert(is_tuple(Server2)).

data_before_headers_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"body">>),
    DataBin = iolist_to_binary(DataFrame),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Server, 0, DataBin, nofin)
    ).

trailers_support(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),

    {ok, DataFrame} = nhttp_h3_frame:data(<<"body">>),
    DataBin = iolist_to_binary(DataFrame),
    {ok, _, Server2, _} = nhttp_h3:recv(Server1, 0, DataBin, nofin),

    Trailers = [{<<"x-checksum">>, <<"abc123">>}],
    TrailersData = encode_headers_for_test(Trailers),
    {ok, Events, _, _} = nhttp_h3:recv(Server2, 0, TrailersData, fin),
    ?assertMatch([{trailers, 0, _}], Events).

send_headers_with_fin(_Config) ->
    {ok, Server} = init_server_with_settings(),
    RespHeaders = [{<<":status">>, <<"204">>}],
    {ok, _, Actions} = nhttp_h3:send_headers(Server, 0, RespHeaders, fin),
    ?assertMatch([{send_fin, 0, _}], Actions).

unknown_frame_on_request_stream(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    TypeBin = nquic_varint:encode(16#FF),
    LenBin = nquic_varint:encode(2),
    UnknownFrame = iolist_to_binary([TypeBin, LenBin, <<"hi">>]),
    {ok, [], _, _} = nhttp_h3:recv(Server1, 0, UnknownFrame, nofin).

multiple_trailers_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"body">>),
    DataBin = iolist_to_binary(DataFrame),
    {ok, _, Server2, _} = nhttp_h3:recv(Server1, 0, DataBin, nofin),
    Trailers = [{<<"x-checksum">>, <<"abc">>}],
    TrailersData = encode_headers_for_test(Trailers),
    {ok, _, Server3, _} = nhttp_h3:recv(Server2, 0, TrailersData, nofin),
    Trailers2 = [{<<"x-extra">>, <<"def">>}],
    Trailers2Data = encode_headers_for_test(Trailers2),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server3, 0, Trailers2Data, fin)
    ).

%%%-----------------------------------------------------------------------------
%%% GOAWAY TESTS
%%%-----------------------------------------------------------------------------

send_goaway_server(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, _, Actions} = nhttp_h3:send_goaway(Server),
    ?assertMatch([{send, 3, _}], Actions).

send_goaway_client(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    {ok, _, Actions} = nhttp_h3:send_goaway(Client),
    ?assertMatch([{send, 2, _}], Actions).

recv_goaway(_Config) ->
    {ok, Client} = init_client_with_settings(),
    {ok, GoawayFrame} = nhttp_h3_frame:goaway(4),
    GoawayBin = iolist_to_binary(GoawayFrame),
    {ok, Events, _, _} = nhttp_h3:recv(Client, 3, GoawayBin, nofin),
    ?assertMatch([{goaway, 4, h3_no_error, <<>>}], Events).

goaway_id_must_not_increase(_Config) ->
    {ok, Client} = init_client_with_settings(),
    {ok, GoawayFrame1} = nhttp_h3_frame:goaway(8),
    {ok, GoawayFrame2} = nhttp_h3_frame:goaway(12),
    GoawayBin1 = iolist_to_binary(GoawayFrame1),
    GoawayBin2 = iolist_to_binary(GoawayFrame2),
    {ok, _, Client1, _} = nhttp_h3:recv(Client, 3, GoawayBin1, nofin),
    ?assertMatch(
        {error, {connection_error, h3_id_error, _}},
        nhttp_h3:recv(Client1, 3, GoawayBin2, nofin)
    ).

stream_opened_after_goaway(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, Server1, _} = nhttp_h3:send_goaway(Server),
    ?assertMatch(
        {error, {stream_error, 100, h3_request_rejected, _}},
        nhttp_h3:stream_opened(Server1, 100, bidi)
    ).

stream_opened_before_goaway_ok(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, _} = nhttp_h3:stream_opened(Server, 0, bidi).

stream_opened_uni_ok(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, _} = nhttp_h3:stream_opened(Server, 14, uni).

stream_opened_goaway_in_range(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 4, HeadersData, fin),
    {ok, Server2, _} = nhttp_h3:send_goaway(Server1),
    {ok, _} = nhttp_h3:stream_opened(Server2, 0, bidi).

%%%-----------------------------------------------------------------------------
%%% HEADER VALIDATION TESTS
%%%-----------------------------------------------------------------------------

request_missing_method(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [{<<":scheme">>, <<"https">>}, {<<":path">>, <<"/">>}],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_missing_scheme(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_missing_path(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [{<<":method">>, <<"GET">>}, {<<":scheme">>, <<"https">>}],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_te_header_forbidden(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"te">>, <<"trailers">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_connection_header_forbidden(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"connection">>, <<"keep-alive">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_duplicate_pseudo_header(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_unknown_pseudo_header(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":unknown">>, <<"val">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_pseudo_after_regular(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"x-custom">>, <<"val">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_authority_host_match(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {ok, [{request, 0, _, fin}], _, _},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_authority_host_mismatch(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"evil.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_host_only(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {ok, [{request, 0, _, fin}], _, _},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_multiple_host(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"a.example">>},
        {<<"host">>, <<"b.example">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_extended_connect_accepted(_Config) ->
    {ok, Server} = init_server_with_extended_connect(),
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/chat">>},
        {<<":protocol">>, <<"websocket">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, [{request, 0, Request, fin}], _, _} =
        nhttp_h3:recv(Server, 0, HeadersData, fin),
    ?assertEqual(<<"websocket">>, maps:get(connect_protocol, Request)),
    ?assertEqual(connect, maps:get(method, Request)).

request_extended_connect_not_enabled(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/chat">>},
        {<<":protocol">>, <<"websocket">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_protocol_without_connect(_Config) ->
    {ok, Server} = init_server_with_extended_connect(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<":protocol">>, <<"websocket">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

request_extended_connect_missing_authority(_Config) ->
    {ok, Server} = init_server_with_extended_connect(),
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/chat">>},
        {<<":protocol">>, <<"websocket">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, HeadersData, fin)
    ).

response_missing_status(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    Headers = [{<<"content-type">>, <<"text/html">>}],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 4, h3_message_error, _}},
        nhttp_h3:recv(Client, 4, HeadersData, fin)
    ).

trailers_with_pseudo_headers_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),

    {ok, DataFrame} = nhttp_h3_frame:data(<<"body">>),
    DataBin = iolist_to_binary(DataFrame),
    {ok, _, Server2, _} = nhttp_h3:recv(Server1, 0, DataBin, nofin),

    BadTrailers = [{<<":status">>, <<"200">>}],
    TrailersData = encode_headers_for_test(BadTrailers),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server2, 0, TrailersData, fin)
    ).

%%%-----------------------------------------------------------------------------
%%% RESPONSE VALIDATION TESTS
%%%-----------------------------------------------------------------------------

response_valid_with_body(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    Headers = [{<<":status">>, <<"200">>}, {<<"content-type">>, <<"text/plain">>}],
    HeadersData = encode_headers_for_test(Headers),
    {ok, [{response, 4, _, nofin}], Client1, _} = nhttp_h3:recv(Client, 4, HeadersData, nofin),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"hello">>),
    DataBin = iolist_to_binary(DataFrame),
    {ok, Events, _, _} = nhttp_h3:recv(Client1, 4, DataBin, fin),
    ?assertMatch([{data, 4, <<"hello">>, fin}], Events).

response_duplicate_status(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    Headers = [{<<":status">>, <<"200">>}, {<<":status">>, <<"404">>}],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 4, h3_message_error, _}},
        nhttp_h3:recv(Client, 4, HeadersData, fin)
    ).

response_invalid_pseudo_header(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    Headers = [{<<":status">>, <<"200">>}, {<<":method">>, <<"GET">>}],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 4, h3_message_error, _}},
        nhttp_h3:recv(Client, 4, HeadersData, fin)
    ).

response_te_header_forbidden(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    Headers = [{<<":status">>, <<"200">>}, {<<"te">>, <<"trailers">>}],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 4, h3_message_error, _}},
        nhttp_h3:recv(Client, 4, HeadersData, fin)
    ).

response_connection_header_forbidden(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    Headers = [{<<":status">>, <<"200">>}, {<<"connection">>, <<"keep-alive">>}],
    HeadersData = encode_headers_for_test(Headers),
    ?assertMatch(
        {error, {stream_error, 4, h3_message_error, _}},
        nhttp_h3:recv(Client, 4, HeadersData, fin)
    ).

%%%-----------------------------------------------------------------------------
%%% STREAM LIFECYCLE TESTS
%%%-----------------------------------------------------------------------------

stream_reset_event(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, Events, _} = nhttp_h3:stream_reset(Server, 0, 16#0108),
    ?assertMatch([{stream_reset, 0, h3_id_error}], Events),
    {ok, OtherEvents, _} = nhttp_h3:stream_reset(Server, 0, 16#999),
    ?assertMatch([{stream_reset, 0, 16#999}], OtherEvents).

send_headers_after_goaway_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, Server1, _} = nhttp_h3:send_goaway(Server),
    RespHeaders = [{<<":status">>, <<"200">>}],
    ?assertMatch(
        {error, {stream_error, 0, h3_request_rejected, _}},
        nhttp_h3:send_headers(Server1, 0, RespHeaders, fin)
    ).

send_data_after_goaway_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, Server1, _} = nhttp_h3:send_goaway(Server),
    ?assertMatch(
        {error, {stream_error, 0, h3_request_rejected, _}},
        nhttp_h3:send_data(Server1, 0, <<"body">>, fin)
    ).

stream_removed_after_full_lifecycle(_Config) ->
    {ok, Server0} = init_server_with_settings(),
    Server1 = complete_n_streams(Server0, 0, 100),
    _Server2 = complete_n_streams(Server1, 400, 100),
    ok.

stream_removed_after_reset(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    {ok, [{stream_reset, 0, 0}], Server2} = nhttp_h3:stream_reset(Server1, 0, 0),
    HeadersData2 = encode_headers_for_test(Headers),
    {ok, [{request, 4, _, fin}], _, _} = nhttp_h3:recv(Server2, 4, HeadersData2, fin),
    ok.

%%%-----------------------------------------------------------------------------
%%% CONTENT-LENGTH TESTS
%%%-----------------------------------------------------------------------------

content_length_exact_match(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>},
        {<<"content-length">>, <<"5">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"hello">>),
    DataBin = iolist_to_binary(DataFrame),
    {ok, [{data, 0, <<"hello">>, fin}], _, _} = nhttp_h3:recv(Server1, 0, DataBin, fin).

content_length_mismatch_on_fin(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>},
        {<<"content-length">>, <<"10">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"hello">>),
    DataBin = iolist_to_binary(DataFrame),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server1, 0, DataBin, fin)
    ).

content_length_exceeded_before_fin(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>},
        {<<"content-length">>, <<"3">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"hello">>),
    DataBin = iolist_to_binary(DataFrame),
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server1, 0, DataBin, nofin)
    ).

%%%-----------------------------------------------------------------------------
%%% PUSH CLIENT TESTS
%%%-----------------------------------------------------------------------------

client_recv_push_promise(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    ReqHeaders = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    {ok, Client1, _} = nhttp_h3:send_headers(Client, 4, ReqHeaders, fin),
    PushHeaders = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/style.css">>},
        {<<":authority">>, <<"example.com">>}
    ],
    PushFieldSection = encode_field_section_for_test(PushHeaders),
    PushPromiseData = make_push_promise_frame(0, PushFieldSection),
    {ok, Events, _, _} = nhttp_h3:recv(Client1, 4, PushPromiseData, nofin),
    ?assertMatch([{push_promise, 4, 0, _}], Events).

push_stream_to_client_ignored(_Config) ->
    {ok, Client} = init_client_with_peer_settings(),
    {ok, [], _, _} = nhttp_h3:recv(Client, 15, <<1>>, nofin).

max_push_id_decrease_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, MaxPush1} = nhttp_h3_frame:max_push_id(10),
    MaxPush1Bin = iolist_to_binary(MaxPush1),
    {ok, [], Server1, _} = nhttp_h3:recv(Server, 2, MaxPush1Bin, nofin),
    {ok, MaxPush2} = nhttp_h3_frame:max_push_id(5),
    MaxPush2Bin = iolist_to_binary(MaxPush2),
    ?assertMatch(
        {error, {connection_error, h3_id_error, _}},
        nhttp_h3:recv(Server1, 2, MaxPush2Bin, nofin)
    ).

%%%-----------------------------------------------------------------------------
%%% ADDITIONAL COVERAGE TESTS
%%%-----------------------------------------------------------------------------

send_data_nofin(_Config) ->
    {ok, Server} = init_server_with_settings(),
    RespHeaders = [{<<":status">>, <<"200">>}],
    {ok, Server1, _} = nhttp_h3:send_headers(Server, 0, RespHeaders, nofin),
    {ok, _, Actions} = nhttp_h3:send_data(Server1, 0, <<"chunk1">>, nofin),
    ?assertMatch([{send, 0, _}], Actions).

partial_uni_stream_type(_Config) ->
    {ok, Client} = init_client(),
    {ok, [], Client1, _} = nhttp_h3:recv(Client, 3, <<16#40>>, nofin),
    {ok, [], _, _} = nhttp_h3:recv(Client1, 3, <<0>>, nofin).

forbidden_h2_frame_on_request_stream(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    TypeBin = nquic_varint:encode(16#02),
    LenBin = nquic_varint:encode(5),
    ForbiddenFrame = iolist_to_binary([TypeBin, LenBin, <<0, 0, 0, 0, 0>>]),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Server1, 0, ForbiddenFrame, nofin)
    ).

partial_uni_stream_type_fin(_Config) ->
    {ok, Client} = init_client(),
    {ok, [], _, _} = nhttp_h3:recv(Client, 3, <<16#40>>, fin).

malformed_frame_on_request_stream(_Config) ->
    {ok, Server} = init_server_with_settings(),
    TypeBin = nquic_varint:encode(16#07),
    LenBin = nquic_varint:encode(0),
    MalformedFrame = iolist_to_binary([TypeBin, LenBin]),
    ?assertMatch(
        {error, {connection_error, h3_frame_error, _}},
        nhttp_h3:recv(Server, 0, MalformedFrame, nofin)
    ).

request_stream_byte_at_a_time(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/byte-stream">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    Bytes = binary_to_list(HeadersData),
    {Events, _Final} = feed_request_byte_at_a_time(Server, Bytes),
    ?assertMatch([{request, 0, _, fin}], Events).

-spec feed_request_byte_at_a_time(nhttp_h3:conn(), [byte()]) ->
    {[nhttp_h3:event()], nhttp_h3:conn()}.
feed_request_byte_at_a_time(Server, Bytes) ->
    feed_request_byte_at_a_time(Server, Bytes, []).

-spec feed_request_byte_at_a_time(nhttp_h3:conn(), [byte()], [nhttp_h3:event()]) ->
    {[nhttp_h3:event()], nhttp_h3:conn()}.
feed_request_byte_at_a_time(Server, [B], Acc) ->
    {ok, Events, Next, _} = nhttp_h3:recv(Server, 0, <<B>>, fin),
    {lists:reverse(Acc, Events), Next};
feed_request_byte_at_a_time(Server, [B | Rest], Acc) ->
    {ok, Events, Next, _} = nhttp_h3:recv(Server, 0, <<B>>, nofin),
    feed_request_byte_at_a_time(Next, Rest, lists:reverse(Events, Acc)).

%%%-----------------------------------------------------------------------------
%%% ERROR CASES
%%%-----------------------------------------------------------------------------

settings_on_request_stream_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Server, 0, SettingsBin, nofin)
    ).

goaway_on_request_stream_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, GoawayFrame} = nhttp_h3_frame:goaway(0),
    GoawayBin = iolist_to_binary(GoawayFrame),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Server, 0, GoawayBin, nofin)
    ).

max_push_id_on_request_stream_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, MaxPushIdFrame} = nhttp_h3_frame:max_push_id(0),
    MaxPushIdBin = iolist_to_binary(MaxPushIdFrame),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Server, 0, MaxPushIdBin, nofin)
    ).

cancel_push_on_request_stream_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, CancelPushFrame} = nhttp_h3_frame:cancel_push(0),
    CancelPushBin = iolist_to_binary(CancelPushFrame),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Server, 0, CancelPushBin, nofin)
    ).

push_promise_to_server_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeadersData, nofin),
    PushPromiseData = make_push_promise_frame(7, <<"field_data">>),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Server1, 0, PushPromiseData, nofin)
    ).

max_push_id_to_client_error(_Config) ->
    {ok, Client} = init_client_with_settings(),
    {ok, MaxPushIdFrame} = nhttp_h3_frame:max_push_id(5),
    MaxPushIdBin = iolist_to_binary(MaxPushIdFrame),
    ?assertMatch(
        {error, {connection_error, h3_frame_unexpected, _}},
        nhttp_h3:recv(Client, 3, MaxPushIdBin, nofin)
    ).

push_stream_to_server_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    ?assertMatch(
        {error, {connection_error, h3_stream_creation_error, _}},
        nhttp_h3:recv(Server, 14, <<1>>, nofin)
    ).

%%%-----------------------------------------------------------------------------
%%% SEND_RESPONSE TESTS
%%%-----------------------------------------------------------------------------

send_response_combined_action(_Config) ->
    {ok, Server} = init_server_with_settings(),
    ReqHeaders = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    ReqData = encode_headers_for_test(ReqHeaders),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, ReqData, fin),
    RespHeaders = [{<<":status">>, <<"200">>}],
    Body = <<"hello world">>,
    {ok, _Server2, Actions} = nhttp_h3:send_response(Server1, 0, RespHeaders, Body),
    ?assertMatch([{send_fin, 0, _}], Actions).

send_response_stream_removed(_Config) ->
    {ok, Server0} = init_server_with_settings(),
    Server1 = complete_n_streams_response(Server0, 0, 100),
    _Server2 = complete_n_streams_response(Server1, 400, 100),
    ok.

send_response_after_goaway_error(_Config) ->
    {ok, Server} = init_server_with_settings(),
    {ok, Server1, _} = nhttp_h3:send_goaway(Server),
    RespHeaders = [{<<":status">>, <<"200">>}],
    ?assertMatch(
        {error, {stream_error, 0, h3_request_rejected, _}},
        nhttp_h3:send_response(Server1, 0, RespHeaders, <<"body">>)
    ).

send_response_decodable_frames(_Config) ->
    {ok, Server} = init_server_with_settings(),
    ReqHeaders = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/submit">>},
        {<<":authority">>, <<"example.com">>}
    ],
    ReqData = encode_headers_for_test(ReqHeaders),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, ReqData, fin),
    RespHeaders = [{<<":status">>, <<"201">>}],
    Body = <<"created">>,
    {ok, _Server2, [{send_fin, 0, CombinedData}]} =
        nhttp_h3:send_response(Server1, 0, RespHeaders, Body),
    CombinedBin = iolist_to_binary(CombinedData),
    {ok, {headers, _FieldSection}, Rest} = nhttp_h3_frame:decode(CombinedBin),
    {ok, {data, <<"created">>}, Leftover} = nhttp_h3_frame:decode(Rest),
    ?assertEqual(<<>>, Leftover).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

init_server() ->
    {ok, nhttp_h3:new(server, #{})}.

init_client() ->
    Client = nhttp_h3:new(client, #{}),
    {ok, Client1, _Actions} = nhttp_h3:init_local_streams(Client, #{
        control => 2, encoder => 6, decoder => 10
    }),
    {ok, Client1}.

init_server_with_settings() ->
    Server = nhttp_h3:new(server, #{}),
    {ok, Server1, _Actions} = nhttp_h3:init_local_streams(Server, #{
        control => 3, encoder => 7, decoder => 11
    }),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    ControlData = <<0, SettingsBin/binary>>,
    {ok, _, Server2, _} = nhttp_h3:recv(Server1, 2, ControlData, nofin),
    {ok, [], Server3, _} = nhttp_h3:recv(Server2, 6, <<2>>, nofin),
    {ok, [], Server4, _} = nhttp_h3:recv(Server3, 10, <<3>>, nofin),
    {ok, Server4}.

init_server_with_extended_connect() ->
    Server = nhttp_h3:new(server, #{enable_connect_protocol => true}),
    {ok, Server1, _Actions} = nhttp_h3:init_local_streams(Server, #{
        control => 3, encoder => 7, decoder => 11
    }),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    ControlData = <<0, SettingsBin/binary>>,
    {ok, _, Server2, _} = nhttp_h3:recv(Server1, 2, ControlData, nofin),
    {ok, [], Server3, _} = nhttp_h3:recv(Server2, 6, <<2>>, nofin),
    {ok, [], Server4, _} = nhttp_h3:recv(Server3, 10, <<3>>, nofin),
    {ok, Server4}.

init_client_with_settings() ->
    {ok, Client} = init_client(),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    ControlData = <<0, SettingsBin/binary>>,
    {ok, _, Client1, _} = nhttp_h3:recv(Client, 3, ControlData, nofin),
    {ok, Client1}.

init_client_with_peer_settings() ->
    {ok, Client} = init_client(),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    ControlData = <<0, SettingsBin/binary>>,
    {ok, _, Client1, _} = nhttp_h3:recv(Client, 3, ControlData, nofin),
    {ok, [], Client2, _} = nhttp_h3:recv(Client1, 7, <<2>>, nofin),
    {ok, [], Client3, _} = nhttp_h3:recv(Client2, 11, <<3>>, nofin),
    {ok, Client3}.

encode_headers_for_test(Headers) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{
        max_table_capacity => 0, max_blocked_streams => 0
    }),
    {ok, _Enc1, _EncStreamData, FieldSection} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    {ok, Frame} = nhttp_h3_frame:headers(FieldSection),
    iolist_to_binary(Frame).

encode_field_section_for_test(Headers) ->
    {ok, Enc} = nhttp_qpack:new_encoder(#{
        max_table_capacity => 0, max_blocked_streams => 0
    }),
    {ok, _Enc1, _EncStreamData, FieldSection} =
        nhttp_qpack:encode_field_section(Enc, 0, Headers),
    iolist_to_binary(FieldSection).

make_push_promise_frame(PushId, FieldSection) ->
    {ok, Frame} = nhttp_h3_frame:push_promise(PushId, FieldSection),
    iolist_to_binary(Frame).

complete_n_streams(Server, _BaseStreamId, 0) ->
    Server;
complete_n_streams(Server, BaseStreamId, N) ->
    StreamId = BaseStreamId + (N - 1) * 4,
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, StreamId, HeadersData, fin),
    RespHeaders = [{<<":status">>, <<"200">>}],
    {ok, Server2, _} = nhttp_h3:send_headers(Server1, StreamId, RespHeaders, fin),
    complete_n_streams(Server2, BaseStreamId, N - 1).

complete_n_streams_response(Server, _BaseStreamId, 0) ->
    Server;
complete_n_streams_response(Server, BaseStreamId, N) ->
    StreamId = BaseStreamId + (N - 1) * 4,
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"example.com">>}
    ],
    HeadersData = encode_headers_for_test(Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, StreamId, HeadersData, fin),
    RespHeaders = [{<<":status">>, <<"200">>}],
    {ok, Server2, _} = nhttp_h3:send_response(Server1, StreamId, RespHeaders, <<"ok">>),
    complete_n_streams_response(Server2, BaseStreamId, N - 1).
