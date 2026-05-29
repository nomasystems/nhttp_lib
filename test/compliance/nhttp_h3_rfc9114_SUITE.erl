%%%-----------------------------------------------------------------------------
-module(nhttp_h3_rfc9114_SUITE).

-moduledoc """
RFC 9114 Compliance Test Suite.

Tests compliance with RFC 9114 (HTTP/3) at the connection and stream
state-machine level. Frame-level wire vectors live in
`nhttp_h3_rfc9114_frames_SUITE`.

Each test case cites the RFC requirement it exercises as
`RFC9114-N.N-K: <paraphrased rule>`.

Run with: rebar3 ct --suite=test/compliance/nhttp_h3_rfc9114_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_4_http_expression},
        {group, section_5_connection},
        {group, section_6_stream_types},
        {group, section_7_frames}
    ].

groups() ->
    [
        {section_4_http_expression, [parallel], [
            request_missing_method_is_stream_error,
            request_missing_scheme_is_stream_error,
            request_missing_path_is_stream_error,
            request_empty_path_is_stream_error,
            request_missing_authority_and_host_is_stream_error,
            request_duplicate_pseudo_is_stream_error,
            request_unknown_pseudo_is_stream_error,
            request_pseudo_after_regular_is_stream_error,
            response_missing_status_is_stream_error,
            te_header_forbidden,
            connection_header_forbidden,
            trailers_with_pseudo_forbidden,
            trailers_delivered_as_event,
            content_length_mismatch_is_stream_error
        ]},
        {section_5_connection, [parallel], [
            goaway_decreasing_id_allowed,
            goaway_increasing_id_is_connection_error
        ]},
        {section_6_stream_types, [parallel], [
            duplicate_peer_control_stream_is_connection_error,
            duplicate_peer_encoder_stream_is_connection_error,
            duplicate_peer_decoder_stream_is_connection_error,
            control_stream_closed_is_connection_error,
            encoder_stream_closed_is_connection_error,
            decoder_stream_closed_is_connection_error,
            server_receives_push_stream_is_connection_error,
            unknown_uni_stream_type_ignored
        ]},
        {section_7_frames, [parallel], [
            first_control_frame_must_be_settings,
            second_settings_on_control_is_connection_error,
            data_on_control_stream_is_connection_error,
            headers_on_control_stream_is_connection_error,
            push_promise_on_control_stream_is_connection_error,
            settings_on_request_stream_is_connection_error,
            cancel_push_on_request_stream_is_connection_error,
            goaway_on_request_stream_is_connection_error,
            max_push_id_on_request_stream_is_connection_error,
            h2_priority_frame_on_control_is_connection_error,
            h2_ping_frame_on_control_is_connection_error,
            h2_window_update_frame_on_control_is_connection_error,
            h2_continuation_frame_on_control_is_connection_error,
            unknown_request_frame_discarded,
            h2_enable_push_setting_is_settings_error,
            h2_initial_window_size_setting_is_settings_error,
            h2_max_frame_size_setting_is_settings_error,
            max_push_id_decreasing_is_id_error,
            client_receives_max_push_id_is_connection_error,
            server_receives_push_promise_is_connection_error
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
%%% UNI STREAM TYPE CONSTANTS (RFC 9114 Section 6.2, RFC 9204)
%%%-----------------------------------------------------------------------------
-define(UNI_CONTROL, 0).
-define(UNI_PUSH, 1).
-define(UNI_QPACK_ENCODER, 2).
-define(UNI_QPACK_DECODER, 3).

-define(PEER_CTRL, 2).
-define(PEER_ENC, 6).
-define(PEER_DEC, 10).

%%%-----------------------------------------------------------------------------
%%% Section 4 - HTTP Expression
%%%-----------------------------------------------------------------------------

request_missing_method_is_stream_error(_Config) ->
    assert_request_stream_error([
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ]).

request_missing_scheme_is_stream_error(_Config) ->
    assert_request_stream_error([
        {<<":method">>, <<"GET">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ]).

request_missing_path_is_stream_error(_Config) ->
    assert_request_stream_error([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>}
    ]).

request_empty_path_is_stream_error(_Config) ->
    assert_request_stream_error([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<>>}
    ]).

request_missing_authority_and_host_is_stream_error(_Config) ->
    assert_request_stream_error([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>}
    ]).

request_duplicate_pseudo_is_stream_error(_Config) ->
    assert_request_stream_error([
        {<<":method">>, <<"GET">>},
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ]).

request_unknown_pseudo_is_stream_error(_Config) ->
    assert_request_stream_error([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<":bogus">>, <<"x">>}
    ]).

request_pseudo_after_regular_is_stream_error(_Config) ->
    assert_request_stream_error([
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<"x-custom">>, <<"v">>},
        {<<":path">>, <<"/">>}
    ]).

response_missing_status_is_stream_error(_Config) ->
    Client = fresh_client(),
    Bytes = encode_request_stream_headers(Client, 1, [
        {<<"content-type">>, <<"text/plain">>}
    ]),
    Result = nhttp_h3:recv(Client, 1, Bytes, fin),
    assert_h3_stream_error(Result, h3_message_error).

te_header_forbidden(_Config) ->
    assert_request_stream_error(
        minimal_request_headers() ++ [{<<"te">>, <<"trailers">>}]
    ).

connection_header_forbidden(_Config) ->
    assert_request_stream_error(
        minimal_request_headers() ++ [{<<"connection">>, <<"close">>}]
    ).

trailers_with_pseudo_forbidden(_Config) ->
    Server = server_with_peer_streams(),
    HeaderBytes = encode_request_stream_headers(
        Server, 0, minimal_request_headers()
    ),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeaderBytes, nofin),
    TrailerBytes = encode_request_stream_headers(
        Server1, 0, [{<<":trailer">>, <<"x">>}]
    ),
    Result = nhttp_h3:recv(Server1, 0, TrailerBytes, fin),
    assert_h3_stream_error(Result, h3_message_error).

trailers_delivered_as_event(_Config) ->
    Server = server_with_peer_streams(),
    HeaderBytes = encode_request_stream_headers(
        Server, 0, minimal_request_headers()
    ),
    {ok, [{request, 0, _, nofin}], Server1, _} =
        nhttp_h3:recv(Server, 0, HeaderBytes, nofin),
    TrailerBytes = encode_request_stream_headers(
        Server1, 0, [{<<"x-trace">>, <<"abc">>}]
    ),
    {ok, Events, _Server2, _} = nhttp_h3:recv(Server1, 0, TrailerBytes, fin),
    ?assertMatch([{trailers, 0, [{<<"x-trace">>, <<"abc">>}]}], Events).

content_length_mismatch_is_stream_error(_Config) ->
    Server = server_with_peer_streams(),
    Headers = minimal_request_headers() ++ [{<<"content-length">>, <<"10">>}],
    HeaderBytes = encode_request_stream_headers(Server, 0, Headers),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeaderBytes, nofin),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"short">>),
    Result = nhttp_h3:recv(Server1, 0, iolist_to_binary(DataFrame), fin),
    assert_h3_stream_error(Result, h3_message_error).

%%%-----------------------------------------------------------------------------
%%% Section 5 - Connection
%%%-----------------------------------------------------------------------------

goaway_decreasing_id_allowed(_Config) ->
    Client = client_with_peer_streams(),
    GoawayBytes1 = encode_control_frames([{goaway, 100}]),
    {ok, _, Client1, _} = nhttp_h3:recv(Client, ?PEER_CTRL, GoawayBytes1, nofin),
    GoawayBytes2 = encode_control_frames([{goaway, 50}]),
    {ok, [{goaway, 50, h3_no_error, <<>>}], _Client2, _} =
        nhttp_h3:recv(Client1, ?PEER_CTRL, GoawayBytes2, nofin),
    ok.

goaway_increasing_id_is_connection_error(_Config) ->
    Client = client_with_peer_streams(),
    GoawayBytes1 = encode_control_frames([{goaway, 50}]),
    {ok, _, Client1, _} = nhttp_h3:recv(Client, ?PEER_CTRL, GoawayBytes1, nofin),
    GoawayBytes2 = encode_control_frames([{goaway, 100}]),
    Result = nhttp_h3:recv(Client1, ?PEER_CTRL, GoawayBytes2, nofin),
    assert_h3_connection_error(Result, h3_id_error).

%%%-----------------------------------------------------------------------------
%%% Section 6 - Stream Types
%%%-----------------------------------------------------------------------------

duplicate_peer_control_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    TypeBin = nquic_varint:encode(?UNI_CONTROL),
    Result = nhttp_h3:recv(Server, 14, iolist_to_binary(TypeBin), nofin),
    assert_h3_connection_error(Result, h3_stream_creation_error).

duplicate_peer_encoder_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    TypeBin = nquic_varint:encode(?UNI_QPACK_ENCODER),
    Result = nhttp_h3:recv(Server, 14, iolist_to_binary(TypeBin), nofin),
    assert_h3_connection_error(Result, h3_stream_creation_error).

duplicate_peer_decoder_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    TypeBin = nquic_varint:encode(?UNI_QPACK_DECODER),
    Result = nhttp_h3:recv(Server, 14, iolist_to_binary(TypeBin), nofin),
    assert_h3_connection_error(Result, h3_stream_creation_error).

control_stream_closed_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    Result = nhttp_h3:recv(Server, ?PEER_CTRL, <<>>, fin),
    assert_h3_connection_error(Result, h3_closed_critical_stream).

encoder_stream_closed_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    Result = nhttp_h3:recv(Server, ?PEER_ENC, <<>>, fin),
    assert_h3_connection_error(Result, h3_closed_critical_stream).

decoder_stream_closed_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    Result = nhttp_h3:recv(Server, ?PEER_DEC, <<>>, fin),
    assert_h3_connection_error(Result, h3_closed_critical_stream).

server_receives_push_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    TypeBin = nquic_varint:encode(?UNI_PUSH),
    Result = nhttp_h3:recv(Server, 14, iolist_to_binary(TypeBin), nofin),
    assert_h3_connection_error(Result, h3_stream_creation_error).

unknown_uni_stream_type_ignored(_Config) ->
    Server = server_with_peer_streams(),
    TypeBin = nquic_varint:encode(16#21),
    {ok, [], _Server1, _} = nhttp_h3:recv(Server, 14, iolist_to_binary(TypeBin), nofin),
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 7 - Frames
%%%-----------------------------------------------------------------------------

first_control_frame_must_be_settings(_Config) ->
    Server = fresh_server(),
    TypeBin = nquic_varint:encode(?UNI_CONTROL),
    {ok, Data} = nhttp_h3_frame:data(<<"x">>),
    Bytes = iolist_to_binary([TypeBin, Data]),
    Result = nhttp_h3:recv(Server, ?PEER_CTRL, Bytes, nofin),
    assert_h3_connection_error(Result, h3_missing_settings).

second_settings_on_control_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    Result = nhttp_h3:recv(
        Server, ?PEER_CTRL, iolist_to_binary(SettingsFrame), nofin
    ),
    assert_h3_connection_error(Result, h3_frame_unexpected).

data_on_control_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, DataFrame} = nhttp_h3_frame:data(<<"x">>),
    Result = nhttp_h3:recv(Server, ?PEER_CTRL, iolist_to_binary(DataFrame), nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

headers_on_control_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, HeadersFrame} = nhttp_h3_frame:headers(<<0, 0>>),
    Result = nhttp_h3:recv(Server, ?PEER_CTRL, iolist_to_binary(HeadersFrame), nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

push_promise_on_control_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, PP} = nhttp_h3_frame:push_promise(1, <<0, 0>>),
    Result = nhttp_h3:recv(Server, ?PEER_CTRL, iolist_to_binary(PP), nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

settings_on_request_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, S} = nhttp_h3_frame:settings(#{}),
    Result = nhttp_h3:recv(Server, 0, iolist_to_binary(S), nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

cancel_push_on_request_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, CP} = nhttp_h3_frame:cancel_push(0),
    Result = nhttp_h3:recv(Server, 0, iolist_to_binary(CP), nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

goaway_on_request_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, G} = nhttp_h3_frame:goaway(0),
    Result = nhttp_h3:recv(Server, 0, iolist_to_binary(G), nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

max_push_id_on_request_stream_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, M} = nhttp_h3_frame:max_push_id(0),
    Result = nhttp_h3:recv(Server, 0, iolist_to_binary(M), nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

h2_priority_frame_on_control_is_connection_error(_Config) ->
    assert_h2_frame_on_control_rejected(16#02).

h2_ping_frame_on_control_is_connection_error(_Config) ->
    assert_h2_frame_on_control_rejected(16#06).

h2_window_update_frame_on_control_is_connection_error(_Config) ->
    assert_h2_frame_on_control_rejected(16#08).

h2_continuation_frame_on_control_is_connection_error(_Config) ->
    assert_h2_frame_on_control_rejected(16#09).

unknown_request_frame_discarded(_Config) ->
    Server = server_with_peer_streams(),
    HeaderBytes = encode_request_stream_headers(
        Server, 0, minimal_request_headers()
    ),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, 0, HeaderBytes, nofin),
    TypeBin = nquic_varint:encode(16#1F + 16#21),
    LenBin = nquic_varint:encode(0),
    UnknownFrame = iolist_to_binary([TypeBin, LenBin]),
    {ok, [], _Server2, _} = nhttp_h3:recv(Server1, 0, UnknownFrame, nofin),
    ok.

h2_enable_push_setting_is_settings_error(_Config) ->
    assert_forbidden_h2_setting(16#02).

h2_initial_window_size_setting_is_settings_error(_Config) ->
    assert_forbidden_h2_setting(16#04).

h2_max_frame_size_setting_is_settings_error(_Config) ->
    assert_forbidden_h2_setting(16#05).

max_push_id_decreasing_is_id_error(_Config) ->
    Server = server_with_peer_streams(),
    Bytes1 = encode_control_frames([{max_push_id, 50}]),
    {ok, _, Server1, _} = nhttp_h3:recv(Server, ?PEER_CTRL, Bytes1, nofin),
    Bytes2 = encode_control_frames([{max_push_id, 10}]),
    Result = nhttp_h3:recv(Server1, ?PEER_CTRL, Bytes2, nofin),
    assert_h3_connection_error(Result, h3_id_error).

client_receives_max_push_id_is_connection_error(_Config) ->
    Client = client_with_peer_streams(),
    Bytes = encode_control_frames([{max_push_id, 10}]),
    Result = nhttp_h3:recv(Client, ?PEER_CTRL, Bytes, nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

server_receives_push_promise_is_connection_error(_Config) ->
    Server = server_with_peer_streams(),
    {ok, PP} = nhttp_h3_frame:push_promise(0, <<0, 0>>),
    Result = nhttp_h3:recv(Server, 0, iolist_to_binary(PP), nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

fresh_server() ->
    C0 = nhttp_h3:new(server, #{}),
    {ok, C1, _} = nhttp_h3:init_local_streams(C0, #{
        control => 3, encoder => 7, decoder => 11
    }),
    C1.

fresh_client() ->
    C0 = nhttp_h3:new(client, #{}),
    {ok, C1, _} = nhttp_h3:init_local_streams(C0, #{
        control => 2, encoder => 6, decoder => 10
    }),
    C1.

server_with_peer_streams() ->
    connect_peer_streams(fresh_server()).

client_with_peer_streams() ->
    connect_peer_streams(fresh_client()).

connect_peer_streams(C0) ->
    CtrlType = nquic_varint:encode(?UNI_CONTROL),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    PeerCtrlInit = iolist_to_binary([CtrlType, SettingsFrame]),
    {ok, _, C1, _} = nhttp_h3:recv(C0, ?PEER_CTRL, PeerCtrlInit, nofin),
    EncType = nquic_varint:encode(?UNI_QPACK_ENCODER),
    {ok, _, C2, _} = nhttp_h3:recv(C1, ?PEER_ENC, iolist_to_binary(EncType), nofin),
    DecType = nquic_varint:encode(?UNI_QPACK_DECODER),
    {ok, _, C3, _} = nhttp_h3:recv(C2, ?PEER_DEC, iolist_to_binary(DecType), nofin),
    C3.

minimal_request_headers() ->
    [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ].

encode_request_stream_headers(_Conn, _StreamId, Headers) ->
    {ok, Enc0} = nhttp_qpack:new_encoder(#{max_table_capacity => 0, max_blocked_streams => 0}),
    {ok, _Enc1, _EncStream, FieldSection} =
        nhttp_qpack:encode_field_section(Enc0, 0, Headers),
    {ok, Frame} = nhttp_h3_frame:headers(FieldSection),
    iolist_to_binary(Frame).

encode_control_frames(Frames) ->
    iolist_to_binary([encode_control_frame(F) || F <- Frames]).

encode_control_frame({goaway, Id}) ->
    {ok, F} = nhttp_h3_frame:goaway(Id),
    F;
encode_control_frame({max_push_id, PushId}) ->
    {ok, F} = nhttp_h3_frame:max_push_id(PushId),
    F;
encode_control_frame({cancel_push, PushId}) ->
    {ok, F} = nhttp_h3_frame:cancel_push(PushId),
    F.

assert_request_stream_error(Headers) ->
    Server = server_with_peer_streams(),
    Bytes = encode_request_stream_headers(Server, 0, Headers),
    Result = nhttp_h3:recv(Server, 0, Bytes, fin),
    assert_h3_stream_error(Result, h3_message_error).

assert_h2_frame_on_control_rejected(TypeCode) ->
    Server = server_with_peer_streams(),
    TypeBin = nquic_varint:encode(TypeCode),
    LenBin = nquic_varint:encode(0),
    Frame = iolist_to_binary([TypeBin, LenBin]),
    Result = nhttp_h3:recv(Server, ?PEER_CTRL, Frame, nofin),
    assert_h3_connection_error(Result, h3_frame_unexpected).

assert_forbidden_h2_setting(SettingId) ->
    Server = fresh_server(),
    CtrlType = nquic_varint:encode(?UNI_CONTROL),
    IdBin = nquic_varint:encode(SettingId),
    ValBin = nquic_varint:encode(1),
    Payload = iolist_to_binary([IdBin, ValBin]),
    FrameType = nquic_varint:encode(16#04),
    LenBin = nquic_varint:encode(byte_size(Payload)),
    SettingsFrame = iolist_to_binary([FrameType, LenBin, Payload]),
    Bytes = iolist_to_binary([CtrlType, SettingsFrame]),
    Result = nhttp_h3:recv(Server, ?PEER_CTRL, Bytes, nofin),
    assert_h3_connection_error(Result, h3_settings_error).

assert_h3_connection_error({error, {connection_error, ExpectedCode, _}}, ExpectedCode) ->
    ok;
assert_h3_connection_error(Other, ExpectedCode) ->
    ct:fail("Expected connection error ~p; got ~p", [ExpectedCode, Other]).

assert_h3_stream_error({error, {stream_error, _, ExpectedCode, _}}, ExpectedCode) ->
    ok;
assert_h3_stream_error(Other, ExpectedCode) ->
    ct:fail("Expected stream error ~p; got ~p", [ExpectedCode, Other]).
