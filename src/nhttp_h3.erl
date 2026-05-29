-module(nhttp_h3).

-moduledoc """
HTTP/3 protocol layer.

Pure functional HTTP/3 connection state machine (RFC 9114). Sits between
the QUIC transport (nquic) and the application layer. The caller manages
QUIC I/O and routes data to/from this module. Return values include
`actions` that the caller must execute via nquic.

## Usage

```erlang
H3 = nhttp_h3:new(server, #{}),
{ok, H3_1, Actions} = nhttp_h3:init_local_streams(H3, #{
    control => CtrlId, encoder => EncId, decoder => DecId
}),
execute_actions(QConn, Actions),
loop(QConn, H3_1).
```

## Sending bodies and trailers

The HTTP/3 send surface is frame-oriented. The canonical
`t:nhttp_lib:request/0` and `t:nhttp_lib:response/0` maps can carry a `body`
and `trailers` field as a convenience for "everything is in memory", but
this layer does not consume those maps directly: the caller breaks the
exchange into discrete frame sends. The pattern is:

1. `send_headers(Conn, StreamId, Headers, nofin)` to emit pseudo-headers
   plus regular headers (HEADERS frame, QPACK-encoded).
2. Zero or more `send_data(Conn, StreamId, Chunk, nofin)` calls.
3. Either `send_data(Conn, StreamId, FinalChunk, fin)` to close on body,
   or `send_headers(Conn, StreamId, Trailers, fin)` to close on trailers.

`send_response/4` is the convenience one-shot for "headers + complete
body + END_STREAM" when the body is already a single `iodata()`.
""".

-include("nhttp_msg.hrl").

%%%-----------------------------------------------------------------------------
%% API EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    init_local_streams/2,
    new/2,
    recv/4,
    send_data/4,
    send_goaway/1,
    send_headers/4,
    send_response/4,
    set_peer/2,
    stream_opened/3,
    stream_reset/3
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    action/0,
    conn/0,
    error_code/0,
    event/0,
    fin/0,
    h3_error/0,
    h3_error_code/0,
    h3_settings/0,
    role/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type fin() :: nhttp_lib:fin().
-type role() :: nhttp_lib:role().

-type h3_settings() :: nhttp_h3_frame:h3_settings().

-type h3_error_code() ::
    h3_no_error
    | h3_general_protocol_error
    | h3_internal_error
    | h3_stream_creation_error
    | h3_closed_critical_stream
    | h3_frame_unexpected
    | h3_frame_error
    | h3_excessive_load
    | h3_id_error
    | h3_settings_error
    | h3_missing_settings
    | h3_request_rejected
    | h3_request_cancelled
    | h3_request_incomplete
    | h3_message_error
    | h3_connect_error
    | h3_version_fallback
    | qpack_decompression_failed
    | qpack_encoder_stream_error
    | qpack_decoder_stream_error.

-type h3_error() ::
    {connection_error, h3_error_code(), binary()}
    | {stream_error, nhttp_lib:stream_id(), h3_error_code(), binary()}.

-type error_code() :: nhttp_lib:error_code().

-type event() ::
    nhttp_lib:event_common()
    | {settings, h3_settings()}
    | {push_promise, nhttp_lib:stream_id(), non_neg_integer(), nhttp_lib:headers()}.

-type action() ::
    {send, nhttp_lib:stream_id(), iodata()}
    | {send_fin, nhttp_lib:stream_id(), iodata()}
    | {close_connection, non_neg_integer(), binary()}.

-type stream_state() ::
    open
    | half_closed_local
    | half_closed_remote
    | closed.

%%%-----------------------------------------------------------------------------
%% CONSTANTS
%%%-----------------------------------------------------------------------------
-define(UNI_CONTROL, 16#00).
-define(UNI_PUSH, 16#01).
-define(UNI_QPACK_ENCODER, 16#02).
-define(UNI_QPACK_DECODER, 16#03).

%%%-----------------------------------------------------------------------------
%% RECORDS
%%%-----------------------------------------------------------------------------
-record(h3_stream, {
    id :: nhttp_lib:stream_id(),
    state = open :: stream_state(),
    headers_received = false :: boolean(),
    trailers_received = false :: boolean(),
    content_length = undefined :: non_neg_integer() | undefined,
    recv_body_length = 0 :: non_neg_integer()
}).

-record(h3_conn, {
    role :: role(),
    state = init :: init | open | closing | closed,

    local_settings :: h3_settings(),
    peer_settings :: h3_settings(),
    settings_received = false :: boolean(),

    local_control_stream :: nhttp_lib:stream_id() | undefined,
    peer_control_stream :: nhttp_lib:stream_id() | undefined,
    local_encoder_stream :: nhttp_lib:stream_id() | undefined,
    peer_encoder_stream :: nhttp_lib:stream_id() | undefined,
    local_decoder_stream :: nhttp_lib:stream_id() | undefined,
    peer_decoder_stream :: nhttp_lib:stream_id() | undefined,

    qpack_enc :: nhttp_qpack:encoder(),
    qpack_dec :: nhttp_qpack:decoder(),

    streams = #{} :: #{nhttp_lib:stream_id() => #h3_stream{}},
    last_peer_stream_id = 0 :: nhttp_lib:stream_id(),

    max_push_id = 0 :: non_neg_integer(),
    peer_max_push_id = 0 :: non_neg_integer(),

    goaway_sent = false :: boolean(),
    goaway_received = false :: boolean(),
    goaway_id = 0 :: non_neg_integer(),

    uni_stream_bufs = #{} :: #{nhttp_lib:stream_id() => binary()},
    ignored_uni_streams = #{} :: #{nhttp_lib:stream_id() => true},
    stream_bufs = #{} :: #{nhttp_lib:stream_id() => binary()},
    peer = undefined :: undefined | nhttp_lib:peer()
}).

-opaque conn() :: #h3_conn{}.

%%%-----------------------------------------------------------------------------
%% API FUNCTIONS
%%%-----------------------------------------------------------------------------
-doc """
Register QUIC stream IDs for local unidirectional streams.
Returns initial data to send on each (stream type prefix + settings on control).
""".
-spec init_local_streams(conn(), #{
    control := nhttp_lib:stream_id(),
    encoder := nhttp_lib:stream_id(),
    decoder := nhttp_lib:stream_id()
}) -> {ok, conn(), [action()]}.
init_local_streams(Conn, #{control := CtrlId, encoder := EncId, decoder := DecId}) ->
    CtrlTypeBin = nquic_varint:encode(?UNI_CONTROL),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(Conn#h3_conn.local_settings),
    CtrlData = [CtrlTypeBin, SettingsFrame],

    EncTypeBin = nquic_varint:encode(?UNI_QPACK_ENCODER),
    DecTypeBin = nquic_varint:encode(?UNI_QPACK_DECODER),

    NewConn = Conn#h3_conn{
        local_control_stream = CtrlId,
        local_encoder_stream = EncId,
        local_decoder_stream = DecId,
        state = open
    },
    Actions = [
        {send, CtrlId, CtrlData},
        {send, EncId, EncTypeBin},
        {send, DecId, DecTypeBin}
    ],
    {ok, NewConn, Actions}.

-doc "Create a new HTTP/3 connection.".
-spec new(role(), h3_settings()) -> conn().
new(Role, Settings) ->
    Merged = maps:merge(default_settings(), Settings),
    QpackMaxCap = maps:get(qpack_max_table_capacity, Merged, 0),
    QpackBlocked = maps:get(qpack_blocked_streams, Merged, 0),
    {ok, Enc} = nhttp_qpack:new_encoder(#{
        max_table_capacity => 0,
        configured_max_capacity => QpackMaxCap,
        max_blocked_streams => 0,
        configured_max_blocked => QpackBlocked
    }),
    {ok, Dec} = nhttp_qpack:new_decoder(#{
        max_table_capacity => QpackMaxCap,
        max_blocked_streams => QpackBlocked
    }),
    #h3_conn{
        role = Role,
        local_settings = Merged,
        peer_settings = default_settings(),
        qpack_enc = Enc,
        qpack_dec = Dec
    }.

-doc "Process incoming data on any QUIC stream.".
-spec recv(conn(), nhttp_lib:stream_id(), binary(), fin()) ->
    {ok, [event()], conn(), [action()]}
    | {error, h3_error()}.
recv(#h3_conn{} = Conn, StreamId, Data, Fin) ->
    case classify_stream(Conn, StreamId) of
        {bidi, request} ->
            recv_request_stream(Conn, StreamId, Data, Fin);
        {uni, control} ->
            recv_control_stream(Conn, StreamId, Data, Fin);
        {uni, qpack_encoder} ->
            recv_encoder_stream(Conn, StreamId, Data, Fin);
        {uni, qpack_decoder} ->
            recv_decoder_stream(Conn, StreamId, Data, Fin);
        ignored_uni ->
            {ok, [], Conn, []};
        unknown_uni ->
            recv_new_uni_stream(Conn, StreamId, Data, Fin)
    end.

-doc "Encode and send data on a request stream.".
-spec send_data(conn(), nhttp_lib:stream_id(), iodata(), fin()) ->
    {ok, conn(), [action()]} | {error, h3_error()}.
send_data(#h3_conn{} = Conn, StreamId, Data, Fin) ->
    case validate_send_state(Conn, StreamId) of
        ok ->
            {ok, DataFrame} = nhttp_h3_frame:data(Data),
            Stream = get_or_create_stream(Conn, StreamId),
            OldState = Stream#h3_stream.state,
            NewState = transition_on_send(OldState, Fin),
            NewStream = Stream#h3_stream{state = NewState},
            NewConn = update_stream(Conn, StreamId, NewStream),
            Action =
                case Fin of
                    fin -> {send_fin, StreamId, DataFrame};
                    nofin -> {send, StreamId, DataFrame}
                end,
            {ok, NewConn, [Action]};
        {error, _} = E ->
            E
    end.

-doc "Send GOAWAY on the control stream.".
-spec send_goaway(conn()) ->
    {ok, conn(), [action()]}.
send_goaway(
    #h3_conn{
        role = server,
        last_peer_stream_id = LastId,
        local_control_stream = CtrlId
    } = Conn
) ->
    {ok, Frame} = nhttp_h3_frame:goaway(LastId),
    NewConn = Conn#h3_conn{
        goaway_sent = true,
        goaway_id = LastId,
        state = closing
    },
    {ok, NewConn, [{send, CtrlId, Frame}]};
send_goaway(
    #h3_conn{
        role = client,
        peer_max_push_id = PushId,
        local_control_stream = CtrlId
    } = Conn
) ->
    {ok, Frame} = nhttp_h3_frame:goaway(PushId),
    NewConn = Conn#h3_conn{
        goaway_sent = true,
        goaway_id = PushId,
        state = closing
    },
    {ok, NewConn, [{send, CtrlId, Frame}]}.

-doc "Encode and send headers on a request stream.".
-spec send_headers(conn(), nhttp_lib:stream_id(), nhttp_lib:headers(), fin()) ->
    {ok, conn(), [action()]} | {error, h3_error()}.
send_headers(
    #h3_conn{qpack_enc = Enc, local_encoder_stream = EncStreamId} = Conn,
    StreamId,
    Headers,
    Fin
) ->
    case validate_send_state(Conn, StreamId) of
        ok ->
            {ok, NewEnc, EncStreamData, FieldSection} =
                nhttp_qpack:encode_field_section(Enc, StreamId, Headers),
            {ok, HeadersFrame} = nhttp_h3_frame:headers(FieldSection),
            Stream = get_or_create_stream(Conn, StreamId),
            OldState = Stream#h3_stream.state,
            NewState = transition_on_send(OldState, Fin),
            NewStream = Stream#h3_stream{state = NewState},
            NewConn0 = Conn#h3_conn{qpack_enc = NewEnc},
            NewConn = update_stream(NewConn0, StreamId, NewStream),
            Actions = build_send_actions(EncStreamId, EncStreamData, StreamId, HeadersFrame, Fin),
            {ok, NewConn, Actions};
        {error, _} = E ->
            E
    end.

-doc """
Encode and send a complete response (headers + body) on a request stream.
Combines HEADERS and DATA frames into a single `send_fin` action, avoiding
redundant stream lookups and state transitions compared to calling
`send_headers/4` then `send_data/4` separately.
""".
-spec send_response(conn(), nhttp_lib:stream_id(), nhttp_lib:headers(), iodata()) ->
    {ok, conn(), [action()]} | {error, h3_error()}.
send_response(
    #h3_conn{qpack_enc = Enc, local_encoder_stream = EncStreamId} = Conn,
    StreamId,
    Headers,
    Body
) ->
    case validate_send_state(Conn, StreamId) of
        ok ->
            {ok, NewEnc, EncStreamData, FieldSection} =
                nhttp_qpack:encode_field_section(Enc, StreamId, Headers),
            {ok, HeadersFrame} = nhttp_h3_frame:headers(FieldSection),
            {ok, DataFrame} = nhttp_h3_frame:data(Body),
            Stream = get_or_create_stream(Conn, StreamId),
            OldState = Stream#h3_stream.state,
            NewState = transition_on_send(OldState, fin),
            NewStream = Stream#h3_stream{state = NewState},
            NewConn0 = Conn#h3_conn{qpack_enc = NewEnc},
            NewConn = update_stream(NewConn0, StreamId, NewStream),
            CombinedData = [HeadersFrame, DataFrame],
            Actions = build_response_actions(
                EncStreamId, EncStreamData, StreamId, CombinedData
            ),
            {ok, NewConn, Actions};
        {error, _} = E ->
            E
    end.

-doc """
Record the peer address on the connection. Called once after the QUIC
connection is established so server-built `t:nhttp_lib:request/0` maps and
client-built `t:nhttp_lib:response/0` events carry the correct remote peer.
""".
-spec set_peer(conn(), nhttp_lib:peer()) -> conn().
set_peer(#h3_conn{} = Conn, {{_, _, _, _}, Port} = Peer) when
    is_integer(Port), Port >= 0, Port =< 65535
->
    Conn#h3_conn{peer = Peer};
set_peer(#h3_conn{} = Conn, {{_, _, _, _, _, _, _, _}, Port} = Peer) when
    is_integer(Port), Port >= 0, Port =< 65535
->
    Conn#h3_conn{peer = Peer}.

-doc "Notify that the peer opened a new stream.".
-spec stream_opened(conn(), nhttp_lib:stream_id(), bidi | uni) ->
    {ok, conn()} | {error, h3_error()}.
stream_opened(Conn, StreamId, bidi) ->
    case Conn#h3_conn.goaway_sent of
        true ->
            GoawayId = Conn#h3_conn.goaway_id,
            case StreamId > GoawayId of
                true ->
                    {error,
                        {stream_error, StreamId, h3_request_rejected,
                            <<"Stream opened after GOAWAY">>}};
                false ->
                    {ok, Conn}
            end;
        false ->
            {ok, Conn}
    end;
stream_opened(Conn, _StreamId, uni) ->
    {ok, Conn}.

-doc "Handle a peer stream reset.".
-spec stream_reset(conn(), nhttp_lib:stream_id(), non_neg_integer()) ->
    {ok, [event()], conn()}.
stream_reset(Conn, StreamId, ErrorCode) ->
    Events = [{stream_reset, StreamId, error_code_atom(ErrorCode)}],
    NewConn = close_stream(Conn, StreamId),
    {ok, Events, NewConn}.

%%%-----------------------------------------------------------------------------
%% INTERNAL: STREAM CLASSIFICATION
%%%-----------------------------------------------------------------------------
-spec classify_stream(conn(), nhttp_lib:stream_id()) ->
    {bidi, request}
    | {uni, control | qpack_encoder | qpack_decoder}
    | ignored_uni
    | unknown_uni.
classify_stream(#h3_conn{peer_control_stream = Id}, Id) when Id =/= undefined ->
    {uni, control};
classify_stream(#h3_conn{peer_encoder_stream = Id}, Id) when Id =/= undefined ->
    {uni, qpack_encoder};
classify_stream(#h3_conn{peer_decoder_stream = Id}, Id) when Id =/= undefined ->
    {uni, qpack_decoder};
classify_stream(#h3_conn{uni_stream_bufs = Bufs, ignored_uni_streams = Ignored}, StreamId) ->
    case maps:is_key(StreamId, Ignored) of
        true ->
            ignored_uni;
        false ->
            case maps:is_key(StreamId, Bufs) of
                true ->
                    unknown_uni;
                false ->
                    case is_uni_stream(StreamId) of
                        true -> unknown_uni;
                        false -> {bidi, request}
                    end
            end
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL: RECEIVING ON DIFFERENT STREAM TYPES
%%%-----------------------------------------------------------------------------
-spec process_control_frame(conn(), nhttp_h3_frame:t()) ->
    {ok, conn(), [event()], [action()]} | {error, h3_error()}.
process_control_frame(#h3_conn{settings_received = false}, Frame) when
    element(1, Frame) =/= settings
->
    {error,
        {connection_error, h3_missing_settings,
            <<"First frame on control stream must be SETTINGS (RFC 9114 Section 6.2.1)">>}};
process_control_frame(#h3_conn{settings_received = true}, {settings, _}) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"Second SETTINGS on control stream (RFC 9114 Section 7.2.4)">>}};
process_control_frame(Conn, {settings, PeerSettings}) ->
    NewConn = apply_peer_settings(Conn, PeerSettings),
    {ok, NewConn, [{settings, PeerSettings}], []};
process_control_frame(Conn, {goaway, Id}) ->
    process_goaway(Conn, Id);
process_control_frame(Conn, {max_push_id, PushId}) ->
    process_max_push_id(Conn, PushId);
process_control_frame(Conn, {cancel_push, PushId}) ->
    {ok, Conn, [{cancel_push, PushId}], []};
process_control_frame(_Conn, {data, _}) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"DATA on control stream (RFC 9114 Section 7.2.1)">>}};
process_control_frame(_Conn, {headers, _}) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"HEADERS on control stream (RFC 9114 Section 7.2.2)">>}};
process_control_frame(_Conn, {push_promise, _, _}) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"PUSH_PROMISE on control stream (RFC 9114 Section 7.2.5)">>}};
process_control_frame(Conn, {unknown, _Type, _Payload}) ->
    {ok, Conn, [], []}.

-spec process_request_frame(conn(), nhttp_lib:stream_id(), nhttp_h3_frame:t(), boolean()) ->
    {ok, conn(), [event()], [action()]} | {error, h3_error()}.
process_request_frame(Conn, StreamId, {headers, FieldSection}, IsFinal) ->
    Stream = get_or_create_stream(Conn, StreamId),
    case Stream#h3_stream.headers_received of
        false ->
            decode_headers(Conn, StreamId, Stream, FieldSection, IsFinal);
        true ->
            case Stream#h3_stream.trailers_received of
                true ->
                    {error,
                        {stream_error, StreamId, h3_message_error,
                            <<"Multiple trailer sections (RFC 9114 Section 4.1)">>}};
                false ->
                    decode_trailers(Conn, StreamId, Stream, FieldSection, IsFinal)
            end
    end;
process_request_frame(Conn, StreamId, {data, Payload}, IsFinal) ->
    Stream = get_or_create_stream(Conn, StreamId),
    case Stream#h3_stream.headers_received of
        false ->
            {error,
                {connection_error, h3_frame_unexpected,
                    <<"DATA before HEADERS (RFC 9114 Section 4.1)">>}};
        true ->
            DataLen = byte_size(Payload),
            NewRecvLen = Stream#h3_stream.recv_body_length + DataLen,
            FinAtom = bool_to_fin(IsFinal),
            case
                nhttp_msg:validate_content_length(
                    Stream#h3_stream.content_length, NewRecvLen, FinAtom
                )
            of
                ok ->
                    NewState = transition_on_recv(Stream#h3_stream.state, FinAtom),
                    NewStream = Stream#h3_stream{
                        state = NewState,
                        recv_body_length = NewRecvLen
                    },
                    NewConn = update_stream(Conn, StreamId, NewStream),
                    {ok, NewConn, [{data, StreamId, Payload, FinAtom}], []};
                {error, content_length_mismatch} ->
                    {error,
                        {stream_error, StreamId, h3_message_error,
                            <<"Content-Length mismatch (RFC 9114 Section 4.1.2)">>}}
            end
    end;
process_request_frame(_Conn, _StreamId, {cancel_push, _}, _IsFinal) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"CANCEL_PUSH on request stream (RFC 9114 Section 7.2.3)">>}};
process_request_frame(_Conn, _StreamId, {settings, _}, _IsFinal) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"SETTINGS on request stream (RFC 9114 Section 7.2.4)">>}};
process_request_frame(_Conn, _StreamId, {goaway, _}, _IsFinal) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"GOAWAY on request stream (RFC 9114 Section 7.2.6)">>}};
process_request_frame(_Conn, _StreamId, {max_push_id, _}, _IsFinal) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"MAX_PUSH_ID on request stream (RFC 9114 Section 7.2.7)">>}};
process_request_frame(Conn, StreamId, {push_promise, PushId, FieldSection}, _IsFinal) ->
    process_push_promise(Conn, StreamId, PushId, FieldSection);
process_request_frame(Conn, _StreamId, {unknown, _Type, _Payload}, _IsFinal) ->
    {ok, Conn, [], []}.

-spec recv_control_frames(conn(), nhttp_lib:stream_id(), binary(), [event()], [action()]) ->
    {ok, [event()], conn(), [action()]} | {error, h3_error()}.
recv_control_frames(Conn, StreamId, Data, Events, Actions) ->
    case nhttp_h3_frame:decode(Data) of
        {ok, Frame, Rest} ->
            case process_control_frame(Conn, Frame) of
                {ok, NewConn, NewEvents, NewActions} ->
                    recv_control_frames(
                        NewConn,
                        StreamId,
                        Rest,
                        lists:reverse(NewEvents, Events),
                        lists:reverse(NewActions, Actions)
                    );
                {error, _} = E ->
                    E
            end;
        {more, _} ->
            NewConn = set_stream_buf(Conn, StreamId, Data),
            {ok, lists:reverse(Events), NewConn, lists:reverse(Actions)};
        {error, h3_frame_unexpected} ->
            {error,
                {connection_error, h3_frame_unexpected,
                    <<"Forbidden H2 frame on control stream (RFC 9114 Section 7.2.8)">>}};
        {error, h3_settings_error} ->
            {error,
                {connection_error, h3_settings_error,
                    <<"Forbidden H2 setting in SETTINGS (RFC 9114 Section 7.2.4.1)">>}};
        {error, h3_frame_error} ->
            {error,
                {connection_error, h3_frame_error,
                    <<"Malformed frame on control stream (RFC 9114 Section 7)">>}}
    end.

-spec recv_control_stream(conn(), nhttp_lib:stream_id(), binary(), fin()) ->
    {ok, [event()], conn(), [action()]} | {error, h3_error()}.
recv_control_stream(Conn, StreamId, Data, Fin) ->
    case Fin of
        fin ->
            {error,
                {connection_error, h3_closed_critical_stream,
                    <<"Control stream closed (RFC 9114 Section 6.2.1)">>}};
        nofin ->
            Combined = prepend_stream_buf(Conn, StreamId, Data),
            recv_control_frames(Conn, StreamId, Combined, [], [])
    end.

-spec recv_decoder_stream(conn(), nhttp_lib:stream_id(), binary(), fin()) ->
    {ok, [event()], conn(), [action()]} | {error, h3_error()}.
recv_decoder_stream(Conn, StreamId, Data, Fin) ->
    case Fin of
        fin ->
            {error,
                {connection_error, h3_closed_critical_stream,
                    <<"QPACK decoder stream closed (RFC 9114 Section 6.2.1)">>}};
        nofin when byte_size(Data) =:= 0 ->
            {ok, [], Conn, []};
        nofin ->
            case nhttp_qpack:feed_decoder_stream(Conn#h3_conn.qpack_enc, Data) of
                {ok, NewEnc} ->
                    NewConn = Conn#h3_conn{qpack_enc = NewEnc},
                    NewConn1 = set_stream_buf(NewConn, StreamId, <<>>),
                    {ok, [], NewConn1, []};
                {error, Reason} ->
                    {error,
                        {connection_error, qpack_decoder_stream_error,
                            iolist_to_binary(
                                io_lib:format("QPACK decoder stream error: ~p", [Reason])
                            )}}
            end
    end.

-spec recv_encoder_stream(conn(), nhttp_lib:stream_id(), binary(), fin()) ->
    {ok, [event()], conn(), [action()]} | {error, h3_error()}.
recv_encoder_stream(Conn, StreamId, Data, Fin) ->
    case Fin of
        fin ->
            {error,
                {connection_error, h3_closed_critical_stream,
                    <<"QPACK encoder stream closed (RFC 9114 Section 6.2.1)">>}};
        nofin when byte_size(Data) =:= 0 ->
            {ok, [], Conn, []};
        nofin ->
            case nhttp_qpack:feed_encoder_stream(Conn#h3_conn.qpack_dec, Data) of
                {ok, NewDec, Unblocked} ->
                    {Events, Actions} = process_unblocked(Unblocked),
                    DecStreamId = Conn#h3_conn.local_decoder_stream,
                    DecActions = decoder_stream_actions(DecStreamId, Unblocked),
                    NewConn = Conn#h3_conn{qpack_dec = NewDec},
                    NewConn1 = set_stream_buf(NewConn, StreamId, <<>>),
                    {ok, Events, NewConn1, Actions ++ DecActions};
                {error, Reason} ->
                    {error,
                        {connection_error, qpack_encoder_stream_error,
                            iolist_to_binary(
                                io_lib:format("QPACK encoder stream error: ~p", [Reason])
                            )}}
            end
    end.

-spec recv_new_uni_stream(conn(), nhttp_lib:stream_id(), binary(), fin()) ->
    {ok, [event()], conn(), [action()]} | {error, h3_error()}.
recv_new_uni_stream(Conn, StreamId, Data, Fin) ->
    Bufs = Conn#h3_conn.uni_stream_bufs,
    Combined = prepend(maps:get(StreamId, Bufs, <<>>), Data),
    case nquic_varint:decode(Combined) of
        {ok, Type, Rest} ->
            NewConn = Conn#h3_conn{
                uni_stream_bufs = maps:remove(StreamId, Bufs)
            },
            register_uni_stream(NewConn, StreamId, Type, Rest, Fin);
        {error, incomplete_binary} ->
            case Fin of
                fin ->
                    {ok, [], Conn, []};
                nofin ->
                    NewConn = Conn#h3_conn{
                        uni_stream_bufs = Bufs#{StreamId => Combined}
                    },
                    {ok, [], NewConn, []}
            end
    end.

-spec recv_request_frames(conn(), nhttp_lib:stream_id(), binary(), fin(), [event()], [action()]) ->
    {ok, [event()], conn(), [action()]} | {error, h3_error()}.
recv_request_frames(Conn, StreamId, Data, Fin, Events, Actions) ->
    case nhttp_h3_frame:decode(Data) of
        {ok, Frame, Rest} ->
            IsFinal = Fin =:= fin andalso Rest =:= <<>>,
            case process_request_frame(Conn, StreamId, Frame, IsFinal) of
                {ok, NewConn, NewEvents, NewActions} ->
                    recv_request_frames(
                        NewConn,
                        StreamId,
                        Rest,
                        Fin,
                        lists:reverse(NewEvents, Events),
                        lists:reverse(NewActions, Actions)
                    );
                {error, _} = E ->
                    E
            end;
        {more, _} ->
            NewConn = set_stream_buf(Conn, StreamId, Data),
            {ok, lists:reverse(Events), NewConn, lists:reverse(Actions)};
        {error, h3_frame_unexpected} ->
            {error,
                {connection_error, h3_frame_unexpected,
                    <<"Forbidden H2 frame on request stream (RFC 9114 Section 7.2.8)">>}};
        {error, ErrorCode} ->
            {error, {connection_error, ErrorCode, <<"Frame error on request stream">>}}
    end.

-spec recv_request_stream(conn(), nhttp_lib:stream_id(), binary(), fin()) ->
    {ok, [event()], conn(), [action()]} | {error, h3_error()}.
recv_request_stream(Conn, StreamId, Data, Fin) ->
    Combined = prepend_stream_buf(Conn, StreamId, Data),
    recv_request_frames(Conn, StreamId, Combined, Fin, [], []).

-spec register_uni_stream(conn(), nhttp_lib:stream_id(), non_neg_integer(), binary(), fin()) ->
    {ok, [event()], conn(), [action()]} | {error, h3_error()}.
register_uni_stream(
    #h3_conn{peer_control_stream = undefined} = Conn,
    StreamId,
    ?UNI_CONTROL,
    Rest,
    Fin
) ->
    NewConn = Conn#h3_conn{peer_control_stream = StreamId},
    recv_control_stream(NewConn, StreamId, Rest, Fin);
register_uni_stream(
    #h3_conn{peer_control_stream = Existing},
    _StreamId,
    ?UNI_CONTROL,
    _Rest,
    _Fin
) when Existing =/= undefined ->
    {error,
        {connection_error, h3_stream_creation_error,
            <<"Duplicate control stream (RFC 9114 Section 6.2.1)">>}};
register_uni_stream(
    #h3_conn{peer_encoder_stream = undefined} = Conn,
    StreamId,
    ?UNI_QPACK_ENCODER,
    Rest,
    Fin
) ->
    NewConn = Conn#h3_conn{peer_encoder_stream = StreamId},
    recv_encoder_stream(NewConn, StreamId, Rest, Fin);
register_uni_stream(
    #h3_conn{peer_encoder_stream = Existing},
    _StreamId,
    ?UNI_QPACK_ENCODER,
    _Rest,
    _Fin
) when Existing =/= undefined ->
    {error,
        {connection_error, h3_stream_creation_error,
            <<"Duplicate QPACK encoder stream (RFC 9114 Section 6.2.1)">>}};
register_uni_stream(
    #h3_conn{peer_decoder_stream = undefined} = Conn,
    StreamId,
    ?UNI_QPACK_DECODER,
    Rest,
    Fin
) ->
    NewConn = Conn#h3_conn{peer_decoder_stream = StreamId},
    recv_decoder_stream(NewConn, StreamId, Rest, Fin);
register_uni_stream(
    #h3_conn{peer_decoder_stream = Existing},
    _StreamId,
    ?UNI_QPACK_DECODER,
    _Rest,
    _Fin
) when Existing =/= undefined ->
    {error,
        {connection_error, h3_stream_creation_error,
            <<"Duplicate QPACK decoder stream (RFC 9114 Section 6.2.1)">>}};
register_uni_stream(Conn, StreamId, ?UNI_PUSH, _Rest, _Fin) ->
    case Conn#h3_conn.role of
        server ->
            {error,
                {connection_error, h3_stream_creation_error,
                    <<"Server received push stream (RFC 9114 Section 6.2.2)">>}};
        client ->
            NewConn = add_ignored_uni(Conn, StreamId),
            {ok, [], NewConn, []}
    end;
register_uni_stream(Conn, StreamId, _Type, _Rest, _Fin) ->
    NewConn = add_ignored_uni(Conn, StreamId),
    {ok, [], NewConn, []}.

%%%-----------------------------------------------------------------------------
%% INTERNAL: HEADER DECODE / VALIDATE
%%%-----------------------------------------------------------------------------
-spec decode_headers(conn(), nhttp_lib:stream_id(), #h3_stream{}, binary(), boolean()) ->
    {ok, conn(), [event()], [action()]} | {error, h3_error()}.
decode_headers(
    #h3_conn{qpack_dec = Dec, local_decoder_stream = DecStreamId} = Conn,
    StreamId,
    Stream,
    FieldSection,
    IsFinal
) ->
    case nhttp_qpack:decode_field_section(Dec, StreamId, FieldSection) of
        {ok, NewDec, DecStreamData, Headers} ->
            FinAtom = bool_to_fin(IsFinal),
            case
                validate_headers(
                    Conn#h3_conn.role, Headers, false, Conn#h3_conn.local_settings
                )
            of
                ok ->
                    NewState = transition_on_recv(Stream#h3_stream.state, FinAtom),
                    ContentLength = nhttp_msg:extract_content_length(Headers),
                    NewStream = Stream#h3_stream{
                        state = NewState,
                        headers_received = true,
                        content_length = ContentLength
                    },
                    NewConn0 = Conn#h3_conn{qpack_dec = NewDec},
                    NewConn = update_stream(NewConn0, StreamId, NewStream),
                    NewConn1 = update_last_peer_stream(NewConn, StreamId),
                    DecActions =
                        case iolist_size(DecStreamData) of
                            0 -> [];
                            _ -> [{send, DecStreamId, DecStreamData}]
                        end,
                    Event = build_initial_headers_event(
                        Conn#h3_conn.role, StreamId, Headers, FinAtom, NewConn1
                    ),
                    {ok, NewConn1, [Event], DecActions};
                {error, Reason} ->
                    {error, {stream_error, StreamId, h3_message_error, Reason}}
            end;
        {blocked, NewDec} ->
            NewConn = Conn#h3_conn{qpack_dec = NewDec},
            {ok, NewConn, [], []};
        {error, Reason} ->
            {error,
                {connection_error, qpack_decompression_failed,
                    iolist_to_binary(
                        io_lib:format("QPACK decode error: ~p", [Reason])
                    )}}
    end.

-spec decode_trailers(conn(), nhttp_lib:stream_id(), #h3_stream{}, binary(), boolean()) ->
    {ok, conn(), [event()], [action()]} | {error, h3_error()}.
decode_trailers(
    #h3_conn{qpack_dec = Dec, local_decoder_stream = DecStreamId} = Conn,
    StreamId,
    Stream,
    FieldSection,
    IsFinal
) ->
    case nhttp_qpack:decode_field_section(Dec, StreamId, FieldSection) of
        {ok, NewDec, DecStreamData, Trailers} ->
            case
                validate_headers(
                    Conn#h3_conn.role, Trailers, true, Conn#h3_conn.local_settings
                )
            of
                ok ->
                    FinAtom = bool_to_fin(IsFinal),
                    NewState = transition_on_recv(Stream#h3_stream.state, FinAtom),
                    NewStream = Stream#h3_stream{
                        state = NewState,
                        trailers_received = true
                    },
                    NewConn0 = Conn#h3_conn{qpack_dec = NewDec},
                    NewConn = update_stream(NewConn0, StreamId, NewStream),
                    DecActions =
                        case iolist_size(DecStreamData) of
                            0 -> [];
                            _ -> [{send, DecStreamId, DecStreamData}]
                        end,
                    {ok, NewConn, [{trailers, StreamId, Trailers}], DecActions};
                {error, Reason} ->
                    {error, {stream_error, StreamId, h3_message_error, Reason}}
            end;
        {blocked, NewDec} ->
            NewConn = Conn#h3_conn{qpack_dec = NewDec},
            {ok, NewConn, [], []};
        {error, Reason} ->
            {error,
                {connection_error, qpack_decompression_failed,
                    iolist_to_binary(
                        io_lib:format("QPACK decode error: ~p", [Reason])
                    )}}
    end.

-spec validate_headers(role(), nhttp_lib:headers(), boolean(), h3_settings()) ->
    ok | {error, binary()}.
validate_headers(_, Headers, true, _Settings) ->
    validate_trailers(Headers);
validate_headers(server, Headers, false, Settings) ->
    validate_request_headers(Headers, Settings);
validate_headers(client, Headers, false, _Settings) ->
    validate_response_headers(Headers).

-define(H3_CONNECTION_HEADERS_SET, ?NHTTP_MSG_CONNECTION_HEADERS_SET).
-spec build_initial_headers_event(
    role(), nhttp_lib:stream_id(), nhttp_lib:headers(), fin(), conn()
) -> event().
build_initial_headers_event(server, StreamId, Headers, Fin, Conn) ->
    Request = build_request(Conn, Headers),
    {request, StreamId, Request, Fin};
build_initial_headers_event(client, StreamId, Headers, Fin, _Conn) ->
    Response = build_response(Headers),
    {response, StreamId, Response, Fin}.

-spec build_request(conn(), nhttp_lib:headers()) -> nhttp_lib:request().
build_request(#h3_conn{peer = Peer}, Headers) ->
    nhttp_msg:build_request(http3, Peer, Headers).

-spec build_response(nhttp_lib:headers()) -> nhttp_lib:response().
build_response(Headers) ->
    nhttp_msg:build_response(http3, Headers).

-spec check_extended_connect(
    binary() | undefined, binary() | undefined, binary() | undefined, h3_settings()
) -> ok | {error, binary()}.
check_extended_connect(Method, Protocol, Authority, Settings) ->
    case nhttp_msg:check_extended_connect(Method, Protocol, Authority, Settings) of
        ok ->
            ok;
        {error, missing_authority} ->
            {error, <<"Extended CONNECT requires :authority (RFC 9220 Section 3)">>};
        {error, not_enabled} ->
            {error,
                <<":protocol received without SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (RFC 9220 Section 3)">>};
        {error, bad_method} ->
            {error, <<":protocol pseudo-header requires :method=CONNECT (RFC 8441 Section 4)">>}
    end.

-spec finalise_request_headers(nhttp_msg:request_shape(), h3_settings()) ->
    ok | {error, binary()}.
finalise_request_headers(#{headers := Headers} = Shape, Settings) ->
    case has_te(Headers) of
        true ->
            {error, <<"te header forbidden in HTTP/3 (RFC 9114 Section 4.2)">>};
        false ->
            #{
                method := Method,
                scheme := Scheme,
                authority := Authority,
                host := Host,
                protocol := Protocol
            } = Shape,
            case
                requires_authority(Scheme) andalso Authority =:= undefined andalso
                    Host =:= undefined
            of
                true ->
                    {error,
                        <<"Missing :authority or Host for authority-requiring scheme (RFC 9114 Section 4.3.1.2)">>};
                false ->
                    check_extended_connect(Method, Protocol, Authority, Settings)
            end
    end.

-spec has_te(nhttp_lib:headers()) -> boolean().
has_te([]) -> false;
has_te([{<<"te">>, _} | _]) -> true;
has_te([_ | Rest]) -> has_te(Rest).

-spec shape_error_message(nhttp_msg:request_shape_error()) -> binary().
shape_error_message(missing_required_pseudo) ->
    <<"Missing required pseudo-headers (RFC 9114 Section 4.3.1)">>;
shape_error_message(bad_wire_scheme) ->
    <<":scheme must be http or https on the wire (RFC 9114 Section 4.3.1)">>;
shape_error_message(authority_host_mismatch) ->
    <<":authority and Host mismatch (RFC 9114 Section 4.3.1)">>;
shape_error_message(duplicate_pseudo) ->
    <<"Duplicate pseudo-header">>;
shape_error_message(unknown_pseudo) ->
    <<"Unknown pseudo-header">>;
shape_error_message(pseudo_after_regular) ->
    <<"Pseudo-header after regular header">>;
shape_error_message(forbidden_connection_header) ->
    <<"Forbidden connection-specific header">>;
shape_error_message(multiple_host_headers) ->
    <<"Multiple Host headers">>.

-spec validate_request_headers(nhttp_lib:headers(), h3_settings()) ->
    ok | {error, binary()}.
validate_request_headers(Headers, Settings) ->
    case nhttp_msg:validate_request_pseudo_shape(Headers) of
        {error, Reason} ->
            {error, shape_error_message(Reason)};
        {ok, Shape} ->
            finalise_request_headers(Shape, Settings)
    end.

-spec validate_response_headers(nhttp_lib:headers()) -> ok | {error, binary()}.
validate_response_headers(Headers) ->
    validate_response_headers_loop(Headers, #{phase => pseudo, has_status => false}).

-spec validate_response_headers_loop(nhttp_lib:headers(), map()) ->
    ok | {error, binary()}.
validate_response_headers_loop([], #{has_status := true}) ->
    ok;
validate_response_headers_loop([], #{has_status := false}) ->
    {error, <<"Missing :status pseudo-header">>};
validate_response_headers_loop(
    [{<<":status">>, _} | Rest], #{phase := pseudo, has_status := false} = State
) ->
    validate_response_headers_loop(Rest, State#{has_status => true});
validate_response_headers_loop([{<<":status">>, _} | _], #{has_status := true}) ->
    {error, <<"Duplicate :status">>};
validate_response_headers_loop([{<<$:, _/binary>>, _} | _], _) ->
    {error, <<"Invalid pseudo-header in response">>};
validate_response_headers_loop([{Name, _Value} | Rest], State) ->
    case maps:is_key(Name, ?H3_CONNECTION_HEADERS_SET) of
        true ->
            {error, <<"Forbidden connection-specific header">>};
        false ->
            case Name of
                <<"te">> ->
                    {error, <<"te header forbidden in HTTP/3 (RFC 9114 Section 4.2)">>};
                _ ->
                    validate_response_headers_loop(Rest, State#{phase => regular})
            end
    end.

-spec validate_trailers(nhttp_lib:headers()) -> ok | {error, binary()}.
validate_trailers(Headers) ->
    case nhttp_msg:validate_trailers(Headers) of
        ok ->
            ok;
        {error, pseudo_in_trailers} ->
            {error, <<"Pseudo-header in trailers (RFC 9114 Section 4.1)">>}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL: GOAWAY / PUSH
%%%-----------------------------------------------------------------------------
-spec process_goaway(conn(), non_neg_integer()) ->
    {ok, conn(), [event()], [action()]} | {error, h3_error()}.
process_goaway(#h3_conn{goaway_received = true, goaway_id = PrevId}, Id) when
    Id > PrevId
->
    {error,
        {connection_error, h3_id_error, <<"GOAWAY ID must not increase (RFC 9114 Section 5.2)">>}};
process_goaway(Conn, Id) ->
    NewConn = Conn#h3_conn{
        goaway_received = true,
        goaway_id = Id,
        state = closing
    },
    {ok, NewConn, [{goaway, Id, h3_no_error, <<>>}], []}.

-spec process_max_push_id(conn(), non_neg_integer()) ->
    {ok, conn(), [event()], [action()]} | {error, h3_error()}.
process_max_push_id(#h3_conn{role = client}, _PushId) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"Client received MAX_PUSH_ID (RFC 9114 Section 7.2.7)">>}};
process_max_push_id(#h3_conn{max_push_id = Current}, PushId) when PushId < Current ->
    {error,
        {connection_error, h3_id_error,
            <<"MAX_PUSH_ID must not decrease (RFC 9114 Section 7.2.7)">>}};
process_max_push_id(Conn, PushId) ->
    {ok, Conn#h3_conn{max_push_id = PushId}, [], []}.

-spec process_push_promise(conn(), nhttp_lib:stream_id(), non_neg_integer(), binary()) ->
    {ok, conn(), [event()], [action()]} | {error, h3_error()}.
process_push_promise(#h3_conn{role = server}, _StreamId, _PushId, _FieldSection) ->
    {error,
        {connection_error, h3_frame_unexpected,
            <<"Server received PUSH_PROMISE (RFC 9114 Section 7.2.5)">>}};
process_push_promise(
    #h3_conn{qpack_dec = Dec, local_decoder_stream = DecStreamId} = Conn,
    StreamId,
    PushId,
    FieldSection
) ->
    case nhttp_qpack:decode_field_section(Dec, StreamId, FieldSection) of
        {ok, NewDec, DecStreamData, Headers} ->
            NewConn = Conn#h3_conn{qpack_dec = NewDec},
            DecActions =
                case iolist_size(DecStreamData) of
                    0 -> [];
                    _ -> [{send, DecStreamId, DecStreamData}]
                end,
            {ok, NewConn, [{push_promise, StreamId, PushId, Headers}], DecActions};
        {blocked, NewDec} ->
            {ok, Conn#h3_conn{qpack_dec = NewDec}, [], []};
        {error, Reason} ->
            {error,
                {connection_error, qpack_decompression_failed,
                    iolist_to_binary(
                        io_lib:format("QPACK decode error in PUSH_PROMISE: ~p", [Reason])
                    )}}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL: SETTINGS
%%%-----------------------------------------------------------------------------
-spec apply_peer_settings(conn(), h3_settings()) -> conn().
apply_peer_settings(#h3_conn{qpack_enc = Enc} = Conn, PeerSettings) ->
    PeerCap = maps:get(qpack_max_table_capacity, PeerSettings, 0),
    PeerBlocked = maps:get(qpack_blocked_streams, PeerSettings, 0),
    Enc1 = nhttp_qpack:reconcile_peer_limits(PeerCap, PeerBlocked, Enc),
    Conn#h3_conn{
        peer_settings = PeerSettings,
        settings_received = true,
        qpack_enc = Enc1
    }.

-spec default_settings() -> h3_settings().
default_settings() ->
    #{
        qpack_max_table_capacity => 0,
        qpack_blocked_streams => 0
    }.

%%%-----------------------------------------------------------------------------
%% INTERNAL: STREAM HELPERS
%%%-----------------------------------------------------------------------------
-spec add_ignored_uni(conn(), nhttp_lib:stream_id()) -> conn().
add_ignored_uni(#h3_conn{ignored_uni_streams = Ignored} = Conn, StreamId) ->
    Conn#h3_conn{ignored_uni_streams = Ignored#{StreamId => true}}.

-spec bool_to_fin(boolean()) -> fin().
bool_to_fin(true) -> fin;
bool_to_fin(false) -> nofin.

-spec build_response_actions(nhttp_lib:stream_id(), iodata(), nhttp_lib:stream_id(), iodata()) ->
    [action()].
build_response_actions(EncStreamId, EncStreamData, StreamId, Data) ->
    EncAction =
        case iolist_size(EncStreamData) of
            0 -> [];
            _ -> [{send, EncStreamId, EncStreamData}]
        end,
    EncAction ++ [{send_fin, StreamId, Data}].

-spec build_send_actions(nhttp_lib:stream_id(), iodata(), nhttp_lib:stream_id(), iodata(), fin()) ->
    [action()].
build_send_actions(EncStreamId, EncStreamData, StreamId, HeadersFrame, Fin) ->
    EncAction =
        case iolist_size(EncStreamData) of
            0 -> [];
            _ -> [{send, EncStreamId, EncStreamData}]
        end,
    HeaderAction =
        case Fin of
            fin -> [{send_fin, StreamId, HeadersFrame}];
            nofin -> [{send, StreamId, HeadersFrame}]
        end,
    EncAction ++ HeaderAction.

-spec close_stream(conn(), nhttp_lib:stream_id()) -> conn().
close_stream(#h3_conn{streams = Streams, stream_bufs = Bufs} = Conn, StreamId) ->
    Conn#h3_conn{
        streams = maps:remove(StreamId, Streams),
        stream_bufs = maps:remove(StreamId, Bufs)
    }.

-spec decoder_stream_actions(
    nhttp_lib:stream_id() | undefined,
    [{nhttp_lib:stream_id(), iodata(), [nhttp_qpack:field_line()]}]
) -> [action()].
decoder_stream_actions(undefined, _) ->
    [];
decoder_stream_actions(_DecStreamId, []) ->
    [];
decoder_stream_actions(DecStreamId, Unblocked) ->
    DecData = [DecStreamData || {_, DecStreamData, _} <- Unblocked],
    case iolist_size(DecData) of
        0 -> [];
        _ -> [{send, DecStreamId, DecData}]
    end.

-spec error_code_atom(non_neg_integer()) -> error_code().
error_code_atom(16#100) -> h3_no_error;
error_code_atom(16#101) -> h3_general_protocol_error;
error_code_atom(16#102) -> h3_internal_error;
error_code_atom(16#103) -> h3_stream_creation_error;
error_code_atom(16#104) -> h3_closed_critical_stream;
error_code_atom(16#105) -> h3_frame_unexpected;
error_code_atom(16#106) -> h3_frame_error;
error_code_atom(16#107) -> h3_excessive_load;
error_code_atom(16#108) -> h3_id_error;
error_code_atom(16#109) -> h3_settings_error;
error_code_atom(16#10A) -> h3_missing_settings;
error_code_atom(16#10B) -> h3_request_rejected;
error_code_atom(16#10C) -> h3_request_cancelled;
error_code_atom(16#10D) -> h3_request_incomplete;
error_code_atom(16#10E) -> h3_message_error;
error_code_atom(16#10F) -> h3_connect_error;
error_code_atom(16#110) -> h3_version_fallback;
error_code_atom(16#200) -> qpack_decompression_failed;
error_code_atom(16#201) -> qpack_encoder_stream_error;
error_code_atom(16#202) -> qpack_decoder_stream_error;
error_code_atom(N) -> N.

-spec get_or_create_stream(conn(), nhttp_lib:stream_id()) -> #h3_stream{}.
get_or_create_stream(#h3_conn{streams = Streams}, StreamId) ->
    case maps:get(StreamId, Streams, undefined) of
        undefined -> #h3_stream{id = StreamId};
        Stream -> Stream
    end.

-spec is_uni_stream(nhttp_lib:stream_id()) -> boolean().
is_uni_stream(StreamId) ->
    StreamId band 2 =:= 2.

-spec prepend(binary(), binary()) -> binary().
prepend(<<>>, Data) -> Data;
prepend(Buffered, Data) -> <<Buffered/binary, Data/binary>>.

-spec prepend_stream_buf(conn(), nhttp_lib:stream_id(), binary()) -> binary().
prepend_stream_buf(#h3_conn{stream_bufs = Bufs}, StreamId, Data) ->
    prepend(maps:get(StreamId, Bufs, <<>>), Data).

-spec process_unblocked([{nhttp_lib:stream_id(), iodata(), [nhttp_qpack:field_line()]}]) ->
    {[event()], [action()]}.
process_unblocked([]) ->
    {[], []};
process_unblocked(Unblocked) ->
    Events = [{headers, StreamId, Headers, nofin} || {StreamId, _, Headers} <- Unblocked],
    {Events, []}.

-spec requires_authority(binary() | undefined) -> boolean().
requires_authority(<<"http">>) -> true;
requires_authority(<<"https">>) -> true;
requires_authority(_) -> false.

-spec set_stream_buf(conn(), nhttp_lib:stream_id(), binary()) -> conn().
set_stream_buf(#h3_conn{stream_bufs = Bufs} = Conn, StreamId, <<>>) ->
    Conn#h3_conn{stream_bufs = maps:remove(StreamId, Bufs)};
set_stream_buf(#h3_conn{stream_bufs = Bufs} = Conn, StreamId, Data) ->
    Conn#h3_conn{stream_bufs = Bufs#{StreamId => Data}}.

-spec transition_on_recv(stream_state(), fin()) -> stream_state().
transition_on_recv(open, fin) -> half_closed_remote;
transition_on_recv(half_closed_local, fin) -> closed;
transition_on_recv(State, _) -> State.

-spec transition_on_send(stream_state(), fin()) -> stream_state().
transition_on_send(open, fin) -> half_closed_local;
transition_on_send(half_closed_remote, fin) -> closed;
transition_on_send(State, _) -> State.

-spec update_last_peer_stream(conn(), nhttp_lib:stream_id()) -> conn().
update_last_peer_stream(#h3_conn{last_peer_stream_id = Last} = Conn, StreamId) when
    StreamId > Last
->
    Conn#h3_conn{last_peer_stream_id = StreamId};
update_last_peer_stream(Conn, _StreamId) ->
    Conn.

-spec update_stream(conn(), nhttp_lib:stream_id(), #h3_stream{}) -> conn().
update_stream(#h3_conn{streams = Streams, stream_bufs = Bufs} = Conn, StreamId, #h3_stream{
    state = closed
}) ->
    Conn#h3_conn{
        streams = maps:remove(StreamId, Streams),
        stream_bufs = maps:remove(StreamId, Bufs)
    };
update_stream(#h3_conn{streams = Streams} = Conn, StreamId, Stream) ->
    Conn#h3_conn{streams = Streams#{StreamId => Stream}}.

-spec validate_send_state(conn(), nhttp_lib:stream_id()) -> ok | {error, h3_error()}.
validate_send_state(#h3_conn{goaway_sent = true}, StreamId) ->
    {error, {stream_error, StreamId, h3_request_rejected, <<"Connection closing">>}};
validate_send_state(#h3_conn{streams = Streams}, StreamId) ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            ok;
        #h3_stream{state = open} ->
            ok;
        #h3_stream{state = half_closed_remote} ->
            ok;
        _ ->
            {error,
                {stream_error, StreamId, h3_frame_unexpected, <<"Stream not in sendable state">>}}
    end.
