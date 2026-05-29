-module(nhttp_h2).

-moduledoc """
HTTP/2 protocol layer.

This module implements RFC 9113 HTTP/2 connection and stream state machines.
It sits between the framing layer (nhttp_h2_frame) and the application layer,
providing:

- Connection lifecycle management (preface, settings, shutdown)
- Stream state machine (RFC 9113 Section 5.1)
- Flow control (connection and stream level)
- Header block assembly (CONTINUATION handling)
- Error handling (connection vs stream errors)

## Usage

```erlang
Conn0 = nhttp_h2:new(client),
Preface = nhttp_h2:preface(Conn0),
ok = ssl:send(Socket, Preface),

{ok, Events, Conn1} = nhttp_h2:recv(Conn0, Data),
lists:foreach(fun handle_event/1, Events),

{ok, Conn2, Frames} = nhttp_h2:send_headers(Conn1, StreamId, Headers, fin),
ok = ssl:send(Socket, Frames).
```

## Sending bodies and trailers

The HTTP/2 send surface is frame-oriented. The canonical
`t:nhttp_lib:request/0` and `t:nhttp_lib:response/0` maps can carry a `body`
and `trailers` field as a convenience for "everything is in memory", but
this layer does not consume those maps directly: the caller breaks the
exchange into discrete frame sends. The pattern is:

1. `send_headers(Conn, StreamId, Headers, nofin)` to emit pseudo-headers
   plus regular headers (HEADERS + optional CONTINUATION).
2. Zero or more `send_data(Conn, StreamId, Chunk, nofin)` calls.
3. Either `send_data(Conn, StreamId, FinalChunk, fin)` to close on body,
   or `send_headers(Conn, StreamId, Trailers, fin)` to close on trailers.

For a one-shot send when the body is already a single `iodata()`, call
`send_headers/4` with `nofin` followed by `send_data/4` with `fin`.
Flow-control and END_STREAM ride on the DATA frame.
""".

-include("nhttp_msg.hrl").

%%%-----------------------------------------------------------------------------
%% INLINE DIRECTIVES (PERFORMANCE OPTIMIZATION)
%%%-----------------------------------------------------------------------------
-compile({inline, [is_active_state/1]}).
-compile({inline, [transition_on_recv_end_stream/2]}).
-compile({inline, [transition_on_send_end_stream/2]}).

%%%-----------------------------------------------------------------------------
%% INITIALIZATION
%%%-----------------------------------------------------------------------------
-export([
    new/1,
    new/2,
    preface/1,
    set_peer/2
]).

%%%-----------------------------------------------------------------------------
%% RECEIVING
%%%-----------------------------------------------------------------------------
-export([
    recv/2
]).

%%%-----------------------------------------------------------------------------
%% SENDING
%%%-----------------------------------------------------------------------------
-export([
    send_data/4,
    send_goaway/3,
    send_headers/4,
    send_ping/2,
    send_rst_stream/3,
    send_window_update/3
]).

%%%-----------------------------------------------------------------------------
%% STREAM MANAGEMENT
%%%-----------------------------------------------------------------------------
-export([
    open_stream/1
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    conn/0,
    error_code/0,
    event/0,
    fin/0,
    priority/0,
    recv_result/0,
    role/0,
    send_error/0,
    send_result/0,
    settings/0,
    stream_state/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type fin() :: nhttp_lib:fin().

-type priority() :: #{
    exclusive := boolean(),
    stream_dependency := nhttp_lib:stream_id(),
    weight := 1..256
}.

-type error_code() :: nhttp_lib:error_code().

-type settings() :: #{
    header_table_size => non_neg_integer(),
    enable_push => boolean(),
    max_concurrent_streams => pos_integer() | infinity,
    initial_window_size => 1..16#7fffffff,
    max_frame_size => 16#4000..16#ffffff,
    max_header_list_size => pos_integer() | infinity,
    enable_connect_protocol => boolean()
}.

-type stream_state() ::
    idle
    | reserved_local
    | reserved_remote
    | open
    | half_closed_local
    | half_closed_remote
    | closed.

-type role() :: nhttp_lib:role().

-type event() ::
    nhttp_lib:event_common()
    | {stream_closed, nhttp_lib:stream_id(), error_code()}
    | {stream_refused, nhttp_lib:stream_id()}
    | {window_update, nhttp_lib:stream_id(), pos_integer()}
    | {settings, settings()}
    | settings_ack
    | {ping, binary()}
    | {ping_ack, binary()}.

-type recv_result() ::
    {ok, [event()], conn()}
    | {ok, [event()], conn(), iodata()}
    | {error, nhttp_h2_frame:decode_error()}.

-type send_error() ::
    connection_closing
    | {unknown_stream, nhttp_lib:stream_id()}
    | {stream_closed, nhttp_lib:stream_id()}
    | {stream_error, nhttp_lib:stream_id(), error_code(), binary()}.

-type send_result() ::
    {ok, conn()}
    | {ok, conn(), iodata()}
    | {partial, conn(), iodata(), binary(), fin(), Window :: integer()}
    | {error, send_error()}.

%%%-----------------------------------------------------------------------------
%% INTERNAL CONSTANTS
%%%-----------------------------------------------------------------------------
-define(H2_DEFAULT_INITIAL_WINDOW_SIZE, 65535).
-define(H2_MAX_WINDOW_SIZE, 16#7fffffff).

%%%-----------------------------------------------------------------------------
%% LOCAL MACROS (RFC 9113 SECTION 6.5.2)
%%%-----------------------------------------------------------------------------
-define(H2_DEFAULT_HEADER_TABLE_SIZE, 4096).
-define(H2_DEFAULT_MAX_FRAME_SIZE, 16384).
-define(H2_DEFAULT_MAX_HEADER_LIST_SIZE, 16384).

%%%-----------------------------------------------------------------------------
%% INTERNAL RECORDS
%%%-----------------------------------------------------------------------------
-record(h2_stream, {
    id :: nhttp_lib:stream_id(),
    state = idle :: stream_state(),
    send_window :: integer(),
    recv_window :: integer(),
    header_buffer = <<>> :: binary(),
    header_end_stream = false :: boolean(),
    content_length = undefined :: non_neg_integer() | undefined,
    recv_body_length = 0 :: non_neg_integer(),
    headers_received = false :: boolean()
}).

-record(h2_conn, {
    role :: role(),
    state = preface :: preface | open | closing | closed,
    local_settings :: settings(),
    peer_settings :: settings(),
    settings_acked = false :: boolean(),
    streams = #{} :: #{nhttp_lib:stream_id() => #h2_stream{}},
    next_stream_id :: nhttp_lib:stream_id(),
    last_peer_stream_id = 0 :: nhttp_lib:stream_id(),
    active_stream_count = 0 :: non_neg_integer(),
    send_window = ?H2_DEFAULT_INITIAL_WINDOW_SIZE :: integer(),
    recv_window = ?H2_DEFAULT_INITIAL_WINDOW_SIZE :: integer(),
    hpack_enc :: nhttp_hpack:state(),
    hpack_dec :: nhttp_hpack:state(),
    continuation_stream = undefined :: undefined | nhttp_lib:stream_id(),
    buffer = <<>> :: binary(),
    goaway_sent = false :: boolean(),
    goaway_received = false :: boolean(),
    last_good_stream_id = 0 :: nhttp_lib:stream_id(),
    peer = undefined :: undefined | nhttp_lib:peer()
}).

-opaque conn() :: #h2_conn{}.

%%%-----------------------------------------------------------------------------
%% INITIALIZATION
%%%-----------------------------------------------------------------------------
-doc "Create a new HTTP/2 connection with default settings.".
-spec new(role()) -> conn().
new(Role) ->
    new(Role, default_settings()).

-doc "Create a new HTTP/2 connection with custom settings.".
-spec new(role(), settings()) -> conn().
new(Role, LocalSettings) ->
    MergedSettings = maps:merge(default_settings(), LocalSettings),
    HeaderTableSize = maps:get(header_table_size, MergedSettings, ?H2_DEFAULT_HEADER_TABLE_SIZE),
    {ok, HpackEnc} = nhttp_hpack:new(HeaderTableSize),
    {ok, HpackDec} = nhttp_hpack:new(HeaderTableSize),
    #h2_conn{
        role = Role,
        state = preface,
        local_settings = MergedSettings,
        peer_settings = default_settings(),
        next_stream_id = initial_stream_id(Role),
        hpack_enc = HpackEnc,
        hpack_dec = HpackDec
    }.

-doc "Generate the connection preface for this role. Client sends: magic + SETTINGS. Server sends: SETTINGS.".
-spec preface(conn()) -> iodata().
preface(#h2_conn{role = client, local_settings = Settings}) ->
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, SettingsFrame} = nhttp_h2_frame:settings(Settings),
    [Preface, SettingsFrame];
preface(#h2_conn{role = server, local_settings = Settings}) ->
    {ok, SettingsFrame} = nhttp_h2_frame:settings(Settings),
    SettingsFrame.

-doc """
Record the peer address on the connection. Called once after the socket is
accepted (or connected) so server-built `t:nhttp_lib:request/0` maps and
client-built `t:nhttp_lib:response/0` events carry the correct remote peer.
""".
-spec set_peer(conn(), nhttp_lib:peer()) -> conn().
set_peer(#h2_conn{} = Conn, {{_, _, _, _}, Port} = Peer) when
    is_integer(Port), Port >= 0, Port =< 65535
->
    Conn#h2_conn{peer = Peer};
set_peer(#h2_conn{} = Conn, {{_, _, _, _, _, _, _, _}, Port} = Peer) when
    is_integer(Port), Port >= 0, Port =< 65535
->
    Conn#h2_conn{peer = Peer}.

%%%-----------------------------------------------------------------------------
%% RECEIVING
%%%-----------------------------------------------------------------------------
-doc "Process incoming data and return events. May return frames to send (e.g., SETTINGS_ACK, PING_ACK, WINDOW_UPDATE).".
-spec recv(conn(), binary()) -> recv_result().
recv(#h2_conn{buffer = <<>>} = Conn, Data) ->
    recv_loop(Conn, Data, [], []);
recv(#h2_conn{buffer = Buffer} = Conn, Data) ->
    recv_loop(Conn#h2_conn{buffer = <<>>}, <<Buffer/binary, Data/binary>>, [], []).

%%%-----------------------------------------------------------------------------
%% SENDING
%%%-----------------------------------------------------------------------------
-doc "Send DATA frame(s).".
-spec send_data(conn(), nhttp_lib:stream_id(), iodata(), fin()) -> send_result().
send_data(#h2_conn{} = Conn, StreamId, Data, EndStream) ->
    case validate_send_data(Conn, StreamId) of
        ok ->
            do_send_data(Conn, StreamId, Data, EndStream);
        {error, _} = Error ->
            Error
    end.

-doc "Send GOAWAY to initiate graceful shutdown.".
-spec send_goaway(conn(), error_code(), binary()) -> send_result().
send_goaway(#h2_conn{last_peer_stream_id = LastStreamId} = Conn, ErrorCode, DebugData) ->
    {ok, Frame} = nhttp_h2_frame:goaway(LastStreamId, ErrorCode, DebugData),
    NewConn = Conn#h2_conn{
        goaway_sent = true,
        state = closing,
        last_good_stream_id = LastStreamId
    },
    {ok, NewConn, Frame}.

-doc "Send HEADERS frame for a new request/response or trailers.".
-spec send_headers(conn(), nhttp_lib:stream_id(), nhttp_lib:headers(), fin()) -> send_result().
send_headers(#h2_conn{} = Conn, StreamId, Headers, EndStream) ->
    case validate_send_headers(Conn, StreamId) of
        ok ->
            do_send_headers(Conn, StreamId, Headers, EndStream);
        {error, _} = Error ->
            Error
    end.

-doc """
Send PING frame with caller-supplied 8-byte opaque data. The caller is
responsible for generating the opaque value (e.g. via
`crypto:strong_rand_bytes(8)`) and matching it against the PING_ACK event.
""".
-spec send_ping(conn(), <<_:64>>) -> send_result().
send_ping(#h2_conn{} = Conn, <<_:8/binary>> = OpaqueData) ->
    {ok, Frame} = nhttp_h2_frame:ping(OpaqueData),
    {ok, Conn, Frame}.

-doc "Send RST_STREAM to cancel a stream.".
-spec send_rst_stream(conn(), nhttp_lib:stream_id(), error_code()) -> send_result().
send_rst_stream(#h2_conn{} = Conn, StreamId, ErrorCode) ->
    {ok, Frame} = nhttp_h2_frame:rst_stream(StreamId, ErrorCode),
    NewConn = close_stream(Conn, StreamId),
    {ok, NewConn, Frame}.

-doc "Send WINDOW_UPDATE for connection or stream.".
-spec send_window_update(conn(), nhttp_lib:stream_id() | connection, pos_integer()) ->
    send_result().
send_window_update(#h2_conn{} = Conn, connection, Increment) when
    Increment > 0, Increment =< ?H2_MAX_WINDOW_SIZE
->
    {ok, Frame} = nhttp_h2_frame:window_update(Increment),
    NewConn = Conn#h2_conn{recv_window = Conn#h2_conn.recv_window + Increment},
    {ok, NewConn, Frame};
send_window_update(#h2_conn{streams = Streams} = Conn, StreamId, Increment) when
    Increment > 0, Increment =< ?H2_MAX_WINDOW_SIZE
->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            {error, {stream_error, StreamId, protocol_error, <<"Unknown stream">>}};
        #h2_stream{recv_window = RecvWindow} = Stream ->
            {ok, Frame} = nhttp_h2_frame:window_update(StreamId, Increment),
            NewStream = Stream#h2_stream{recv_window = RecvWindow + Increment},
            NewConn = Conn#h2_conn{streams = Streams#{StreamId => NewStream}},
            {ok, NewConn, Frame}
    end.

%%%-----------------------------------------------------------------------------
%% STREAM MANAGEMENT
%%%-----------------------------------------------------------------------------
-spec check_peer_max_streams(non_neg_integer(), settings()) ->
    ok | {error, max_streams_reached}.
check_peer_max_streams(ActiveCount, PeerSettings) ->
    case maps:get(max_concurrent_streams, PeerSettings, infinity) of
        infinity -> ok;
        Max when ActiveCount >= Max -> {error, max_streams_reached};
        _ -> ok
    end.

-doc "Open a new stream and return its ID.".
-spec open_stream(conn()) ->
    {ok, nhttp_lib:stream_id(), conn()} | {error, connection_closing | max_streams_reached}.
open_stream(#h2_conn{goaway_sent = true}) ->
    {error, connection_closing};
open_stream(#h2_conn{goaway_received = true}) ->
    {error, connection_closing};
open_stream(
    #h2_conn{
        next_stream_id = StreamId,
        streams = Streams,
        peer_settings = PeerSettings,
        active_stream_count = ActiveCount
    } = Conn
) ->
    case check_peer_max_streams(ActiveCount, PeerSettings) of
        ok ->
            InitialWindow = maps:get(
                initial_window_size, PeerSettings, ?H2_DEFAULT_INITIAL_WINDOW_SIZE
            ),
            Stream = #h2_stream{
                id = StreamId,
                state = idle,
                send_window = InitialWindow,
                recv_window = ?H2_DEFAULT_INITIAL_WINDOW_SIZE
            },
            NewConn = Conn#h2_conn{
                next_stream_id = StreamId + 2,
                streams = Streams#{StreamId => Stream}
            },
            {ok, StreamId, NewConn};
        {error, _} = Error ->
            Error
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec check_header_block_size(conn(), non_neg_integer()) -> ok | {error, exceeded}.
check_header_block_size(#h2_conn{local_settings = Settings}, Size) ->
    case maps:get(max_header_list_size, Settings, infinity) of
        infinity -> ok;
        Max when Size =< Max -> ok;
        _ -> {error, exceeded}
    end.

-spec check_stream_concurrency(conn()) -> ok | {error, at_limit}.
check_stream_concurrency(#h2_conn{
    active_stream_count = Count,
    local_settings = Settings
}) ->
    MaxStreams = maps:get(max_concurrent_streams, Settings, 100),
    case MaxStreams of
        infinity -> ok;
        Max when Count >= Max -> {error, at_limit};
        _ -> ok
    end.

-spec close_stream(conn(), nhttp_lib:stream_id()) -> conn().
close_stream(#h2_conn{streams = Streams, active_stream_count = Count} = Conn, StreamId) ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            Conn;
        #h2_stream{state = closed} ->
            Conn#h2_conn{streams = maps:remove(StreamId, Streams)};
        #h2_stream{state = OldState} ->
            NewCount =
                case is_active_state(OldState) of
                    true -> max(0, Count - 1);
                    false -> Count
                end,
            Conn#h2_conn{
                streams = maps:remove(StreamId, Streams),
                active_stream_count = NewCount
            }
    end.

-spec decode_and_emit_headers(conn(), nhttp_lib:stream_id(), fin(), binary()) ->
    {ok, conn(), [event()], iodata()} | {error, nhttp_h2_frame:decode_error()}.
decode_and_emit_headers(
    #h2_conn{hpack_dec = HpackDec, streams = Streams} = Conn, StreamId, EndStream, HeaderBlock
) ->
    DecodeOpts = hpack_decode_opts(Conn),
    case maps:is_key(StreamId, Streams) of
        true ->
            decode_headers_internal(Conn, StreamId, EndStream, HeaderBlock);
        false ->
            case validate_peer_stream_id(Conn, StreamId) of
                ok ->
                    case check_stream_concurrency(Conn) of
                        ok ->
                            decode_headers_internal(Conn, StreamId, EndStream, HeaderBlock);
                        {error, at_limit} ->
                            _ = nhttp_hpack:decode(HeaderBlock, HpackDec, DecodeOpts),
                            {ok, RstFrame} = nhttp_h2_frame:rst_stream(StreamId, refused_stream),
                            {ok, Conn, [{stream_refused, StreamId}], RstFrame}
                    end;
                {error, _} = Error ->
                    _ = nhttp_hpack:decode(HeaderBlock, HpackDec, DecodeOpts),
                    Error
            end
    end.

-spec decode_headers_internal(conn(), nhttp_lib:stream_id(), fin(), binary()) ->
    {ok, conn(), [event()], iodata()} | {error, nhttp_h2_frame:decode_error()}.
decode_headers_internal(
    #h2_conn{role = Role, hpack_dec = HpackDec, streams = Streams} = Conn,
    StreamId,
    EndStream,
    HeaderBlock
) ->
    DecodeOpts = hpack_decode_opts(Conn),
    case nhttp_hpack:decode(HeaderBlock, HpackDec, DecodeOpts) of
        {ok, Headers, NewHpackDec} ->
            Stream = get_or_create_stream(Conn, StreamId),
            StreamState = Stream#h2_stream.state,
            case StreamState of
                half_closed_remote ->
                    {error,
                        {stream_error, StreamId, stream_closed,
                            <<"HEADERS on half-closed (remote) stream (RFC 9113 Section 5.1)">>}};
                closed ->
                    {error,
                        {connection_error, stream_closed,
                            <<"HEADERS on closed stream (RFC 9113 Section 5.1)">>}};
                _ ->
                    IsTrailers = Stream#h2_stream.headers_received,
                    case IsTrailers andalso EndStream =:= nofin of
                        true ->
                            {error,
                                {stream_error, StreamId, protocol_error,
                                    <<"Second HEADERS without END_STREAM (RFC 9113 Section 8.1)">>}};
                        false ->
                            ValidationResult = validate_decoded_headers(
                                Role, Headers, IsTrailers, Conn#h2_conn.local_settings
                            ),
                            case ValidationResult of
                                ok ->
                                    OldState = Stream#h2_stream.state,
                                    NewState = transition_on_recv_headers(OldState, EndStream),
                                    ContentLength =
                                        case IsTrailers of
                                            true -> Stream#h2_stream.content_length;
                                            false -> nhttp_msg:extract_content_length(Headers)
                                        end,
                                    NewStream = Stream#h2_stream{
                                        state = NewState,
                                        header_buffer = <<>>,
                                        header_end_stream = false,
                                        content_length = ContentLength,
                                        headers_received = true
                                    },
                                    ActiveCount = Conn#h2_conn.active_stream_count,
                                    NewActiveCount = update_active_count_on_transition(
                                        OldState, NewState, ActiveCount
                                    ),
                                    NewConn = Conn#h2_conn{
                                        hpack_dec = NewHpackDec,
                                        streams = store_or_remove_stream(
                                            Streams, StreamId, NewStream
                                        ),
                                        last_peer_stream_id = max(
                                            Conn#h2_conn.last_peer_stream_id, StreamId
                                        ),
                                        active_stream_count = NewActiveCount
                                    },
                                    Events = build_headers_event(
                                        Role, IsTrailers, StreamId, Headers, EndStream, NewConn
                                    ),
                                    {ok, NewConn, Events, []};
                                {error, protocol_error} ->
                                    {error,
                                        {stream_error, StreamId, protocol_error,
                                            <<"Invalid header field (RFC 9113 Section 8.1)">>}}
                            end
                    end
            end;
        {error, uppercase_header_name} ->
            {error,
                {stream_error, StreamId, protocol_error,
                    <<"Uppercase header name (RFC 9113 Section 8.2)">>}};
        {error, header_list_too_large} ->
            {error,
                {connection_error, enhance_your_calm, <<
                    "Decoded header list exceeds SETTINGS_MAX_HEADER_LIST_SIZE "
                    "(RFC 9113 Section 10.5.1)"
                >>}};
        {error, HpackError} ->
            {error,
                {connection_error, compression_error,
                    iolist_to_binary(io_lib:format("HPACK decode error: ~p", [HpackError]))}}
    end.

-spec default_settings() -> settings().
default_settings() ->
    #{
        header_table_size => ?H2_DEFAULT_HEADER_TABLE_SIZE,
        initial_window_size => ?H2_DEFAULT_INITIAL_WINDOW_SIZE,
        max_frame_size => ?H2_DEFAULT_MAX_FRAME_SIZE,
        max_concurrent_streams => 100,
        max_header_list_size => ?H2_DEFAULT_MAX_HEADER_LIST_SIZE
    }.

-spec do_send_data(conn(), nhttp_lib:stream_id(), iodata(), fin()) -> send_result().
do_send_data(
    #h2_conn{streams = Streams, send_window = ConnWindow, peer_settings = PeerSettings} = Conn,
    StreamId,
    Data,
    EndStream
) ->
    #h2_stream{send_window = StreamWindow} = Stream = maps:get(StreamId, Streams),
    DataSize = iolist_size(Data),
    EffectiveWindow = min(ConnWindow, StreamWindow),
    MaxFrameSize = maps:get(max_frame_size, PeerSettings, ?H2_DEFAULT_MAX_FRAME_SIZE),
    MaxSend = min(EffectiveWindow, MaxFrameSize),
    case DataSize =< MaxSend of
        true when EffectiveWindow > 0 ->
            {ok, Frame} = nhttp_h2_frame:data(StreamId, EndStream, Data),
            OldState = Stream#h2_stream.state,
            NewState = transition_on_send_end_stream(OldState, EndStream),
            NewStream = Stream#h2_stream{
                state = NewState,
                send_window = StreamWindow - DataSize
            },
            ActiveCount = Conn#h2_conn.active_stream_count,
            NewActiveCount = update_active_count_on_transition(OldState, NewState, ActiveCount),
            NewConn = Conn#h2_conn{
                streams = store_or_remove_stream(Streams, StreamId, NewStream),
                send_window = ConnWindow - DataSize,
                active_stream_count = NewActiveCount
            },
            {ok, NewConn, Frame};
        true when EffectiveWindow =< 0 ->
            {partial, Conn, [], <<>>, EndStream, EffectiveWindow};
        false when MaxSend > 0 ->
            DataBin = iolist_to_binary(Data),
            <<ToSend:MaxSend/binary, Remaining/binary>> = DataBin,
            {ok, Frame} = nhttp_h2_frame:data(StreamId, nofin, ToSend),
            NewStream = Stream#h2_stream{
                send_window = StreamWindow - MaxSend
            },
            NewConn = Conn#h2_conn{
                streams = store_or_remove_stream(Streams, StreamId, NewStream),
                send_window = ConnWindow - MaxSend
            },
            {partial, NewConn, Frame, Remaining, EndStream, EffectiveWindow - MaxSend};
        false ->
            {partial, Conn, [], iolist_to_binary(Data), EndStream, EffectiveWindow}
    end.

-spec do_send_headers(conn(), nhttp_lib:stream_id(), nhttp_lib:headers(), fin()) -> send_result().
do_send_headers(
    #h2_conn{hpack_enc = HpackEnc, streams = Streams, peer_settings = PeerSettings} = Conn,
    StreamId,
    Headers,
    EndStream
) ->
    {ok, HeaderBlock, NewHpackEnc} = nhttp_hpack:encode(Headers, HpackEnc),
    MaxFrameSize = maps:get(max_frame_size, PeerSettings, ?H2_DEFAULT_MAX_FRAME_SIZE),
    {ok, Frame} = nhttp_h2_frame:headers_with_continuation(
        StreamId, EndStream, HeaderBlock, MaxFrameSize
    ),
    Stream = get_or_create_stream(Conn, StreamId),
    OldState = Stream#h2_stream.state,
    NewState = transition_on_send_headers(OldState, EndStream),
    NewStream = Stream#h2_stream{state = NewState},
    ActiveCount = Conn#h2_conn.active_stream_count,
    NewActiveCount = update_active_count_on_transition(OldState, NewState, ActiveCount),
    NewConn = Conn#h2_conn{
        hpack_enc = NewHpackEnc,
        streams = store_or_remove_stream(Streams, StreamId, NewStream),
        active_stream_count = NewActiveCount
    },
    {ok, NewConn, Frame}.

-spec get_or_create_stream(conn(), nhttp_lib:stream_id()) -> #h2_stream{}.
get_or_create_stream(#h2_conn{streams = Streams, peer_settings = PeerSettings}, StreamId) ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            InitialWindow = maps:get(
                initial_window_size, PeerSettings, ?H2_DEFAULT_INITIAL_WINDOW_SIZE
            ),
            #h2_stream{
                id = StreamId,
                state = idle,
                send_window = InitialWindow,
                recv_window = ?H2_DEFAULT_INITIAL_WINDOW_SIZE
            };
        Stream ->
            Stream
    end.

-spec header_block_too_large_error() -> {error, nhttp_h2_frame:decode_error()}.
header_block_too_large_error() ->
    {error,
        {connection_error, enhance_your_calm,
            <<"Header block exceeds SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113 Section 10.5.1)">>}}.

-spec hpack_decode_opts(conn()) -> nhttp_hpack:decode_opts().
hpack_decode_opts(#h2_conn{local_settings = Settings}) ->
    case maps:get(max_header_list_size, Settings, infinity) of
        infinity -> #{};
        Max -> #{max_list_size => Max}
    end.

-spec initial_stream_id(role()) -> nhttp_lib:stream_id().
initial_stream_id(client) -> 1;
initial_stream_id(server) -> 2.

-spec is_active_state(stream_state()) -> boolean().
is_active_state(open) -> true;
is_active_state(half_closed_local) -> true;
is_active_state(half_closed_remote) -> true;
is_active_state(_) -> false.

-spec process_continuation(conn(), nhttp_lib:stream_id(), fin(), binary()) ->
    {ok, conn(), [event()], iodata()} | {error, nhttp_h2_frame:decode_error()}.
process_continuation(
    #h2_conn{continuation_stream = undefined}, StreamId, _EndHeaders, _HeaderBlock
) ->
    {error,
        {connection_error, protocol_error,
            <<"Unexpected CONTINUATION for stream ", (integer_to_binary(StreamId))/binary>>}};
process_continuation(
    #h2_conn{continuation_stream = StreamId} = Conn, StreamId, EndHeaders, HeaderBlock
) ->
    #h2_stream{header_buffer = Buffer, header_end_stream = EndStream} =
        Stream =
        maps:get(StreamId, Conn#h2_conn.streams),
    NewBuffer = <<Buffer/binary, HeaderBlock/binary>>,
    case check_header_block_size(Conn, byte_size(NewBuffer)) of
        ok ->
            case EndHeaders of
                fin ->
                    NewConn = Conn#h2_conn{continuation_stream = undefined},
                    EndStreamFin =
                        case EndStream of
                            true -> fin;
                            false -> nofin
                        end,
                    decode_and_emit_headers(NewConn, StreamId, EndStreamFin, NewBuffer);
                nofin ->
                    NewStream = Stream#h2_stream{header_buffer = NewBuffer},
                    NewConn = Conn#h2_conn{
                        streams = (Conn#h2_conn.streams)#{StreamId => NewStream}
                    },
                    {ok, NewConn, [], []}
            end;
        {error, exceeded} ->
            header_block_too_large_error()
    end;
process_continuation(#h2_conn{continuation_stream = Expected}, StreamId, _EndHeaders, _HeaderBlock) ->
    {error,
        {connection_error, protocol_error,
            <<"CONTINUATION for stream ", (integer_to_binary(StreamId))/binary,
                " while expecting stream ", (integer_to_binary(Expected))/binary>>}}.

-spec process_data(conn(), nhttp_lib:stream_id(), fin(), binary()) ->
    {ok, conn(), [event()], iodata()} | {error, nhttp_h2_frame:decode_error()}.
process_data(#h2_conn{streams = Streams} = Conn, StreamId, EndStream, Payload) ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            {error,
                {connection_error, protocol_error,
                    <<"DATA frame on unknown stream (RFC 9113 Section 6.1)">>}};
        #h2_stream{state = State, content_length = ContentLength, recv_body_length = RecvBodyLen} =
                Stream ->
            case validate_recv_data(State) of
                ok ->
                    DataLen = byte_size(Payload),
                    NewRecvBodyLen = RecvBodyLen + DataLen,
                    NewConnWindow = Conn#h2_conn.recv_window - DataLen,
                    NewStreamWindow = Stream#h2_stream.recv_window - DataLen,
                    case validate_recv_flow(NewConnWindow, NewStreamWindow, StreamId) of
                        ok ->
                            case
                                nhttp_msg:validate_content_length(
                                    ContentLength, NewRecvBodyLen, EndStream
                                )
                            of
                                ok ->
                                    NewState = transition_on_recv_end_stream(State, EndStream),
                                    NewStream = Stream#h2_stream{
                                        state = NewState,
                                        recv_window = NewStreamWindow,
                                        recv_body_length = NewRecvBodyLen
                                    },
                                    ActiveCount = Conn#h2_conn.active_stream_count,
                                    NewActiveCount = update_active_count_on_transition(
                                        State, NewState, ActiveCount
                                    ),
                                    NewConn = Conn#h2_conn{
                                        streams = store_or_remove_stream(
                                            Streams, StreamId, NewStream
                                        ),
                                        recv_window = NewConnWindow,
                                        active_stream_count = NewActiveCount
                                    },
                                    Events = [{data, StreamId, Payload, EndStream}],
                                    {ok, NewConn, Events, []};
                                {error, content_length_mismatch} ->
                                    {error,
                                        {stream_error, StreamId, protocol_error,
                                            <<"Content-Length mismatch (RFC 9113 Section 8.1.2.6)">>}}
                            end;
                        {error, _} = FlowError ->
                            FlowError
                    end;
                {error, Reason} ->
                    {error, {stream_error, StreamId, stream_closed, Reason}}
            end
    end.

-spec process_frame(conn(), nhttp_h2_frame:t()) ->
    {ok, conn(), [event()], iodata()} | {error, nhttp_h2_frame:decode_error()}.
process_frame(#h2_conn{continuation_stream = ExpectedId}, Frame) when
    ExpectedId =/= undefined,
    not (is_tuple(Frame) andalso
        tuple_size(Frame) >= 2 andalso
        element(1, Frame) =:= continuation andalso
        element(2, Frame) =:= ExpectedId)
->
    {error,
        {connection_error, protocol_error,
            <<"Received non-CONTINUATION frame while expecting CONTINUATION (RFC 9113 Section 4.3)">>}};
process_frame(#h2_conn{role = server, state = preface} = Conn, preface) ->
    {ok, Conn#h2_conn{state = open}, [], []};
process_frame(#h2_conn{role = server, state = preface}, _Frame) ->
    {error,
        {connection_error, protocol_error,
            <<"Client must send connection preface first (RFC 9113 Section 3.4)">>}};
process_frame(
    #h2_conn{role = server, streams = Streams, last_peer_stream_id = LastPeer} = Conn,
    {rst_stream, StreamId, _ErrorCode}
) when StreamId band 1 =:= 1, StreamId > LastPeer ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            {error,
                {connection_error, protocol_error,
                    <<"RST_STREAM on idle stream (RFC 9113 Section 5.1)">>}};
        _ ->
            process_rst_stream(Conn, StreamId, protocol_error)
    end;
process_frame(
    #h2_conn{role = server, streams = Streams, last_peer_stream_id = LastPeer} = Conn,
    {window_update, StreamId, _Increment}
) when StreamId band 1 =:= 1, StreamId > LastPeer ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            {error,
                {connection_error, protocol_error,
                    <<"WINDOW_UPDATE on idle stream (RFC 9113 Section 5.1)">>}};
        _ ->
            {ok, Conn, [], []}
    end;
process_frame(#h2_conn{} = Conn, {settings, Settings}) ->
    process_settings(Conn, Settings);
process_frame(#h2_conn{settings_acked = false} = Conn, settings_ack) ->
    NewConn = Conn#h2_conn{settings_acked = true, state = open},
    {ok, NewConn, [settings_ack], []};
process_frame(#h2_conn{settings_acked = true} = Conn, settings_ack) ->
    {ok, Conn, [], []};
process_frame(#h2_conn{} = Conn, {ping, OpaqueData}) ->
    {ok, PongFrame} = nhttp_h2_frame:ping_ack(OpaqueData),
    {ok, Conn, [{ping, OpaqueData}], PongFrame};
process_frame(#h2_conn{} = Conn, {ping_ack, OpaqueData}) ->
    {ok, Conn, [{ping_ack, OpaqueData}], []};
process_frame(#h2_conn{send_window = Window} = Conn, {window_update, Increment}) ->
    NewWindow = Window + Increment,
    case NewWindow > ?H2_MAX_WINDOW_SIZE of
        true ->
            {error,
                {connection_error, flow_control_error,
                    <<"Connection window overflow (RFC 9113 Section 6.9)">>}};
        false ->
            {ok, Conn#h2_conn{send_window = NewWindow}, [{window_update, 0, Increment}], []}
    end;
process_frame(#h2_conn{streams = Streams} = Conn, {window_update, StreamId, Increment}) ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            {ok, Conn, [], []};
        #h2_stream{send_window = Window, state = State} = Stream ->
            case State of
                closed ->
                    {ok, Conn, [], []};
                _ ->
                    NewWindow = Window + Increment,
                    case NewWindow > ?H2_MAX_WINDOW_SIZE of
                        true ->
                            {error,
                                {stream_error, StreamId, flow_control_error,
                                    <<"Stream window overflow (RFC 9113 Section 6.9)">>}};
                        false ->
                            NewStream = Stream#h2_stream{send_window = NewWindow},
                            NewConn = Conn#h2_conn{streams = Streams#{StreamId => NewStream}},
                            {ok, NewConn, [{window_update, StreamId, Increment}], []}
                    end
            end
    end;
process_frame(#h2_conn{} = Conn, {goaway, LastStreamId, ErrorCode, DebugData}) ->
    NewConn = Conn#h2_conn{
        goaway_received = true,
        state = closing,
        last_good_stream_id = LastStreamId
    },
    {ok, NewConn, [{goaway, LastStreamId, ErrorCode, DebugData}], []};
process_frame(#h2_conn{} = Conn, {rst_stream, StreamId, ErrorCode}) ->
    process_rst_stream(Conn, StreamId, ErrorCode);
process_frame(#h2_conn{} = Conn, {data, StreamId, EndStream, Payload}) ->
    process_data(Conn, StreamId, EndStream, Payload);
process_frame(#h2_conn{} = Conn, {headers, StreamId, EndStream, EndHeaders, HeaderBlock}) ->
    process_headers(Conn, StreamId, EndStream, EndHeaders, HeaderBlock);
process_frame(
    #h2_conn{} = Conn, {headers, StreamId, EndStream, EndHeaders, _Priority, HeaderBlock}
) ->
    process_headers(Conn, StreamId, EndStream, EndHeaders, HeaderBlock);
process_frame(#h2_conn{} = Conn, {continuation, StreamId, EndHeaders, HeaderBlock}) ->
    process_continuation(Conn, StreamId, EndHeaders, HeaderBlock);
process_frame(#h2_conn{} = Conn, {priority, _StreamId, _Priority}) ->
    {ok, Conn, [], []};
process_frame(#h2_conn{} = Conn, {push_promise, _StreamId, _EndHeaders, PromisedId, _HeaderBlock}) ->
    process_push_promise(Conn, PromisedId);
process_frame(#h2_conn{} = Conn, {unknown, _Type}) ->
    {ok, Conn, [], []}.

-spec process_headers(conn(), nhttp_lib:stream_id(), fin(), fin(), binary()) ->
    {ok, conn(), [event()], iodata()} | {error, nhttp_h2_frame:decode_error()}.
process_headers(
    #h2_conn{continuation_stream = undefined} = Conn, StreamId, EndStream, EndHeaders, HeaderBlock
) ->
    case check_header_block_size(Conn, byte_size(HeaderBlock)) of
        ok ->
            case EndHeaders of
                fin ->
                    decode_and_emit_headers(Conn, StreamId, EndStream, HeaderBlock);
                nofin ->
                    Stream = get_or_create_stream(Conn, StreamId),
                    NewStream = Stream#h2_stream{
                        header_buffer = HeaderBlock,
                        header_end_stream = EndStream =:= fin
                    },
                    NewConn = Conn#h2_conn{
                        streams = (Conn#h2_conn.streams)#{StreamId => NewStream},
                        continuation_stream = StreamId
                    },
                    {ok, NewConn, [], []}
            end;
        {error, exceeded} ->
            header_block_too_large_error()
    end;
process_headers(#h2_conn{continuation_stream = Expected}, _StreamId, _ES, _EH, _HB) ->
    {error,
        {connection_error, protocol_error,
            <<"HEADERS while expecting CONTINUATION for stream ",
                (integer_to_binary(Expected))/binary>>}}.

-spec process_push_promise(conn(), nhttp_lib:stream_id()) ->
    {ok, conn(), [event()], iodata()} | {error, nhttp_h2_frame:decode_error()}.
process_push_promise(#h2_conn{role = client} = Conn, PromisedId) ->
    {ok, RstFrame} = nhttp_h2_frame:rst_stream(PromisedId, refused_stream),
    {ok, Conn, [], RstFrame};
process_push_promise(#h2_conn{role = server}, _PromisedId) ->
    {error,
        {connection_error, protocol_error,
            <<"Server received PUSH_PROMISE (RFC 9113 Section 6.6)">>}}.

-spec process_rst_stream(conn(), nhttp_lib:stream_id(), error_code()) ->
    {ok, conn(), [event()], iodata()}.
process_rst_stream(#h2_conn{streams = Streams} = Conn, StreamId, ErrorCode) ->
    NewConn = close_stream(Conn, StreamId),
    Event =
        case maps:get(StreamId, Streams, undefined) of
            undefined -> [];
            _ -> [{stream_reset, StreamId, ErrorCode}]
        end,
    {ok, NewConn, Event, []}.

-spec process_settings(conn(), settings()) ->
    {ok, conn(), [event()], iodata()} | {error, nhttp_h2_frame:decode_error()}.
process_settings(#h2_conn{peer_settings = OldSettings, streams = Streams} = Conn, NewSettings) ->
    MergedSettings = maps:merge(OldSettings, NewSettings),
    NewHpackEnc =
        case maps:get(header_table_size, NewSettings, undefined) of
            undefined ->
                Conn#h2_conn.hpack_enc;
            TableSize ->
                {ok, UpdatedEnc} = nhttp_hpack:set_max_table_size(
                    TableSize, Conn#h2_conn.hpack_enc
                ),
                UpdatedEnc
        end,
    {NewStreams, WindowEvents} =
        case maps:get(initial_window_size, NewSettings, undefined) of
            undefined ->
                {Streams, []};
            NewInitialWindow ->
                OldInitialWindow = maps:get(
                    initial_window_size, OldSettings, ?H2_DEFAULT_INITIAL_WINDOW_SIZE
                ),
                Delta = NewInitialWindow - OldInitialWindow,
                UpdatedStreams = maps:map(
                    fun(_Id, Stream) ->
                        Stream#h2_stream{
                            send_window = Stream#h2_stream.send_window + Delta
                        }
                    end,
                    Streams
                ),
                Events =
                    case Delta > 0 of
                        true ->
                            [{window_update, Id, Delta} || Id <- maps:keys(Streams)];
                        false ->
                            []
                    end,
                {UpdatedStreams, Events}
        end,
    NewConn = Conn#h2_conn{
        peer_settings = MergedSettings,
        streams = NewStreams,
        hpack_enc = NewHpackEnc,
        state = open
    },
    {ok, AckFrame} = nhttp_h2_frame:settings_ack(),
    {ok, NewConn, [{settings, NewSettings}] ++ WindowEvents, AckFrame}.

-spec recv_loop(conn(), binary(), [[event()]], iodata()) -> recv_result().
recv_loop(Conn, Data, EventsAcc, ToSend) ->
    MaxFrameSize = maps:get(
        max_frame_size, Conn#h2_conn.local_settings, ?H2_DEFAULT_MAX_FRAME_SIZE
    ),
    case nhttp_h2_frame:decode(Data, MaxFrameSize) of
        {ok, Frame, Consumed} ->
            Rest = nhttp_h2_frame:split_at(Data, Consumed),
            case process_frame(Conn, Frame) of
                {ok, NewConn, [], []} ->
                    recv_loop(NewConn, Rest, EventsAcc, ToSend);
                {ok, NewConn, NewEvents, []} ->
                    recv_loop(NewConn, Rest, [NewEvents | EventsAcc], ToSend);
                {ok, NewConn, [], FramesToSend} ->
                    recv_loop(NewConn, Rest, EventsAcc, [ToSend, FramesToSend]);
                {ok, NewConn, NewEvents, FramesToSend} ->
                    recv_loop(NewConn, Rest, [NewEvents | EventsAcc], [ToSend, FramesToSend]);
                {error, {stream_error, StreamId, ErrorCode, _Reason}} ->
                    {ok, RstFrame} = nhttp_h2_frame:rst_stream(StreamId, ErrorCode),
                    NewConn = close_stream(Conn, StreamId),
                    recv_loop(NewConn, Rest, EventsAcc, [ToSend, RstFrame]);
                {error, _} = Error ->
                    Error
            end;
        {more, _} ->
            case validate_preface_buffer(Conn, Data) of
                ok ->
                    FinalConn = Conn#h2_conn{buffer = Data},
                    FinalEvents = lists:append(lists:reverse(EventsAcc)),
                    case iolist_size(ToSend) of
                        0 -> {ok, FinalEvents, FinalConn};
                        _ -> {ok, FinalEvents, FinalConn, ToSend}
                    end;
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end.

-spec store_or_remove_stream(
    #{nhttp_lib:stream_id() => #h2_stream{}}, nhttp_lib:stream_id(), #h2_stream{}
) -> #{nhttp_lib:stream_id() => #h2_stream{}}.
store_or_remove_stream(Streams, StreamId, #h2_stream{state = closed}) ->
    maps:remove(StreamId, Streams);
store_or_remove_stream(Streams, StreamId, Stream) ->
    Streams#{StreamId => Stream}.

-spec transition_on_recv_end_stream(stream_state(), fin()) -> stream_state().
transition_on_recv_end_stream(open, fin) -> half_closed_remote;
transition_on_recv_end_stream(half_closed_local, fin) -> closed;
transition_on_recv_end_stream(State, _) -> State.

-spec transition_on_recv_headers(stream_state(), fin()) -> stream_state().
transition_on_recv_headers(idle, fin) -> half_closed_remote;
transition_on_recv_headers(idle, nofin) -> open;
transition_on_recv_headers(reserved_remote, _) -> half_closed_local;
transition_on_recv_headers(open, fin) -> half_closed_remote;
transition_on_recv_headers(half_closed_local, fin) -> closed;
transition_on_recv_headers(State, _) -> State.

-spec transition_on_send_end_stream(stream_state(), fin()) -> stream_state().
transition_on_send_end_stream(open, fin) -> half_closed_local;
transition_on_send_end_stream(half_closed_remote, fin) -> closed;
transition_on_send_end_stream(State, _) -> State.

-spec transition_on_send_headers(stream_state(), fin()) -> stream_state().
transition_on_send_headers(idle, fin) -> half_closed_local;
transition_on_send_headers(idle, nofin) -> open;
transition_on_send_headers(reserved_local, _) -> half_closed_remote;
transition_on_send_headers(open, fin) -> half_closed_local;
transition_on_send_headers(half_closed_remote, fin) -> closed;
transition_on_send_headers(State, _) -> State.

-spec update_active_count_on_transition(
    stream_state(), stream_state(), non_neg_integer()
) -> non_neg_integer().
update_active_count_on_transition(OldState, NewState, Count) ->
    WasActive = is_active_state(OldState),
    IsActive = is_active_state(NewState),
    case {WasActive, IsActive} of
        {false, true} -> Count + 1;
        {true, false} -> max(0, Count - 1);
        _ -> Count
    end.

-spec validate_decoded_headers(role(), nhttp_lib:headers(), boolean(), settings()) ->
    ok | {error, protocol_error}.
validate_decoded_headers(_, Headers, true, _Settings) ->
    validate_trailers(Headers);
validate_decoded_headers(server, Headers, false, Settings) ->
    validate_request_headers(Headers, Settings);
validate_decoded_headers(client, Headers, false, _Settings) ->
    validate_response_headers(Headers).

-spec validate_peer_stream_id(conn(), nhttp_lib:stream_id()) ->
    ok | {error, {connection_error, error_code(), binary()}}.
validate_peer_stream_id(#h2_conn{role = server, last_peer_stream_id = LastPeer}, StreamId) ->
    case StreamId band 1 of
        0 ->
            {error,
                {connection_error, protocol_error,
                    <<"Client sent even-numbered stream ID (RFC 9113 Section 5.1.1)">>}};
        1 when StreamId =< LastPeer ->
            {error,
                {connection_error, protocol_error,
                    <<"Stream ID less than or equal to previous (RFC 9113 Section 5.1.1)">>}};
        1 ->
            ok
    end;
validate_peer_stream_id(#h2_conn{role = client, last_peer_stream_id = LastPeer}, StreamId) ->
    case StreamId band 1 of
        1 ->
            {error,
                {connection_error, protocol_error,
                    <<"Server sent odd-numbered stream ID (RFC 9113 Section 5.1.1)">>}};
        0 when StreamId =< LastPeer, StreamId =/= 0 ->
            {error,
                {connection_error, protocol_error,
                    <<"Stream ID less than or equal to previous (RFC 9113 Section 5.1.1)">>}};
        0 ->
            ok
    end.

-spec validate_preface_buffer(conn(), binary()) -> ok | {error, nhttp_h2_frame:decode_error()}.
validate_preface_buffer(#h2_conn{role = server, state = preface}, Data) when
    byte_size(Data) >= 24
->
    case Data of
        <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", _/binary>> ->
            ok;
        _ ->
            {error,
                {connection_error, protocol_error,
                    <<"Invalid connection preface (RFC 9113 Section 3.4)">>}}
    end;
validate_preface_buffer(_, _) ->
    ok.

-spec validate_recv_data(stream_state()) -> ok | {error, binary()}.
validate_recv_data(open) -> ok;
validate_recv_data(half_closed_local) -> ok;
validate_recv_data(_) -> {error, <<"DATA on closed or half-closed stream">>}.

-spec validate_recv_flow(integer(), integer(), nhttp_lib:stream_id()) ->
    ok | {error, nhttp_h2_frame:decode_error()}.
validate_recv_flow(ConnWindow, _StreamWindow, _StreamId) when ConnWindow < 0 ->
    {error,
        {connection_error, flow_control_error,
            <<"DATA exceeds connection flow-control window (RFC 9113 Section 6.9)">>}};
validate_recv_flow(_ConnWindow, StreamWindow, StreamId) when StreamWindow < 0 ->
    {error,
        {stream_error, StreamId, flow_control_error,
            <<"DATA exceeds stream flow-control window (RFC 9113 Section 6.9)">>}};
validate_recv_flow(_ConnWindow, _StreamWindow, _StreamId) ->
    ok.

-define(CONNECTION_HEADERS_SET, ?NHTTP_MSG_CONNECTION_HEADERS_SET).
-spec build_headers_event(
    role(), boolean(), nhttp_lib:stream_id(), nhttp_lib:headers(), fin(), conn()
) ->
    [event()].
build_headers_event(_, true, StreamId, Headers, _Fin, _Conn) ->
    [{trailers, StreamId, Headers}];
build_headers_event(server, false, StreamId, Headers, Fin, Conn) ->
    Request = build_request(Conn, Headers),
    [{request, StreamId, Request, Fin}];
build_headers_event(client, false, StreamId, Headers, Fin, _Conn) ->
    Response = build_response(Headers),
    [{response, StreamId, Response, Fin}].

-spec build_request(conn(), nhttp_lib:headers()) -> nhttp_lib:request().
build_request(#h2_conn{peer = Peer}, Headers) ->
    nhttp_msg:build_request(http2, Peer, Headers).

-spec build_response(nhttp_lib:headers()) -> nhttp_lib:response().
build_response(Headers) ->
    nhttp_msg:build_response(http2, Headers).

-spec check_extended_connect(
    binary() | undefined, binary() | undefined, binary() | undefined, settings()
) -> ok | {error, protocol_error}.
check_extended_connect(Method, Protocol, Authority, Settings) ->
    case nhttp_msg:check_extended_connect(Method, Protocol, Authority, Settings) of
        ok -> ok;
        {error, _} -> {error, protocol_error}
    end.

-spec finalise_request_headers(nhttp_msg:request_shape(), settings()) ->
    ok | {error, protocol_error}.
finalise_request_headers(#{headers := Headers} = Shape, Settings) ->
    case has_non_trailers_te(Headers) of
        true ->
            {error, protocol_error};
        false ->
            #{method := Method, protocol := Protocol, authority := Authority} = Shape,
            check_extended_connect(Method, Protocol, Authority, Settings)
    end.

-spec has_non_trailers_te(nhttp_lib:headers()) -> boolean().
has_non_trailers_te([]) -> false;
has_non_trailers_te([{<<"te">>, V} | _]) when V =/= <<"trailers">> -> true;
has_non_trailers_te([_ | Rest]) -> has_non_trailers_te(Rest).

-spec validate_request_headers(nhttp_lib:headers(), settings()) ->
    ok | {error, protocol_error}.
validate_request_headers(Headers, Settings) ->
    case nhttp_msg:validate_request_pseudo_shape(Headers) of
        {error, _} ->
            {error, protocol_error};
        {ok, Shape} ->
            finalise_request_headers(Shape, Settings)
    end.

-spec validate_response_headers(nhttp_lib:headers()) -> ok | {error, protocol_error}.
validate_response_headers(Headers) ->
    validate_response_headers(Headers, #{phase => pseudo, has_status => false}).

-spec validate_response_headers(nhttp_lib:headers(), map()) -> ok | {error, protocol_error}.
validate_response_headers([], #{has_status := true}) ->
    ok;
validate_response_headers([], #{has_status := false}) ->
    {error, protocol_error};
validate_response_headers(
    [{<<":status">>, _} | Rest], #{phase := pseudo, has_status := false} = State
) ->
    validate_response_headers(Rest, State#{has_status => true});
validate_response_headers([{<<":status">>, _} | _], #{has_status := true}) ->
    {error, protocol_error};
validate_response_headers([{<<$:, _/binary>>, _} | _], _) ->
    {error, protocol_error};
validate_response_headers([{Name, Value} | Rest], State) ->
    case maps:is_key(Name, ?CONNECTION_HEADERS_SET) of
        true ->
            {error, protocol_error};
        false ->
            case Name of
                <<"te">> when Value =/= <<"trailers">> ->
                    {error, protocol_error};
                _ ->
                    validate_response_headers(Rest, State#{phase => regular})
            end
    end.

-spec validate_send_data(conn(), nhttp_lib:stream_id()) -> ok | {error, term()}.
validate_send_data(#h2_conn{streams = Streams}, StreamId) ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            {error, {unknown_stream, StreamId}};
        #h2_stream{state = State} ->
            case State of
                open -> ok;
                half_closed_remote -> ok;
                _ -> {error, {stream_closed, StreamId}}
            end
    end.

-spec validate_send_headers(conn(), nhttp_lib:stream_id()) -> ok | {error, term()}.
validate_send_headers(#h2_conn{goaway_sent = true}, _StreamId) ->
    {error, connection_closing};
validate_send_headers(
    #h2_conn{
        role = Role,
        streams = Streams,
        next_stream_id = NextId,
        last_peer_stream_id = LastPeer
    },
    StreamId
) ->
    case maps:get(StreamId, Streams, undefined) of
        undefined ->
            case was_stream_used(Role, StreamId, NextId, LastPeer) of
                true -> {error, {stream_closed, StreamId}};
                false -> ok
            end;
        #h2_stream{state = State} ->
            case State of
                idle -> ok;
                open -> ok;
                half_closed_remote -> ok;
                reserved_local -> ok;
                _ -> {error, {stream_closed, StreamId}}
            end
    end.

-spec validate_trailers(nhttp_lib:headers()) -> ok | {error, protocol_error}.
validate_trailers(Headers) ->
    case nhttp_msg:validate_trailers(Headers) of
        ok -> ok;
        {error, pseudo_in_trailers} -> {error, protocol_error}
    end.

-spec was_stream_used(role(), nhttp_lib:stream_id(), nhttp_lib:stream_id(), nhttp_lib:stream_id()) ->
    boolean().
was_stream_used(client, StreamId, NextId, _LastPeer) when StreamId band 1 =:= 1 ->
    StreamId < NextId;
was_stream_used(server, StreamId, _NextId, LastPeer) when StreamId band 1 =:= 1 ->
    StreamId =< LastPeer;
was_stream_used(client, StreamId, _NextId, LastPeer) when StreamId band 1 =:= 0 ->
    StreamId =< LastPeer;
was_stream_used(server, StreamId, NextId, _LastPeer) when StreamId band 1 =:= 0 ->
    StreamId < NextId;
was_stream_used(_, _, _, _) ->
    false.
