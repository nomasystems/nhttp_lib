-module(nhttp_ws).

-moduledoc """
WebSocket message-level codec, handshake, and session API (RFC 6455).

Sits on top of `nhttp_ws_frame` (per-frame codec) and adds:

- The handshake half: server validation and client/server response
  builders, `Sec-WebSocket-Accept` derivation.
- A framing-aware buffer (`ws_decoder/0`) that reassembles continuation
  frames into messages and surfaces interleaved control frames inline.
- A process-coupled session API used by the H1 / H2 / H3 connection
  processes after upgrade.

The pure per-frame primitives (`encode/1,2`, `decode/1`, `decode_unmasked/1`,
`encode_masked/1`) are exported here as thin shims over `nhttp_ws_frame`
for backwards compatibility.
""".

%%%-----------------------------------------------------------------------------
%% SERVER HANDSHAKE
%%%-----------------------------------------------------------------------------
-export([
    accept_key/1,
    handshake_response/1,
    handshake_response/2,
    validate_upgrade/1
]).

%%%-----------------------------------------------------------------------------
%% CLIENT HANDSHAKE
%%%-----------------------------------------------------------------------------
-export([
    generate_key/0,
    validate_accept/2
]).

%%%-----------------------------------------------------------------------------
%% FRAME ENCODING (DELEGATED TO NHTTP_WS_FRAME)
%%%-----------------------------------------------------------------------------
-export([
    encode/1,
    encode/2,
    encode_binary/1,
    encode_close/0,
    encode_close/2,
    encode_ping/0,
    encode_ping/1,
    encode_pong/1,
    encode_text/1
]).

-export([
    encode_masked/1,
    encode_masked_binary/1,
    encode_masked_close/0,
    encode_masked_close/2,
    encode_masked_ping/0,
    encode_masked_ping/1,
    encode_masked_pong/1,
    encode_masked_text/1
]).

%%%-----------------------------------------------------------------------------
%% FRAME DECODING (DELEGATED TO NHTTP_WS_FRAME)
%%%-----------------------------------------------------------------------------
-export([
    decode/1,
    decode_unmasked/1
]).

%%%-----------------------------------------------------------------------------
%% STATEFUL DECODING (FRAGMENTATION + INTERLEAVED CONTROL FRAMES)
%%%-----------------------------------------------------------------------------
-export([
    decode_with_state/2, decoder_new/1, decoder_new/2
]).

%%%-----------------------------------------------------------------------------
%% SESSION CONSTRUCTOR + ACCESSORS
%%%-----------------------------------------------------------------------------
-export([
    is_alive/1,
    new_session/3,
    new_session/4,
    owner/1,
    session_ref/1,
    stream_id/1,
    transport/1
]).

%%%-----------------------------------------------------------------------------
%% SESSION API (SERVER- AND CLIENT-SIDE)
%%%-----------------------------------------------------------------------------
-export([
    broadcast/2,
    close/1,
    close/3,
    close/4,
    info/2,
    ping/1,
    ping/2,
    send/2,
    send/3,
    send_async/2,
    send_binary/2,
    send_text/2
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-export_type([
    close_code/0,
    decode_result/0,
    session/0,
    stateful_decode_result/0,
    ws_close_opts/0,
    ws_decoder/0,
    ws_frame/0,
    ws_message/0,
    ws_opcode/0,
    ws_runtime_opts/0,
    ws_send_opts/0,
    ws_session_opts/0
]).

-type close_code() :: nhttp_ws_frame:close_code().

-type decode_result() :: nhttp_ws_frame:decode_result().

-type ws_message() :: nhttp_ws_frame:ws_message().

-type ws_frame() ::
    {text, binary()}
    | {binary, binary()}
    | {ping, binary()}
    | {pong, binary()}.

-type ws_opcode() :: nhttp_ws_frame:ws_opcode().

-type stateful_decode_result() ::
    {ok, ws_message(), Rest :: binary(), ws_decoder()}
    | {more, MinBytes :: pos_integer(), ws_decoder()}
    | {error, term()}.

-type ws_send_opts() :: #{
    timeout => timeout(),
    priority => low | normal
}.

-type ws_runtime_opts() :: #{
    deliver_ping => boolean(),
    deliver_pong => boolean(),
    max_message_size => pos_integer() | infinity,
    outbound_high_water => pos_integer(),
    outbound_low_water => pos_integer(),
    idle_timeout => timeout()
}.

-type ws_session_opts() :: #{
    subprotocol => binary() | undefined,
    extensions => [binary()]
}.

-type ws_close_opts() :: #{
    force => boolean(),
    timeout => timeout()
}.

%%%-----------------------------------------------------------------------------
%% LOCAL MACROS
%%%-----------------------------------------------------------------------------
-define(WS_MAGIC, <<"258EAFA5-E914-47DA-95CA-C5AB0DC85B11">>).
-define(OP_CONTINUATION, 0).
-define(OP_TEXT, 1).
-define(OP_BINARY, 2).
-define(OP_CLOSE, 8).
-define(OP_PING, 9).
-define(OP_PONG, 10).
-define(IS_CONTROL(Op), (Op =:= ?OP_CLOSE orelse Op =:= ?OP_PING orelse Op =:= ?OP_PONG)).

%%%-----------------------------------------------------------------------------
%% INTERNAL RECORDS
%%%-----------------------------------------------------------------------------
-record(nhttp_ws_session, {
    transport :: h1 | h2 | h3,
    conn_pid :: pid(),
    stream_id :: undefined | nhttp_lib:stream_id(),
    ref :: reference()
}).

%%%-----------------------------------------------------------------------------
%% RECORDS
%%%-----------------------------------------------------------------------------
-record(ws_decoder, {
    role :: client | server,
    frag_opcode :: 0..15 | undefined,
    frag_acc = [] :: [binary()],
    frag_acc_size = 0 :: non_neg_integer(),
    max_message_size = infinity :: pos_integer() | infinity
}).

-opaque ws_decoder() :: #ws_decoder{}.

-opaque session() :: #nhttp_ws_session{}.

%%%-----------------------------------------------------------------------------
%% SERVER HANDSHAKE
%%%-----------------------------------------------------------------------------
-doc "Generate the Sec-WebSocket-Accept header value.".
-spec accept_key(Key :: binary()) -> binary().
accept_key(Key) ->
    Hash = crypto:hash(sha, <<Key/binary, ?WS_MAGIC/binary>>),
    base64:encode(Hash).

-doc "Generate the complete handshake response.".
-spec handshake_response(Key :: binary()) -> iodata().
handshake_response(Key) ->
    Accept = accept_key(Key),
    [
        <<"HTTP/1.1 101 Switching Protocols\r\n">>,
        <<"Upgrade: websocket\r\n">>,
        <<"Connection: Upgrade\r\n">>,
        <<"Sec-WebSocket-Accept: ">>,
        Accept,
        <<"\r\n">>,
        <<"\r\n">>
    ].

-spec handshake_response(Key :: binary(), SessionOpts :: ws_session_opts()) -> iodata().
handshake_response(Key, SessionOpts) ->
    Accept = accept_key(Key),
    SubprotocolHeader =
        case maps:get(subprotocol, SessionOpts, undefined) of
            undefined -> [];
            P -> [<<"Sec-WebSocket-Protocol: ">>, P, <<"\r\n">>]
        end,
    ExtensionsHeader =
        case maps:get(extensions, SessionOpts, []) of
            [] -> [];
            Exts -> [<<"Sec-WebSocket-Extensions: ">>, lists:join(<<", ">>, Exts), <<"\r\n">>]
        end,
    [
        <<"HTTP/1.1 101 Switching Protocols\r\n">>,
        <<"Upgrade: websocket\r\n">>,
        <<"Connection: Upgrade\r\n">>,
        <<"Sec-WebSocket-Accept: ">>,
        Accept,
        <<"\r\n">>,
        SubprotocolHeader,
        ExtensionsHeader,
        <<"\r\n">>
    ].

-doc """
Validate WebSocket upgrade request headers.
Returns `{ok, Key}` if valid, `{error, Reason}` otherwise.
""".
-spec validate_upgrade(nhttp_h1:req()) -> {ok, binary()} | {error, term()}.
validate_upgrade(#{headers := Headers}) ->
    maybe
        ok ?= validate_upgrade_header(Headers),
        ok ?= validate_connection_header(Headers),
        {ok, Key} ?= get_websocket_key(Headers),
        ok ?= validate_websocket_version(Headers),
        {ok, Key}
    end.

%%%-----------------------------------------------------------------------------
%% CLIENT HANDSHAKE
%%%-----------------------------------------------------------------------------
-doc "Generate a random Sec-WebSocket-Key (RFC 6455 Section 4.1).".
-spec generate_key() -> binary().
generate_key() ->
    base64:encode(crypto:strong_rand_bytes(16)).

-doc "Validate the server's Sec-WebSocket-Accept value against the client key.".
-spec validate_accept(ClientKey :: binary(), ServerAccept :: binary()) ->
    ok | {error, invalid_accept}.
validate_accept(ClientKey, ServerAccept) ->
    Expected = accept_key(ClientKey),
    case Expected =:= ServerAccept of
        true -> ok;
        false -> {error, invalid_accept}
    end.

%%%-----------------------------------------------------------------------------
%% FRAME ENCODING (DELEGATED)
%%%-----------------------------------------------------------------------------
-doc "Encode a WebSocket message as an unmasked frame (server-to-client).".
-spec encode(ws_message()) -> iodata().
encode(Message) ->
    nhttp_ws_frame:encode(Message).

-doc """
Encode a WebSocket message with options. The only option is
`mask => boolean()`; defaults to `false`.
""".
-spec encode(ws_message(), nhttp_ws_frame:encode_opts()) -> iodata().
encode(Message, Opts) ->
    nhttp_ws_frame:encode(Message, Opts).

-doc "Encode a binary message (server, unmasked).".
-spec encode_binary(iodata()) -> iodata().
encode_binary(Data) ->
    nhttp_ws_frame:encode({binary, iolist_to_binary(Data)}).

-doc "Encode a close frame with no status code (server, unmasked).".
-spec encode_close() -> iodata().
encode_close() ->
    nhttp_ws_frame:encode(close).

-doc "Encode a close frame with status code and reason (server, unmasked).".
-spec encode_close(Code :: close_code(), Reason :: binary()) -> iodata().
encode_close(Code, Reason) ->
    nhttp_ws_frame:encode({close, Code, Reason}).

-doc "Encode a ping frame with empty payload (server, unmasked).".
-spec encode_ping() -> iodata().
encode_ping() ->
    nhttp_ws_frame:encode(ping).

-doc "Encode a ping frame with payload (server, unmasked).".
-spec encode_ping(binary()) -> iodata().
encode_ping(Data) ->
    nhttp_ws_frame:encode({ping, Data}).

-doc "Encode a pong frame, must echo ping payload (server, unmasked).".
-spec encode_pong(binary()) -> iodata().
encode_pong(Data) ->
    nhttp_ws_frame:encode({pong, Data}).

-doc "Encode a text message (server, unmasked).".
-spec encode_text(iodata()) -> iodata().
encode_text(Data) ->
    nhttp_ws_frame:encode({text, iolist_to_binary(Data)}).

%%%-----------------------------------------------------------------------------
%% FRAME ENCODING (CLIENT, MASKED, DELEGATED)
%%%-----------------------------------------------------------------------------
-doc "Encode a masked WebSocket message (client, RFC 6455 Section 5.1).".
-spec encode_masked(ws_message()) -> iodata().
encode_masked(Message) ->
    nhttp_ws_frame:encode_masked(Message).

-doc "Encode a masked binary message (client).".
-spec encode_masked_binary(iodata()) -> iodata().
encode_masked_binary(Data) ->
    nhttp_ws_frame:encode_masked({binary, iolist_to_binary(Data)}).

-doc "Encode a masked close frame with no status code (client).".
-spec encode_masked_close() -> iodata().
encode_masked_close() ->
    nhttp_ws_frame:encode_masked(close).

-doc "Encode a masked close frame with status code and reason (client).".
-spec encode_masked_close(Code :: close_code(), Reason :: binary()) -> iodata().
encode_masked_close(Code, Reason) ->
    nhttp_ws_frame:encode_masked({close, Code, Reason}).

-doc "Encode a masked ping frame with empty payload (client).".
-spec encode_masked_ping() -> iodata().
encode_masked_ping() ->
    nhttp_ws_frame:encode_masked(ping).

-doc "Encode a masked ping frame with payload (client).".
-spec encode_masked_ping(binary()) -> iodata().
encode_masked_ping(Data) ->
    nhttp_ws_frame:encode_masked({ping, Data}).

-doc "Encode a masked pong frame (client).".
-spec encode_masked_pong(binary()) -> iodata().
encode_masked_pong(Data) ->
    nhttp_ws_frame:encode_masked({pong, Data}).

-doc "Encode a masked text message (client).".
-spec encode_masked_text(iodata()) -> iodata().
encode_masked_text(Data) ->
    nhttp_ws_frame:encode_masked({text, iolist_to_binary(Data)}).

%%%-----------------------------------------------------------------------------
%% FRAME DECODING (DELEGATED)
%%%-----------------------------------------------------------------------------
-doc """
Decode a masked WebSocket frame (client-to-server).
Returns `{ok, Message, Rest}` on success, `{more, MinBytes}` if more data needed.
""".
-spec decode(binary()) -> decode_result().
decode(Data) ->
    nhttp_ws_frame:decode(Data).

-doc """
Decode an unmasked WebSocket frame (server-to-client).
RFC 6455 Section 5.1: a server MUST NOT mask frames sent to clients.
""".
-spec decode_unmasked(binary()) -> decode_result().
decode_unmasked(Data) ->
    nhttp_ws_frame:decode_unmasked(Data).

%%%-----------------------------------------------------------------------------
%% STATEFUL DECODING (FRAGMENTATION SUPPORT, RFC 6455 SECTION 5.4)
%%%-----------------------------------------------------------------------------
-doc """
Decode a frame with fragmentation support.
Continuation frames are accumulated until FIN=1, then the complete
message is delivered. Control frames (ping, pong, close) may appear
between fragments and are delivered immediately.
""".
-spec decode_with_state(binary(), ws_decoder()) -> stateful_decode_result().
decode_with_state(Data, #ws_decoder{role = Role} = Dec) ->
    case nhttp_ws_frame:decode_raw(Data, Role) of
        {ok, Fin, Opcode, Payload, Rest} ->
            case nhttp_ws_frame:validate_control_frame(Fin, Opcode, Payload) of
                ok -> process_fragment(Fin, Opcode, Payload, Rest, Dec);
                {error, _} = Err -> Err
            end;
        {more, Needed} ->
            {more, Needed, Dec};
        {error, _} = Err ->
            Err
    end.

-doc "Create a new stateful decoder for the given role.".
-spec decoder_new(client | server) -> ws_decoder().
decoder_new(Role) ->
    decoder_new(Role, #{}).

-doc """
Create a new stateful decoder honouring `max_message_size` from the runtime
opts. The cap applies to the cumulative payload of fragmented messages and
to single non-control frames; exceeding it returns `{error, message_too_large}`.
""".
-spec decoder_new(client | server, ws_runtime_opts()) -> ws_decoder().
decoder_new(Role, Opts) ->
    Max = maps:get(max_message_size, Opts, infinity),
    #ws_decoder{
        role = Role,
        frag_opcode = undefined,
        frag_acc = [],
        max_message_size = Max
    }.

%%%-----------------------------------------------------------------------------
%% SESSION CONSTRUCTOR + ACCESSORS
%%%-----------------------------------------------------------------------------
-doc "Liveness check for the connection process owning the session.".
-spec is_alive(session()) -> boolean().
is_alive(#nhttp_ws_session{conn_pid = Pid}) ->
    is_process_alive(Pid).

-doc """
Build a fresh session handle owned by the calling process. Used by the
nhttp connection processes (H1/H2/H3) at upgrade time. The constructor is
the only sanctioned way to mint a session. The record itself is opaque
to callers outside `nhttp_lib`.
""".
-spec new_session(h1 | h2 | h3, pid(), undefined | nhttp_lib:stream_id()) -> session().
new_session(Transport, ConnPid, StreamId) ->
    new_session(Transport, ConnPid, StreamId, make_ref()).

-doc """
Same as `new_session/3` but lets the caller supply an existing reference
(useful when the conn process needs to keep the same `ref` across two
different per-stream records, e.g. during in-place migrations).
""".
-spec new_session(h1 | h2 | h3, pid(), undefined | nhttp_lib:stream_id(), reference()) ->
    session().
new_session(Transport, ConnPid, StreamId, Ref) when
    Transport =:= h1 orelse Transport =:= h2 orelse Transport =:= h3,
    is_pid(ConnPid),
    (StreamId =:= undefined orelse (is_integer(StreamId) andalso StreamId >= 0)),
    is_reference(Ref)
->
    #nhttp_ws_session{
        transport = Transport, conn_pid = ConnPid, stream_id = StreamId, ref = Ref
    }.

-doc "Return the connection process pid for the session.".
-spec owner(session()) -> pid().
owner(#nhttp_ws_session{conn_pid = Pid}) ->
    Pid.

-doc """
Return the unique reference stamped on the session at creation. The conn
process compares it against the ref it remembers per active stream and
rejects sends whose ref no longer matches (stale handle after the stream
ended but before the conn pid died).
""".
-spec session_ref(session()) -> reference().
session_ref(#nhttp_ws_session{ref = Ref}) ->
    Ref.

-doc "Return the transport-level stream id, or `undefined` for HTTP/1.1.".
-spec stream_id(session()) -> undefined | nhttp_lib:stream_id().
stream_id(#nhttp_ws_session{stream_id = StreamId}) ->
    StreamId.

-doc "Return the transport carrying the session.".
-spec transport(session()) -> h1 | h2 | h3.
transport(#nhttp_ws_session{transport = Transport}) ->
    Transport.

%%%-----------------------------------------------------------------------------
%% SESSION API
%%%-----------------------------------------------------------------------------
-doc """
Send a message to every WebSocket session multiplexed on the connection
that owns `Session` (or directly to the connection pid). Equivalent to
`Pid ! Msg`. Handlers receive it via `handle_ws_info/3` with broadcast
semantics.
""".
-spec broadcast(session() | pid(), term()) -> ok.
broadcast(#nhttp_ws_session{conn_pid = Pid}, Msg) ->
    Pid ! Msg,
    ok;
broadcast(Pid, Msg) when is_pid(Pid) ->
    Pid ! Msg,
    ok.

-doc "Initiate the §5.5.1 close handshake with status 1000 and no reason.".
-spec close(session()) -> ok.
close(Session) ->
    close(Session, 1000, <<>>, #{}).

-doc "Initiate the §5.5.1 close handshake with explicit code and reason.".
-spec close(session(), close_code(), binary()) -> ok.
close(Session, Code, Reason) ->
    close(Session, Code, Reason, #{}).

-doc """
Initiate the §5.5.1 close handshake. Pending sends flush before the
reciprocal CLOSE is written unless `force => true` is set in `Opts`.
""".
-spec close(session(), close_code(), binary(), ws_close_opts()) -> ok.
close(#nhttp_ws_session{conn_pid = Pid, stream_id = StreamId, ref = Ref}, Code, Reason, Opts) when
    is_integer(Code), Code >= 0, Code =< 65535, is_binary(Reason), is_map(Opts)
->
    gen_server:cast(Pid, {ws_close, Ref, StreamId, Code, Reason, Opts}).

-doc """
Deliver an arbitrary Erlang term to a specific session's `handle_ws_info/3`
callback. Use this instead of a bare `Pid ! Msg` when the connection
multiplexes more than one session and you want to address one in particular.
""".
-spec info(session(), term()) -> ok.
info(#nhttp_ws_session{conn_pid = Pid, stream_id = StreamId}, Msg) ->
    gen_server:cast(Pid, {ws_info, StreamId, Msg}).

-doc "Send an empty WebSocket PING (§5.5.2) on the session.".
-spec ping(session()) -> ok | {error, term()}.
ping(Session) ->
    send(Session, ping).

-doc "Send a WebSocket PING with the given payload (≤ 125 bytes per §5.5).".
-spec ping(session(), binary()) -> ok | {error, term()}.
ping(Session, Payload) when is_binary(Payload), byte_size(Payload) =< 125 ->
    send(Session, {ping, Payload}).

-doc """
Synchronously send a WebSocket message on the session. Returns once the
frame has cleared the per-stream flow control (or the TCP send buffer for
HTTP/1.1) or after `Opts#timeout` ms.
Returns `{error, gone}` if the session has been closed, `{error, timeout}`
if the deadline elapses before the write completes, or any error reported
by the transport.
""".
-spec send(session(), ws_message()) -> ok | {error, term()}.
send(Session, Msg) ->
    send(Session, Msg, #{}).

-spec send(session(), ws_message(), ws_send_opts()) -> ok | {error, term()}.
send(#nhttp_ws_session{conn_pid = Pid, stream_id = StreamId, ref = Ref}, Msg, Opts) when
    is_map(Opts)
->
    Timeout = maps:get(timeout, Opts, 5000),
    call_conn(Pid, {ws_send, Ref, StreamId, Msg}, Timeout).

-doc """
Asynchronously enqueue a WebSocket message. Returns `{error, would_block}`
immediately if the session's outbox has crossed its high-water mark, leaving
the caller free to drop, retry, or close. Never blocks waiting for the
transport, only for the connection process to ack the enqueue (or reject
it).
""".
-spec send_async(session(), ws_message()) -> ok | {error, would_block | gone | term()}.
send_async(#nhttp_ws_session{conn_pid = Pid, stream_id = StreamId, ref = Ref}, Msg) ->
    call_conn(Pid, {ws_send_async, Ref, StreamId, Msg}, 5000).

-doc "Send a binary message.".
-spec send_binary(session(), iodata()) -> ok | {error, term()}.
send_binary(Session, Data) ->
    send(Session, {binary, iolist_to_binary(Data)}).

-doc "Send a UTF-8 text message (caller is responsible for valid UTF-8).".
-spec send_text(session(), iodata()) -> ok | {error, term()}.
send_text(Session, Data) ->
    send(Session, {text, iolist_to_binary(Data)}).

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec call_conn(pid(), term(), timeout()) -> ok | {error, term()}.
call_conn(Pid, Request, Timeout) ->
    try gen_server:call(Pid, Request, Timeout) of
        Reply -> Reply
    catch
        exit:{noproc, _} -> {error, gone};
        exit:{normal, _} -> {error, gone};
        exit:{shutdown, _} -> {error, gone};
        exit:{timeout, _} -> {error, timeout};
        exit:{Reason, _} -> {error, Reason}
    end.

-spec check_message_size(non_neg_integer(), ws_decoder()) ->
    ok | {error, message_too_large}.
check_message_size(_Size, #ws_decoder{max_message_size = infinity}) ->
    ok;
check_message_size(Size, #ws_decoder{max_message_size = Max}) when Size =< Max ->
    ok;
check_message_size(_Size, _Dec) ->
    {error, message_too_large}.

-spec get_websocket_key(nhttp_lib:headers()) -> {ok, binary()} | {error, missing_key}.
get_websocket_key(Headers) ->
    case nhttp_headers:get(<<"sec-websocket-key">>, Headers) of
        undefined -> {error, missing_key};
        Key -> {ok, Key}
    end.

-spec process_fragment(0 | 1, 0..15, binary(), binary(), ws_decoder()) -> stateful_decode_result().
process_fragment(1, Opcode, Payload, Rest, #ws_decoder{frag_opcode = undefined} = Dec) when
    not ?IS_CONTROL(Opcode)
->
    case check_message_size(byte_size(Payload), Dec) of
        ok ->
            case nhttp_ws_frame:opcode_to_complete_message(Opcode, Payload) of
                {ok, Msg} -> {ok, Msg, Rest, Dec};
                {error, _} = Err -> Err
            end;
        {error, _} = Err ->
            Err
    end;
process_fragment(0, Opcode, Payload, _Rest, #ws_decoder{frag_opcode = undefined} = Dec) when
    Opcode =:= ?OP_TEXT; Opcode =:= ?OP_BINARY
->
    Size = byte_size(Payload),
    case check_message_size(Size, Dec) of
        ok ->
            {more, 1, Dec#ws_decoder{
                frag_opcode = Opcode, frag_acc = [Payload], frag_acc_size = Size
            }};
        {error, _} = Err ->
            Err
    end;
process_fragment(
    _Fin, Opcode, Payload, Rest, #ws_decoder{frag_opcode = _FragOp} = Dec
) when ?IS_CONTROL(Opcode) ->
    case nhttp_ws_frame:opcode_to_complete_message(Opcode, Payload) of
        {ok, Msg} -> {ok, Msg, Rest, Dec};
        {error, _} = Err -> Err
    end;
process_fragment(
    0,
    ?OP_CONTINUATION,
    Payload,
    _Rest,
    #ws_decoder{frag_opcode = FragOp, frag_acc = Acc, frag_acc_size = AccSize} = Dec
) when FragOp =/= undefined ->
    NewSize = AccSize + byte_size(Payload),
    case check_message_size(NewSize, Dec) of
        ok ->
            {more, 1, Dec#ws_decoder{frag_acc = [Payload | Acc], frag_acc_size = NewSize}};
        {error, _} = Err ->
            Err
    end;
process_fragment(
    1,
    ?OP_CONTINUATION,
    Payload,
    Rest,
    #ws_decoder{frag_opcode = FragOp, frag_acc = Acc, frag_acc_size = AccSize} = Dec
) when FragOp =/= undefined ->
    NewSize = AccSize + byte_size(Payload),
    case check_message_size(NewSize, Dec) of
        ok ->
            FullPayload = iolist_to_binary(lists:reverse([Payload | Acc])),
            case nhttp_ws_frame:opcode_to_complete_message(FragOp, FullPayload) of
                {ok, Msg} ->
                    {ok, Msg, Rest, Dec#ws_decoder{
                        frag_opcode = undefined, frag_acc = [], frag_acc_size = 0
                    }};
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end;
process_fragment(_, _, _, _, _) ->
    {error, expected_continuation}.

-spec validate_connection_header(nhttp_lib:headers()) -> ok | {error, invalid_connection}.
validate_connection_header(Headers) ->
    case nhttp_headers:get(<<"connection">>, Headers) of
        undefined ->
            {error, invalid_connection};
        Value ->
            LowerValue = nhttp_headers:to_lower(Value),
            Tokens = binary:split(LowerValue, <<",">>, [global, trim_all]),
            TrimmedTokens = [string:trim(T) || T <- Tokens],
            case lists:member(<<"upgrade">>, TrimmedTokens) of
                true -> ok;
                false -> {error, invalid_connection}
            end
    end.

-spec validate_upgrade_header(nhttp_lib:headers()) -> ok | {error, invalid_upgrade}.
validate_upgrade_header(Headers) ->
    case nhttp_headers:get(<<"upgrade">>, Headers) of
        undefined ->
            {error, invalid_upgrade};
        Value ->
            case nhttp_headers:to_lower(Value) of
                <<"websocket">> -> ok;
                _ -> {error, invalid_upgrade}
            end
    end.

-spec validate_websocket_version(nhttp_lib:headers()) -> ok | {error, unsupported_version}.
validate_websocket_version(Headers) ->
    case nhttp_headers:get(<<"sec-websocket-version">>, Headers) of
        <<"13">> -> ok;
        undefined -> {error, unsupported_version};
        _ -> {error, unsupported_version}
    end.
