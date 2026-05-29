-module(nhttp_error).

-moduledoc """
Unified error handling for nhttp HTTP library.

Provides a consistent error taxonomy across client and server components.
All errors use the format `{error, {Category, Reason}}` where Category
identifies the error domain and Reason provides specific details.

## Error Categories

- `connection` - Connection establishment failures
- `request` - Request/response cycle failures
- `http2` - HTTP/2 protocol-specific errors
- `pool` - Connection pool errors
- `server` - Server-side acceptor / listener / handler failures

## Usage

```erlang
case connect(Host, Port) of
    {ok, Conn} -> {ok, Conn};
    {error, econnrefused} -> nhttp_error:connect_refused(econnrefused);
    {error, timeout} -> nhttp_error:connect_timeout()
end.

case nhttpc:get(Url) of
    {ok, Resp} -> handle_response(Resp);
    {error, {connection, _}} -> retry_with_backoff();
    {error, {request, {timeout, _}}} -> return_504();
    {error, {pool, checkout_timeout}} -> return_503()
end.

case nhttp_error:is_retryable(Error) of
    true -> retry_request();
    false -> return_error()
end.
```
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    category/1,
    format/1,
    is_retryable/1,
    is_transient/1,
    normalize/1
]).

%%%-----------------------------------------------------------------------------
%% CONNECTION ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-export([
    alpn_error/1,
    connect_failed/1,
    connect_not_ready/0,
    connect_refused/1,
    connect_timeout/0,
    connect_timeout/1,
    tls_error/1
]).

%%%-----------------------------------------------------------------------------
%% REQUEST ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-export([
    body_timeout/1,
    connection_closed/0,
    connection_closed/1,
    malformed_response/2,
    max_redirects/1,
    recv_error/1,
    redirect_loop/1,
    request_timeout/0,
    request_timeout/1,
    response_too_large/2,
    send_error/1
]).

%%%-----------------------------------------------------------------------------
%% HTTP/2 ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-export([
    flow_control_error/1,
    goaway/1,
    goaway/2,
    rate_limited/0,
    stream_cancelled/0,
    stream_closed/1,
    stream_refused/0,
    stream_reset/1
]).

%%%-----------------------------------------------------------------------------
%% POOL ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-export([
    checkout_timeout/0,
    no_connections/0,
    pool_draining/0,
    pool_exhausted/1
]).

%%%-----------------------------------------------------------------------------
%% FILE/UPLOAD ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-export([
    file_error/2,
    file_error/3,
    upload_error/1
]).

%%%-----------------------------------------------------------------------------
%% STREAM ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-export([
    stream_stopped/1,
    stream_stopped/2
]).

%%%-----------------------------------------------------------------------------
%% SERVER ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-export([
    accept_closed/0,
    accept_emfile/0,
    accept_timeout/0,
    at_capacity/0,
    connection_closing/0,
    flow_control_blocked/2,
    h2_connection_error/1,
    h2_error/1,
    handler_init_error/1,
    listen_failed/1,
    missing_config/1,
    protocol_error/1,
    server_socket_error/1,
    server_stream_closed/1,
    ws_error/1,
    ws_upgrade_error/1
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-export_type([category/0, reason/0, t/0]).

-type category() :: connection | request | http2 | pool | server.

-type reason() :: #{type := atom(), _ => _}.

-type t() :: {error, {category(), reason()}}.

%%%-----------------------------------------------------------------------------
%% CONNECTION ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc "ALPN protocol negotiation failed.".
-spec alpn_error(term()) -> t().
alpn_error(Reason) ->
    {error, {connection, #{type => alpn_error, reason => Reason}}}.

-doc "Connection attempt failed with the given POSIX error.".
-spec connect_failed(inet:posix()) -> t().
connect_failed(Posix) ->
    {error, {connection, #{type => connect_failed, posix => Posix}}}.

-doc "Connection is not ready for use.".
-spec connect_not_ready() -> t().
connect_not_ready() ->
    {error, {connection, #{type => not_ready}}}.

-doc "Connection was refused by the remote host.".
-spec connect_refused(inet:posix()) -> t().
connect_refused(Posix) ->
    {error, {connection, #{type => connect_refused, posix => Posix}}}.

-doc "Connection attempt timed out.".
-spec connect_timeout() -> t().
connect_timeout() ->
    {error, {connection, #{type => connect_timeout}}}.

-doc "Connection attempt timed out after the specified duration.".
-spec connect_timeout(timeout()) -> t().
connect_timeout(Timeout) ->
    {error, {connection, #{type => connect_timeout, value => Timeout}}}.

-doc "TLS handshake or protocol error.".
-spec tls_error(term()) -> t().
tls_error(Reason) ->
    {error, {connection, #{type => tls_error, reason => Reason}}}.

%%%-----------------------------------------------------------------------------
%% REQUEST ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc "Body receive timed out after the specified duration.".
-spec body_timeout(timeout()) -> t().
body_timeout(Timeout) ->
    {error, {request, #{type => body_timeout, value => Timeout}}}.

-doc "Connection was closed during request processing.".
-spec connection_closed() -> t().
connection_closed() ->
    {error, {request, #{type => connection_closed}}}.

-doc "Connection was closed with a retryable or unexpected tag.".
-spec connection_closed(retryable | unexpected) -> t().
connection_closed(Tag) ->
    {error, {request, #{type => connection_closed, tag => Tag}}}.

-doc "Received a malformed response that could not be parsed.".
-spec malformed_response(atom(), binary()) -> t().
malformed_response(ParseError, Data) ->
    {error, {request, #{type => malformed_response, parse_error => ParseError, data => Data}}}.

-doc "Maximum number of redirects exceeded.".
-spec max_redirects(non_neg_integer()) -> t().
max_redirects(Count) ->
    {error, {request, #{type => max_redirects_exceeded, count => Count}}}.

-doc "Error receiving data from the socket.".
-spec recv_error(inet:posix()) -> t().
recv_error(Posix) ->
    {error, {request, #{type => recv_error, posix => Posix}}}.

-doc "Redirect loop detected at the given URL.".
-spec redirect_loop(binary()) -> t().
redirect_loop(Url) ->
    {error, {request, #{type => redirect_loop, url => Url}}}.

-doc "Request timed out.".
-spec request_timeout() -> t().
request_timeout() ->
    {error, {request, #{type => request_timeout}}}.

-doc "Request timed out after the specified duration.".
-spec request_timeout(timeout()) -> t().
request_timeout(Timeout) ->
    {error, {request, #{type => request_timeout, value => Timeout}}}.

-doc "Response body exceeded the maximum allowed size.".
-spec response_too_large(non_neg_integer(), non_neg_integer()) -> t().
response_too_large(Size, MaxSize) ->
    {error, {request, #{type => response_too_large, size => Size, max_size => MaxSize}}}.

-doc "Error sending data on the socket.".
-spec send_error(inet:posix()) -> t().
send_error(Posix) ->
    {error, {request, #{type => send_error, posix => Posix}}}.

%%%-----------------------------------------------------------------------------
%% HTTP/2 ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc "HTTP/2 flow control error.".
-spec flow_control_error(term()) -> t().
flow_control_error(Reason) ->
    {error, {http2, #{type => flow_control_error, reason => Reason}}}.

-doc "Received GOAWAY frame with the given error code.".
-spec goaway(nhttp_h2:error_code()) -> t().
goaway(ErrorCode) ->
    {error, {http2, #{type => goaway, error_code => ErrorCode}}}.

-doc "Received GOAWAY frame, marked as retryable.".
-spec goaway(nhttp_h2:error_code(), retryable) -> t().
goaway(ErrorCode, retryable) ->
    {error, {http2, #{type => goaway, error_code => ErrorCode, retryable => true}}}.

-doc "HTTP/2 rate limiting applied by the peer.".
-spec rate_limited() -> t().
rate_limited() ->
    {error, {http2, #{type => rate_limited, retryable => true}}}.

-doc "HTTP/2 stream was cancelled.".
-spec stream_cancelled() -> t().
stream_cancelled() ->
    {error, {http2, #{type => cancelled}}}.

-doc "HTTP/2 stream was closed.".
-spec stream_closed(graceful | term()) -> t().
stream_closed(graceful) ->
    {error, {http2, #{type => stream_closed, reason => graceful}}};
stream_closed(Reason) ->
    {error, {http2, #{type => stream_closed, reason => Reason}}}.

-doc "HTTP/2 stream was refused by the peer (retryable).".
-spec stream_refused() -> t().
stream_refused() ->
    {error, {http2, #{type => refused, retryable => true}}}.

-doc "HTTP/2 stream was reset with the given error code.".
-spec stream_reset(nhttp_h2:error_code()) -> t().
stream_reset(ErrorCode) ->
    {error, {http2, #{type => stream_reset, error_code => ErrorCode}}}.

%%%-----------------------------------------------------------------------------
%% POOL ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc "Timed out waiting for a connection from the pool.".
-spec checkout_timeout() -> t().
checkout_timeout() ->
    {error, {pool, #{type => checkout_timeout}}}.

-doc "No connections available in the pool.".
-spec no_connections() -> t().
no_connections() ->
    {error, {pool, #{type => no_connections_available}}}.

-doc "Connection pool is draining and not accepting new requests.".
-spec pool_draining() -> t().
pool_draining() ->
    {error, {pool, #{type => draining}}}.

-doc "Connection pool is exhausted.".
-spec pool_exhausted(term()) -> t().
pool_exhausted(Reason) ->
    {error, {pool, #{type => exhausted, reason => Reason}}}.

%%%-----------------------------------------------------------------------------
%% FILE/UPLOAD ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc "File operation failed during request processing.".
-spec file_error(atom(), term()) -> t().
file_error(Operation, Reason) ->
    {error, {request, #{type => file_error, operation => Operation, reason => Reason}}}.

-doc "File operation failed for the given path.".
-spec file_error(atom(), file:filename(), term()) -> t().
file_error(Operation, Path, Reason) ->
    {error,
        {request, #{type => file_error, operation => Operation, path => Path, reason => Reason}}}.

-doc "Upload processing failed.".
-spec upload_error(term()) -> t().
upload_error(Reason) ->
    {error, {request, #{type => upload_error, reason => Reason}}}.

%%%-----------------------------------------------------------------------------
%% STREAM ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc "Response stream was stopped by the caller.".
-spec stream_stopped(term()) -> t().
stream_stopped(Reason) ->
    {error, {request, #{type => stream_stopped, reason => Reason}}}.

-doc "Response stream was stopped with accumulated partial data.".
-spec stream_stopped(term(), term()) -> t().
stream_stopped(Reason, Acc) ->
    {error, {request, #{type => stream_stopped, reason => Reason, acc => Acc}}}.

%%%-----------------------------------------------------------------------------
%% SERVER ERROR CONSTRUCTORS
%%%-----------------------------------------------------------------------------
-doc "Accept socket was closed.".
-spec accept_closed() -> t().
accept_closed() ->
    {error, {server, #{type => accept_closed}}}.

-doc "File descriptor limit reached during accept (retryable).".
-spec accept_emfile() -> t().
accept_emfile() ->
    {error, {server, #{type => accept_emfile, retryable => true}}}.

-doc "Accept timed out waiting for a new connection.".
-spec accept_timeout() -> t().
accept_timeout() ->
    {error, {server, #{type => accept_timeout}}}.

-doc "Server is at connection capacity.".
-spec at_capacity() -> t().
at_capacity() ->
    {error, {server, #{type => at_capacity}}}.

-doc "Connection is in the process of closing.".
-spec connection_closing() -> t().
connection_closing() ->
    {error, {server, #{type => connection_closing}}}.

-doc "Send blocked by HTTP/2 flow control window.".
-spec flow_control_blocked(integer(), pos_integer()) -> t().
flow_control_blocked(Window, Size) ->
    {error, {server, #{type => flow_control_blocked, window => Window, size => Size}}}.

-doc "HTTP/2 connection-level error.".
-spec h2_connection_error(atom()) -> t().
h2_connection_error(ErrorCode) ->
    {error, {server, #{type => h2_connection_error, error_code => ErrorCode}}}.

-doc "HTTP/2 protocol error.".
-spec h2_error(term()) -> t().
h2_error(Reason) ->
    {error, {server, #{type => h2_error, reason => Reason}}}.

-doc "Handler init callback failed.".
-spec handler_init_error(term()) -> t().
handler_init_error(Reason) ->
    {error, {server, #{type => handler_init, reason => Reason}}}.

-doc "Listen socket could not be opened.".
-spec listen_failed(inet:posix()) -> t().
listen_failed(Posix) ->
    {error, {server, #{type => listen_failed, posix => Posix}}}.

-doc "Required configuration key is missing.".
-spec missing_config(atom()) -> t().
missing_config(Key) ->
    {error, {server, #{type => missing_config, key => Key}}}.

-doc "Protocol-level error on a server connection.".
-spec protocol_error(atom()) -> t().
protocol_error(Reason) ->
    {error, {server, #{type => protocol_error, reason => Reason}}}.

-doc "Server socket error.".
-spec server_socket_error(inet:posix()) -> t().
server_socket_error(Posix) ->
    {error, {server, #{type => socket_error, posix => Posix}}}.

-doc "Server-side stream was closed.".
-spec server_stream_closed(non_neg_integer()) -> t().
server_stream_closed(StreamId) ->
    {error, {server, #{type => stream_closed, stream_id => StreamId}}}.

-doc "WebSocket protocol error.".
-spec ws_error(term()) -> t().
ws_error(Reason) ->
    {error, {server, #{type => ws_error, reason => Reason}}}.

-doc "WebSocket upgrade handshake failed.".
-spec ws_upgrade_error(term()) -> t().
ws_upgrade_error(Reason) ->
    {error, {server, #{type => ws_upgrade_error, reason => Reason}}}.

%%%-----------------------------------------------------------------------------
%% NORMALIZATION
%%%-----------------------------------------------------------------------------
-doc "Normalize raw errors into structured t() tuples. Converts various error formats from sockets, TLS, and protocol layers into a consistent categorized format.".
-spec normalize(term()) -> t() | {error, term()}.
normalize({error, {connection, _Reason}} = E) ->
    E;
normalize({error, {request, _Reason}} = E) ->
    E;
normalize({error, {http2, _Reason}} = E) ->
    E;
normalize({error, {pool, _Reason}} = E) ->
    E;
normalize({error, Category, Reason}) when is_atom(Category) ->
    {error, {Category, Reason}};
normalize({error, econnrefused}) ->
    connect_refused(econnrefused);
normalize({error, {connect_error, econnrefused}}) ->
    connect_refused(econnrefused);
normalize({error, etimedout}) ->
    connect_timeout();
normalize({error, timeout}) ->
    connect_timeout();
normalize({error, {connect_timeout, _}}) ->
    connect_timeout();
normalize({error, connect_timeout}) ->
    connect_timeout();
normalize({error, {connect_error, Posix}}) when is_atom(Posix) ->
    connect_failed(Posix);
normalize({error, enetunreach}) ->
    connect_failed(enetunreach);
normalize({error, ehostunreach}) ->
    connect_failed(ehostunreach);
normalize({error, eaddrnotavail}) ->
    connect_failed(eaddrnotavail);
normalize({error, {tls_error, Reason}}) ->
    tls_error(Reason);
normalize({error, {ssl, Reason}}) ->
    tls_error(Reason);
normalize({error, {tls_alert, Alert}}) ->
    tls_error({tls_alert, Alert});
normalize({error, {alpn_error, Reason}}) ->
    alpn_error(Reason);
normalize({error, no_alpn_protocol}) ->
    alpn_error(no_protocol);
normalize({error, closed}) ->
    connection_closed();
normalize({error, {closed, unexpected}}) ->
    connection_closed(unexpected);
normalize({error, {request_timeout, Timeout}}) ->
    request_timeout(Timeout);
normalize({error, {body_timeout, Timeout}}) ->
    body_timeout(Timeout);
normalize({error, {send_error, Posix}}) when is_atom(Posix) ->
    send_error(Posix);
normalize({error, {recv_error, Posix}}) when is_atom(Posix) ->
    recv_error(Posix);
normalize({error, econnreset}) ->
    recv_error(econnreset);
normalize({error, epipe}) ->
    send_error(epipe);
normalize({error, {malformed_response, Type, Data}}) ->
    malformed_response(Type, Data);
normalize({error, bad_status_line}) ->
    malformed_response(status_line, <<>>);
normalize({error, bad_header}) ->
    malformed_response(header, <<>>);
normalize({error, {response_too_large, Size, MaxSize}}) ->
    response_too_large(Size, MaxSize);
normalize({error, {body_too_large, Size, MaxSize}}) ->
    response_too_large(Size, MaxSize);
normalize({error, {goaway, ErrorCode}}) ->
    goaway(ErrorCode);
normalize({error, {goaway, ErrorCode, retryable}}) ->
    goaway(ErrorCode, retryable);
normalize({error, {http2_error, {goaway, ErrorCode}}}) ->
    goaway(ErrorCode);
normalize({error, goaway}) ->
    goaway(no_error);
normalize({error, {stream_reset, ErrorCode}}) ->
    stream_reset(ErrorCode);
normalize({error, {rst_stream, ErrorCode}}) ->
    stream_reset(ErrorCode);
normalize({error, cancelled}) ->
    stream_cancelled();
normalize({error, stream_cancelled}) ->
    stream_cancelled();
normalize({error, refused_stream}) ->
    stream_refused();
normalize({error, {refused, retryable}}) ->
    stream_refused();
normalize({error, {flow_control_error, Reason}}) ->
    flow_control_error(Reason);
normalize({error, checkout_timeout}) ->
    checkout_timeout();
normalize({error, {checkout_timeout, _}}) ->
    checkout_timeout();
normalize({error, pool_full}) ->
    pool_exhausted(full);
normalize({error, {pool_exhausted, Reason}}) ->
    pool_exhausted(Reason);
normalize({error, no_connections_available}) ->
    no_connections();
normalize({error, pool_closed}) ->
    pool_exhausted(closed);
normalize({error, {handler_init, Reason}}) ->
    handler_init_error(Reason);
normalize({error, connection_closing}) ->
    connection_closing();
normalize({error, {stream_closed, StreamId}}) when is_integer(StreamId) ->
    server_stream_closed(StreamId);
normalize({error, {flow_control_blocked, Window, Size}}) ->
    flow_control_blocked(Window, Size);
normalize({error, {protocol_error, Reason}}) ->
    protocol_error(Reason);
normalize({error, {socket_error, Posix}}) ->
    server_socket_error(Posix);
normalize({error, {h2_connection_error, ErrorCode}}) ->
    h2_connection_error(ErrorCode);
normalize({error, {h2_error, Reason}}) ->
    h2_error(Reason);
normalize({error, {ws_upgrade_error, Reason}}) ->
    ws_upgrade_error(Reason);
normalize({error, {ws_error, Reason}}) ->
    ws_error(Reason);
normalize({error, {listen_failed, Posix}}) ->
    listen_failed(Posix);
normalize({error, at_capacity}) ->
    at_capacity();
normalize({error, emfile}) ->
    accept_emfile();
normalize({error, missing_port}) ->
    missing_config(port);
normalize({error, missing_handler}) ->
    missing_config(handler);
normalize({error, no_acceptors}) ->
    {error, {server, #{type => no_acceptors}}};
normalize({error, Reason}) ->
    {error, Reason};
normalize(Other) ->
    {error, Other}.

%%%-----------------------------------------------------------------------------
%% CLASSIFICATION
%%%-----------------------------------------------------------------------------
-doc "Get the category of an error.".
-spec category(t() | term()) -> category() | unknown.
category({error, {connection, _}}) ->
    connection;
category({error, {request, _}}) ->
    request;
category({error, {http2, _}}) ->
    http2;
category({error, {pool, _}}) ->
    pool;
category({error, {server, _}}) ->
    server;
category({error, Reason}) when not is_tuple(Reason) ->
    case normalize({error, Reason}) of
        {error, {Category, _}} when is_atom(Category) -> Category;
        _ -> unknown
    end;
category(_) ->
    unknown.

-doc "Check if error is retryable (connection-level or transient). Retryable errors are those where a fresh connection or retry might succeed.".
-spec is_retryable(t() | term()) -> boolean().
is_retryable({error, {connection, _}}) ->
    true;
is_retryable({error, {request, #{type := connection_closed}}}) ->
    true;
is_retryable({error, {request, #{type := recv_error, posix := econnreset}}}) ->
    true;
is_retryable({error, {http2, #{type := goaway}}}) ->
    true;
is_retryable({error, {http2, #{type := refused, retryable := true}}}) ->
    true;
is_retryable({error, {http2, #{type := rate_limited, retryable := true}}}) ->
    true;
is_retryable({error, {pool, #{type := checkout_timeout}}}) ->
    true;
is_retryable({error, econnrefused}) ->
    true;
is_retryable({error, econnreset}) ->
    true;
is_retryable({error, closed}) ->
    true;
is_retryable({error, timeout}) ->
    true;
is_retryable({error, {server, #{type := at_capacity}}}) ->
    true;
is_retryable({error, {server, #{type := accept_emfile}}}) ->
    true;
is_retryable({error, {server, #{type := accept_timeout}}}) ->
    true;
is_retryable({error, {server, _}}) ->
    false;
is_retryable({error, Reason} = E) when is_atom(Reason) ->
    case normalize(E) of
        E -> false;
        Normalized -> is_retryable(Normalized)
    end;
is_retryable(_) ->
    false.

-doc "Check if error is transient (may succeed on immediate retry). Transient errors are a subset of retryable errors where the issue is likely temporary (e.g., connection reset vs. server down).".
-spec is_transient(t() | term()) -> boolean().
is_transient({error, {request, #{type := connection_closed}}}) ->
    true;
is_transient({error, {http2, #{type := goaway, error_code := no_error}}}) ->
    true;
is_transient({error, {http2, #{type := goaway, retryable := true}}}) ->
    true;
is_transient({error, {http2, #{type := refused, retryable := true}}}) ->
    true;
is_transient({error, {request, #{type := recv_error, posix := econnreset}}}) ->
    true;
is_transient({error, closed}) ->
    true;
is_transient({error, econnreset}) ->
    true;
is_transient({error, Reason} = E) when is_atom(Reason) ->
    case normalize(E) of
        E -> false;
        Normalized -> is_transient(Normalized)
    end;
is_transient(_) ->
    false.

%%%-----------------------------------------------------------------------------
%% FORMATTING
%%%-----------------------------------------------------------------------------
-doc "Format error for logging.".
-spec format(t() | term()) -> iodata().
format({error, {connection, #{type := connect_timeout, value := V}}}) ->
    io_lib:format("connection timeout after ~pms", [V]);
format({error, {connection, #{type := connect_timeout}}}) ->
    <<"connection timeout">>;
format({error, {connection, #{type := connect_refused, posix := Posix}}}) ->
    io_lib:format("connection refused: ~p", [Posix]);
format({error, {connection, #{type := connect_failed, posix := Posix}}}) ->
    io_lib:format("connection failed: ~p", [Posix]);
format({error, {connection, #{type := tls_error, reason := Reason}}}) ->
    io_lib:format("TLS error: ~p", [Reason]);
format({error, {connection, #{type := alpn_error, reason := Reason}}}) ->
    io_lib:format("ALPN negotiation failed: ~p", [Reason]);
format({error, {connection, #{type := not_ready}}}) ->
    <<"connection not ready">>;
format({error, {request, #{type := request_timeout, value := V}}}) ->
    io_lib:format("request timeout after ~pms", [V]);
format({error, {request, #{type := request_timeout}}}) ->
    <<"request timeout">>;
format({error, {request, #{type := body_timeout, value := V}}}) ->
    io_lib:format("body timeout after ~pms", [V]);
format({error, {request, #{type := send_error, posix := Posix}}}) ->
    io_lib:format("send error: ~p", [Posix]);
format({error, {request, #{type := recv_error, posix := Posix}}}) ->
    io_lib:format("receive error: ~p", [Posix]);
format({error, {request, #{type := connection_closed, tag := unexpected}}}) ->
    <<"connection closed unexpectedly">>;
format({error, {request, #{type := connection_closed, tag := retryable}}}) ->
    <<"connection closed (retryable)">>;
format({error, {request, #{type := connection_closed}}}) ->
    <<"connection closed">>;
format({error, {request, #{type := malformed_response, parse_error := ParseError}}}) ->
    io_lib:format("malformed response: invalid ~p", [ParseError]);
format({error, {request, #{type := response_too_large, size := Size, max_size := MaxSize}}}) ->
    io_lib:format("response too large: ~p bytes (max ~p)", [Size, MaxSize]);
format({error, {request, #{type := max_redirects_exceeded, count := C}}}) ->
    io_lib:format("max redirects exceeded: ~p", [C]);
format({error, {request, #{type := redirect_loop, url := U}}}) ->
    io_lib:format("redirect loop detected: ~s", [U]);
format({error, {request, #{type := file_error, operation := Op, reason := R}}}) ->
    io_lib:format("file error (~p): ~p", [Op, R]);
format({error, {request, #{type := upload_error, reason := R}}}) ->
    io_lib:format("upload error: ~p", [R]);
format({error, {request, #{type := stream_stopped, reason := R}}}) ->
    io_lib:format("stream stopped: ~p", [R]);
format({error, {http2, #{type := goaway, error_code := EC, retryable := true}}}) ->
    io_lib:format("HTTP/2 GOAWAY (retryable): ~p", [EC]);
format({error, {http2, #{type := goaway, error_code := EC}}}) ->
    io_lib:format("HTTP/2 GOAWAY: ~p", [EC]);
format({error, {http2, #{type := stream_reset, error_code := EC}}}) ->
    io_lib:format("HTTP/2 stream reset: ~p", [EC]);
format({error, {http2, #{type := cancelled}}}) ->
    <<"HTTP/2 stream cancelled">>;
format({error, {http2, #{type := refused, retryable := true}}}) ->
    <<"HTTP/2 stream refused (retryable)">>;
format({error, {http2, #{type := stream_closed, reason := graceful}}}) ->
    <<"HTTP/2 stream closed gracefully">>;
format({error, {http2, #{type := stream_closed, reason := R}}}) ->
    io_lib:format("HTTP/2 stream closed: ~p", [R]);
format({error, {http2, #{type := rate_limited, retryable := true}}}) ->
    <<"HTTP/2 rate limited (retryable)">>;
format({error, {http2, #{type := flow_control_error, reason := R}}}) ->
    io_lib:format("HTTP/2 flow control error: ~p", [R]);
format({error, {pool, #{type := checkout_timeout}}}) ->
    <<"pool checkout timeout">>;
format({error, {pool, #{type := exhausted, reason := R}}}) ->
    io_lib:format("pool exhausted: ~p", [R]);
format({error, {pool, #{type := no_connections_available}}}) ->
    <<"no connections available">>;
format({error, {pool, #{type := draining}}}) ->
    <<"pool draining">>;
format({error, {server, #{type := handler_init, reason := R}}}) ->
    io_lib:format("handler init failed: ~p", [R]);
format({error, {server, #{type := connection_closing}}}) ->
    <<"connection closing">>;
format({error, {server, #{type := stream_closed, stream_id := Id}}}) ->
    io_lib:format("stream ~p closed", [Id]);
format({error, {server, #{type := flow_control_blocked, window := W, size := S}}}) ->
    io_lib:format("flow control blocked: window=~p, size=~p", [W, S]);
format({error, {server, #{type := protocol_error, reason := R}}}) ->
    io_lib:format("protocol error: ~p", [R]);
format({error, {server, #{type := socket_error, posix := P}}}) ->
    io_lib:format("socket error: ~p", [P]);
format({error, {server, #{type := h2_connection_error, error_code := EC}}}) ->
    io_lib:format("HTTP/2 connection error: ~p", [EC]);
format({error, {server, #{type := h2_error, reason := R}}}) ->
    io_lib:format("HTTP/2 error: ~p", [R]);
format({error, {server, #{type := ws_upgrade_error, reason := R}}}) ->
    io_lib:format("WebSocket upgrade error: ~p", [R]);
format({error, {server, #{type := ws_error, reason := R}}}) ->
    io_lib:format("WebSocket error: ~p", [R]);
format({error, {server, #{type := listen_failed, posix := P}}}) ->
    io_lib:format("listen failed: ~p", [P]);
format({error, {server, #{type := accept_timeout}}}) ->
    <<"accept timeout">>;
format({error, {server, #{type := accept_closed}}}) ->
    <<"accept socket closed">>;
format({error, {server, #{type := accept_emfile}}}) ->
    <<"file descriptor limit reached (emfile)">>;
format({error, {server, #{type := at_capacity}}}) ->
    <<"server at capacity">>;
format({error, {server, #{type := missing_config, key := K}}}) ->
    io_lib:format("missing config: ~p", [K]);
format({error, {server, #{type := no_acceptors}}}) ->
    <<"no acceptors available">>;
format({error, {_Category, Reason}}) ->
    io_lib:format("error: ~p", [Reason]);
format({error, Reason}) ->
    io_lib:format("error: ~p", [Reason]);
format(Other) ->
    io_lib:format("~p", [Other]).
