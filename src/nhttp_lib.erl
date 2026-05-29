-module(nhttp_lib).

-moduledoc """
Core HTTP types for the nhttp library.

This module is the umbrella for the type vocabulary used across the
nhttp HTTP framework. Types defined elsewhere are re-exported here as
thin aliases so consumers only ever import from one upstream module.

## Core Types

- `method/0` - HTTP request methods (GET, POST, etc.)
- `version/0` - HTTP version (`http1_0` | `http1_1` | `http2` | `http3`)
- `scheme/0` - URI / wire scheme (`http` | `https` | `ws` | `wss`)
- `authority/0` - Authority component (`host[:port]`)
- `peer/0` - Remote socket address
- `header_name/0` / `header_value/0` - Header field name/value (binary)
- `headers/0` - HTTP headers as a list of name/value pairs
- `status/0` - HTTP response status codes (100-599)
- `stream_id/0` - Transport-level stream identifier (HTTP/2, HTTP/3, QPACK)
- `fin/0` - End-of-stream marker shared by HTTP/2 and HTTP/3
- `role/0` - Connection role (client or server)
- `error_code/0` - Open peer error code: an RFC-defined atom or the raw integer
- `action/0` - Caller-executed I/O action emitted by H2 / H3 codecs
- `error/0` - Unified error shape across H2 and H3
- `event_common/0` - Shape-shared events emitted by both H2 and H3 codecs
- `event_h2/0` - Alias for `t:nhttp_h2:event/0`
- `event_h3/0` - Alias for `t:nhttp_h3:event/0`
- `event/0` - Cross-protocol union; prefer `event_h2/0` or `event_h3/0`
- `request/0` - Canonical HTTP request shape across H1, H2, and H3
- `response/0` - Canonical HTTP response shape across H1, H2, and H3

The `version` field on `request/0` and `response/0` records the HTTP
version (`http1_0` | `http1_1` | `http2` | `http3`) and is filled by
every server parser. The `scheme` field is `http` or `https` on the
wire; `ws`/`wss` only appear when a client preserved the URI scheme as
parsed from a URL. WebSocket upgrades ride on `http`/`https` with
`Upgrade: websocket` (H1) or `:protocol = websocket` (H2/H3 Extended
CONNECT, RFC 8441 §4 / RFC 9220 §3).

The `connect_protocol` field on `request/0` carries the RFC 8441 / 9220
`:protocol` pseudo-header sent on Extended CONNECT requests
(`<<"websocket">>` for the WS upgrade case). It is independent of the
wire `version` field above and is only present when the peer sent
`:protocol`.

The `body` field is for the convenience case where the whole payload is
already in memory. The `streaming` atom signals that the body is being
fed chunk-by-chunk through the streaming-body callback (see
`nhttp_h1:parse_request_headers/2` and `parse_request_body/2`).

The `trailers` field is the symmetric convenience for trailing header
fields (RFC 9110 §6.5) when sent alongside an in-memory body. For
streaming, emit trailers separately after the body. H1 emits trailer
fields between `encode_last_chunk/0` and the closing CRLF; H2 / H3
emit them via a final `send_headers/4` call with `fin`.

## WebSocket umbrella re-exports

WS frame, message, and option types live in `nhttp_ws` / `nhttp_ws_frame`
and are re-exported here as aliases (`ws_message/0`, `ws_frame/0`,
`close_code/0`, `ws_send_opts/0`, `ws_session_opts/0`,
`ws_runtime_opts/0`, `ws_close_opts/0`).
""".

-export([
    decode_method/1,
    decode_scheme/1,
    encode_method/1,
    encode_scheme/1,
    request_to_pseudo_headers/1
]).

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    action/0,
    authority/0,
    error/0,
    error_code/0,
    event/0,
    event_common/0,
    event_h2/0,
    event_h3/0,
    fin/0,
    header_name/0,
    header_value/0,
    headers/0,
    method/0,
    peer/0,
    request/0,
    response/0,
    role/0,
    scheme/0,
    status/0,
    stream_id/0,
    version/0
]).

-export_type([
    close_code/0,
    ws_close_opts/0,
    ws_frame/0,
    ws_message/0,
    ws_runtime_opts/0,
    ws_send_opts/0,
    ws_session_opts/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type method() ::
    get
    | head
    | post
    | put
    | delete
    | connect
    | options
    | trace
    | patch
    | binary().

-type version() :: http1_0 | http1_1 | http2 | http3.

-type scheme() :: http | https | ws | wss.

-type authority() :: binary().

-type peer() :: {inet:ip_address(), inet:port_number()}.

-type header_name() :: binary().

-type header_value() :: binary().

-type status() :: 100..599.

-type headers() :: [{header_name(), header_value()}].

-type stream_id() :: non_neg_integer().

-type fin() :: fin | nofin.

-type role() :: client | server.

-type error_code() :: atom() | non_neg_integer().

-type action() ::
    {send, stream_id() | connection, iodata()}
    | {send_fin, stream_id(), iodata()}
    | {close, error_code(), binary()}.

-type error() ::
    {connection_error, error_code(), binary()}
    | {stream_error, stream_id(), error_code(), binary()}
    | {protocol_violation, atom(), binary()}.

-type event_common() ::
    {request, stream_id(), request(), fin()}
    | {response, stream_id(), response(), fin()}
    | {data, stream_id(), binary(), fin()}
    | {trailers, stream_id(), headers()}
    | {stream_reset, stream_id(), error_code()}
    | {goaway, stream_id(), error_code(), binary()}.

-type event_h2() :: nhttp_h2:event().

-type event_h3() :: nhttp_h3:event().

-type event() :: event_h2() | event_h3().

-type request() :: #{
    method := method(),
    path := binary(),
    scheme := scheme(),
    authority := authority(),
    headers := headers(),
    peer => peer(),
    version => version(),
    body => iodata() | streaming,
    trailers => headers(),
    connect_protocol => binary()
}.

-type response() :: #{
    status := status(),
    version => version(),
    reason => binary(),
    headers := headers(),
    body => iodata(),
    trailers => headers()
}.

-type close_code() :: nhttp_ws:close_code().

-type ws_close_opts() :: nhttp_ws:ws_close_opts().

-type ws_frame() :: nhttp_ws:ws_frame().

-type ws_message() :: nhttp_ws:ws_message().

-type ws_runtime_opts() :: nhttp_ws:ws_runtime_opts().

-type ws_send_opts() :: nhttp_ws:ws_send_opts().

-type ws_session_opts() :: nhttp_ws:ws_session_opts().

%%%-----------------------------------------------------------------------------
%% CODECS
%%%-----------------------------------------------------------------------------
-doc """
Decode an HTTP method from its wire binary form. Known methods become
the corresponding atom (`get`, `post`, ...); unknown methods stay as
the input binary.
""".
-spec decode_method(binary()) -> method().
decode_method(<<"GET">>) -> get;
decode_method(<<"HEAD">>) -> head;
decode_method(<<"POST">>) -> post;
decode_method(<<"PUT">>) -> put;
decode_method(<<"DELETE">>) -> delete;
decode_method(<<"CONNECT">>) -> connect;
decode_method(<<"OPTIONS">>) -> options;
decode_method(<<"TRACE">>) -> trace;
decode_method(<<"PATCH">>) -> patch;
decode_method(M) when is_binary(M) -> M.

-doc """
Decode a scheme from its binary form. Strict: crashes with
`function_clause` on unknown values. The closed `t:scheme/0` union is
enforced here, so callers must validate untrusted input first (or wrap
the call in `try/catch`).
""".
-spec decode_scheme(binary()) -> scheme().
decode_scheme(<<"http">>) -> http;
decode_scheme(<<"https">>) -> https;
decode_scheme(<<"ws">>) -> ws;
decode_scheme(<<"wss">>) -> wss.

-doc "Encode an HTTP method to its wire binary form (`get` -> `<<\"GET\">>`).".
-spec encode_method(method()) -> binary().
encode_method(get) -> <<"GET">>;
encode_method(head) -> <<"HEAD">>;
encode_method(post) -> <<"POST">>;
encode_method(put) -> <<"PUT">>;
encode_method(delete) -> <<"DELETE">>;
encode_method(connect) -> <<"CONNECT">>;
encode_method(options) -> <<"OPTIONS">>;
encode_method(trace) -> <<"TRACE">>;
encode_method(patch) -> <<"PATCH">>;
encode_method(M) when is_binary(M) -> M.

-doc "Encode a URI / wire scheme to its binary form.".
-spec encode_scheme(scheme()) -> binary().
encode_scheme(http) -> <<"http">>;
encode_scheme(https) -> <<"https">>;
encode_scheme(ws) -> <<"ws">>;
encode_scheme(wss) -> <<"wss">>.

-doc """
Build the pseudo-header prefix plus regular headers for an HTTP/2 or
HTTP/3 request, ready to feed into `nhttp_h2:send_headers/4` or
`nhttp_h3:send_headers/4`.
Pseudo-header order is `:method`, `:scheme`, `:authority`, `:path`,
the conventional order; HTTP/2 (RFC 9113 §8.3) and HTTP/3 (RFC 9114
§4.3) require only that pseudo-headers precede regular fields.
The `Host` header is filtered out of the regular set because its value
already lives in `:authority` (which is required on `t:request/0`).
Other headers are passed through in their original order.
Extended CONNECT (RFC 8441 / 9220) is supported by leaving any
caller-supplied `{<<\":protocol\">>, _}` entry in the request's
`headers` list. The helper does not touch entries other than `Host`.
""".
-spec request_to_pseudo_headers(request()) -> headers().
request_to_pseudo_headers(
    #{method := M, path := P, scheme := S, authority := A, headers := H}
) ->
    [
        {<<":method">>, encode_method(M)},
        {<<":scheme">>, encode_scheme(S)},
        {<<":authority">>, A},
        {<<":path">>, P}
        | nhttp_headers:delete(<<"host">>, H)
    ].
