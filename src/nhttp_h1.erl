-module(nhttp_h1).

-moduledoc """
HTTP/1.1 codec module - High-performance binary:split implementation.

Provides parsing and encoding for HTTP/1.1 requests and responses.
Uses binary:split BIF for optimal parsing performance.

## Parsing

Parsing functions return `{ok, Result, BytesConsumed}` where BytesConsumed
is the number of bytes consumed from the input. Use `split_at/2` to get
the remaining buffer:

```erlang
{ok, Request, Consumed} = nhttp_h1:parse_request(Binary),
Rest = nhttp_h1:split_at(Binary, Consumed).
```

This pattern is optimal for performance as it avoids creating intermediate
binaries until the consumer explicitly needs the remainder.

For incomplete data, parsing returns `{more, MinBytes}` where MinBytes
is a hint for how many more bytes might be needed.

## Options

The `opts()` map supports the following limits:

- `max_header_size` - Maximum total size of all headers in bytes (default: infinity)
- `max_headers_count` - Maximum number of headers (default: infinity)
- `max_body_size` - Maximum body size in bytes (default: infinity)

When a limit is exceeded, parsing returns `{error, header_too_large}`,
`{error, too_many_headers}`, or `{error, {body_too_large, Size, Max}}`
respectively.

With `max_header_size` set, an incomplete request head is also rejected
as `header_too_large` once the buffered input exceeds `max_header_size`
plus an 8 KiB request-line allowance: a head that never terminates (for
example a header line with no CRLF) cannot grow the caller's buffer
without bound. The same budget bounds chunked trailer sections, and
chunk-size lines longer than 1 KiB are rejected as
`invalid_chunk_size`.

```erlang
Opts = #{max_header_size => 8192, max_headers_count => 100, max_body_size => 1048576},
case nhttp_h1:parse_request(Binary, Opts) of
    {ok, Request, Consumed} -> handle_request(Request);
    {error, header_too_large} -> respond_413();
    {error, too_many_headers} -> respond_431();
    {error, {body_too_large, _Size, _Max}} -> respond_413()
end.
```

## Encoding

```erlang
{ok, IOList} = nhttp_h1:encode_request(Request).
{ok, IOList} = nhttp_h1:encode_response(Response).
```

The encoders validate what they serialise and return
`{error, t:encode_error/0}` for a field name that is not a token, a field
value or reason phrase that carries CR, LF, NUL, or another control byte,
and a request target that carries a byte at or below `0x20`. RFC 9112
Section 11.1 names that filter as the mitigation for response splitting and
request smuggling. A refused message is never repaired and never truncated.

`encode_request/1` and `encode_response/1` consume the canonical
`t:nhttp_lib:request/0` / `t:nhttp_lib:response/0` map shape. The `body`
field is for the convenience case where the whole payload fits in
memory: it is emitted inline after the header block and a
`Content-Length` is derived if neither `Content-Length` nor
`Transfer-Encoding` is present in `headers`.

For streaming bodies, do not populate `body` in the map. Send the
header block first via `encode_response_head/3`, then emit each chunk
via `encode_chunk/1`, then close the body with `encode_last_chunk/0`
(set `Transfer-Encoding: chunked` in the headers). The same staged
pattern applies to chunked requests.
""".

-compile(
    {inline, [
        trim_ows/1,
        encode_version/1
    ]}
).

%%%-----------------------------------------------------------------------------
%% PARSING
%%%-----------------------------------------------------------------------------
-export([
    body_stream_from_response/3,
    finalize_response_body/1,
    parse_request/1,
    parse_request/2,
    parse_request_body/2,
    parse_request_headers/1,
    parse_request_headers/2,
    parse_response/1,
    parse_response/2,
    parse_response_body/2,
    parse_response_head/1,
    parse_response_head/2,
    parse_response_headers/1,
    parse_response_headers/2
]).

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-export([
    encode_chunk/1,
    encode_last_chunk/0,
    encode_request/1,
    encode_response/1,
    encode_response/2,
    encode_response_head/3
]).

%%%-----------------------------------------------------------------------------
%% UTILITIES
%%%-----------------------------------------------------------------------------
-export([
    split_at/2
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-export_type([
    body_chunk/0,
    body_mode/0,
    body_stream/0,
    chunked_st/0,
    enc_opts/0,
    encode_error/0,
    opts/0,
    parse_error/0,
    parse_result/1,
    req/0,
    resp/0,
    version/0
]).

-type version() :: http1_0 | http1_1.

-type req() :: nhttp_lib:request().

-type resp() :: nhttp_lib:response().

-type body_mode() ::
    undefined
    | {content_length, non_neg_integer()}
    | chunked.

-type body_chunk() ::
    {data, binary()}
    | {fin, nhttp_lib:headers()}
    | {abort, nhttp_lib:error()}.

-type body_stream() ::
    {chunked, chunked_st()}
    | {length, non_neg_integer()}
    | until_close
    | none.

-doc """
Encoder options for `encode_response/2`.

`content_length` selects how the encoder frames a response:

- `auto` (the default) adds `Content-Length` when the header list carries
  neither `content-length` nor `transfer-encoding`, and the status permits
  the field.
- `omit` suppresses the automatic field at any status. A server that
  answers a `CONNECT` request with a 2xx status uses it, because RFC 9110
  Section 8.6 forbids the field there and the response map carries no
  request method.
""".
-type enc_opts() :: #{content_length => auto | omit}.

-doc """
Reason an encoder refuses to serialise a message.

Each arm carries the offending value so that the caller can log it. The
encoder never repairs the value and never strips a byte from it.
""".
-type encode_error() ::
    {invalid_field_name, binary()}
    | {invalid_field_value, binary()}
    | {invalid_reason_phrase, binary()}
    | {invalid_request_target, binary()}.

-type opts() :: #{
    max_header_size => pos_integer(),
    max_headers_count => pos_integer(),
    max_body_size => pos_integer(),
    scheme => nhttp_lib:scheme(),
    peer => nhttp_lib:peer()
}.

-type parse_error() ::
    bad_request_line
    | bad_status_line
    | bad_header
    | header_too_large
    | too_many_headers
    | {body_too_large, Size :: non_neg_integer(), Max :: non_neg_integer()}
    | invalid_content_length
    | duplicate_content_length
    | conflicting_framing
    | unsupported_transfer_encoding
    | invalid_chunk_size
    | incomplete_chunk
    | invalid_method
    | invalid_version
    | unexpected_eof
    | {protocol_error, term()}.

-type header_limit() :: pos_integer() | infinity.

-type parse_result(T) ::
    {ok, T, BytesConsumed :: pos_integer()}
    | {more, MinBytes :: pos_integer()}
    | {error, parse_error()}.
-record(chunked_st, {
    phase = size :: size | {data, non_neg_integer()} | trailers,
    trailers_acc = [] :: nhttp_lib:headers(),
    headers_size = 0 :: non_neg_integer(),
    max_header_size = infinity :: header_limit(),
    max_headers_count = infinity :: header_limit(),
    max_body_size = infinity :: header_limit(),
    body_size = 0 :: non_neg_integer()
}).

-opaque chunked_st() :: #chunked_st{}.

%%%-----------------------------------------------------------------------------
%% LOCAL MACROS
%%%-----------------------------------------------------------------------------
-define(REQUEST_LINE_ALLOWANCE, 8192).
-define(MAX_CHUNK_SIZE_LINE, 1024).

%%%-----------------------------------------------------------------------------
%% COMPILED PATTERNS
%%%-----------------------------------------------------------------------------
-define(PT_CRLF, {?MODULE, crlf_pattern}).
-define(PT_COLON, {?MODULE, colon_pattern}).
-define(PT_URI_DELIMS, {?MODULE, uri_delims_pattern}).
-define(PT_NON_TCHAR, {?MODULE, non_tchar_pattern}).
-define(PT_FIELD_VALUE_BAD, {?MODULE, field_value_bad_pattern}).
-define(PT_TARGET_BAD, {?MODULE, target_bad_pattern}).

-on_load(init_patterns/0).

-spec init_patterns() -> ok.
init_patterns() ->
    ok = persistent_term:put(?PT_CRLF, binary:compile_pattern(<<"\r\n">>)),
    ok = persistent_term:put(?PT_COLON, binary:compile_pattern(<<":">>)),
    ok = persistent_term:put(
        ?PT_URI_DELIMS, binary:compile_pattern([<<"/">>, <<"?">>, <<"#">>])
    ),
    ok = persistent_term:put(?PT_NON_TCHAR, binary:compile_pattern(non_tchar_bytes())),
    ok = persistent_term:put(
        ?PT_FIELD_VALUE_BAD, binary:compile_pattern(field_value_bad_bytes())
    ),
    ok = persistent_term:put(?PT_TARGET_BAD, binary:compile_pattern(target_bad_bytes())),
    ok.

%% RFC 9110 Section 5.6.2: a token is 1*tchar. The pattern is the complement
%% of the tchar set, so `nhttp_headers:is_tchar/1` stays the one definition.
-spec non_tchar_bytes() -> [binary(), ...].
non_tchar_bytes() ->
    [<<C>> || C <- lists:seq(0, 255), not nhttp_headers:is_tchar(C)].

%% RFC 9110 Section 5.5: a field value is *( field-vchar [ 1*( SP / HTAB )
%% field-vchar ] ), so every control byte other than HTAB, and DEL, is out.
-spec field_value_bad_bytes() -> [binary(), ...].
field_value_bad_bytes() ->
    [<<C>> || C <- lists:seq(16#00, 16#1F), C =/= $\t] ++ [<<16#7F>>].

%% RFC 9112 Section 3.2: a request target carries no whitespace and no
%% control byte.
-spec target_bad_bytes() -> [binary(), ...].
target_bad_bytes() ->
    [<<C>> || C <- lists:seq(16#00, 16#20)] ++ [<<16#7F>>].

%%%-----------------------------------------------------------------------------
%% PARSING
%%%-----------------------------------------------------------------------------
-doc """
Compute the response body framing mode from the request method, response
status, and response headers (RFC 9112 §6.3).

Pure helper: pass the values parsed by `parse_response_headers/1,2` plus
the method of the matching request. The returned `body_stream()` is fed
into `parse_response_body/2`.

Framing rules in order:

- `HEAD` request → `none` (HEAD responses never have a body).
- 1xx, 204, 304 status → `none`.
- `Transfer-Encoding` with `chunked` as the single final coding →
  `{chunked, _}`. Every `Transfer-Encoding` field line contributes to the
  coding list, in order of receipt (RFC 9110 §5.3).
- `Transfer-Encoding` with any other coding list → `until_close`
  (RFC 9112 §6.3 #4).
- `Content-Length: N` → `{length, N}`.
- otherwise → `until_close` (RFC 9112 §6.3 #7).

The chunked / length walkers do not enforce header or body size limits in
this entry point. Callers reading from untrusted peers should validate
sizes at the recv site or wrap the stream.
""".
-spec body_stream_from_response(
    nhttp_lib:method(), nhttp_lib:status(), nhttp_lib:headers()
) -> body_stream().
body_stream_from_response(head, _Status, _Headers) ->
    none;
body_stream_from_response(_Method, Status, _Headers) when
    Status >= 100, Status =< 199; Status =:= 204; Status =:= 304
->
    none;
body_stream_from_response(_Method, _Status, Headers) ->
    detect_response_body_stream(Headers).

-spec detect_response_body_stream(nhttp_lib:headers()) -> body_stream().
detect_response_body_stream(Headers) ->
    case transfer_codings(Headers) of
        absent -> content_length_body_stream(Headers);
        Codings -> chunked_body_stream(Codings)
    end.

-doc """
Signal end-of-stream for a response body parse driven by
`parse_response_body/2`.
Used to terminate `until_close` framing when the underlying transport
closes, and to surface mid-body framing errors for `{length, _}` and
`{chunked, _}`.
- `none`, `{length, 0}`, or `until_close` → `{ok, [{fin, []}]}`.
- `{length, N>0}` → `{error, unexpected_eof}`.
- `{chunked, _}` mid-body → `{error, unexpected_eof}`.
""".
-spec finalize_response_body(body_stream()) ->
    {ok, [body_chunk()]} | {error, parse_error()}.
finalize_response_body(none) ->
    {ok, [{fin, []}]};
finalize_response_body({length, 0}) ->
    {ok, [{fin, []}]};
finalize_response_body({length, _Remaining}) ->
    {error, unexpected_eof};
finalize_response_body({chunked, _St}) ->
    {error, unexpected_eof};
finalize_response_body(until_close) ->
    {ok, [{fin, []}]}.

-doc "Parse an HTTP/1.1 request from binary. Returns {ok, Request, BytesConsumed} on success. Use split_at/2 to get the remaining buffer.".
-spec parse_request(binary()) -> parse_result(req()).
parse_request(<<Data/binary>>) ->
    parse_request(Data, #{}).

-doc "Parse HTTP/1.1 request with options. Options can include: max_header_size, max_headers_count, max_body_size.".
-spec parse_request(binary(), opts()) -> parse_result(req()).
parse_request(<<>>, _Opts) ->
    {more, 1};
parse_request(<<Bin/binary>>, Opts) ->
    OriginalSize = byte_size(Bin),
    MaxHeaderSize = maps:get(max_header_size, Opts, infinity),
    MaxHeadersCount = maps:get(max_headers_count, Opts, infinity),
    Result =
        maybe
            {ok, Method, Path, Version, Rest} ?= parse_request_line(Bin),
            {ok, Headers, BodyRest} ?=
                parse_headers_acc(Rest, [], 0, MaxHeaderSize, MaxHeadersCount),
            HeadersConsumed = OriginalSize - byte_size(BodyRest),
            Req = build_request(Method, Path, Version, Headers, Opts),
            finish_request(Req, BodyRest, Headers, HeadersConsumed, Opts)
        end,
    cap_incomplete_head(Result, OriginalSize, MaxHeaderSize).

-doc """
Feed body bytes for a streaming request whose headers were parsed via
`parse_request_headers/1,2`.
Returns one of:
- `{ok, Chunks, NewStream, BytesConsumed}`: emits zero or more
  `body_chunk()` events. A `{fin, Trailers}` chunk signals the body is
  fully consumed; subsequent calls on the returned stream are not needed.
- `{more, MinBytes, NewStream}`: not enough buffer to make progress.
  The caller should buffer at least `MinBytes` more bytes and call again
  with the same `NewStream`.
- `{error, parse_error()}`: framing error (bad chunk size, body too
  large, header limits exceeded in trailers).
""".
-spec parse_request_body(binary(), body_stream()) ->
    {ok, [body_chunk()], body_stream(), non_neg_integer()}
    | {more, pos_integer(), body_stream()}
    | {error, parse_error()}.
parse_request_body(_Bin, none) ->
    {ok, [{fin, []}], none, 0};
parse_request_body(<<Bin/binary>>, {length, 0}) ->
    _ = Bin,
    {ok, [{fin, []}], none, 0};
parse_request_body(<<>>, {length, Remaining}) ->
    {more, Remaining, {length, Remaining}};
parse_request_body(<<Bin/binary>>, {length, Remaining}) ->
    Available = byte_size(Bin),
    case Available >= Remaining of
        true ->
            <<Body:Remaining/binary, _/binary>> = Bin,
            {ok, [{data, Body}, {fin, []}], none, Remaining};
        false ->
            {ok, [{data, Bin}], {length, Remaining - Available}, Available}
    end;
parse_request_body(<<Bin/binary>>, {chunked, St}) ->
    parse_chunked_stream(Bin, 0, [], St).

-doc """
> #### Warning {: .warning}
> This zero-arg variant enforces **no** size or count limits on the input
> and is unsafe to use against untrusted peers. Production callers reading
> from the network MUST use `parse_request_headers/2` and pass
> `max_header_size`, `max_headers_count`, and `max_body_size` (see
> `t:opts/0`).
Parse HTTP/1.1 request headers only, without consuming the body. Returns
`{ok, Request, BodyStream, BytesConsumed}`. The returned request map has
`body => streaming`; the body bytes (if any) are read separately via
`parse_request_body/2`.
""".
-doc #{equiv => parse_request_headers / 2}.
-spec parse_request_headers(binary()) ->
    {ok, req(), body_stream(), non_neg_integer()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_request_headers(<<Bin/binary>>) ->
    parse_request_headers(Bin, #{}).

-doc """
Parse HTTP/1.1 request headers only, without consuming the body, enforcing
the supplied limits. Returns `{ok, Request, BodyStream, BytesConsumed}`.
The body framing mode is encoded in `BodyStream`:
- `none`: no body (no `Content-Length`, no `Transfer-Encoding`, or
  `Content-Length: 0`).
- `{length, N}`: `N` body bytes remain to be read.
- `{chunked, _}`: chunked transfer encoding; opaque state to feed back
  into `parse_request_body/2`.
The returned request map carries `body => streaming` instead of buffered
bytes. Use `parse_request_body/2` to drive the body stream.

Every `Transfer-Encoding` field line contributes to one coding list, in
order of receipt (RFC 9110 §5.3). The parser returns
`{error, unsupported_transfer_encoding}` unless that list holds `chunked`
exactly once, as the final coding (RFC 9112 §6.1 and §6.3 #4).
""".
-spec parse_request_headers(binary(), opts()) ->
    {ok, req(), body_stream(), non_neg_integer()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_request_headers(<<>>, _Opts) ->
    {more, 1};
parse_request_headers(<<Bin/binary>>, Opts) ->
    OriginalSize = byte_size(Bin),
    MaxHeaderSize = maps:get(max_header_size, Opts, infinity),
    MaxHeadersCount = maps:get(max_headers_count, Opts, infinity),
    MaxBodySize = maps:get(max_body_size, Opts, infinity),
    Result =
        maybe
            {ok, Method, Path, Version, Rest} ?= parse_request_line(Bin),
            {ok, Headers, BodyRest} ?=
                parse_headers_acc(Rest, [], 0, MaxHeaderSize, MaxHeadersCount),
            HeadersConsumed = OriginalSize - byte_size(BodyRest),
            Req0 = build_request(Method, Path, Version, Headers, Opts),
            Req = Req0#{body => streaming},
            case detect_body_mode(Headers) of
                undefined ->
                    {ok, Req, none, HeadersConsumed};
                {content_length, Len} ->
                    case check_body_size(Len, MaxBodySize) of
                        ok -> {ok, Req, {length, Len}, HeadersConsumed};
                        {error, _} = Err -> Err
                    end;
                chunked ->
                    St = #chunked_st{
                        max_header_size = MaxHeaderSize,
                        max_headers_count = MaxHeadersCount,
                        max_body_size = MaxBodySize
                    },
                    {ok, Req, {chunked, St}, HeadersConsumed};
                {error, _} = Err ->
                    Err
            end
        end,
    cap_incomplete_head(Result, OriginalSize, MaxHeaderSize).

-doc "Parse an HTTP/1.1 response from binary. Returns {ok, Response, BytesConsumed} on success. Use split_at/2 to get the remaining buffer.".
-spec parse_response(binary()) -> parse_result(resp()).
parse_response(<<Data/binary>>) ->
    parse_response(Data, #{}).

-doc "Parse HTTP/1.1 response with options. Options can include: max_header_size, max_headers_count, max_body_size.".
-spec parse_response(binary(), opts()) -> parse_result(resp()).
parse_response(<<>>, _Opts) ->
    {more, 1};
parse_response(<<Bin/binary>>, Opts) ->
    OriginalSize = byte_size(Bin),
    MaxHeaderSize = maps:get(max_header_size, Opts, infinity),
    MaxHeadersCount = maps:get(max_headers_count, Opts, infinity),
    maybe
        {ok, Status, Reason, Version, Rest} ?= parse_status_line(Bin),
        {ok, Headers, BodyRest} ?= parse_headers_acc(Rest, [], 0, MaxHeaderSize, MaxHeadersCount),
        HeadersConsumed = OriginalSize - byte_size(BodyRest),
        Resp = #{
            status => Status,
            reason => Reason,
            version => Version,
            headers => Headers,
            body => <<>>
        },
        finish_response(Resp, BodyRest, Headers, HeadersConsumed, Opts)
    end.

-doc """
Feed body bytes for a streaming response whose headers were parsed via
`parse_response_headers/1,2` and whose framing mode was selected via
`body_stream_from_response/3`.
For `none` and `{length, 0}`, returns `{ok, [{fin, []}], none, 0}`.
For `{length, N>0}` and `{chunked, _}`, behaves identically to
`parse_request_body/2`.
For `until_close`, emits `[{data, _}]` for whatever bytes are in the
buffer and keeps the stream open. The caller must signal EOF via
`finalize_response_body/1` when the underlying transport closes.
""".
-spec parse_response_body(binary(), body_stream()) ->
    {ok, [body_chunk()], body_stream(), non_neg_integer()}
    | {more, pos_integer(), body_stream()}
    | {error, parse_error()}.
parse_response_body(_Bin, none) ->
    {ok, [{fin, []}], none, 0};
parse_response_body(<<Bin/binary>>, {length, 0}) ->
    _ = Bin,
    {ok, [{fin, []}], none, 0};
parse_response_body(<<>>, {length, Remaining}) ->
    {more, Remaining, {length, Remaining}};
parse_response_body(<<Bin/binary>>, {length, Remaining}) ->
    Available = byte_size(Bin),
    case Available >= Remaining of
        true ->
            <<Body:Remaining/binary, _/binary>> = Bin,
            {ok, [{data, Body}, {fin, []}], none, Remaining};
        false ->
            {ok, [{data, Bin}], {length, Remaining - Available}, Available}
    end;
parse_response_body(<<Bin/binary>>, {chunked, St}) ->
    parse_chunked_stream(Bin, 0, [], St);
parse_response_body(<<>>, until_close) ->
    {more, 1, until_close};
parse_response_body(<<Bin/binary>>, until_close) ->
    Size = byte_size(Bin),
    {ok, [{data, Bin}], until_close, Size}.

-doc """
> #### Warning {: .warning}
> This zero-arg variant enforces **no** size or count limits on the input
> and is unsafe to use against untrusted peers. A malicious response can
> exhaust memory by sending arbitrarily many or arbitrarily large header
> fields. Production callers reading from the network MUST use
> `parse_response_headers/2` and pass `max_header_size` and
> `max_headers_count` (see `t:opts/0`).
Parse HTTP/1.1 response headers only, without body. Returns
`{ok, Status, Headers, Rest}` where `Rest` is the binary after headers.
Used for streaming responses where the body is read separately.
""".
-doc #{equiv => parse_response_headers / 2}.
-spec parse_response_headers(binary()) ->
    {ok, nhttp_lib:status(), nhttp_lib:headers(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_response_headers(<<Bin/binary>>) ->
    parse_response_headers(Bin, #{}).

-doc """
Parse HTTP/1.1 response headers only, without body, enforcing the supplied
limits (`max_header_size`, `max_headers_count`).
""".
-spec parse_response_headers(binary(), opts()) ->
    {ok, nhttp_lib:status(), nhttp_lib:headers(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_response_headers(<<>>, _Opts) ->
    {more, 1};
parse_response_headers(<<Bin/binary>>, Opts) ->
    MaxHeaderSize = maps:get(max_header_size, Opts, infinity),
    MaxHeadersCount = maps:get(max_headers_count, Opts, infinity),
    maybe
        {ok, Status, _Reason, _Version, Rest} ?= parse_status_line(Bin),
        {ok, Headers, BodyRest} ?=
            parse_headers_acc(Rest, [], 0, MaxHeaderSize, MaxHeadersCount),
        {ok, Status, Headers, BodyRest}
    end.

-doc #{equiv => parse_response_head / 2}.
-spec parse_response_head(binary()) ->
    {ok, nhttp_lib:status(), binary(), version(), nhttp_lib:headers(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_response_head(<<Bin/binary>>) ->
    parse_response_head(Bin, #{}).

-doc """
Parse HTTP/1.1 response headers only, like `parse_response_headers/2`, but
also return the reason phrase and protocol version from the status line.
Returns `{ok, Status, Reason, Version, Headers, Rest}` where `Rest` is the
binary after the headers. Used by streaming callers that must preserve the
full response head (status, reason, version) while reading the body
separately via `parse_response_body/2`.
""".
-spec parse_response_head(binary(), opts()) ->
    {ok, nhttp_lib:status(), binary(), version(), nhttp_lib:headers(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_response_head(<<>>, _Opts) ->
    {more, 1};
parse_response_head(<<Bin/binary>>, Opts) ->
    MaxHeaderSize = maps:get(max_header_size, Opts, infinity),
    MaxHeadersCount = maps:get(max_headers_count, Opts, infinity),
    maybe
        {ok, Status, Reason, Version, Rest} ?= parse_status_line(Bin),
        {ok, Headers, BodyRest} ?=
            parse_headers_acc(Rest, [], 0, MaxHeaderSize, MaxHeadersCount),
        {ok, Status, Reason, Version, Headers, BodyRest}
    end.

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc "Encode a chunk for chunked transfer encoding.".
-spec encode_chunk(iodata()) -> iolist().
encode_chunk(Data) when is_binary(Data) ->
    Size = integer_to_binary(byte_size(Data), 16),
    [Size, <<"\r\n">>, Data, <<"\r\n">>];
encode_chunk(Data) when is_list(Data) ->
    Size = integer_to_binary(iolist_size(Data), 16),
    [Size, <<"\r\n">>, Data, <<"\r\n">>].

-doc "Encode the final (zero-length) chunk.".
-spec encode_last_chunk() -> binary().
encode_last_chunk() ->
    <<"0\r\n\r\n">>.

-doc """
Encode an HTTP/1.1 request to iolist.

The encoder refuses a message that cannot be framed unambiguously on the
wire. It returns `{error, {invalid_request_target, Target}}` for a target
that is empty or that carries a byte at or below `0x20` or the byte `0x7F`,
`{error, {invalid_field_name, Name}}` for a field name that is not a token
(RFC 9110 Section 5.6.2), and `{error, {invalid_field_value, Value}}` for a
field value that carries CR, LF, NUL, another control byte, or `0x7F`
(RFC 9110 Section 5.5).

RFC 9112 Section 2.2 forbids a sender to generate a bare CR in any protocol
element other than the content, and Section 11.1 names this filtering as the
mitigation for request smuggling and response splitting. No value is
repaired and no byte is stripped. The message is refused whole.
""".
-spec encode_request(req()) -> {ok, iolist()} | {error, encode_error()}.
encode_request(#{method := Method, path := Path} = Req) ->
    Headers = maps:get(headers, Req, []),
    maybe
        ok ?= validate_request_target(Path),
        Version = maps:get(version, Req, http1_1),
        Body = maps:get(body, Req, <<>>),
        Len = iolist_size(Body),
        FinalHeaders = maybe_add_content_length(Headers, Len, Len > 0),
        {ok, EncHeaders} ?= encode_headers(FinalHeaders),
        {ok, [
            nhttp_lib:encode_method(Method),
            <<" ">>,
            Path,
            <<" ">>,
            encode_version(Version),
            <<"\r\n">>,
            EncHeaders,
            <<"\r\n">>,
            Body
        ]}
    end.

-doc """
Encode an HTTP/1.1 response to iolist.

Equivalent to `encode_response(Resp, #{})`. The encoder adds
`Content-Length` when the header list carries neither `content-length` nor
`transfer-encoding`, including a `Content-Length: 0` on an empty body.

The encoder adds no `Content-Length` at a 1xx, 204, or 304 status. RFC 9110
Section 8.6 forbids the field at 1xx and 204. It permits the field at 304
only at the length that a 200 response would have carried, which this
encoder cannot compute, so a caller that knows the value supplies it in the
header list.

A 2xx response to a `CONNECT` request also carries no `Content-Length`. The
response map holds no request method, so that case needs
`encode_response/2` with `#{content_length => omit}`.

The encoder refuses a message that cannot be framed unambiguously on the
wire. It returns `{error, {invalid_reason_phrase, Reason}}` for a reason
phrase outside `1*( HTAB / SP / VCHAR / obs-text )` (RFC 9112 Section 4.1),
`{error, {invalid_field_name, Name}}` for a field name that is not a token
(RFC 9110 Section 5.6.2), and `{error, {invalid_field_value, Value}}` for a
field value that carries CR, LF, NUL, another control byte, or `0x7F`
(RFC 9110 Section 5.5). An empty reason phrase stays legal, because the
status-line grammar makes the element optional.

RFC 9112 Section 2.2 forbids a sender to generate a bare CR in any protocol
element other than the content, and Section 11.1 names this filtering as the
mitigation for response splitting. No value is repaired and no byte is
stripped. The message is refused whole.
""".
-spec encode_response(resp()) -> {ok, iolist()} | {error, encode_error()}.
encode_response(Resp) ->
    encode_response(Resp, #{}).

-doc """
Encode an HTTP/1.1 response to iolist under the given encoder options.

See `encode_response/1` for the framing rules, the rejected byte classes,
and `t:enc_opts/0` for the options.
""".
-spec encode_response(resp(), enc_opts()) -> {ok, iolist()} | {error, encode_error()}.
encode_response(#{status := Status} = Resp, EncOpts) ->
    Reason = maps:get(reason, Resp, <<>>),
    Headers = maps:get(headers, Resp, []),
    maybe
        ok ?= validate_reason_phrase(Reason),
        Version = maps:get(version, Resp, http1_1),
        Body = maps:get(body, Resp, <<>>),
        FinalHeaders = maybe_add_content_length(
            Headers, iolist_size(Body), allows_content_length(Status, EncOpts)
        ),
        {ok, EncHeaders} ?= encode_headers(FinalHeaders),
        {ok, [
            encode_version(Version),
            <<" ">>,
            integer_to_binary(Status),
            <<" ">>,
            Reason,
            <<"\r\n">>,
            EncHeaders,
            <<"\r\n">>,
            Body
        ]}
    end.

-doc """
Encode HTTP/1.x response headers for streaming.

Used when sending chunked responses - sends status line + headers only. The
reason phrase comes from the status code, so only the header list is subject
to validation. See `encode_response/1` for the rejected byte classes.
""".
-spec encode_response_head(version(), nhttp_lib:status(), nhttp_lib:headers()) ->
    {ok, iolist()} | {error, encode_error()}.
encode_response_head(Version, Status, Headers) ->
    maybe
        {ok, EncHeaders} ?= encode_headers(Headers),
        {ok, [
            encode_version(Version),
            <<" ">>,
            integer_to_binary(Status),
            <<" ">>,
            reason_phrase(Status),
            <<"\r\n">>,
            EncHeaders,
            <<"\r\n">>
        ]}
    end.

%%%-----------------------------------------------------------------------------
%% UTILITIES
%%%-----------------------------------------------------------------------------
-doc "Split buffer at position, returning the remainder.".
-spec split_at(binary(), non_neg_integer()) -> binary().
split_at(<<Bin/binary>>, Pos) ->
    <<_:Pos/binary, Rest/binary>> = Bin,
    Rest.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec build_request(
    nhttp_lib:method(), binary(), version(), nhttp_lib:headers(), opts()
) -> nhttp_lib:request().
build_request(Method, Path, Version, Headers, Opts) ->
    Scheme = maps:get(scheme, Opts, http),
    Authority = derive_authority(Path, Headers),
    case maps:find(peer, Opts) of
        {ok, Peer} ->
            #{
                method => Method,
                path => Path,
                scheme => Scheme,
                authority => Authority,
                version => Version,
                headers => Headers,
                peer => Peer,
                body => <<>>
            };
        error ->
            #{
                method => Method,
                path => Path,
                scheme => Scheme,
                authority => Authority,
                version => Version,
                headers => Headers,
                body => <<>>
            }
    end.

-doc """
Reject an incomplete request head whose buffered input already exceeds the
header budget. Without this, a head that never terminates (e.g. a header
line with no CRLF) bypasses the per-line limit checks and grows the
caller's buffer without bound, while each new arrival rescans the whole
tail (O(n^2)).
""".
-spec cap_incomplete_head(Result, non_neg_integer(), header_limit()) ->
    Result | {error, header_too_large}
when
    Result :: term().
cap_incomplete_head({more, _}, BufferedSize, MaxHeaderSize) when
    is_integer(MaxHeaderSize), BufferedSize > MaxHeaderSize + ?REQUEST_LINE_ALLOWANCE
->
    {error, header_too_large};
cap_incomplete_head(Result, _BufferedSize, _MaxHeaderSize) ->
    Result.

-spec check_body_size(non_neg_integer(), header_limit()) ->
    ok | {error, {body_too_large, non_neg_integer(), non_neg_integer()}}.
check_body_size(Size, MaxSize) when is_integer(MaxSize), Size > MaxSize ->
    {error, {body_too_large, Size, MaxSize}};
check_body_size(_Size, _MaxSize) ->
    ok.

-spec check_header_limits(non_neg_integer(), header_limit(), non_neg_integer(), header_limit()) ->
    ok | {error, parse_error()}.
check_header_limits(Size, MaxSize, _Count, _MaxCount) when is_integer(MaxSize), Size > MaxSize ->
    {error, header_too_large};
check_header_limits(_Size, _MaxSize, Count, MaxCount) when is_integer(MaxCount), Count > MaxCount ->
    {error, too_many_headers};
check_header_limits(_Size, _MaxSize, _Count, _MaxCount) ->
    ok.

-spec chunked_body_mode([binary()]) -> chunked | {error, unsupported_transfer_encoding}.
chunked_body_mode(Codings) ->
    case is_chunked_framing(Codings) of
        true -> chunked;
        false -> {error, unsupported_transfer_encoding}
    end.

%% RFC 9112 Section 6.3 item 4: a response whose final transfer coding is not
%% chunked is delimited by the connection close, so this path has no error.
-spec chunked_body_stream([binary()]) -> body_stream().
chunked_body_stream(Codings) ->
    case is_chunked_framing(Codings) of
        true -> {chunked, #chunked_st{}};
        false -> until_close
    end.

-spec content_length_body_mode([binary()]) ->
    body_mode() | {error, duplicate_content_length | invalid_content_length}.
content_length_body_mode([]) ->
    undefined;
content_length_body_mode([LenBin]) ->
    content_length_mode(LenBin);
content_length_body_mode([First | Rest]) ->
    case lists:all(fun(V) -> V =:= First end, Rest) of
        true -> content_length_mode(First);
        false -> {error, duplicate_content_length}
    end.

-spec content_length_body_stream(nhttp_lib:headers()) -> body_stream().
content_length_body_stream(Headers) ->
    case nhttp_headers:get(<<"content-length">>, Headers) of
        undefined ->
            until_close;
        LenBin ->
            case parse_content_length(LenBin) of
                {ok, Len} -> {length, Len};
                {error, _} -> until_close
            end
    end.

-spec content_length_mode(binary()) -> body_mode() | {error, invalid_content_length}.
content_length_mode(LenBin) ->
    case parse_content_length(LenBin) of
        {ok, 0} -> undefined;
        {ok, Len} -> {content_length, Len};
        {error, _} -> {error, invalid_content_length}
    end.

-spec consume_chunk_trailing_crlf(binary(), non_neg_integer(), [body_chunk()], chunked_st()) ->
    {ok, [body_chunk()], body_stream(), non_neg_integer()}
    | {more, pos_integer(), body_stream()}
    | {error, parse_error()}.
consume_chunk_trailing_crlf(Bin, Consumed, Acc, St) ->
    case Bin of
        <<_:Consumed/binary, "\r\n", _/binary>> ->
            parse_chunked_stream(Bin, Consumed + 2, Acc, St#chunked_st{phase = size});
        <<_:Consumed/binary, "\r">> ->
            %% Only the CR has arrived; wait for the LF rather than erroring.
            finish_chunked_step(Acc, St, Consumed, 1);
        <<_:Consumed/binary, C, _/binary>> when C =/= $\r ->
            {error, incomplete_chunk};
        <<_:Consumed/binary, $\r, C, _/binary>> when C =/= $\n ->
            {error, incomplete_chunk};
        _ ->
            Available = byte_size(Bin) - Consumed,
            finish_chunked_step(Acc, St, Consumed, 2 - Available)
    end.

-spec derive_authority(binary(), nhttp_lib:headers()) -> nhttp_lib:authority().
derive_authority(<<"http://", Rest/binary>>, Headers) ->
    extract_authority_from_uri(Rest, Headers);
derive_authority(<<"https://", Rest/binary>>, Headers) ->
    extract_authority_from_uri(Rest, Headers);
derive_authority(_Path, Headers) ->
    case nhttp_headers:get(<<"host">>, Headers) of
        undefined -> <<>>;
        Host -> Host
    end.

-spec detect_body_mode(nhttp_lib:headers()) ->
    body_mode()
    | {error,
        conflicting_framing
        | duplicate_content_length
        | invalid_content_length
        | unsupported_transfer_encoding}.
detect_body_mode(Headers) ->
    case transfer_codings(Headers) of
        absent ->
            content_length_body_mode(get_all_content_lengths(Headers));
        Codings ->
            case nhttp_headers:has(<<"content-length">>, Headers) of
                true -> {error, conflicting_framing};
                false -> chunked_body_mode(Codings)
            end
    end.

%% One walk validates and builds. The iolist reaches the caller only when the
%% whole list passes, so the encoder never emits the prefix of a message it
%% goes on to refuse.
-spec encode_headers(nhttp_lib:headers()) -> {ok, iolist()} | {error, encode_error()}.
encode_headers(Headers) ->
    Lines = encode_lines(
        Headers,
        persistent_term:get(?PT_NON_TCHAR),
        persistent_term:get(?PT_FIELD_VALUE_BAD)
    ),
    case Lines of
        {error, _} = Err -> Err;
        _ -> {ok, Lines}
    end.

%% The success value is a list and the failure value is a tagged tuple, so the
%% recursion carries no per-element wrapper. Ten field lines cost ten cons
%% cells, not ten cons cells and ten tuples.
-spec encode_lines(nhttp_lib:headers(), binary:cp(), binary:cp()) ->
    iolist() | {error, encode_error()}.
encode_lines([], _NamePat, _ValuePat) ->
    [];
encode_lines([{Name, Value} | Rest], NamePat, ValuePat) ->
    maybe
        ok ?= validate_field_name(Name, NamePat),
        ok ?= validate_field_value(Value, ValuePat),
        case encode_lines(Rest, NamePat, ValuePat) of
            {error, _} = Err -> Err;
            Tail -> [Name, <<": ">>, Value, <<"\r\n">> | Tail]
        end
    end.

-spec encode_version(version()) -> binary().
encode_version(http1_1) -> <<"HTTP/1.1">>;
encode_version(http1_0) -> <<"HTTP/1.0">>.

-spec extract_authority_from_uri(binary(), nhttp_lib:headers()) -> nhttp_lib:authority().
extract_authority_from_uri(Rest, Headers) ->
    case binary:match(Rest, persistent_term:get(?PT_URI_DELIMS)) of
        nomatch ->
            Rest;
        {0, _} ->
            case nhttp_headers:get(<<"host">>, Headers) of
                undefined -> <<>>;
                Host -> Host
            end;
        {Pos, _} ->
            binary:part(Rest, 0, Pos)
    end.

-spec extract_chunk_size_hex(binary()) -> {binary(), binary()}.
extract_chunk_size_hex(Bin) ->
    extract_chunk_size_hex(Bin, 0).

-spec extract_chunk_size_hex(binary(), non_neg_integer()) -> {binary(), binary()}.
extract_chunk_size_hex(Bin, Pos) ->
    case Bin of
        <<_:Pos/binary, C, _/binary>> when
            (C >= $0 andalso C =< $9) orelse
                (C >= $a andalso C =< $f) orelse
                (C >= $A andalso C =< $F)
        ->
            extract_chunk_size_hex(Bin, Pos + 1);
        <<Hex:Pos/binary, Tail/binary>> ->
            {Hex, Tail}
    end.

-spec find_chunk_crlf(binary(), non_neg_integer(), non_neg_integer()) ->
    {ok, binary(), pos_integer()}
    | {final, pos_integer()}
    | {more, pos_integer()}
    | {error, parse_error()}.
find_chunk_crlf(<<Original/binary>>, Skip, SizeLen) ->
    Pos = Skip + SizeLen,
    case Original of
        <<_:Pos/binary, "\r\n", _/binary>> ->
            <<_:Skip/binary, SizeLine:SizeLen/binary, _/binary>> = Original,
            parse_chunk_body_after_size(Original, Skip, SizeLen, SizeLine);
        <<_:Pos/binary, _, _/binary>> ->
            find_chunk_crlf(Original, Skip, SizeLen + 1);
        _ ->
            {more, 1}
    end.

-spec find_path_version(binary(), nhttp_lib:method()) ->
    {ok, nhttp_lib:method(), binary(), version(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
find_path_version(<<Bin/binary>>, Method) ->
    case scan_request_target(Bin, 0, false) of
        {ok, Len, Bad} ->
            case Bin of
                <<Path:Len/binary, " HTTP/1.", Tail/binary>> ->
                    find_version(Tail, Method, Path, Bad);
                _ ->
                    {error, bad_request_line}
            end;
        nomatch ->
            find_path_version_cold(Bin)
    end.

-spec scan_request_target(binary(), non_neg_integer(), boolean()) ->
    {ok, non_neg_integer(), boolean()} | nomatch.
scan_request_target(<<" HTTP/1.", _/binary>>, Pos, Bad) ->
    {ok, Pos, Bad};
scan_request_target(<<C, Rest/binary>>, Pos, _Bad) when C =< 16#20; C =:= 16#7F ->
    scan_request_target(Rest, Pos + 1, true);
scan_request_target(<<_C, Rest/binary>>, Pos, Bad) ->
    scan_request_target(Rest, Pos + 1, Bad);
scan_request_target(<<>>, _Pos, _Bad) ->
    nomatch.

-spec find_version(binary(), nhttp_lib:method(), binary(), boolean()) ->
    {ok, nhttp_lib:method(), binary(), version(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
find_version(<<"1\r\n", _/binary>>, _Method, _Path, true) ->
    {error, bad_request_line};
find_version(<<"0\r\n", _/binary>>, _Method, _Path, true) ->
    {error, bad_request_line};
find_version(<<"1\r\n", Rest/binary>>, Method, Path, false) ->
    {ok, Method, Path, http1_1, Rest};
find_version(<<"0\r\n", Rest/binary>>, Method, Path, false) ->
    {ok, Method, Path, http1_0, Rest};
find_version(<<"1\r">>, _Method, _Path, _Bad) ->
    {more, 1};
find_version(<<"0\r">>, _Method, _Path, _Bad) ->
    {more, 1};
find_version(<<"1">>, _Method, _Path, _Bad) ->
    {more, 2};
find_version(<<"0">>, _Method, _Path, _Bad) ->
    {more, 2};
find_version(<<>>, _Method, _Path, _Bad) ->
    {more, 3};
find_version(_Tail, _Method, _Path, _Bad) ->
    {error, invalid_version}.

-spec find_path_version_cold(binary()) ->
    {more, pos_integer()} | {error, parse_error()}.
find_path_version_cold(Bin) ->
    case binary:match(Bin, <<"\r\n">>) of
        nomatch when byte_size(Bin) < 12 ->
            {more, 12 - byte_size(Bin)};
        nomatch ->
            {more, 1};
        _ ->
            case binary:match(Bin, <<" HTTP/">>) of
                nomatch -> {error, bad_request_line};
                _ -> {error, invalid_version}
            end
    end.

-spec finish_chunked_step(
    [body_chunk()], chunked_st(), non_neg_integer(), pos_integer()
) ->
    {ok, [body_chunk()], body_stream(), non_neg_integer()}
    | {more, pos_integer(), body_stream()}.
finish_chunked_step([], St, 0, MinBytes) ->
    {more, MinBytes, {chunked, St}};
finish_chunked_step(Acc, St, Consumed, _MinBytes) ->
    {ok, lists:reverse(Acc), {chunked, St}, Consumed}.

-spec finish_request(req(), binary(), nhttp_lib:headers(), pos_integer(), opts()) ->
    parse_result(req()).
finish_request(Req, BodyRest, Headers, HeadersConsumed, Opts) ->
    MaxBodySize = maps:get(max_body_size, Opts, infinity),
    case detect_body_mode(Headers) of
        undefined ->
            {ok, Req#{body => <<>>}, HeadersConsumed};
        {content_length, Len} ->
            case check_body_size(Len, MaxBodySize) of
                ok ->
                    case BodyRest of
                        <<Body:Len/binary, _/binary>> ->
                            {ok, Req#{body => Body}, HeadersConsumed + Len};
                        _ ->
                            {more, Len - byte_size(BodyRest)}
                    end;
                {error, _} = Err ->
                    Err
            end;
        chunked ->
            parse_chunks_req(BodyRest, 0, [], Req, HeadersConsumed, MaxBodySize);
        {error, _} = Err ->
            Err
    end.

-spec finish_response(resp(), binary(), nhttp_lib:headers(), pos_integer(), opts()) ->
    parse_result(resp()).
finish_response(Resp, BodyRest, Headers, HeadersConsumed, Opts) ->
    MaxBodySize = maps:get(max_body_size, Opts, infinity),
    case detect_body_mode(Headers) of
        undefined ->
            {ok, Resp#{body => <<>>}, HeadersConsumed};
        {content_length, Len} ->
            case check_body_size(Len, MaxBodySize) of
                ok ->
                    case BodyRest of
                        <<Body:Len/binary, _/binary>> ->
                            {ok, Resp#{body => Body}, HeadersConsumed + Len};
                        _ ->
                            {more, Len - byte_size(BodyRest)}
                    end;
                {error, _} = Err ->
                    Err
            end;
        chunked ->
            parse_chunks_resp(BodyRest, 0, [], Resp, HeadersConsumed, MaxBodySize);
        {error, _} = Err ->
            Err
    end.

-spec get_all_content_lengths(nhttp_lib:headers()) -> [binary()].
get_all_content_lengths(Headers) ->
    [V || {<<"content-length">>, V} <- Headers].

%% RFC 9110 Section 5.6.2: field-name is a token, and a token is 1*tchar, so
%% an empty name is not one. `binary:match/2` calls the empty binary a match
%% for nothing, which makes the empty case a separate clause.
-compile({inline, [validate_field_name/2, validate_field_value/2]}).

-spec validate_field_name(binary(), binary:cp()) -> ok | {error, encode_error()}.
validate_field_name(<<>>, _NamePat) ->
    {error, {invalid_field_name, <<>>}};
validate_field_name(Name, NamePat) ->
    case binary:match(Name, NamePat) of
        nomatch -> ok;
        _ -> {error, {invalid_field_name, Name}}
    end.

-spec validate_field_value(binary(), binary:cp()) -> ok | {error, encode_error()}.
validate_field_value(Value, ValuePat) ->
    case binary:match(Value, ValuePat) of
        nomatch -> ok;
        _ -> {error, {invalid_field_value, Value}}
    end.

-spec validate_reason_phrase(binary()) -> ok | {error, encode_error()}.
validate_reason_phrase(Reason) ->
    %% RFC 9112 Section 4.1: 1*( HTAB / SP / VCHAR / obs-text ), and the
    %% status-line grammar makes the whole element optional.
    case has_invalid_char(Reason) of
        false -> ok;
        true -> {error, {invalid_reason_phrase, Reason}}
    end.

-spec validate_request_target(binary()) -> ok | {error, encode_error()}.
validate_request_target(<<>>) ->
    {error, {invalid_request_target, <<>>}};
validate_request_target(Target) ->
    case binary:match(Target, persistent_term:get(?PT_TARGET_BAD)) of
        nomatch -> ok;
        _ -> {error, {invalid_request_target, Target}}
    end.

-spec has_invalid_char(binary()) -> boolean().
has_invalid_char(Bin) ->
    binary:match(Bin, persistent_term:get(?PT_FIELD_VALUE_BAD)) =/= nomatch.

%% RFC 9112 Section 6.1: chunked is the final transfer coding, and a sender
%% applies it at most once. Two recipients that disagree on the number of
%% chunked layers disagree on every byte after the first chunk.
-spec is_chunked_framing([binary()]) -> boolean().
is_chunked_framing(Codings) ->
    is_chunked_framing(Codings, 0).

-spec is_chunked_framing([binary()], non_neg_integer()) -> boolean().
is_chunked_framing([], _Seen) -> false;
is_chunked_framing([<<"chunked">>], Seen) -> Seen =:= 0;
is_chunked_framing([<<"chunked">> | Rest], Seen) -> is_chunked_framing(Rest, Seen + 1);
is_chunked_framing([_Coding | Rest], Seen) -> is_chunked_framing(Rest, Seen).

-spec is_valid_chunk_ext_tail(binary()) -> boolean().
is_valid_chunk_ext_tail(<<>>) -> true;
is_valid_chunk_ext_tail(Bin) -> skip_bws_to_semi(Bin).

-spec maybe_add_content_length(nhttp_lib:headers(), non_neg_integer(), boolean()) ->
    nhttp_lib:headers().
maybe_add_content_length(Headers, _Len, false) ->
    Headers;
maybe_add_content_length(Headers, Len, true) ->
    case
        nhttp_headers:has(<<"content-length">>, Headers) orelse
            nhttp_headers:has(<<"transfer-encoding">>, Headers)
    of
        true ->
            Headers;
        false ->
            [{<<"content-length">>, integer_to_binary(Len)} | Headers]
    end.

-spec allows_content_length(nhttp_lib:status(), enc_opts()) -> boolean().
allows_content_length(Status, EncOpts) ->
    case maps:get(content_length, EncOpts, auto) of
        auto -> not forbids_content_length(Status);
        omit -> false
    end.

-spec forbids_content_length(nhttp_lib:status()) -> boolean().
forbids_content_length(Status) when Status >= 100, Status =< 199 -> true;
forbids_content_length(204) -> true;
forbids_content_length(304) -> true;
forbids_content_length(_Status) -> false.

-spec parse_chunk_body_after_size(binary(), non_neg_integer(), non_neg_integer(), binary()) ->
    {ok, binary(), pos_integer()}
    | {final, pos_integer()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_chunk_body_after_size(<<Original/binary>>, Skip, SizeLen, SizeLine) ->
    case parse_chunk_size(SizeLine) of
        {ok, 0} ->
            HeaderLen = SizeLen + 2,
            TrailerStart = Skip + HeaderLen,
            skip_trailer_fields(Original, TrailerStart, HeaderLen);
        {ok, Size} ->
            HeaderLen = SizeLen + 2,
            BodyStart = Skip + HeaderLen,
            TotalNeeded = Size + 2,
            Available = byte_size(Original) - BodyStart,
            %% RFC 9112 Section 7.1: a short body waits, a wrong terminator refuses.
            maybe
                true ?= Available >= TotalNeeded,
                <<_:BodyStart/binary, ChunkData:Size/binary, "\r\n", _/binary>> ?= Original,
                {ok, ChunkData, HeaderLen + Size + 2}
            else
                false ->
                    {more, TotalNeeded - Available};
                <<_/binary>> ->
                    {error, incomplete_chunk}
            end;
        error ->
            {error, invalid_chunk_size}
    end.

-spec parse_chunk_size(binary()) -> {ok, non_neg_integer()} | error.
parse_chunk_size(Bin) ->
    case extract_chunk_size_hex(Bin) of
        {<<>>, _} ->
            error;
        {HexPart, Tail} ->
            case is_valid_chunk_ext_tail(Tail) of
                true ->
                    try
                        {ok, binary_to_integer(HexPart, 16)}
                    catch
                        error:badarg -> error
                    end;
                false ->
                    error
            end
    end.

-spec parse_chunk_size_line(binary(), non_neg_integer()) ->
    {ok, non_neg_integer(), non_neg_integer()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_chunk_size_line(Bin, Skip) ->
    Available = byte_size(Bin) - Skip,
    case Available > 0 of
        true ->
            scan_chunk_size_line(Bin, Skip, 0);
        false ->
            {more, 1}
    end.

-spec parse_chunked_stream(binary(), non_neg_integer(), [body_chunk()], chunked_st()) ->
    {ok, [body_chunk()], body_stream(), non_neg_integer()}
    | {more, pos_integer(), body_stream()}
    | {error, parse_error()}.
parse_chunked_stream(Bin, Consumed, Acc, #chunked_st{phase = size} = St) ->
    case parse_chunk_size_line(Bin, Consumed) of
        {ok, 0, NewConsumed} ->
            parse_chunked_stream(Bin, NewConsumed, Acc, St#chunked_st{phase = trailers});
        {ok, Size, NewConsumed} ->
            case check_body_size(St#chunked_st.body_size + Size, St#chunked_st.max_body_size) of
                ok ->
                    parse_chunked_stream(Bin, NewConsumed, Acc, St#chunked_st{
                        phase = {data, Size}
                    });
                {error, _} = Err ->
                    Err
            end;
        {more, MinBytes} ->
            finish_chunked_step(Acc, St, Consumed, MinBytes);
        {error, _} = Err ->
            Err
    end;
parse_chunked_stream(Bin, Consumed, Acc, #chunked_st{phase = {data, Remaining}} = St) ->
    Available = byte_size(Bin) - Consumed,
    case Remaining of
        0 ->
            consume_chunk_trailing_crlf(Bin, Consumed, Acc, St);
        _ when Available =< 0 ->
            finish_chunked_step(Acc, St, Consumed, Remaining + 2);
        _ ->
            Take = min(Available, Remaining),
            <<_:Consumed/binary, Data:Take/binary, _/binary>> = Bin,
            NewSt = St#chunked_st{
                phase = {data, Remaining - Take},
                body_size = St#chunked_st.body_size + Take
            },
            parse_chunked_stream(Bin, Consumed + Take, [{data, Data} | Acc], NewSt)
    end;
parse_chunked_stream(Bin, Consumed, Acc, #chunked_st{phase = trailers} = St) ->
    Available = byte_size(Bin) - Consumed,
    case Available >= 2 of
        true ->
            <<_:Consumed/binary, Rest/binary>> = Bin,
            #chunked_st{
                trailers_acc = TAcc,
                headers_size = HSize,
                max_header_size = MaxSize,
                max_headers_count = MaxCount
            } = St,
            case parse_headers_acc(Rest, TAcc, HSize, MaxSize, MaxCount) of
                {ok, Trailers, AfterTrailers} ->
                    Used = byte_size(Rest) - byte_size(AfterTrailers),
                    NewConsumed = Consumed + Used,
                    FinalAcc = lists:reverse([{fin, Trailers} | Acc]),
                    {ok, FinalAcc, none, NewConsumed};
                {more, _MinBytes} when
                    is_integer(MaxSize), HSize + byte_size(Rest) > MaxSize
                ->
                    {error, header_too_large};
                {more, MinBytes} ->
                    finish_chunked_step(Acc, St, Consumed, MinBytes);
                {error, _} = Err ->
                    Err
            end;
        false ->
            finish_chunked_step(Acc, St, Consumed, 2 - Available)
    end.

-spec parse_chunks_req(
    binary(), non_neg_integer(), [binary()], req(), pos_integer(), header_limit()
) ->
    parse_result(req()).
parse_chunks_req(<<Original/binary>>, Skip, Acc, Partial, HeadersConsumed, MaxBodySize) ->
    case parse_one_chunk(Original, Skip) of
        {final, ChunkConsumed} ->
            Body = iolist_to_binary(lists:reverse(Acc)),
            FinalReq = Partial#{body => Body},
            {ok, FinalReq, HeadersConsumed + Skip + ChunkConsumed};
        {ok, ChunkData, ChunkConsumed} ->
            CurrentSize = iolist_size(Acc) + byte_size(ChunkData),
            case check_body_size(CurrentSize, MaxBodySize) of
                ok ->
                    parse_chunks_req(
                        Original,
                        Skip + ChunkConsumed,
                        [ChunkData | Acc],
                        Partial,
                        HeadersConsumed,
                        MaxBodySize
                    );
                {error, _} = Err ->
                    Err
            end;
        {more, MinBytes} ->
            {more, MinBytes};
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_chunks_resp(
    binary(), non_neg_integer(), [binary()], resp(), pos_integer(), header_limit()
) ->
    parse_result(resp()).
parse_chunks_resp(<<Original/binary>>, Skip, Acc, Partial, HeadersConsumed, MaxBodySize) ->
    case parse_one_chunk(Original, Skip) of
        {final, ChunkConsumed} ->
            Body = iolist_to_binary(lists:reverse(Acc)),
            FinalResp = Partial#{body => Body},
            {ok, FinalResp, HeadersConsumed + Skip + ChunkConsumed};
        {ok, ChunkData, ChunkConsumed} ->
            CurrentSize = iolist_size(Acc) + byte_size(ChunkData),
            case check_body_size(CurrentSize, MaxBodySize) of
                ok ->
                    parse_chunks_resp(
                        Original,
                        Skip + ChunkConsumed,
                        [ChunkData | Acc],
                        Partial,
                        HeadersConsumed,
                        MaxBodySize
                    );
                {error, _} = Err ->
                    Err
            end;
        {more, MinBytes} ->
            {more, MinBytes};
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_content_length(binary()) -> {ok, non_neg_integer()} | {error, badarg}.
parse_content_length(Bin) ->
    case nhttp_msg:parse_content_length(Bin) of
        undefined -> {error, badarg};
        Len -> {ok, Len}
    end.

-spec parse_header_value_direct(
    binary(),
    pos_integer(),
    binary(),
    nhttp_lib:headers(),
    non_neg_integer(),
    non_neg_integer(),
    header_limit(),
    header_limit()
) ->
    {ok, nhttp_lib:headers(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_header_value_direct(Name, PrefixLen, <<Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    case scan_header_value(Rest, 0, 0, 0, false) of
        {ok, Skip, Len, Drop} ->
            LineSize = PrefixLen + Skip + Len + Drop + 2,
            NewSize = Size + LineSize,
            NewCount = Count + 1,
            case check_header_limits(NewSize, MaxSize, NewCount, MaxCount) of
                ok ->
                    case Rest of
                        <<_:Skip/binary, Value:Len/binary, _:Drop/binary, "\r\n", Tail/binary>> ->
                            parse_headers_acc(
                                Tail,
                                [{Name, Value} | Acc],
                                NewCount,
                                NewSize,
                                MaxSize,
                                MaxCount
                            );
                        _ ->
                            {error, bad_header}
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err;
        more ->
            {more, 2}
    end.

-spec scan_header_value(
    binary(), non_neg_integer(), non_neg_integer(), non_neg_integer(), boolean()
) ->
    {ok, non_neg_integer(), non_neg_integer(), non_neg_integer()}
    | {error, bad_header}
    | more.
scan_header_value(<<"\r\n", _/binary>>, _Pos, _Skip, _Drop, true) ->
    {error, bad_header};
scan_header_value(<<"\r\n", _/binary>>, Pos, Skip, Drop, false) ->
    {ok, Skip, Pos - Skip - Drop, Drop};
scan_header_value(<<$\s, Rest/binary>>, Pos, Skip, Drop, Bad) when Pos =:= Skip ->
    scan_header_value(Rest, Pos + 1, Skip + 1, Drop, Bad);
scan_header_value(<<$\t, Rest/binary>>, Pos, Skip, Drop, Bad) when Pos =:= Skip ->
    scan_header_value(Rest, Pos + 1, Skip + 1, Drop, Bad);
scan_header_value(<<$\s, Rest/binary>>, Pos, Skip, Drop, Bad) ->
    scan_header_value(Rest, Pos + 1, Skip, Drop + 1, Bad);
scan_header_value(<<$\t, Rest/binary>>, Pos, Skip, Drop, Bad) ->
    scan_header_value(Rest, Pos + 1, Skip, Drop + 1, Bad);
scan_header_value(<<C, Rest/binary>>, Pos, Skip, _Drop, _Bad) when C =< 16#1F; C =:= 16#7F ->
    scan_header_value(Rest, Pos + 1, Skip, 0, true);
scan_header_value(<<_C, Rest/binary>>, Pos, Skip, _Drop, Bad) ->
    scan_header_value(Rest, Pos + 1, Skip, 0, Bad);
scan_header_value(<<>>, _Pos, _Skip, _Drop, _Bad) ->
    more.

-spec parse_headers_acc(
    binary(), nhttp_lib:headers(), non_neg_integer(), header_limit(), header_limit()
) ->
    {ok, nhttp_lib:headers(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_headers_acc(Bin, Acc, Size, MaxSize, MaxCount) ->
    parse_headers_acc(Bin, Acc, length(Acc), Size, MaxSize, MaxCount).

-spec parse_headers_acc(
    binary(),
    nhttp_lib:headers(),
    non_neg_integer(),
    non_neg_integer(),
    header_limit(),
    header_limit()
) ->
    {ok, nhttp_lib:headers(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_headers_acc(<<"\r\n", Rest/binary>>, Acc, _Count, _Size, _MaxSize, _MaxCount) ->
    {ok, lists:reverse(Acc), Rest};
parse_headers_acc(<<"\r">>, _Acc, _Count, _Size, _MaxSize, _MaxCount) ->
    {more, 1};
parse_headers_acc(<<>>, _Acc, _Count, _Size, _MaxSize, _MaxCount) ->
    {more, 2};
parse_headers_acc(<<"Content-Length: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"content-length">>,
        byte_size(<<"Content-Length: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"content-length: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"content-length">>,
        byte_size(<<"content-length: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Content-Type: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"content-type">>,
        byte_size(<<"Content-Type: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"content-type: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"content-type">>,
        byte_size(<<"content-type: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Date: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"date">>, byte_size(<<"Date: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"date: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"date">>, byte_size(<<"date: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Connection: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"connection">>, byte_size(<<"Connection: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"connection: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"connection">>, byte_size(<<"connection: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Transfer-Encoding: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"transfer-encoding">>,
        byte_size(<<"Transfer-Encoding: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"transfer-encoding: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"transfer-encoding">>,
        byte_size(<<"transfer-encoding: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Server: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"server">>, byte_size(<<"Server: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"server: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"server">>, byte_size(<<"server: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Host: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"host">>, byte_size(<<"Host: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"host: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"host">>, byte_size(<<"host: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"User-Agent: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"user-agent">>, byte_size(<<"User-Agent: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"user-agent: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"user-agent">>, byte_size(<<"user-agent: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Accept: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"accept">>, byte_size(<<"Accept: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"accept: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"accept">>, byte_size(<<"accept: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Accept-Encoding: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"accept-encoding">>,
        byte_size(<<"Accept-Encoding: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"accept-encoding: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"accept-encoding">>,
        byte_size(<<"accept-encoding: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Accept-Language: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"accept-language">>,
        byte_size(<<"Accept-Language: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"accept-language: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"accept-language">>,
        byte_size(<<"accept-language: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Cookie: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"cookie">>, byte_size(<<"Cookie: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"cookie: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"cookie">>, byte_size(<<"cookie: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Authorization: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"authorization">>,
        byte_size(<<"Authorization: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"authorization: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"authorization">>,
        byte_size(<<"authorization: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Referer: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"referer">>, byte_size(<<"Referer: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"referer: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"referer">>, byte_size(<<"referer: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Origin: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"origin">>, byte_size(<<"Origin: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"origin: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"origin">>, byte_size(<<"origin: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Cache-Control: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"cache-control">>,
        byte_size(<<"Cache-Control: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"cache-control: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"cache-control">>,
        byte_size(<<"cache-control: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"If-None-Match: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"if-none-match">>,
        byte_size(<<"If-None-Match: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"if-none-match: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"if-none-match">>,
        byte_size(<<"if-none-match: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"If-Modified-Since: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"if-modified-since">>,
        byte_size(<<"If-Modified-Since: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"if-modified-since: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"if-modified-since">>,
        byte_size(<<"if-modified-since: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Range: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"range">>, byte_size(<<"Range: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"range: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"range">>, byte_size(<<"range: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"X-Forwarded-For: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"x-forwarded-for">>,
        byte_size(<<"X-Forwarded-For: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"x-forwarded-for: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"x-forwarded-for">>,
        byte_size(<<"x-forwarded-for: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"X-Forwarded-Proto: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"x-forwarded-proto">>,
        byte_size(<<"X-Forwarded-Proto: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"x-forwarded-proto: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"x-forwarded-proto">>,
        byte_size(<<"x-forwarded-proto: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"TE: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"te">>, byte_size(<<"TE: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"te: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"te">>, byte_size(<<"te: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Last-Modified: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"last-modified">>,
        byte_size(<<"Last-Modified: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"last-modified: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"last-modified">>,
        byte_size(<<"last-modified: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"ETag: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"etag">>, byte_size(<<"ETag: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"etag: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"etag">>, byte_size(<<"etag: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Accept-Ranges: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"accept-ranges">>,
        byte_size(<<"Accept-Ranges: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"accept-ranges: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"accept-ranges">>,
        byte_size(<<"accept-ranges: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Expires: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"expires">>, byte_size(<<"Expires: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"expires: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"expires">>, byte_size(<<"expires: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Vary: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"vary">>, byte_size(<<"Vary: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"vary: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"vary">>, byte_size(<<"vary: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Location: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"location">>, byte_size(<<"Location: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"location: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"location">>, byte_size(<<"location: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Content-Encoding: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"content-encoding">>,
        byte_size(<<"Content-Encoding: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"content-encoding: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"content-encoding">>,
        byte_size(<<"content-encoding: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(<<"Set-Cookie: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"set-cookie">>, byte_size(<<"Set-Cookie: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"set-cookie: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"set-cookie">>, byte_size(<<"set-cookie: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"Age: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"age">>, byte_size(<<"Age: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(<<"age: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_header_value_direct(
        <<"age">>, byte_size(<<"age: ">>), Rest, Acc, Count, Size, MaxSize, MaxCount
    );
parse_headers_acc(
    <<"Strict-Transport-Security: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount
) ->
    parse_header_value_direct(
        <<"strict-transport-security">>,
        byte_size(<<"Strict-Transport-Security: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(
    <<"strict-transport-security: ", Rest/binary>>, Acc, Count, Size, MaxSize, MaxCount
) ->
    parse_header_value_direct(
        <<"strict-transport-security">>,
        byte_size(<<"strict-transport-security: ">>),
        Rest,
        Acc,
        Count,
        Size,
        MaxSize,
        MaxCount
    );
parse_headers_acc(Bin, Acc, Count, Size, MaxSize, MaxCount) ->
    parse_headers_acc_generic(Bin, Acc, Count, Size, MaxSize, MaxCount).

-spec parse_headers_acc_generic(
    binary(),
    nhttp_lib:headers(),
    non_neg_integer(),
    non_neg_integer(),
    header_limit(),
    header_limit()
) ->
    {ok, nhttp_lib:headers(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_headers_acc_generic(Bin, Acc, Count, Size, MaxSize, MaxCount) ->
    case binary:split(Bin, persistent_term:get(?PT_CRLF)) of
        [Line, Rest] ->
            case binary:split(Line, persistent_term:get(?PT_COLON)) of
                [Name, Value] ->
                    case nhttp_headers:is_token(Name) of
                        false ->
                            {error, bad_header};
                        true ->
                            TrimmedValue = trim_ows(Value),
                            case has_invalid_char(TrimmedValue) of
                                true ->
                                    {error, bad_header};
                                false ->
                                    LineSize = byte_size(Line) + 2,
                                    NewSize = Size + LineSize,
                                    NewCount = Count + 1,
                                    case
                                        check_header_limits(NewSize, MaxSize, NewCount, MaxCount)
                                    of
                                        ok ->
                                            LowerName = nhttp_headers:to_lower(Name),
                                            parse_headers_acc(
                                                Rest,
                                                [{LowerName, TrimmedValue} | Acc],
                                                NewCount,
                                                NewSize,
                                                MaxSize,
                                                MaxCount
                                            );
                                        {error, _} = Err ->
                                            Err
                                    end
                            end
                    end;
                [_] ->
                    {error, bad_header}
            end;
        [_] ->
            {more, 2}
    end.

-spec parse_one_chunk(binary(), non_neg_integer()) ->
    {ok, binary(), pos_integer()}
    | {final, pos_integer()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_one_chunk(<<Original/binary>>, Skip) ->
    Available = byte_size(Original) - Skip,
    case Available > 0 of
        true ->
            find_chunk_crlf(Original, Skip, 0);
        false ->
            {more, 1}
    end.

-spec parse_reason_line(binary(), nhttp_lib:status(), version()) ->
    {ok, nhttp_lib:status(), binary(), version(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_reason_line(Bin, Status, Version) ->
    case binary:split(Bin, <<"\r\n">>) of
        [Reason, Rest] ->
            {ok, Status, Reason, Version, Rest};
        [_] ->
            {more, 2}
    end.

-spec parse_request_line(binary()) ->
    {ok, nhttp_lib:method(), binary(), version(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_request_line(<<"GET ", Rest/binary>>) ->
    find_path_version(Rest, get);
parse_request_line(<<"POST ", Rest/binary>>) ->
    find_path_version(Rest, post);
parse_request_line(<<"PUT ", Rest/binary>>) ->
    find_path_version(Rest, put);
parse_request_line(<<"HEAD ", Rest/binary>>) ->
    find_path_version(Rest, head);
parse_request_line(<<"DELETE ", Rest/binary>>) ->
    find_path_version(Rest, delete);
parse_request_line(<<"PATCH ", Rest/binary>>) ->
    find_path_version(Rest, patch);
parse_request_line(<<"OPTIONS ", Rest/binary>>) ->
    find_path_version(Rest, options);
parse_request_line(<<"CONNECT ", Rest/binary>>) ->
    find_path_version(Rest, connect);
parse_request_line(<<"TRACE ", Rest/binary>>) ->
    find_path_version(Rest, trace);
parse_request_line(<<C, _/binary>> = Bin) when C >= $A, C =< $Z ->
    parse_request_line_token(Bin);
parse_request_line(<<C, _/binary>>) when C >= $a, C =< $z ->
    {error, invalid_method};
parse_request_line(<<"\r\n", _/binary>>) ->
    {error, bad_request_line};
parse_request_line(<<C, _/binary>> = Bin) ->
    case nhttp_headers:is_tchar(C) of
        true -> parse_request_line_token(Bin);
        false -> parse_request_line_cold(Bin)
    end;
parse_request_line(<<>>) ->
    {more, 16}.

-spec parse_request_line_token(binary()) ->
    {ok, nhttp_lib:method(), binary(), version(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_request_line_token(Bin) ->
    case binary:split(Bin, <<" ">>) of
        [Method, Rest] when byte_size(Method) =< 16 ->
            case nhttp_headers:is_token(Method) of
                true -> find_path_version(Rest, Method);
                false -> {error, invalid_method}
            end;
        [_] when byte_size(Bin) < 18 ->
            case binary:match(Bin, <<"\r\n">>) of
                nomatch -> {more, 18 - byte_size(Bin)};
                _ -> {error, bad_request_line}
            end;
        _ ->
            {error, bad_request_line}
    end.

-spec parse_request_line_cold(binary()) ->
    {more, pos_integer()} | {error, parse_error()}.
parse_request_line_cold(Bin) when byte_size(Bin) < 16 ->
    {more, 16 - byte_size(Bin)};
parse_request_line_cold(_) ->
    {error, bad_request_line}.

-spec parse_status_line(binary()) ->
    {ok, nhttp_lib:status(), binary(), version(), binary()}
    | {more, pos_integer()}
    | {error, parse_error()}.
parse_status_line(<<"HTTP/1.1 200 OK\r\n", Rest/binary>>) ->
    {ok, 200, <<"OK">>, http1_1, Rest};
parse_status_line(<<"HTTP/1.1 204 No Content\r\n", Rest/binary>>) ->
    {ok, 204, <<"No Content">>, http1_1, Rest};
parse_status_line(<<"HTTP/1.1 301 Moved Permanently\r\n", Rest/binary>>) ->
    {ok, 301, <<"Moved Permanently">>, http1_1, Rest};
parse_status_line(<<"HTTP/1.1 302 Found\r\n", Rest/binary>>) ->
    {ok, 302, <<"Found">>, http1_1, Rest};
parse_status_line(<<"HTTP/1.1 400 Bad Request\r\n", Rest/binary>>) ->
    {ok, 400, <<"Bad Request">>, http1_1, Rest};
parse_status_line(<<"HTTP/1.1 404 Not Found\r\n", Rest/binary>>) ->
    {ok, 404, <<"Not Found">>, http1_1, Rest};
parse_status_line(<<"HTTP/1.1 500 Internal Server Error\r\n", Rest/binary>>) ->
    {ok, 500, <<"Internal Server Error">>, http1_1, Rest};
parse_status_line(<<"HTTP/1.1 ", S1, S2, S3, " ", Rest/binary>>) when
    S1 >= $0, S1 =< $9, S2 >= $0, S2 =< $9, S3 >= $0, S3 =< $9
->
    Status = (S1 - $0) * 100 + (S2 - $0) * 10 + (S3 - $0),
    parse_reason_line(Rest, Status, http1_1);
parse_status_line(<<"HTTP/1.0 ", S1, S2, S3, " ", Rest/binary>>) when
    S1 >= $0, S1 =< $9, S2 >= $0, S2 =< $9, S3 >= $0, S3 =< $9
->
    Status = (S1 - $0) * 100 + (S2 - $0) * 10 + (S3 - $0),
    parse_reason_line(Rest, Status, http1_0);
parse_status_line(<<"HTTP/1.1\r\n", _/binary>>) ->
    {error, bad_status_line};
parse_status_line(<<"HTTP/1.0\r\n", _/binary>>) ->
    {error, bad_status_line};
parse_status_line(<<"HTTP/1.1 ", C, _/binary>>) when C < $0; C > $9 ->
    {error, bad_status_line};
parse_status_line(<<"HTTP/1.0 ", C, _/binary>>) when C < $0; C > $9 ->
    {error, bad_status_line};
parse_status_line(Bin) when byte_size(Bin) < 13 ->
    {more, 13 - byte_size(Bin)};
parse_status_line(_) ->
    {error, bad_status_line}.

-spec reason_phrase(nhttp_lib:status()) -> binary().
reason_phrase(100) -> <<"Continue">>;
reason_phrase(101) -> <<"Switching Protocols">>;
reason_phrase(200) -> <<"OK">>;
reason_phrase(201) -> <<"Created">>;
reason_phrase(202) -> <<"Accepted">>;
reason_phrase(204) -> <<"No Content">>;
reason_phrase(206) -> <<"Partial Content">>;
reason_phrase(301) -> <<"Moved Permanently">>;
reason_phrase(302) -> <<"Found">>;
reason_phrase(303) -> <<"See Other">>;
reason_phrase(304) -> <<"Not Modified">>;
reason_phrase(307) -> <<"Temporary Redirect">>;
reason_phrase(308) -> <<"Permanent Redirect">>;
reason_phrase(400) -> <<"Bad Request">>;
reason_phrase(401) -> <<"Unauthorized">>;
reason_phrase(403) -> <<"Forbidden">>;
reason_phrase(404) -> <<"Not Found">>;
reason_phrase(405) -> <<"Method Not Allowed">>;
reason_phrase(408) -> <<"Request Timeout">>;
reason_phrase(409) -> <<"Conflict">>;
reason_phrase(410) -> <<"Gone">>;
reason_phrase(411) -> <<"Length Required">>;
reason_phrase(413) -> <<"Content Too Large">>;
reason_phrase(414) -> <<"URI Too Long">>;
reason_phrase(415) -> <<"Unsupported Media Type">>;
reason_phrase(416) -> <<"Range Not Satisfiable">>;
reason_phrase(417) -> <<"Expectation Failed">>;
reason_phrase(422) -> <<"Unprocessable Content">>;
reason_phrase(426) -> <<"Upgrade Required">>;
reason_phrase(429) -> <<"Too Many Requests">>;
reason_phrase(500) -> <<"Internal Server Error">>;
reason_phrase(501) -> <<"Not Implemented">>;
reason_phrase(502) -> <<"Bad Gateway">>;
reason_phrase(503) -> <<"Service Unavailable">>;
reason_phrase(504) -> <<"Gateway Timeout">>;
reason_phrase(505) -> <<"HTTP Version Not Supported">>;
reason_phrase(_) -> <<>>.

-spec scan_chunk_size_line(binary(), non_neg_integer(), non_neg_integer()) ->
    {ok, non_neg_integer(), non_neg_integer()}
    | {more, pos_integer()}
    | {error, parse_error()}.
scan_chunk_size_line(Bin, Skip, SizeLen) ->
    Pos = Skip + SizeLen,
    case Bin of
        <<_:Pos/binary, "\r\n", _/binary>> ->
            <<_:Skip/binary, SizeLine:SizeLen/binary, _/binary>> = Bin,
            case parse_chunk_size(SizeLine) of
                {ok, Size} -> {ok, Size, Skip + SizeLen + 2};
                error -> {error, invalid_chunk_size}
            end;
        <<_:Pos/binary, _, _/binary>> when SizeLen =< ?MAX_CHUNK_SIZE_LINE ->
            scan_chunk_size_line(Bin, Skip, SizeLen + 1);
        <<_:Pos/binary, _, _/binary>> ->
            {error, invalid_chunk_size};
        _ ->
            {more, 1}
    end.

-spec skip_bws_to_semi(binary()) -> boolean().
skip_bws_to_semi(<<";", _/binary>>) -> true;
skip_bws_to_semi(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t -> skip_bws_to_semi(Rest);
skip_bws_to_semi(_) -> false.

-spec skip_to_next_crlf(binary(), non_neg_integer(), non_neg_integer()) ->
    {final, pos_integer()} | {more, pos_integer()}.
skip_to_next_crlf(Original, Pos, Consumed) ->
    case Original of
        <<_:Pos/binary, "\r\n", _/binary>> ->
            skip_trailer_fields(Original, Pos + 2, Consumed + 2);
        <<_:Pos/binary, _, _/binary>> ->
            skip_to_next_crlf(Original, Pos + 1, Consumed + 1);
        <<_:Pos/binary>> ->
            {more, 1}
    end.

-spec skip_trailer_fields(binary(), non_neg_integer(), non_neg_integer()) ->
    {final, pos_integer()} | {more, pos_integer()}.
skip_trailer_fields(Original, Pos, Consumed) ->
    Available = byte_size(Original) - Pos,
    case Available >= 2 of
        true ->
            case Original of
                <<_:Pos/binary, "\r\n", _/binary>> ->
                    {final, Consumed + 2};
                <<_:Pos/binary, _/binary>> ->
                    skip_to_next_crlf(Original, Pos, Consumed)
            end;
        false ->
            {more, 2 - Available}
    end.

%% RFC 9110 Section 5.6.1.2: a recipient ignores empty list elements.
-spec split_transfer_codings([binary()], [binary()]) -> [binary()].
split_transfer_codings([], Acc) ->
    Acc;
split_transfer_codings([Raw | Rest], Acc) ->
    case trim_ows(Raw) of
        <<>> -> split_transfer_codings(Rest, Acc);
        Coding -> split_transfer_codings(Rest, [nhttp_headers:to_lower(Coding) | Acc])
    end.

%% RFC 9110 Section 5.3: multiple field lines with the same name combine into
%% one comma-separated list, in order of receipt. `absent` and `[]` differ:
%% an empty list is a declared framing that names no transfer coding.
-spec transfer_codings(nhttp_lib:headers()) -> absent | [binary()].
transfer_codings(Headers) ->
    case [Value || {<<"transfer-encoding">>, Value} <- Headers] of
        [] -> absent;
        Values -> lists:reverse(transfer_codings(Values, []))
    end.

-spec transfer_codings([binary()], [binary()]) -> [binary()].
transfer_codings([], Acc) ->
    Acc;
transfer_codings([Value | Rest], Acc) ->
    transfer_codings(Rest, split_transfer_codings(binary:split(Value, <<",">>, [global]), Acc)).

-spec trim_ows(binary()) -> binary().
trim_ows(<<" ", Rest/binary>>) -> trim_ows(Rest);
trim_ows(<<"\t", Rest/binary>>) -> trim_ows(Rest);
trim_ows(Bin) -> trim_trailing_ows(Bin).

-spec trim_trailing_ows(binary()) -> binary().
trim_trailing_ows(<<>>) ->
    <<>>;
trim_trailing_ows(Bin) ->
    case binary:last(Bin) of
        $\s ->
            Size = byte_size(Bin) - 1,
            <<Head:Size/binary, _>> = Bin,
            trim_trailing_ows(Head);
        $\t ->
            Size = byte_size(Bin) - 1,
            <<Head:Size/binary, _>> = Bin,
            trim_trailing_ows(Head);
        _ ->
            Bin
    end.
