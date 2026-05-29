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
IOList = nhttp_h1:encode_request(Request).
IOList = nhttp_h1:encode_response(Response).
```

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
        is_tchar/1,
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
%% COMPILED PATTERNS
%%%-----------------------------------------------------------------------------
-define(PT_CRLF, {?MODULE, crlf_pattern}).
-define(PT_COLON, {?MODULE, colon_pattern}).
-define(PT_URI_DELIMS, {?MODULE, uri_delims_pattern}).

-on_load(init_patterns/0).

-spec init_patterns() -> ok.
init_patterns() ->
    ok = persistent_term:put(?PT_CRLF, binary:compile_pattern(<<"\r\n">>)),
    ok = persistent_term:put(?PT_COLON, binary:compile_pattern(<<":">>)),
    ok = persistent_term:put(
        ?PT_URI_DELIMS, binary:compile_pattern([<<"/">>, <<"?">>, <<"#">>])
    ),
    ok.

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
- `Transfer-Encoding: chunked` → `{chunked, _}`.
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
    case nhttp_headers:get(<<"transfer-encoding">>, Headers) of
        TE when is_binary(TE) ->
            case is_chunked_transfer_encoding(TE) of
                true -> {chunked, #chunked_st{}};
                false -> until_close
            end;
        undefined ->
            case nhttp_headers:get(<<"content-length">>, Headers) of
                undefined ->
                    until_close;
                LenBin ->
                    case parse_content_length(LenBin) of
                        {ok, Len} -> {length, Len};
                        {error, _} -> until_close
                    end
            end
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
    maybe
        {ok, Method, Path, Version, Rest} ?= parse_request_line(Bin),
        {ok, Headers, BodyRest} ?= parse_headers_acc(Rest, [], 0, MaxHeaderSize, MaxHeadersCount),
        HeadersConsumed = OriginalSize - byte_size(BodyRest),
        Req = build_request(Method, Path, Version, Headers, Opts),
        finish_request(Req, BodyRest, Headers, HeadersConsumed, Opts)
    end.

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
    end.

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

-doc "Encode an HTTP/1.1 request to iolist.".
-spec encode_request(req()) -> iolist().
encode_request(#{method := Method, path := Path} = Req) ->
    Version = maps:get(version, Req, http1_1),
    Headers = maps:get(headers, Req, []),
    Body = maps:get(body, Req, <<>>),
    FinalHeaders = maybe_add_content_length(Headers, Body),
    [
        nhttp_lib:encode_method(Method),
        <<" ">>,
        Path,
        <<" ">>,
        encode_version(Version),
        <<"\r\n">>,
        encode_headers(FinalHeaders),
        <<"\r\n">>,
        Body
    ].

-doc "Encode an HTTP/1.1 response to iolist.".
-spec encode_response(resp()) -> iolist().
encode_response(#{status := Status} = Resp) ->
    Version = maps:get(version, Resp, http1_1),
    Reason = maps:get(reason, Resp, <<>>),
    Headers = maps:get(headers, Resp, []),
    Body = maps:get(body, Resp, <<>>),
    FinalHeaders = maybe_add_content_length(Headers, Body),
    [
        encode_version(Version),
        <<" ">>,
        integer_to_binary(Status),
        <<" ">>,
        Reason,
        <<"\r\n">>,
        encode_headers(FinalHeaders),
        <<"\r\n">>,
        Body
    ].

-doc "Encode HTTP/1.x response headers for streaming. Used when sending chunked responses - sends status line + headers only.".
-spec encode_response_head(version(), nhttp_lib:status(), nhttp_lib:headers()) ->
    iolist().
encode_response_head(Version, Status, Headers) ->
    Reason = reason_phrase(Status),
    [
        encode_version(Version),
        <<" ">>,
        integer_to_binary(Status),
        <<" ">>,
        Reason,
        <<"\r\n">>,
        encode_headers(Headers),
        <<"\r\n">>
    ].

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
    case nhttp_headers:get(<<"transfer-encoding">>, Headers) of
        TE when is_binary(TE) ->
            case nhttp_headers:has(<<"content-length">>, Headers) of
                true ->
                    {error, conflicting_framing};
                false ->
                    case is_chunked_transfer_encoding(TE) of
                        true -> chunked;
                        false -> {error, unsupported_transfer_encoding}
                    end
            end;
        undefined ->
            case get_all_content_lengths(Headers) of
                [] ->
                    undefined;
                [LenBin] ->
                    case parse_content_length(LenBin) of
                        {ok, 0} -> undefined;
                        {ok, Len} -> {content_length, Len};
                        {error, _} -> {error, invalid_content_length}
                    end;
                [First | Rest] ->
                    case lists:all(fun(V) -> V =:= First end, Rest) of
                        true ->
                            case parse_content_length(First) of
                                {ok, 0} -> undefined;
                                {ok, Len} -> {content_length, Len};
                                {error, _} -> {error, invalid_content_length}
                            end;
                        false ->
                            {error, duplicate_content_length}
                    end
            end
    end.

-spec encode_headers(nhttp_lib:headers()) -> iolist().
encode_headers(Headers) ->
    [[Name, <<": ">>, Value, <<"\r\n">>] || {Name, Value} <- Headers].

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
find_path_version(Bin, Method) ->
    case binary:split(Bin, <<" HTTP/1.">>) of
        [Path, <<Ver:1/binary, "\r\n", Rest/binary>>] when Ver =:= <<"1">>; Ver =:= <<"0">> ->
            Version =
                case Ver of
                    <<"1">> -> http1_1;
                    <<"0">> -> http1_0
                end,
            {ok, Method, Path, Version, Rest};
        [_Path, <<Ver:1/binary, "\r">>] when Ver =:= <<"1">>; Ver =:= <<"0">> ->
            {more, 1};
        [_Path, <<Ver:1/binary>>] when Ver =:= <<"1">>; Ver =:= <<"0">> ->
            {more, 2};
        [_Path, <<>>] ->
            {more, 3};
        [_Path, <<_/binary>>] ->
            {error, invalid_version};
        [_] ->
            find_path_version_cold(Bin)
    end.

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

-spec has_invalid_char(binary()) -> boolean().
has_invalid_char(<<>>) -> false;
has_invalid_char(<<$\r, _/binary>>) -> true;
has_invalid_char(<<$\n, _/binary>>) -> true;
has_invalid_char(<<0, _/binary>>) -> true;
has_invalid_char(<<_, Rest/binary>>) -> has_invalid_char(Rest).

-spec is_chunked_transfer_encoding(binary()) -> boolean().
is_chunked_transfer_encoding(Bin) ->
    Codings = binary:split(Bin, <<",">>, [global, trim_all]),
    case lists:reverse(Codings) of
        [Last | _] -> nhttp_headers:to_lower(trim_ows(Last)) =:= <<"chunked">>;
        [] -> false
    end.

-spec is_tchar(byte()) -> boolean().
is_tchar(C) when C >= $a, C =< $z -> true;
is_tchar(C) when C >= $A, C =< $Z -> true;
is_tchar(C) when C >= $0, C =< $9 -> true;
is_tchar($!) -> true;
is_tchar($#) -> true;
is_tchar($$) -> true;
is_tchar($%) -> true;
is_tchar($&) -> true;
is_tchar($') -> true;
is_tchar($*) -> true;
is_tchar($+) -> true;
is_tchar($-) -> true;
is_tchar($.) -> true;
is_tchar($^) -> true;
is_tchar($_) -> true;
is_tchar($`) -> true;
is_tchar($|) -> true;
is_tchar($~) -> true;
is_tchar(_) -> false.

-spec is_token(binary()) -> boolean().
is_token(<<>>) -> false;
is_token(Bin) -> is_token_chars(Bin).

-spec is_token_chars(binary()) -> boolean().
is_token_chars(<<>>) ->
    true;
is_token_chars(<<C, Rest/binary>>) ->
    case is_tchar(C) of
        true -> is_token_chars(Rest);
        false -> false
    end.

-spec is_valid_chunk_ext_tail(binary()) -> boolean().
is_valid_chunk_ext_tail(<<>>) -> true;
is_valid_chunk_ext_tail(Bin) -> skip_bws_to_semi(Bin).

-spec maybe_add_content_length(nhttp_lib:headers(), iodata()) -> nhttp_lib:headers().
maybe_add_content_length(Headers, Body) ->
    case iolist_size(Body) of
        0 ->
            Headers;
        Len ->
            case
                nhttp_headers:has(<<"content-length">>, Headers) orelse
                    nhttp_headers:has(<<"transfer-encoding">>, Headers)
            of
                true ->
                    Headers;
                false ->
                    [{<<"content-length">>, integer_to_binary(Len)} | Headers]
            end
    end.

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
            case Available >= TotalNeeded of
                true ->
                    <<_:BodyStart/binary, ChunkData:Size/binary, "\r\n", _/binary>> = Original,
                    {ok, ChunkData, HeaderLen + Size + 2};
                false ->
                    {more, TotalNeeded - Available}
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
    try
        case binary_to_integer(Bin) of
            N when N >= 0 -> {ok, N};
            _ -> {error, badarg}
        end
    catch
        error:badarg -> {error, badarg}
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
parse_header_value_direct(Name, PrefixLen, Rest, Acc, Count, Size, MaxSize, MaxCount) ->
    case binary:match(Rest, persistent_term:get(?PT_CRLF)) of
        {Pos, 2} ->
            Value = trim_ows(binary:part(Rest, 0, Pos)),
            case has_invalid_char(Value) of
                true ->
                    {error, bad_header};
                false ->
                    LineSize = PrefixLen + Pos + 2,
                    NewSize = Size + LineSize,
                    NewCount = Count + 1,
                    case check_header_limits(NewSize, MaxSize, NewCount, MaxCount) of
                        ok ->
                            Remaining = binary:part(Rest, Pos + 2, byte_size(Rest) - Pos - 2),
                            parse_headers_acc(
                                Remaining,
                                [{Name, Value} | Acc],
                                NewCount,
                                NewSize,
                                MaxSize,
                                MaxCount
                            );
                        {error, _} = Err ->
                            Err
                    end
            end;
        nomatch ->
            {more, 2}
    end.

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
                    case is_token(Name) of
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
    case binary:split(Bin, <<" ">>) of
        [Method, Rest] when byte_size(Method) =< 16 ->
            find_path_version(Rest, Method);
        [_] when byte_size(Bin) < 18 ->
            case binary:match(Bin, <<"\r\n">>) of
                nomatch -> {more, 18 - byte_size(Bin)};
                _ -> {error, bad_request_line}
            end;
        _ ->
            {error, bad_request_line}
    end;
parse_request_line(<<C, _/binary>>) when C >= $a, C =< $z ->
    {error, invalid_method};
parse_request_line(<<"\r\n", _/binary>>) ->
    {error, bad_request_line};
parse_request_line(Bin) when byte_size(Bin) < 16 ->
    {more, 16 - byte_size(Bin)};
parse_request_line(_) ->
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
        <<_:Pos/binary, _, _/binary>> ->
            scan_chunk_size_line(Bin, Skip, SizeLen + 1);
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
