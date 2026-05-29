# nhttp_lib

[![Hex.pm](https://img.shields.io/hexpm/v/nhttp_lib.svg)](https://hex.pm/packages/nhttp_lib)
[![CI](https://github.com/nomasystems/nhttp_lib/actions/workflows/ci.yml/badge.svg)](https://github.com/nomasystems/nhttp_lib/actions/workflows/ci.yml)

Pure functional HTTP/1.1, HTTP/2, and HTTP/3 codec for Erlang/OTP 27+.

## Getting started

```erlang
%% rebar.config
{deps, [nhttp_lib]}.
```

### Parsing

```erlang
Data = <<"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n">>,
Opts = #{scheme => http, peer => {{127,0,0,1}, 54321}},
case nhttp_h1:parse_request(Data, Opts) of
    {ok, #{method := Method, path := Path} = _Request, _Consumed} ->
        {Method, Path};
    {more, _MinBytes} ->
        need_more_data;
    {error, Reason} ->
        {error, Reason}
end.
```

The request map is the canonical `t:nhttp_lib:request/0` shape: `method`,
`path`, `scheme`, `authority`, and `headers` are always populated; `peer`,
`protocol`, and `version` are filled by the parser. Use `nhttp_headers:get/2`
to look up header values.

### Encoding

```erlang
Response = #{
    status => 200,
    headers => [{<<"content-type">>, <<"text/plain">>}],
    body => <<"Hello, World!">>
},
IoData = nhttp_h1:encode_response(Response).
```

`encode_request/1` and `encode_response/1` return an `iolist()` directly.
For chunked / streaming bodies, omit `body` from the map and emit the
header block with `encode_response_head/3`, body chunks with
`encode_chunk/1`, and a trailing `encode_last_chunk/0`.

## Features

- **HTTP/1.1** request/response parsing and encoding ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112))
- **HTTP/2** connection and stream state machine ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113))
- **HTTP/3** connection state machine, QUIC transport agnostic ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114))
- **HTTP semantics** shared across versions ([RFC 9110](https://www.rfc-editor.org/rfc/rfc9110))
- **HPACK** header compression for HTTP/2 ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541))
- **QPACK** field compression for HTTP/3 ([RFC 9204](https://www.rfc-editor.org/rfc/rfc9204))
- **WebSocket** frame codec with masking ([RFC 6455](https://www.rfc-editor.org/rfc/rfc6455))
- **Cookies** parsing and encoding ([RFC 6265](https://www.rfc-editor.org/rfc/rfc6265))
- **Compression** gzip/deflate content encoding
- **Socket** unified TCP/TLS interface with ALPN
- **Minimal dependencies** OTP stdlib apps plus `nquic` (QUIC varint codec from [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), shared with the QUIC transport)

## Documentation

[nhttp_lib on HexDocs](https://hexdocs.pm/nhttp_lib)

## License

Apache License 2.0
