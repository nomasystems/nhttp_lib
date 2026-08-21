# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.5] - 2026-08-21

### Added

- `certs_keys` client TLS option in `nhttp_sock:build_client_ssl_opts/1` and
  `t:nhttp_sock:connect_opts/0`, forwarding in-memory client certificates for
  mutual TLS (mTLS) without writing cert/key to disk

## [1.0.4] - 2026-08-20

### Added

- `nhttp_h1:encode_response/2` takes `t:nhttp_h1:enc_opts/0`.
  `#{content_length => omit}` suppresses the automatic `Content-Length`
  field. A server that answers a `CONNECT` request with a 2xx status uses
  it, because RFC 9110 Section 8.6 forbids the field there and the response
  map carries no request method

### Fixed

- `nhttp_h1:encode_response/1` emits `Content-Length: 0` on a response with
  an empty body. The call omitted the field before, so a client on a
  persistent connection read the next response as content
- `nhttp_h1:encode_response/1` emits no `Content-Length` at a 1xx, 204, or
  304 status (RFC 9110 Section 8.6). At 304 the field is valid only at the
  length that a 200 response carries, which the encoder cannot compute, so a
  caller that knows the value supplies it in the header list

## [1.0.3] - 2026-08-10

### Added

- `nhttp_ws_frame:scan_utf8/1` and `nhttp_ws_frame:scan_utf8/2` scan a run
  of text for UTF-8 validity and return the trailing bytes that do not yet
  form a character

### Changed

- `nhttp_ws:decode_with_state/2` returns `{continue, Rest, Decoder}` when it
  consumes a non-final fragment. The call returned `{more, 1, Decoder}`
  before, which hid the fact that the frame was consumed

### Fixed

- Return the unconsumed rest of the buffer after a WebSocket fragment. A
  caller that kept the whole buffer decoded the same fragment again and
  failed with `expected_continuation`
- Validate a fragmented text message as UTF-8 (RFC 6455 §5.6) per fragment,
  with the character that spans two frames carried across. A message that
  ends with a truncated character is refused as `invalid_utf8`

## [1.0.2] - 2026-06-12

### Changed

- Listen sockets set `{send_timeout_close, true}` so a send that hits
  `send_timeout` closes the socket instead of leaving it half-dead

### Fixed

- Reject an incomplete HTTP/1.1 request head as `header_too_large` once
  the buffered input exceeds `max_header_size` plus an 8 KiB
  request-line allowance, bounding both memory and the repeated rescan
  of the unparsed tail
- Apply the same `max_header_size` budget to incomplete chunked trailer
  sections
- Reject chunk-size lines longer than 1 KiB as `invalid_chunk_size`

## [1.0.1] - 2026-06-09

### Fixed

- Reject control characters in HTTP/1.1 header field values (RFC 9110)
- Reject whitespace in the HTTP/1.1 request-target (RFC 9112)

## [1.0.0] - 2026-04-20

Initial public release.

### Added

- HTTP/1.1 request and response codec (RFC 9110, RFC 9112)
- HTTP/2 connection and stream state machine (RFC 9113)
- HTTP/3 connection state machine, QUIC transport agnostic (RFC 9114)
- HPACK header compression (RFC 7541)
- QPACK header compression (RFC 9204)
- WebSocket frame codec (RFC 6455)
- Cookie parsing and encoding (RFC 6265)
- Content compression (gzip, deflate)
- Unified TCP/SSL socket abstraction with ALPN negotiation
- Sans-io design: pure functional state machines, no process spawning
- Property-based test suites backed by triq
- RFC 9110 and RFC 9112 compliance test suites
