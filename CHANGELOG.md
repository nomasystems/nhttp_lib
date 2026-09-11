# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### Performance

- Header operations optimized

## [1.1.1]

### Fixed

- A release started with `-mode embedded` failed to boot. The `-on_load`
  functions of `nhttp_cookie` and `nhttp_h1` called `nhttp_headers`, which
  the boot loader reaches later in alphabetical order, so the call raised
  `undef` and `kernel` did not start. Both modules now compile their own
  patterns from the octet sets in `src/nhttp_ascii.hrl` and call nothing
  outside kernel and stdlib

### Added

- `test/nhttp_load_SUITE` holds the module load contract: no `-on_load`
  function of this application calls another module of this application

## [1.1.0] - 2026-09-10

### Added

- `nhttp_h1:prepare_headers/1` validates a header list once and returns a
  block that `encode_request/2` and `encode_response/2` reuse
- `nhttp_h1:encode_trailers/1` and `nhttp_h1:encode_response_head/4`
- `nhttp_h2:stream_stats/1` reports the active, peer-opened, and peer-reset
  stream counts
- `max_reset_streams` and `max_continuation_frames` in `t:nhttp_h2:settings/0`.
  Both are local bounds and go on no wire. `max_continuation_frames` defaults
  to a value derived from `max_header_list_size`
- `t:nhttp_ws_frame:frame_limits/0` and the capped arities
  `nhttp_ws_frame:decode/2`, `decode_raw/3`, and `decode_unmasked/2`
- `nhttp_headers:validate_field_name/1`, `validate_field_value/1`,
  `lower_field_name/1`, `name_eq/2`, `is_token/1`, and `is_tchar/1`

### Changed

- `nhttp_h1:encode_request/1,2` and `nhttp_h1:encode_response/1,2` return
  `{ok, iolist()} | {error, t:nhttp_h1:encode_error/0}`. They returned
  `iolist()` before
- `nhttp_cookie:encode_cookie/1` and `nhttp_cookie:encode_set_cookie/1` return
  `{ok, binary()} | {error, _}`, and the error names the class of the
  violation
- `nhttp_msg:build_response/2` returns
  `{ok, response()} | {error, invalid_status | missing_status}`
- `nhttp_hpack:decode/2,3` answers `{invalid_field, Reason, State}`, a shape
  apart from the `{error, Reason}` of a decompression failure. `State` carries
  every dynamic table update that the block asks for (RFC 9113 Section 4.3)
- `nhttp_h1` and `nhttp_cookie` scan with patterns that `-on_load` compiles
  into `persistent_term`, and the encode and parse paths build no intermediate
  binary

### Security

- Refuse a field name that is not a token, and a field value that carries CR,
  LF, NUL, another control byte, or `0x7F`, at the HTTP/1.1 encoder. The
  message is refused whole (RFC 9110 Sections 5.5 and 5.6.2, RFC 9112 Section
  11.1). Response splitting and request smuggling (CVE-2020-11709,
  CVE-2023-26130, CVE-2025-0825, CVE-2026-21428, CVE-2026-45372)
- Validate a cookie name, a cookie value, a `Path`, and a `Domain` against the
  RFC 6265 Section 4.1.1 grammar on encode. No value is stripped, quoted, or
  truncated (CVE-2020-11709, CVE-2023-26130, CVE-2025-0825, CVE-2026-21428,
  CVE-2026-45372)
- Read every literal field name and every literal field value in the HPACK and
  the QPACK decoder. An uppercase name, an invalid octet, an interior colon, or
  a value with leading or trailing whitespace is a stream error of type
  PROTOCOL_ERROR on HTTP/2 and H3_MESSAGE_ERROR on HTTP/3 (RFC 9113 Section
  8.2.1, RFC 9114 Section 4.1.2)
- Combine every `Transfer-Encoding` field line into one coding list, and accept
  the message only when that list holds `chunked` once, as the final coding
  (RFC 9112 Sections 6.1 and 6.3). Refuse a chunk that does not end with CRLF
  as `incomplete_chunk`, and refuse a `Content-Length` value that is not a run
  of digits (CVE-2026-34441, CVE-2026-45352, CVE-2026-46527)
- Refuse a declared WebSocket payload length above `max_frame_size` as
  `{error, {frame_too_large, DeclaredLength}}`, before the payload is buffered
  (RFC 6455 Section 10.4). `nhttp_ws` caps at its maximum message size
  (CVE-2025-46728, CVE-2025-53629)
- Refuse a byte that follows a complete gzip or deflate stream as
  `{error, trailing_data}` (CVE-2026-22776, CVE-2026-28435)
- Count the streams that the peer opens and resets, and fail the connection
  with ENHANCE_YOUR_CALM above `max_reset_streams` (CVE-2023-44487). Bound the
  number of CONTINUATION frames in one field block (CVE-2026-29076)
- `nhttp_msg:build_response/2` never raises on peer input. A missing or
  malformed `:status` is a stream error (CVE-2026-31870)

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
