# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-06-12

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
