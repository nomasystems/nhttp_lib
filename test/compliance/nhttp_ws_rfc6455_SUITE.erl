%%%-----------------------------------------------------------------------------
-module(nhttp_ws_rfc6455_SUITE).

-moduledoc """
RFC 6455 Compliance Test Suite.

This suite tests compliance with RFC 6455 (The WebSocket Protocol) for
the bounds that a decoder must place on an attacker-declared frame
header. Each group is linked to the section of the specification that
governs it.

Section 10.4 requires an implementation to protect itself against "a
single big frame (e.g., of size 2**60)". Section 5.5 makes 125 bytes a
legal payload length for every control frame, so the bound of Section
10.4 never refuses one. Section 5.2 requires a nonzero RSV bit to fail
the connection.

Run with: rebar3 ct --suite=test/compliance/nhttp_ws_rfc6455_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_10_4_frame_size_limit},
        {group, section_5_5_control_frames},
        {group, section_5_2_reserved_bits}
    ].

groups() ->
    [
        {section_10_4_frame_size_limit, [parallel], [
            declared_2_pow_60_refused_before_buffering,
            declared_2_pow_60_refused_on_the_unmasked_path,
            declared_length_refused_by_the_stateful_decoder,
            stateful_decoder_bounds_by_default,
            declared_length_at_the_limit_accepted,
            declared_length_above_the_limit_refused,
            truncated_header_still_requests_header_bytes,
            no_limit_leaves_the_declared_length_untouched
        ]},
        {section_5_5_control_frames, [parallel], [
            control_frame_of_125_bytes_accepted_under_a_smaller_limit,
            control_frame_above_125_bytes_refused
        ]},
        {section_5_2_reserved_bits, [parallel], [
            reserved_bit_fails_the_raw_masked_path,
            reserved_bit_fails_the_raw_unmasked_path,
            reserved_bit_fails_the_message_path
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% SECTION 10.4: IMPLEMENTATION-SPECIFIC LIMITS
%%%
%%% "Implementations that have implementation- and/or platform-specific
%%% limitations regarding the frame size or total message size after
%%% reassembly from multiple frames MUST protect themselves against
%%% exceeding those limits. (For example, a malicious endpoint can try to
%%% exhaust its peer's memory or mount a denial-of-service attack by
%%% sending either a single big frame (e.g., of size 2**60) ...)"
%%%-----------------------------------------------------------------------------

declared_2_pow_60_refused_before_buffering(_Config) ->
    Header = <<1:1, 0:3, 2:4, 1:1, 127:7, 0:1, (1 bsl 60):63, 0, 0, 0, 0>>,
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws_frame:decode_raw(Header, server, #{max_frame_size => 1 bsl 20})
    ).

declared_2_pow_60_refused_on_the_unmasked_path(_Config) ->
    Header = <<1:1, 0:3, 2:4, 0:1, 127:7, 0:1, (1 bsl 60):63>>,
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws_frame:decode_raw(Header, client, #{max_frame_size => 1 bsl 20})
    ).

declared_length_refused_by_the_stateful_decoder(_Config) ->
    Dec = nhttp_ws:decoder_new(client, #{max_message_size => 1 bsl 20}),
    Header = <<16#82, 127, 0:1, (1 bsl 60):63>>,
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws:decode_with_state(Header, Dec)
    ).

stateful_decoder_bounds_by_default(_Config) ->
    Dec = nhttp_ws:decoder_new(client),
    Header = <<16#82, 127, 0:1, (1 bsl 60):63>>,
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws:decode_with_state(Header, Dec)
    ).

declared_length_at_the_limit_accepted(_Config) ->
    Header = <<16#82, 16#FE, 4096:16>>,
    ?assertEqual(
        {more, 4100},
        nhttp_ws_frame:decode_raw(Header, server, #{max_frame_size => 4096})
    ).

declared_length_above_the_limit_refused(_Config) ->
    Header = <<16#82, 16#FE, 4097:16>>,
    ?assertEqual(
        {error, {frame_too_large, 4097}},
        nhttp_ws_frame:decode_raw(Header, server, #{max_frame_size => 4096})
    ).

truncated_header_still_requests_header_bytes(_Config) ->
    ?assertEqual(
        {more, 2},
        nhttp_ws_frame:decode_raw(<<16#82, 16#FE>>, server, #{max_frame_size => 4096})
    ),
    ?assertEqual(
        {more, 6},
        nhttp_ws_frame:decode_raw(<<16#82, 16#FF, 0, 0>>, server, #{max_frame_size => 4096})
    ).

no_limit_leaves_the_declared_length_untouched(_Config) ->
    Header = <<1:1, 0:3, 2:4, 1:1, 127:7, 0:1, (1 bsl 60):63, 0, 0, 0, 0>>,
    ?assertEqual(
        {more, 1 bsl 60},
        nhttp_ws_frame:decode_raw(Header, server, #{max_frame_size => infinity})
    ),
    ?assertEqual({more, 1 bsl 60}, nhttp_ws_frame:decode_raw(Header, server)).

%%%-----------------------------------------------------------------------------
%%% SECTION 5.5: CONTROL FRAMES
%%%
%%% "All control frames MUST have a payload length of 125 bytes or less
%%% and MUST NOT be fragmented."
%%%-----------------------------------------------------------------------------

control_frame_of_125_bytes_accepted_under_a_smaller_limit(_Config) ->
    Payload = binary:copy(<<7>>, 125),
    Frame = iolist_to_binary(nhttp_ws_frame:encode_masked({ping, Payload})),
    ?assertEqual(
        {ok, 1, 9, Payload, <<>>},
        nhttp_ws_frame:decode_raw(Frame, server, #{max_frame_size => 8})
    ).

control_frame_above_125_bytes_refused(_Config) ->
    Payload = binary:copy(<<7>>, 126),
    Frame = iolist_to_binary(nhttp_ws_frame:encode_masked({ping, Payload})),
    ?assertEqual(
        {error, control_frame_too_large},
        nhttp_ws_frame:decode(Frame, #{max_frame_size => 4096})
    ).

%%%-----------------------------------------------------------------------------
%%% SECTION 5.2: RSV1, RSV2, RSV3
%%%
%%% "MUST be 0 unless an extension is negotiated that defines meanings
%%% for non-zero values. If a nonzero value is received and none of the
%%% negotiated extensions defines the meaning of such a nonzero value,
%%% the receiving endpoint MUST _Fail the WebSocket Connection_."
%%%-----------------------------------------------------------------------------

reserved_bit_fails_the_raw_masked_path(_Config) ->
    Frame = <<1:1, 4:3, 1:4, 1:1, 0:7, 0:32>>,
    ?assertEqual({error, reserved_bits_set}, nhttp_ws_frame:decode_raw(Frame, server)).

reserved_bit_fails_the_raw_unmasked_path(_Config) ->
    Frame = <<1:1, 1:3, 1:4, 0:1, 0:7>>,
    ?assertEqual({error, reserved_bits_set}, nhttp_ws_frame:decode_raw(Frame, client)).

reserved_bit_fails_the_message_path(_Config) ->
    Frame = <<1:1, 2:3, 1:4, 0:1, 0:7>>,
    ?assertEqual({error, reserved_bits_set}, nhttp_ws_frame:decode_unmasked(Frame)).
