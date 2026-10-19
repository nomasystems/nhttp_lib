-module(nhttp_ws_SUITE).

-moduledoc """
WebSocket codec test suite (RFC 6455).

Tests frame encoding/decoding, handshake validation, masking, unmasked
decoding, and stateful fragmentation for both server and client roles.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1
]).

%%%-----------------------------------------------------------------------------
%%% TEST CASES
%%%-----------------------------------------------------------------------------
-export([
    accept_key_generation/1,
    handshake_response/1,
    validate_upgrade_valid/1,
    validate_upgrade_missing_upgrade/1,
    validate_upgrade_missing_connection/1,
    validate_upgrade_missing_key/1,
    validate_upgrade_wrong_version/1,
    validate_upgrade_wrong_upgrade_value/1,
    validate_upgrade_connection_not_upgrade/1,
    validate_version_missing/1,
    generate_key/1,
    validate_accept/1,
    validate_accept_invalid/1,
    encode_text/1,
    encode_binary/1,
    encode_ping/1,
    encode_ping_with_data/1,
    encode_pong/1,
    encode_close/1,
    encode_close_with_code/1,
    encode_extended_16/1,
    encode_extended_64/1,
    decode_text/1,
    decode_binary/1,
    decode_ping/1,
    decode_ping_with_data/1,
    decode_pong/1,
    decode_close/1,
    decode_close_with_code/1,
    decode_large_payload/1,
    decode_extended_64/1,
    decode_incomplete/1,
    decode_unmasked_error/1,
    decode_reserved_bits_error/1,
    decode_fragmentation_error/1,
    decode_unknown_opcode_error/1,
    decode_partial_masked/1,
    decode_partial_ext16/1,
    decode_partial_ext64/1,
    decode_oversized_ping_rejected/1,
    decode_oversized_close_rejected/1,
    decode_fragmented_ping_rejected/1,
    decode_fragmented_close_rejected/1,
    encode_masked_roundtrip/1,
    encode_masked_all_types/1,
    encode_masked_helpers/1,
    encode_masked_large_16/1,
    encode_masked_large_64/1,
    decode_unmasked_text/1,
    decode_unmasked_all_types/1,
    decode_unmasked_extended_16/1,
    decode_unmasked_extended_64/1,
    decode_unmasked_incomplete/1,
    decode_unmasked_masked_error/1,
    decode_unmasked_reserved_bits/1,
    decode_unmasked_partial_ext16/1,
    decode_unmasked_partial_ext64/1,
    frag_text/1,
    frag_binary/1,
    frag_with_control/1,
    frag_coalesced_fragments/1,
    frag_coalesced_with_control/1,
    frag_text_invalid_utf8_fails_at_fragment/1,
    frag_text_split_code_point/1,
    frag_text_truncated_at_fin/1,
    frag_binary_not_utf8_checked/1,
    frag_error_no_start/1,
    frag_server_decoder/1,
    frag_message_too_large_start/1,
    frag_message_too_large_continuation/1,
    frag_single_frame_too_large/1,
    frag_max_message_size_infinity/1,
    frag_frame_cap_refuses_before_buffering/1,
    frag_length_top_bit_refused/1,
    frag_frame_cap_infinity_buffers/1,
    frag_default_max_message_size_is_finite/1,
    partial_autobahn_6_4_3/1,
    partial_autobahn_6_4_4/1,
    partial_text_split_code_point_survives/1,
    partial_text_completes_after_chops/1,
    partial_binary_not_scanned/1,
    partial_continuation_scanned/1,
    partial_text_mid_fragment_not_scanned/1,
    partial_repeat_without_new_bytes/1,
    partial_control_frame_not_scanned/1,
    session_accessors/1,
    session_send_envelope/1,
    session_send_async_envelope/1,
    session_send_gone_when_pid_dead/1,
    session_send_timeout_when_no_reply/1,
    session_info_envelope/1,
    session_close_envelope/1,
    session_broadcast_to_session/1,
    session_broadcast_to_pid/1,
    session_is_alive/1,
    session_send_refuses_close/1,
    session_send_refuses_oversize_control/1,
    session_close_refuses_invalid/1,
    session_h1_without_socket_routes_to_conn/1,
    feed_empty_input/1,
    feed_header_split_at_every_boundary_unmasked/1,
    feed_header_split_at_every_boundary_masked/1,
    feed_header_one_byte_at_a_time/1,
    feed_chunk_ends_at_frame_boundary/1,
    feed_chunk_spans_two_frames/1,
    feed_many_frames_in_one_chunk/1,
    feed_frame_too_large_at_header/1,
    feed_message_too_large_at_continuation_header/1,
    feed_single_frame_too_large_at_byte_count/1,
    feed_control_frame_too_large_at_header/1,
    feed_fragmented_control_frame_at_header/1,
    feed_control_frame_inside_fragmented_message/1,
    feed_error_returns_earlier_messages/1,
    feed_invalid_utf8_on_carrying_chunk/1,
    feed_utf8_carry_across_chunks_and_fragments/1,
    feed_truncated_utf8_at_fin/1,
    feed_binary_not_utf8_checked/1,
    feed_masked_frame_refused_by_client/1,
    feed_unmasked_frame_refused_by_server/1,
    feed_reserved_bits_refused/1,
    feed_length_top_bit_refused/1,
    feed_expected_continuation/1,
    feed_close_frame_validated/1,
    feed_frame_pending/1,
    feed_16mib_binary_in_16kib_chunks/1,
    feed_16mib_text_in_16kib_chunks/1
]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, handshake},
        {group, client_handshake},
        {group, server_encoding},
        {group, server_decoding},
        {group, client_encoding},
        {group, client_decoding},
        {group, fragmentation},
        {group, partial_scan},
        {group, session},
        {group, feed},
        {group, feed_timing}
    ].

groups() ->
    [
        {handshake, [parallel], [
            accept_key_generation,
            handshake_response,
            validate_upgrade_valid,
            validate_upgrade_missing_upgrade,
            validate_upgrade_missing_connection,
            validate_upgrade_missing_key,
            validate_upgrade_wrong_version,
            validate_upgrade_wrong_upgrade_value,
            validate_upgrade_connection_not_upgrade,
            validate_version_missing
        ]},
        {client_handshake, [parallel], [
            generate_key,
            validate_accept,
            validate_accept_invalid
        ]},
        {server_encoding, [parallel], [
            encode_text,
            encode_binary,
            encode_ping,
            encode_ping_with_data,
            encode_pong,
            encode_close,
            encode_close_with_code,
            encode_extended_16,
            encode_extended_64
        ]},
        {server_decoding, [parallel], [
            decode_text,
            decode_binary,
            decode_ping,
            decode_ping_with_data,
            decode_pong,
            decode_close,
            decode_close_with_code,
            decode_large_payload,
            decode_extended_64,
            decode_incomplete,
            decode_unmasked_error,
            decode_reserved_bits_error,
            decode_fragmentation_error,
            decode_unknown_opcode_error,
            decode_partial_masked,
            decode_partial_ext16,
            decode_partial_ext64,
            decode_oversized_ping_rejected,
            decode_oversized_close_rejected,
            decode_fragmented_ping_rejected,
            decode_fragmented_close_rejected
        ]},
        {client_encoding, [parallel], [
            encode_masked_roundtrip,
            encode_masked_all_types,
            encode_masked_helpers,
            encode_masked_large_16,
            encode_masked_large_64
        ]},
        {client_decoding, [parallel], [
            decode_unmasked_text,
            decode_unmasked_all_types,
            decode_unmasked_extended_16,
            decode_unmasked_extended_64,
            decode_unmasked_incomplete,
            decode_unmasked_masked_error,
            decode_unmasked_reserved_bits,
            decode_unmasked_partial_ext16,
            decode_unmasked_partial_ext64
        ]},
        {fragmentation, [parallel], [
            frag_text,
            frag_binary,
            frag_with_control,
            frag_coalesced_fragments,
            frag_coalesced_with_control,
            frag_text_invalid_utf8_fails_at_fragment,
            frag_text_split_code_point,
            frag_text_truncated_at_fin,
            frag_binary_not_utf8_checked,
            frag_error_no_start,
            frag_server_decoder,
            frag_message_too_large_start,
            frag_message_too_large_continuation,
            frag_single_frame_too_large,
            frag_max_message_size_infinity,
            frag_frame_cap_refuses_before_buffering,
            frag_length_top_bit_refused,
            frag_frame_cap_infinity_buffers,
            frag_default_max_message_size_is_finite
        ]},
        {partial_scan, [parallel], [
            partial_autobahn_6_4_3,
            partial_autobahn_6_4_4,
            partial_text_split_code_point_survives,
            partial_text_completes_after_chops,
            partial_binary_not_scanned,
            partial_continuation_scanned,
            partial_text_mid_fragment_not_scanned,
            partial_repeat_without_new_bytes,
            partial_control_frame_not_scanned
        ]},
        {session, [parallel], [
            session_accessors,
            session_send_envelope,
            session_send_async_envelope,
            session_send_gone_when_pid_dead,
            session_send_timeout_when_no_reply,
            session_info_envelope,
            session_close_envelope,
            session_broadcast_to_session,
            session_broadcast_to_pid,
            session_is_alive,
            session_send_refuses_close,
            session_send_refuses_oversize_control,
            session_close_refuses_invalid,
            session_h1_without_socket_routes_to_conn
        ]},
        {feed, [parallel], [
            feed_empty_input,
            feed_header_split_at_every_boundary_unmasked,
            feed_header_split_at_every_boundary_masked,
            feed_header_one_byte_at_a_time,
            feed_chunk_ends_at_frame_boundary,
            feed_chunk_spans_two_frames,
            feed_many_frames_in_one_chunk,
            feed_frame_too_large_at_header,
            feed_message_too_large_at_continuation_header,
            feed_single_frame_too_large_at_byte_count,
            feed_control_frame_too_large_at_header,
            feed_fragmented_control_frame_at_header,
            feed_control_frame_inside_fragmented_message,
            feed_error_returns_earlier_messages,
            feed_invalid_utf8_on_carrying_chunk,
            feed_utf8_carry_across_chunks_and_fragments,
            feed_truncated_utf8_at_fin,
            feed_binary_not_utf8_checked,
            feed_masked_frame_refused_by_client,
            feed_unmasked_frame_refused_by_server,
            feed_reserved_bits_refused,
            feed_length_top_bit_refused,
            feed_expected_continuation,
            feed_close_frame_validated,
            feed_frame_pending
        ]},
        {feed_timing, [], [
            feed_16mib_binary_in_16kib_chunks,
            feed_16mib_text_in_16kib_chunks
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% HANDSHAKE TESTS
%%%-----------------------------------------------------------------------------

accept_key_generation(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    Expected = <<"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=">>,
    ?assertEqual(Expected, nhttp_ws:accept_key(Key)).

handshake_response(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    Response = iolist_to_binary(nhttp_ws:handshake_response(Key)),
    ?assertMatch(<<"HTTP/1.1 101 Switching Protocols\r\n", _/binary>>, Response),
    ?assert(binary:match(Response, <<"Upgrade: websocket\r\n">>) =/= nomatch),
    ?assert(binary:match(Response, <<"Connection: Upgrade\r\n">>) =/= nomatch),
    ?assert(
        binary:match(Response, <<"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=">>) =/=
            nomatch
    ).

validate_upgrade_valid(_Config) ->
    Req = #{
        headers => [
            {<<"upgrade">>, <<"websocket">>},
            {<<"connection">>, <<"Upgrade">>},
            {<<"sec-websocket-key">>, <<"dGhlIHNhbXBsZSBub25jZQ==">>},
            {<<"sec-websocket-version">>, <<"13">>}
        ]
    },
    ?assertMatch({ok, <<"dGhlIHNhbXBsZSBub25jZQ==">>}, nhttp_ws:validate_upgrade(Req)).

validate_upgrade_missing_upgrade(_Config) ->
    Req = #{
        headers => [
            {<<"connection">>, <<"Upgrade">>},
            {<<"sec-websocket-key">>, <<"dGhlIHNhbXBsZSBub25jZQ==">>},
            {<<"sec-websocket-version">>, <<"13">>}
        ]
    },
    ?assertMatch({error, invalid_upgrade}, nhttp_ws:validate_upgrade(Req)).

validate_upgrade_missing_connection(_Config) ->
    Req = #{
        headers => [
            {<<"upgrade">>, <<"websocket">>},
            {<<"sec-websocket-key">>, <<"dGhlIHNhbXBsZSBub25jZQ==">>},
            {<<"sec-websocket-version">>, <<"13">>}
        ]
    },
    ?assertMatch({error, invalid_connection}, nhttp_ws:validate_upgrade(Req)).

validate_upgrade_missing_key(_Config) ->
    Req = #{
        headers => [
            {<<"upgrade">>, <<"websocket">>},
            {<<"connection">>, <<"Upgrade">>},
            {<<"sec-websocket-version">>, <<"13">>}
        ]
    },
    ?assertMatch({error, missing_key}, nhttp_ws:validate_upgrade(Req)).

validate_upgrade_wrong_version(_Config) ->
    Req = #{
        headers => [
            {<<"upgrade">>, <<"websocket">>},
            {<<"connection">>, <<"Upgrade">>},
            {<<"sec-websocket-key">>, <<"dGhlIHNhbXBsZSBub25jZQ==">>},
            {<<"sec-websocket-version">>, <<"8">>}
        ]
    },
    ?assertMatch({error, unsupported_version}, nhttp_ws:validate_upgrade(Req)).

validate_upgrade_wrong_upgrade_value(_Config) ->
    Req = #{
        headers => [
            {<<"upgrade">>, <<"http/2.0">>},
            {<<"connection">>, <<"Upgrade">>},
            {<<"sec-websocket-key">>, <<"dGhlIHNhbXBsZSBub25jZQ==">>},
            {<<"sec-websocket-version">>, <<"13">>}
        ]
    },
    ?assertMatch({error, invalid_upgrade}, nhttp_ws:validate_upgrade(Req)).

validate_upgrade_connection_not_upgrade(_Config) ->
    Req = #{
        headers => [
            {<<"upgrade">>, <<"websocket">>},
            {<<"connection">>, <<"keep-alive">>},
            {<<"sec-websocket-key">>, <<"dGhlIHNhbXBsZSBub25jZQ==">>},
            {<<"sec-websocket-version">>, <<"13">>}
        ]
    },
    ?assertMatch({error, invalid_connection}, nhttp_ws:validate_upgrade(Req)).

validate_version_missing(_Config) ->
    Req = #{
        headers => [
            {<<"upgrade">>, <<"websocket">>},
            {<<"connection">>, <<"Upgrade">>},
            {<<"sec-websocket-key">>, <<"dGhlIHNhbXBsZSBub25jZQ==">>}
        ]
    },
    ?assertMatch({error, unsupported_version}, nhttp_ws:validate_upgrade(Req)).

%%%-----------------------------------------------------------------------------
%%% CLIENT HANDSHAKE TESTS
%%%-----------------------------------------------------------------------------

generate_key(_Config) ->
    Key = nhttp_ws:generate_key(),
    ?assertEqual(24, byte_size(Key)),
    Key2 = nhttp_ws:generate_key(),
    ?assertNotEqual(Key, Key2).

validate_accept(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    Accept = nhttp_ws:accept_key(Key),
    ?assertEqual(ok, nhttp_ws:validate_accept(Key, Accept)).

validate_accept_invalid(_Config) ->
    Key = <<"dGhlIHNhbXBsZSBub25jZQ==">>,
    ?assertEqual({error, invalid_accept}, nhttp_ws:validate_accept(Key, <<"wrong">>)).

%%%-----------------------------------------------------------------------------
%%% SERVER ENCODING TESTS (unmasked)
%%%-----------------------------------------------------------------------------

encode_text(_Config) ->
    Frame = nhttp_ws:encode({text, <<"Hello">>}),
    ?assertEqual(<<16#81, 5, "Hello">>, iolist_to_binary(Frame)).

encode_binary(_Config) ->
    Frame = nhttp_ws:encode({binary, <<1, 2, 3, 4>>}),
    ?assertEqual(<<16#82, 4, 1, 2, 3, 4>>, iolist_to_binary(Frame)).

encode_ping(_Config) ->
    ?assertEqual(<<16#89, 0>>, iolist_to_binary(nhttp_ws:encode(ping))).

encode_ping_with_data(_Config) ->
    ?assertEqual(<<16#89, 4, "test">>, iolist_to_binary(nhttp_ws:encode({ping, <<"test">>}))).

encode_pong(_Config) ->
    ?assertEqual(<<16#8A, 4, "data">>, iolist_to_binary(nhttp_ws:encode({pong, <<"data">>}))).

encode_close(_Config) ->
    ?assertEqual(<<16#88, 0>>, iolist_to_binary(nhttp_ws:encode(close))).

encode_close_with_code(_Config) ->
    ?assertEqual(
        <<16#88, 8, 1000:16, "Normal">>,
        iolist_to_binary(nhttp_ws:encode({close, 1000, <<"Normal">>}))
    ).

encode_extended_16(_Config) ->
    Data = binary:copy(<<"X">>, 1000),
    Frame = iolist_to_binary(nhttp_ws:encode({text, Data})),
    ?assertMatch(<<16#81, 126, 1000:16, _:1000/binary>>, Frame).

encode_extended_64(_Config) ->
    Data = binary:copy(<<"X">>, 70000),
    Frame = iolist_to_binary(nhttp_ws:encode({text, Data})),
    ?assertMatch(<<16#81, 127, 70000:64, _:70000/binary>>, Frame).

%%%-----------------------------------------------------------------------------
%%% SERVER DECODING TESTS (masked client frames)
%%%-----------------------------------------------------------------------------

decode_text(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Payload = mask(<<"Hello">>, MaskKey),
    Frame = <<16#81, 16#85, MaskKey/binary, Payload/binary>>,
    ?assertMatch({ok, {text, <<"Hello">>}, <<>>}, nhttp_ws:decode(Frame)).

decode_binary(_Config) ->
    MaskKey = <<5, 6, 7, 8>>,
    Payload = mask(<<1, 2, 3, 4>>, MaskKey),
    Frame = <<16#82, 16#84, MaskKey/binary, Payload/binary>>,
    ?assertMatch({ok, {binary, <<1, 2, 3, 4>>}, <<>>}, nhttp_ws:decode(Frame)).

decode_ping(_Config) ->
    MaskKey = <<9, 10, 11, 12>>,
    Frame = <<16#89, 16#80, MaskKey/binary>>,
    ?assertMatch({ok, ping, <<>>}, nhttp_ws:decode(Frame)).

decode_ping_with_data(_Config) ->
    MaskKey = <<9, 10, 11, 12>>,
    Payload = mask(<<"data">>, MaskKey),
    Frame = <<16#89, 16#84, MaskKey/binary, Payload/binary>>,
    ?assertMatch({ok, {ping, <<"data">>}, <<>>}, nhttp_ws:decode(Frame)).

decode_pong(_Config) ->
    MaskKey = <<13, 14, 15, 16>>,
    Payload = mask(<<"pong">>, MaskKey),
    Frame = <<16#8A, 16#84, MaskKey/binary, Payload/binary>>,
    ?assertMatch({ok, {pong, <<"pong">>}, <<>>}, nhttp_ws:decode(Frame)).

decode_close(_Config) ->
    MaskKey = <<17, 18, 19, 20>>,
    Frame = <<16#88, 16#80, MaskKey/binary>>,
    ?assertMatch({ok, close, <<>>}, nhttp_ws:decode(Frame)).

decode_close_with_code(_Config) ->
    MaskKey = <<21, 22, 23, 24>>,
    Payload = mask(<<1000:16, "bye">>, MaskKey),
    Frame = <<16#88, 16#85, MaskKey/binary, Payload/binary>>,
    ?assertMatch({ok, {close, 1000, <<"bye">>}, <<>>}, nhttp_ws:decode(Frame)).

decode_large_payload(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Data = binary:copy(<<"X">>, 1000),
    Payload = mask(Data, MaskKey),
    Frame = <<16#81, 16#FE, 1000:16, MaskKey/binary, Payload/binary>>,
    ?assertMatch({ok, {text, Data}, <<>>}, nhttp_ws:decode(Frame)).

decode_extended_64(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Data = binary:copy(<<"Y">>, 70000),
    Payload = mask(Data, MaskKey),
    Frame = <<16#81, 16#FF, 70000:64, MaskKey/binary, Payload/binary>>,
    ?assertMatch({ok, {text, Data}, <<>>}, nhttp_ws:decode(Frame)).

decode_incomplete(_Config) ->
    ?assertMatch({more, _}, nhttp_ws:decode(<<16#81>>)),
    MaskKey = <<1, 2, 3, 4>>,
    ?assertMatch({more, _}, nhttp_ws:decode(<<16#81, 16#85, MaskKey/binary, "He">>)).

decode_unmasked_error(_Config) ->
    Frame = <<16#81, 5, "Hello">>,
    ?assertMatch({error, unmasked_client_frame}, nhttp_ws:decode(Frame)).

decode_reserved_bits_error(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Payload = mask(<<"Hi">>, MaskKey),
    Frame = <<16#C1, 16#82, MaskKey/binary, Payload/binary>>,
    ?assertMatch({error, reserved_bits_set}, nhttp_ws:decode(Frame)).

decode_fragmentation_error(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Payload = mask(<<"Hi">>, MaskKey),
    Frame = <<16#01, 16#82, MaskKey/binary, Payload/binary>>,
    ?assertMatch({error, fragmentation_not_supported}, nhttp_ws:decode(Frame)).

decode_unknown_opcode_error(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Payload = mask(<<"Hi">>, MaskKey),
    Frame = <<16#8F, 16#82, MaskKey/binary, Payload/binary>>,
    ?assertMatch({error, {unknown_opcode, _}}, nhttp_ws:decode(Frame)).

decode_partial_masked(_Config) ->
    ?assertMatch({more, _}, nhttp_ws:decode(<<16#81, 16#85>>)),
    ?assertMatch({more, _}, nhttp_ws:decode(<<16#81, 16#FE>>)),
    ?assertMatch({more, _}, nhttp_ws:decode(<<16#81, 16#FF>>)).

decode_partial_ext16(_Config) ->
    Frame = <<16#81, 16#FE, 200:16, 1, 2, 3>>,
    ?assertMatch({more, _}, nhttp_ws:decode(Frame)).

decode_partial_ext64(_Config) ->
    Frame = <<16#81, 16#FF, 0:1, 200:63, 1, 2>>,
    ?assertMatch({more, _}, nhttp_ws:decode(Frame)).

decode_oversized_ping_rejected(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Data = binary:copy(<<"P">>, 126),
    Payload = mask(Data, MaskKey),
    Frame = <<16#89, 16#FE, 126:16, MaskKey/binary, Payload/binary>>,
    ?assertEqual({error, control_frame_too_large}, nhttp_ws:decode(Frame)).

decode_oversized_close_rejected(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Data = binary:copy(<<"X">>, 200),
    Payload = mask(Data, MaskKey),
    Frame = <<16#88, 16#FE, 200:16, MaskKey/binary, Payload/binary>>,
    ?assertEqual({error, control_frame_too_large}, nhttp_ws:decode(Frame)).

decode_fragmented_ping_rejected(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Payload = mask(<<"hi">>, MaskKey),
    Frame = <<16#09, 16#82, MaskKey/binary, Payload/binary>>,
    ?assertEqual({error, fragmented_control_frame}, nhttp_ws:decode(Frame)).

decode_fragmented_close_rejected(_Config) ->
    MaskKey = <<1, 2, 3, 4>>,
    Frame = <<16#08, 16#80, MaskKey/binary>>,
    ?assertEqual({error, fragmented_control_frame}, nhttp_ws:decode(Frame)).

%%%-----------------------------------------------------------------------------
%%% CLIENT ENCODING TESTS (masked)
%%%-----------------------------------------------------------------------------

encode_masked_roundtrip(_Config) ->
    Msg = {text, <<"Hello codec">>},
    Encoded = iolist_to_binary(nhttp_ws:encode_masked(Msg)),
    {ok, Decoded, <<>>} = nhttp_ws:decode(Encoded),
    ?assertEqual(Msg, Decoded).

encode_masked_all_types(_Config) ->
    Types = [
        {text, <<"test">>},
        {binary, <<1, 2, 3>>},
        ping,
        {ping, <<"data">>},
        pong,
        {pong, <<"data">>},
        close,
        {close, 1000, <<"bye">>}
    ],
    lists:foreach(
        fun(Msg) ->
            Encoded = iolist_to_binary(nhttp_ws:encode_masked(Msg)),
            {ok, Decoded, <<>>} = nhttp_ws:decode(Encoded),
            ?assertEqual(Msg, Decoded)
        end,
        Types
    ).

encode_masked_helpers(_Config) ->
    {ok, {text, <<"h">>}, <<>>} = nhttp_ws:decode(
        iolist_to_binary(nhttp_ws:encode_masked_text(<<"h">>))
    ),
    {ok, {binary, <<1>>}, <<>>} = nhttp_ws:decode(
        iolist_to_binary(nhttp_ws:encode_masked_binary(<<1>>))
    ),
    {ok, ping, <<>>} = nhttp_ws:decode(iolist_to_binary(nhttp_ws:encode_masked_ping())),
    {ok, {ping, <<"p">>}, <<>>} = nhttp_ws:decode(
        iolist_to_binary(nhttp_ws:encode_masked_ping(<<"p">>))
    ),
    {ok, {pong, <<"p">>}, <<>>} = nhttp_ws:decode(
        iolist_to_binary(nhttp_ws:encode_masked_pong(<<"p">>))
    ),
    {ok, close, <<>>} = nhttp_ws:decode(iolist_to_binary(nhttp_ws:encode_masked_close())),
    {ok, {close, 1001, <<"g">>}, <<>>} = nhttp_ws:decode(
        iolist_to_binary(nhttp_ws:encode_masked_close(1001, <<"g">>))
    ).

encode_masked_large_16(_Config) ->
    Data = binary:copy(<<"A">>, 200),
    Frame = iolist_to_binary(nhttp_ws:encode_masked({text, Data})),
    {ok, {text, Data}, <<>>} = nhttp_ws:decode(Frame).

encode_masked_large_64(_Config) ->
    Data = binary:copy(<<"B">>, 70000),
    Frame = iolist_to_binary(nhttp_ws:encode_masked({binary, Data})),
    {ok, {binary, Data}, <<>>} = nhttp_ws:decode(Frame).

%%%-----------------------------------------------------------------------------
%%% CLIENT DECODING TESTS (unmasked server frames)
%%%-----------------------------------------------------------------------------

decode_unmasked_text(_Config) ->
    Encoded = iolist_to_binary(nhttp_ws:encode({text, <<"Server msg">>})),
    ?assertMatch({ok, {text, <<"Server msg">>}, <<>>}, nhttp_ws:decode_unmasked(Encoded)).

decode_unmasked_all_types(_Config) ->
    Types = [
        {text, <<"msg">>},
        {binary, <<4, 5>>},
        ping,
        {ping, <<"hi">>},
        pong,
        {pong, <<"hi">>},
        close,
        {close, 1000, <<"bye">>}
    ],
    lists:foreach(
        fun(Msg) ->
            Encoded = iolist_to_binary(nhttp_ws:encode(Msg)),
            {ok, Decoded, <<>>} = nhttp_ws:decode_unmasked(Encoded),
            ?assertEqual(Msg, Decoded)
        end,
        Types
    ).

decode_unmasked_extended_16(_Config) ->
    Data = binary:copy(<<"X">>, 200),
    Frame = iolist_to_binary(nhttp_ws:encode({text, Data})),
    ?assertMatch({ok, {text, Data}, <<>>}, nhttp_ws:decode_unmasked(Frame)).

decode_unmasked_extended_64(_Config) ->
    Data = binary:copy(<<"Y">>, 70000),
    Frame = iolist_to_binary(nhttp_ws:encode({text, Data})),
    ?assertMatch({ok, {text, Data}, <<>>}, nhttp_ws:decode_unmasked(Frame)).

decode_unmasked_incomplete(_Config) ->
    ?assertMatch({more, _}, nhttp_ws:decode_unmasked(<<16#81>>)),
    ?assertMatch({more, _}, nhttp_ws:decode_unmasked(<<16#81, 5, "He">>)).

decode_unmasked_masked_error(_Config) ->
    Frame = iolist_to_binary(nhttp_ws:encode_masked({text, <<"Hello">>})),
    ?assertMatch({error, masked_server_frame}, nhttp_ws:decode_unmasked(Frame)).

decode_unmasked_reserved_bits(_Config) ->
    Frame = <<16#C1, 5, "Hello">>,
    ?assertMatch({error, reserved_bits_set}, nhttp_ws:decode_unmasked(Frame)).

decode_unmasked_partial_ext16(_Config) ->
    ?assertMatch({more, _}, nhttp_ws:decode_unmasked(<<16#81, 126>>)),
    ?assertMatch({more, _}, nhttp_ws:decode_unmasked(<<16#81, 126, 0, 200, "short">>)).

decode_unmasked_partial_ext64(_Config) ->
    ?assertMatch({more, _}, nhttp_ws:decode_unmasked(<<16#81, 127, 0, 0>>)),
    ?assertMatch({more, _}, nhttp_ws:decode_unmasked(<<16#81, 127, 0:1, 200:63, "short">>)).

%%%-----------------------------------------------------------------------------
%%% FRAGMENTATION TESTS
%%%-----------------------------------------------------------------------------

frag_text(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    First = <<16#01, 3, "Hel">>,
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(First, Dec0),
    Cont = <<16#80, 2, "lo">>,
    {ok, {text, <<"Hello">>}, <<>>, _Dec2} = nhttp_ws:decode_with_state(Cont, Dec1).

frag_binary(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    First = <<16#02, 2, "AB">>,
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(First, Dec0),
    Cont = <<16#80, 2, "CD">>,
    {ok, {binary, <<"ABCD">>}, <<>>, _Dec2} = nhttp_ws:decode_with_state(Cont, Dec1).

frag_with_control(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    First = <<16#01, 3, "Hel">>,
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(First, Dec0),
    Ping = <<16#89, 0>>,
    {ok, ping, <<>>, Dec2} = nhttp_ws:decode_with_state(Ping, Dec1),
    Cont = <<16#80, 2, "lo">>,
    {ok, {text, <<"Hello">>}, <<>>, _Dec3} = nhttp_ws:decode_with_state(Cont, Dec2).

frag_coalesced_fragments(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    Buffer = <<16#01, 3, "Hel", 16#80, 2, "lo">>,
    {continue, Rest, Dec1} = nhttp_ws:decode_with_state(Buffer, Dec0),
    ?assertEqual(<<16#80, 2, "lo">>, Rest),
    {ok, {text, <<"Hello">>}, <<>>, _Dec2} = nhttp_ws:decode_with_state(Rest, Dec1).

frag_coalesced_with_control(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    Buffer = <<16#01, 3, "Hel", 16#89, 0, 16#80, 2, "lo">>,
    {continue, Rest1, Dec1} = nhttp_ws:decode_with_state(Buffer, Dec0),
    {ok, ping, Rest2, Dec2} = nhttp_ws:decode_with_state(Rest1, Dec1),
    {ok, {text, <<"Hello">>}, <<>>, _Dec3} = nhttp_ws:decode_with_state(Rest2, Dec2).

frag_text_invalid_utf8_fails_at_fragment(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(<<16#01, 3, "Hel">>, Dec0),
    Broken = <<16#00, 2, 16#C0, 16#AF>>,
    ?assertEqual({error, invalid_utf8}, nhttp_ws:decode_with_state(Broken, Dec1)).

frag_text_split_code_point(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(<<16#01, 1, 16#C3>>, Dec0),
    Last = <<16#80, 1, 16#A9>>,
    {ok, {text, <<16#C3, 16#A9>>}, <<>>, _Dec2} = nhttp_ws:decode_with_state(Last, Dec1).

frag_text_truncated_at_fin(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(<<16#01, 1, 16#C3>>, Dec0),
    ?assertEqual({error, invalid_utf8}, nhttp_ws:decode_with_state(<<16#80, 0>>, Dec1)).

frag_binary_not_utf8_checked(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(<<16#02, 2, 16#C0, 16#AF>>, Dec0),
    Last = <<16#80, 1, 16#FF>>,
    {ok, {binary, <<16#C0, 16#AF, 16#FF>>}, <<>>, _Dec2} = nhttp_ws:decode_with_state(Last, Dec1).

frag_error_no_start(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    NonFrag = <<16#81, 3, "ABC">>,
    {ok, {text, <<"ABC">>}, <<>>, Dec1} = nhttp_ws:decode_with_state(NonFrag, Dec0),
    ContWithoutStart = <<16#80, 2, "XX">>,
    ?assertMatch({error, _}, nhttp_ws:decode_with_state(ContWithoutStart, Dec1)).

frag_server_decoder(_Config) ->
    Dec0 = nhttp_ws:decoder_new(server),
    MaskKey = <<1, 2, 3, 4>>,
    Payload = mask(<<"Hello">>, MaskKey),
    Frame = <<16#81, 16#85, MaskKey/binary, Payload/binary>>,
    {ok, {text, <<"Hello">>}, <<>>, _Dec1} = nhttp_ws:decode_with_state(Frame, Dec0).

frag_message_too_large_start(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client, #{max_message_size => 4}),
    First = <<16#01, 5, "Hello">>,
    ?assertEqual({error, message_too_large}, nhttp_ws:decode_with_state(First, Dec0)).

frag_message_too_large_continuation(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client, #{max_message_size => 5}),
    First = <<16#01, 3, "Hel">>,
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(First, Dec0),
    Cont = <<16#80, 5, "lothe">>,
    ?assertEqual({error, message_too_large}, nhttp_ws:decode_with_state(Cont, Dec1)).

frag_single_frame_too_large(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client, #{max_message_size => 4}),
    Frame = <<16#81, 5, "Hello">>,
    ?assertEqual({error, message_too_large}, nhttp_ws:decode_with_state(Frame, Dec0)).

frag_max_message_size_infinity(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client, #{max_message_size => infinity}),
    Big = binary:copy(<<"x">>, 1024),
    Frame = <<16#81, 16#7E, 1024:16, Big/binary>>,
    {ok, {text, Big}, <<>>, _Dec1} = nhttp_ws:decode_with_state(Frame, Dec0).

frag_frame_cap_refuses_before_buffering(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client, #{max_message_size => 1024}),
    Header = <<16#82, 127, 0:1, (1 bsl 40):63>>,
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 40}},
        nhttp_ws:decode_with_state(Header, Dec0)
    ).

frag_length_top_bit_refused(_Config) ->
    Frame = <<16#82, 127, 1:1, 5:63, "hello">>,
    Dec0 = nhttp_ws:decoder_new(client),
    ?assertEqual({error, decode_failed}, nhttp_ws:decode_with_state(Frame, Dec0)),
    ?assertEqual(
        {error, decode_failed}, nhttp_ws:decode_with_state(binary:part(Frame, 0, 3), Dec0)
    ).

frag_frame_cap_infinity_buffers(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client, #{max_message_size => infinity}),
    Header = <<16#82, 127, 0:1, (1 bsl 40):63>>,
    ?assertMatch({more, _, _}, nhttp_ws:decode_with_state(Header, Dec0)).

frag_default_max_message_size_is_finite(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    Header = <<16#82, 127, 0:1, (1 bsl 60):63>>,
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws:decode_with_state(Header, Dec0)
    ),
    Small = <<16#82, 2, "hi">>,
    ?assertMatch({ok, {binary, <<"hi">>}, <<>>, _}, nhttp_ws:decode_with_state(Small, Dec0)).

%%%-----------------------------------------------------------------------------
%%% SESSION TESTS
%%%
%%% Tests share two helpers (`spawn_probe/1`, `stop_probe/1`) so that every
%%% case is self-cleaning: spawned processes are linked, monitor-then-signal
%%% is the only termination path, and a kill fallback prevents leaks if the
%%% probe ignores the polite exit.
%%%-----------------------------------------------------------------------------

session_accessors(_Config) ->
    Pid = self(),
    Ref = make_ref(),
    SessH1 = make_session(h1, Pid, undefined, Ref),
    ?assertEqual(h1, nhttp_ws:transport(SessH1)),
    ?assertEqual(Pid, nhttp_ws:owner(SessH1)),
    ?assertEqual(undefined, nhttp_ws:stream_id(SessH1)),
    SessH2 = make_session(h2, Pid, 7, Ref),
    ?assertEqual(h2, nhttp_ws:transport(SessH2)),
    ?assertEqual(7, nhttp_ws:stream_id(SessH2)),
    SessH3 = make_session(h3, Pid, 12, Ref),
    ?assertEqual(h3, nhttp_ws:transport(SessH3)).

session_send_envelope(_Config) ->
    Owner = self(),
    Probe = spawn_probe(fun() ->
        receive
            {'$gen_call', From, {ws_send, _SessRef, undefined, {text, <<"hi">>}}} ->
                Owner ! observed,
                gen_server:reply(From, ok)
        end
    end),
    Sess = make_session(h1, Probe, undefined),
    ?assertEqual(ok, nhttp_ws:send(Sess, {text, <<"hi">>})),
    ?assertEqual(observed, await(observed, 1000)),
    stop_probe(Probe).

session_send_async_envelope(_Config) ->
    Probe = spawn_probe(fun() ->
        receive
            {'$gen_call', From, {ws_send_async, _SessRef, 5, {binary, <<"x">>}}} ->
                gen_server:reply(From, {error, gone})
        end
    end),
    Sess = make_session(h2, Probe, 5),
    ?assertEqual({error, gone}, nhttp_ws:send_async(Sess, {binary, <<"x">>})),
    stop_probe(Probe).

session_send_gone_when_pid_dead(_Config) ->
    Probe = proc_lib:spawn(fun() -> ok end),
    MRef = monitor(process, Probe),
    receive
        {'DOWN', MRef, process, Probe, _} -> ok
    after 1000 ->
        exit(Probe, kill),
        ct:fail(probe_did_not_exit)
    end,
    Sess = make_session(h1, Probe, undefined),
    ?assertEqual({error, gone}, nhttp_ws:send(Sess, ping)).

session_send_timeout_when_no_reply(_Config) ->
    Probe = spawn_probe(fun() -> receive
        after infinity -> ok
        end end),
    Sess = make_session(h1, Probe, undefined),
    ?assertEqual({error, timeout}, nhttp_ws:send(Sess, ping, #{timeout => 100})),
    stop_probe(Probe).

session_info_envelope(_Config) ->
    Sess = make_session(h2, self(), 9),
    ?assertEqual(ok, nhttp_ws:info(Sess, {tick, 1})),
    ?assertEqual({'$gen_cast', {ws_info, 9, {tick, 1}}}, await_msg(1000)).

session_close_envelope(_Config) ->
    Ref = make_ref(),
    Sess = make_session(h1, self(), undefined, Ref),
    ?assertEqual(ok, nhttp_ws:close(Sess)),
    ?assertEqual({'$gen_cast', {ws_close, Ref, undefined, 1000, <<>>, #{}}}, await_msg(1000)),
    ?assertEqual(ok, nhttp_ws:close(Sess, 1011, <<"oops">>)),
    ?assertEqual({'$gen_cast', {ws_close, Ref, undefined, 1011, <<"oops">>, #{}}}, await_msg(1000)),
    ?assertEqual(ok, nhttp_ws:close(Sess, 1001, <<"bye">>, #{})),
    Expected = {'$gen_cast', {ws_close, Ref, undefined, 1001, <<"bye">>, #{}}},
    ?assertEqual(Expected, await_msg(1000)).

session_broadcast_to_session(_Config) ->
    Sess = make_session(h2, self(), 3),
    ?assertEqual(ok, nhttp_ws:broadcast(Sess, {bcast, 42})),
    ?assertEqual({bcast, 42}, await_msg(1000)).

session_broadcast_to_pid(_Config) ->
    ?assertEqual(ok, nhttp_ws:broadcast(self(), bare_msg)),
    ?assertEqual(bare_msg, await_msg(1000)).

session_is_alive(_Config) ->
    Probe = spawn_probe(fun() -> receive
        after infinity -> ok
        end end),
    SessAlive = make_session(h1, Probe, undefined),
    ?assert(nhttp_ws:is_alive(SessAlive)),
    stop_probe(Probe),
    SessDead = make_session(h1, Probe, undefined),
    ?assertNot(nhttp_ws:is_alive(SessDead)).

session_send_refuses_close(_Config) ->
    Probe = spawn_probe(fun() -> receive
        after infinity -> ok
        end end),
    Sess = make_session(h1, Probe, undefined),
    ?assertEqual({error, close_not_allowed}, nhttp_ws:send(Sess, close)),
    ?assertEqual({error, close_not_allowed}, nhttp_ws:send(Sess, {close, 1000, <<>>})),
    ?assertEqual({error, close_not_allowed}, nhttp_ws:send(Sess, close, #{timeout => 100})),
    ?assertEqual({error, close_not_allowed}, nhttp_ws:send_async(Sess, {close, 1000, <<"bye">>})),
    ?assertEqual({messages, []}, process_info(Probe, messages)),
    stop_probe(Probe).

session_send_refuses_oversize_control(_Config) ->
    Probe = spawn_probe(fun() ->
        receive
            {'$gen_call', From, {ws_send, _, 3, {ping, _}}} -> gen_server:reply(From, ok)
        end
    end),
    Sess = make_session(h2, Probe, 3),
    Big = binary:copy(<<"x">>, 126),
    ?assertEqual({error, control_frame_too_large}, nhttp_ws:send(Sess, {ping, Big})),
    ?assertEqual({error, control_frame_too_large}, nhttp_ws:send(Sess, {pong, Big})),
    ?assertEqual({error, control_frame_too_large}, nhttp_ws:send_async(Sess, {pong, Big})),
    ?assertEqual({error, control_frame_too_large}, nhttp_ws:ping(Sess, Big)),
    ?assertEqual({messages, []}, process_info(Probe, messages)),
    ?assertEqual(ok, nhttp_ws:ping(Sess, binary:copy(<<"x">>, 125))),
    stop_probe(Probe).

session_close_refuses_invalid(_Config) ->
    Sess = make_session(h3, self(), 4),
    Invalid = [0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535],
    [
        ?assertEqual({error, invalid_close_code}, nhttp_ws:close(Sess, Code, <<>>))
     || Code <- Invalid
    ],
    ?assertEqual(
        {error, close_reason_too_large}, nhttp_ws:close(Sess, 1000, binary:copy(<<"r">>, 124))
    ),
    ?assertEqual({error, invalid_close_reason}, nhttp_ws:close(Sess, 1000, <<16#FF>>, #{})),
    ?assertEqual(ok, nhttp_ws:close(Sess, 4999, binary:copy(<<"r">>, 123))),
    ?assertMatch({'$gen_cast', {ws_close, _, 4, 4999, _, #{}}}, await_msg(1000)),
    receive
        Other -> ct:fail({unexpected_message, Other})
    after 0 -> ok
    end.

session_h1_without_socket_routes_to_conn(_Config) ->
    Owner = self(),
    Probe = spawn_probe(fun() ->
        receive
            {'$gen_call', From1, {ws_send, _, undefined, {text, <<"a">>}}} ->
                gen_server:reply(From1, ok)
        end,
        receive
            {'$gen_call', From2, {ws_send_async, _, undefined, {text, <<"b">>}}} ->
                gen_server:reply(From2, {error, gone})
        end,
        Owner ! routed
    end),
    Sess = make_session(h1, Probe, undefined, make_ref()),
    ?assertEqual(ok, nhttp_ws:send(Sess, {text, <<"a">>})),
    ?assertEqual({error, gone}, nhttp_ws:send_async(Sess, {text, <<"b">>})),
    ?assertEqual(routed, await(routed, 1000)),
    stop_probe(Probe).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec mask(binary(), binary()) -> binary().
mask(Data, <<K1, K2, K3, K4>>) ->
    mask_loop(Data, <<K1, K2, K3, K4>>, 0, <<>>).

mask_loop(<<>>, _Key, _Idx, Acc) ->
    Acc;
mask_loop(<<B, Rest/binary>>, <<K1, K2, K3, K4>> = Key, Idx, Acc) ->
    KeyByte =
        case Idx rem 4 of
            0 -> K1;
            1 -> K2;
            2 -> K3;
            3 -> K4
        end,
    mask_loop(Rest, Key, Idx + 1, <<Acc/binary, (B bxor KeyByte)>>).

%%%-----------------------------------------------------------------------------
%%% SESSION TEST HELPERS
%%%-----------------------------------------------------------------------------

-spec spawn_probe(fun(() -> any())) -> pid().
spawn_probe(Body) ->
    proc_lib:spawn_link(Body).

-spec stop_probe(pid()) -> ok.
stop_probe(Pid) ->
    case is_process_alive(Pid) of
        false ->
            ok;
        true ->
            MRef = monitor(process, Pid),
            unlink(Pid),
            exit(Pid, normal),
            receive
                {'DOWN', MRef, process, Pid, _} -> ok
            after 1000 ->
                exit(Pid, kill),
                receive
                    {'DOWN', MRef, process, Pid, _} -> ok
                end
            end
    end.

-spec make_session(h1 | h2 | h3, pid(), undefined | nhttp_lib:stream_id()) ->
    nhttp_ws:session().
make_session(Transport, Pid, StreamId) ->
    nhttp_ws:new_session(Transport, Pid, StreamId).

-spec make_session(h1 | h2 | h3, pid(), undefined | nhttp_lib:stream_id(), reference()) ->
    nhttp_ws:session().
make_session(Transport, Pid, StreamId, Ref) ->
    nhttp_ws:new_session(Transport, Pid, StreamId, Ref).

-spec await(term(), timeout()) -> term() | no_return().
await(Expected, Timeout) ->
    receive
        Expected -> Expected
    after Timeout ->
        ct:fail({timeout_waiting_for, Expected})
    end.

-spec await_msg(timeout()) -> term() | no_return().
await_msg(Timeout) ->
    receive
        Msg -> Msg
    after Timeout ->
        ct:fail(no_message_received)
    end.

%%%-----------------------------------------------------------------------------
%%% PARTIAL SCAN TESTS
%%%-----------------------------------------------------------------------------

partial_autobahn_6_4_3(_Config) ->
    Dec0 = nhttp_ws:decoder_new(server),
    Header = binary:decode_hex(<<"01951cad1226">>),
    Chop1 = binary:decode_hex(<<"d217f39ba56291e8a063a7">>),
    Chop2 = binary:decode_hex(<<"d28c2d92">>),
    {more, _, Dec1} = nhttp_ws:decode_with_state(<<Header/binary, Chop1/binary>>, Dec0),
    ?assertEqual(
        {error, invalid_utf8},
        nhttp_ws:decode_with_state(<<Header/binary, Chop1/binary, Chop2/binary>>, Dec1)
    ).

partial_autobahn_6_4_4(_Config) ->
    Dec0 = nhttp_ws:decoder_new(server),
    Header = binary:decode_hex(<<"01950b5f0010">>),
    Chop1 = binary:decode_hex(<<"c5e5e1adb29083deb791b5e4">>),
    Chop2 = binary:decode_hex(<<"9b">>),
    {more, _, Dec1} = nhttp_ws:decode_with_state(<<Header/binary, Chop1/binary>>, Dec0),
    ?assertEqual(
        {error, invalid_utf8},
        nhttp_ws:decode_with_state(<<Header/binary, Chop1/binary, Chop2/binary>>, Dec1)
    ).

partial_text_split_code_point_survives(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {more, _, Dec1} = nhttp_ws:decode_with_state(<<16#81, 5, 16#C3>>, Dec0),
    {more, _, Dec2} = nhttp_ws:decode_with_state(<<16#81, 5, 16#C3, 16#A9, 16#E2>>, Dec1),
    Full = <<16#81, 5, 16#C3, 16#A9, 16#E2, 16#82>>,
    {more, _, Dec3} = nhttp_ws:decode_with_state(Full, Dec2),
    {ok, {text, Payload}, <<>>, _Dec4} =
        nhttp_ws:decode_with_state(<<Full/binary, 16#AC>>, Dec3),
    ?assertEqual(<<"é€"/utf8>>, Payload).

partial_text_completes_after_chops(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {more, _, Dec1} = nhttp_ws:decode_with_state(<<16#81, 5, "he">>, Dec0),
    {ok, {text, <<"hello">>}, <<>>, Dec2} =
        nhttp_ws:decode_with_state(<<16#81, 5, "hello">>, Dec1),
    {ok, {text, <<"hi">>}, <<>>, _Dec3} =
        nhttp_ws:decode_with_state(<<16#81, 2, "hi">>, Dec2).

partial_binary_not_scanned(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {more, _, Dec1} = nhttp_ws:decode_with_state(<<16#82, 4, 16#F4, 16#90>>, Dec0),
    {ok, {binary, Payload}, <<>>, _Dec2} =
        nhttp_ws:decode_with_state(<<16#82, 4, 16#F4, 16#90, 16#80, 16#80>>, Dec1),
    ?assertEqual(<<16#F4, 16#90, 16#80, 16#80>>, Payload).

partial_continuation_scanned(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(<<16#01, 3, "Hel">>, Dec0),
    {more, _, Dec2} = nhttp_ws:decode_with_state(<<16#80, 4, "lo">>, Dec1),
    ?assertEqual(
        {error, invalid_utf8},
        nhttp_ws:decode_with_state(<<16#80, 4, "lo", 16#C0>>, Dec2)
    ).

partial_text_mid_fragment_not_scanned(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {continue, <<>>, Dec1} = nhttp_ws:decode_with_state(<<16#01, 3, "Hel">>, Dec0),
    {more, _, Dec2} = nhttp_ws:decode_with_state(<<16#81, 2, 16#C0>>, Dec1),
    ?assertEqual(
        {error, expected_continuation},
        nhttp_ws:decode_with_state(<<16#81, 2, 16#C0, 16#AF>>, Dec2)
    ).

partial_repeat_without_new_bytes(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    Partial = <<16#81, 5, "he">>,
    {more, N, Dec1} = nhttp_ws:decode_with_state(Partial, Dec0),
    ?assertEqual({more, N, Dec1}, nhttp_ws:decode_with_state(Partial, Dec1)).

partial_control_frame_not_scanned(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    {more, _, Dec1} = nhttp_ws:decode_with_state(<<16#89, 2, 16#C0>>, Dec0),
    {ok, {ping, Payload}, <<>>, _Dec2} =
        nhttp_ws:decode_with_state(<<16#89, 2, 16#C0, 16#AF>>, Dec1),
    ?assertEqual(<<16#C0, 16#AF>>, Payload).

%%%-----------------------------------------------------------------------------
%%% FEED TESTS
%%%-----------------------------------------------------------------------------

-define(MIB16, 16777216).
-define(KIB16, 16384).
-define(MAX_CHUNKED_RATIO, 4).
-define(TIMING_RUNS, 3).

feed_empty_input(_Config) ->
    {ok, [], Dec1} = nhttp_ws:feed(<<>>, nhttp_ws:decoder_new(server)),
    Frame = server_frame(1, 1, <<"hi">>, <<1, 2, 3, 4>>),
    ?assertMatch({ok, [{text, <<"hi">>}], _}, nhttp_ws:feed(Frame, Dec1)).

feed_header_split_at_every_boundary_unmasked(_Config) ->
    lists:foreach(
        fun({Len, HeaderSize}) ->
            Payload = payload(Len),
            Frame = client_frame(1, 2, Payload),
            [
                ?assertEqual([{binary, Payload}], split_feed(client, Frame, I), {Len, I})
             || I <- lists:seq(1, HeaderSize + 1)
            ]
        end,
        [{5, 2}, {300, 4}, {70000, 10}]
    ).

feed_header_split_at_every_boundary_masked(_Config) ->
    lists:foreach(
        fun({Len, HeaderSize}) ->
            Payload = payload(Len),
            Frame = server_frame(1, 2, Payload, <<16#A1, 16#B2, 16#C3, 16#D4>>),
            [
                ?assertEqual([{binary, Payload}], split_feed(server, Frame, I), {Len, I})
             || I <- lists:seq(1, HeaderSize + 1)
            ]
        end,
        [{5, 6}, {300, 8}, {70000, 14}]
    ).

feed_header_one_byte_at_a_time(_Config) ->
    Payload = payload(70000),
    Frame = server_frame(1, 2, Payload, <<9, 8, 7, 6>>),
    <<Header:14/binary, Body/binary>> = Frame,
    Dec = lists:foldl(
        fun(Byte, D0) ->
            {ok, [], D1} = nhttp_ws:feed(<<Byte>>, D0),
            D1
        end,
        nhttp_ws:decoder_new(server),
        binary_to_list(Header)
    ),
    ?assertMatch({ok, [{binary, Payload}], _}, nhttp_ws:feed(Body, Dec)).

feed_chunk_ends_at_frame_boundary(_Config) ->
    F1 = server_frame(1, 1, <<"first">>, <<1, 2, 3, 4>>),
    F2 = server_frame(1, 2, payload(300), <<5, 6, 7, 8>>),
    {ok, [{text, <<"first">>}], Dec1} = nhttp_ws:feed(F1, nhttp_ws:decoder_new(server)),
    ?assertMatch({ok, [{binary, _}], _}, nhttp_ws:feed(F2, Dec1)).

feed_chunk_spans_two_frames(_Config) ->
    P1 = payload(300),
    P2 = payload(301),
    F1 = server_frame(1, 2, P1, <<1, 2, 3, 4>>),
    F2 = server_frame(1, 2, P2, <<5, 6, 7, 8>>),
    [
        begin
            {A, F1Tail} = split_binary(F1, Cut1),
            {F2Head, B} = split_binary(F2, Cut2),
            {ok, [], D1} = nhttp_ws:feed(A, nhttp_ws:decoder_new(server)),
            {ok, [{binary, P1}], D2} = nhttp_ws:feed(<<F1Tail/binary, F2Head/binary>>, D1),
            ?assertMatch({ok, [{binary, P2}], _}, nhttp_ws:feed(B, D2), {Cut1, Cut2})
        end
     || Cut1 <- [1, 3, 8, 100, 307], Cut2 <- lists:seq(1, 9)
    ].

feed_many_frames_in_one_chunk(_Config) ->
    Msgs = [{text, integer_to_binary(I)} || I <- lists:seq(1, 10)],
    Frames = [server_frame(1, 1, T, <<I:32>>) || {I, {text, T}} <- lists:enumerate(Msgs)],
    Last = server_frame(1, 2, payload(200), <<0:32>>),
    {Head, Tail} = split_binary(Last, 100),
    {ok, Got, Dec1} =
        nhttp_ws:feed(iolist_to_binary([Frames, Head]), nhttp_ws:decoder_new(server)),
    ?assertEqual(Msgs, Got),
    ?assertMatch({ok, [{binary, _}], _}, nhttp_ws:feed(Tail, Dec1)).

feed_frame_too_large_at_header(_Config) ->
    Client = nhttp_ws:decoder_new(client, #{max_message_size => 1000}),
    ?assertEqual(
        {error, {frame_too_large, 2000}, []},
        nhttp_ws:feed(<<16#82, 126, 2000:16>>, Client)
    ),
    Server = nhttp_ws:decoder_new(server, #{max_message_size => 1000}),
    {ok, [], Server1} = nhttp_ws:feed(<<16#82, 16#FE>>, Server),
    ?assertEqual({error, {frame_too_large, 2000}, []}, nhttp_ws:feed(<<2000:16>>, Server1)).

feed_message_too_large_at_continuation_header(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client, #{max_message_size => 1000}),
    {ok, [], Dec1} = nhttp_ws:feed(client_frame(0, 2, payload(900)), Dec0),
    ?assertEqual({error, message_too_large, []}, nhttp_ws:feed(<<16#80, 126, 900:16>>, Dec1)).

feed_single_frame_too_large_at_byte_count(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client, #{max_message_size => 50}),
    {Head, Last} = split_binary(client_frame(1, 2, payload(100)), 101),
    {ok, [], Dec1} = nhttp_ws:feed(Head, Dec0),
    ?assertEqual({error, message_too_large, []}, nhttp_ws:feed(Last, Dec1)).

feed_control_frame_too_large_at_header(_Config) ->
    Dec = nhttp_ws:decoder_new(client),
    ?assertEqual(
        {error, control_frame_too_large, []},
        nhttp_ws:feed(<<16#89, 126, 126:16>>, Dec)
    ).

feed_fragmented_control_frame_at_header(_Config) ->
    Dec = nhttp_ws:decoder_new(client),
    ?assertEqual({error, fragmented_control_frame, []}, nhttp_ws:feed(<<16#09, 5>>, Dec)).

feed_control_frame_inside_fragmented_message(_Config) ->
    Wire = iolist_to_binary([
        server_frame(0, 1, <<"Hel">>, <<1, 2, 3, 4>>),
        server_frame(1, 9, <<"p">>, <<5, 6, 7, 8>>),
        server_frame(1, 0, <<"lo">>, <<9, 10, 11, 12>>)
    ]),
    Expected = [{ping, <<"p">>}, {text, <<"Hello">>}],
    ?assertMatch({ok, Expected, _}, nhttp_ws:feed(Wire, nhttp_ws:decoder_new(server))),
    ?assertEqual(Expected, feed_bytes(Wire, nhttp_ws:decoder_new(server))).

feed_error_returns_earlier_messages(_Config) ->
    Wire = <<16#81, 2, "hi", 16#89, 0, 16#85, 0>>,
    ?assertEqual(
        {error, {unknown_opcode, 5}, [{text, <<"hi">>}, ping]},
        nhttp_ws:feed(Wire, nhttp_ws:decoder_new(client))
    ).

feed_invalid_utf8_on_carrying_chunk(_Config) ->
    {ok, [], Dec1} = nhttp_ws:feed(<<16#81, 6, "Hel">>, nhttp_ws:decoder_new(client)),
    ?assertEqual({error, invalid_utf8, []}, nhttp_ws:feed(<<16#C0>>, Dec1)),
    Header = binary:decode_hex(<<"01951cad1226">>),
    Chop1 = binary:decode_hex(<<"d217f39ba56291e8a063a7">>),
    Chop2 = binary:decode_hex(<<"d28c2d92">>),
    {ok, [], Dec2} = nhttp_ws:feed(<<Header/binary, Chop1/binary>>, nhttp_ws:decoder_new(server)),
    ?assertEqual({error, invalid_utf8, []}, nhttp_ws:feed(Chop2, Dec2)).

feed_utf8_carry_across_chunks_and_fragments(_Config) ->
    Wire = <<16#01, 1, 16#E2, 16#00, 1, 16#82, 16#80, 2, 16#AC, $!>>,
    Expected = [{text, <<"€!"/utf8>>}],
    ?assertMatch({ok, Expected, _}, nhttp_ws:feed(Wire, nhttp_ws:decoder_new(client))),
    ?assertEqual(Expected, feed_bytes(Wire, nhttp_ws:decoder_new(client))).

feed_truncated_utf8_at_fin(_Config) ->
    {ok, [], Dec1} = nhttp_ws:feed(<<16#01, 1, 16#C3>>, nhttp_ws:decoder_new(client)),
    ?assertEqual({error, invalid_utf8, []}, nhttp_ws:feed(<<16#80, 0>>, Dec1)),
    ?assertEqual(
        {error, invalid_utf8, []},
        nhttp_ws:feed(<<16#81, 1, 16#C3>>, nhttp_ws:decoder_new(client))
    ).

feed_binary_not_utf8_checked(_Config) ->
    Wire = <<16#02, 2, 16#C0, 16#AF, 16#80, 1, 16#FF>>,
    ?assertEqual(
        [{binary, <<16#C0, 16#AF, 16#FF>>}], feed_bytes(Wire, nhttp_ws:decoder_new(client))
    ).

feed_masked_frame_refused_by_client(_Config) ->
    ?assertEqual(
        {error, masked_server_frame, []},
        nhttp_ws:feed(<<16#81, 16#80, 0:32>>, nhttp_ws:decoder_new(client))
    ).

feed_unmasked_frame_refused_by_server(_Config) ->
    ?assertEqual(
        {error, unmasked_client_frame, []},
        nhttp_ws:feed(<<16#81, 0>>, nhttp_ws:decoder_new(server))
    ).

feed_reserved_bits_refused(_Config) ->
    ?assertEqual(
        {error, reserved_bits_set, []},
        nhttp_ws:feed(<<16#C1, 0>>, nhttp_ws:decoder_new(client))
    ).

feed_length_top_bit_refused(_Config) ->
    Client = <<16#82, 127, 1:1, 5:63, "hello">>,
    Server = <<16#82, 16#FF, 1:1, 5:63, 1, 2, 3, 4, "hello">>,
    [
        ?assertEqual(
            {error, decode_failed, [{text, <<"hi">>}]},
            nhttp_ws:feed(<<Hi/binary, Wire/binary>>, nhttp_ws:decoder_new(Role))
        )
     || {Role, Hi, Wire} <- [
            {client, client_frame(1, 1, <<"hi">>), Client},
            {server, server_frame(1, 1, <<"hi">>, <<1, 2, 3, 4>>), Server}
        ]
    ],
    {ok, [], Dec1} = nhttp_ws:feed(<<16#82, 127>>, nhttp_ws:decoder_new(client)),
    ?assertEqual({error, decode_failed, []}, nhttp_ws:feed(<<16#80>>, Dec1)).

feed_expected_continuation(_Config) ->
    ?assertEqual(
        {error, expected_continuation, []},
        nhttp_ws:feed(<<16#01, 1, "a", 16#81, 1, "b">>, nhttp_ws:decoder_new(client))
    ),
    ?assertMatch({error, _, []}, nhttp_ws:feed(<<16#80, 1, "x">>, nhttp_ws:decoder_new(client))).

feed_close_frame_validated(_Config) ->
    ?assertEqual(
        {error, invalid_close_code, []},
        nhttp_ws:feed(<<16#88, 2, 999:16>>, nhttp_ws:decoder_new(client))
    ),
    ?assertMatch(
        {ok, [{close, 1000, <<"ok">>}], _},
        nhttp_ws:feed(<<16#88, 4, 1000:16, "ok">>, nhttp_ws:decoder_new(client))
    ).

feed_frame_pending(_Config) ->
    Dec0 = nhttp_ws:decoder_new(server),
    ?assertNot(nhttp_ws:frame_pending(Dec0)),
    Frame = server_frame(0, 2, payload(300), <<1, 2, 3, 4>>),
    {Head, Tail} = split_binary(Frame, 1),
    {ok, [], Dec1} = nhttp_ws:feed(Head, Dec0),
    ?assert(nhttp_ws:frame_pending(Dec1)),
    {Mid, Last} = split_binary(Tail, 100),
    {ok, [], Dec2} = nhttp_ws:feed(Mid, Dec1),
    ?assert(nhttp_ws:frame_pending(Dec2)),
    {ok, [], Dec3} = nhttp_ws:feed(Last, Dec2),
    ?assertNot(nhttp_ws:frame_pending(Dec3)),
    {ok, [{binary, _}], Dec4} = nhttp_ws:feed(server_frame(1, 0, <<"end">>, <<5, 6, 7, 8>>), Dec3),
    ?assertNot(nhttp_ws:frame_pending(Dec4)).

feed_16mib_binary_in_16kib_chunks(_Config) ->
    Payload = binary:copy(<<"0123456789abcdef">>, ?MIB16 div 16),
    assert_feed_time({binary, Payload}).

feed_16mib_text_in_16kib_chunks(_Config) ->
    Unit = <<"aé€😀"/utf8>>,
    Pad = binary:copy(<<"x">>, ?MIB16 rem byte_size(Unit)),
    Payload = <<(binary:copy(Unit, ?MIB16 div byte_size(Unit)))/binary, Pad/binary>>,
    assert_feed_time({text, Payload}).

%%%-----------------------------------------------------------------------------
%%% FEED HELPERS
%%%-----------------------------------------------------------------------------

-spec payload(non_neg_integer()) -> binary().
payload(Len) ->
    <<<<(I rem 251)>> || I <- lists:seq(1, Len)>>.

-spec client_frame(0 | 1, 0..15, binary()) -> binary().
client_frame(Fin, Opcode, Payload) ->
    <<(length_header(Fin, Opcode, 0, byte_size(Payload)))/binary, Payload/binary>>.

-spec server_frame(0 | 1, 0..15, binary(), binary()) -> binary().
server_frame(Fin, Opcode, Payload, Key) ->
    Header = length_header(Fin, Opcode, 1, byte_size(Payload)),
    <<Header/binary, Key/binary, (mask(Payload, Key))/binary>>.

-spec length_header(0 | 1, 0..15, 0 | 1, non_neg_integer()) -> binary().
length_header(Fin, Opcode, Mask, Len) when Len < 126 ->
    <<Fin:1, 0:3, Opcode:4, Mask:1, Len:7>>;
length_header(Fin, Opcode, Mask, Len) when Len < 65536 ->
    <<Fin:1, 0:3, Opcode:4, Mask:1, 126:7, Len:16>>;
length_header(Fin, Opcode, Mask, Len) ->
    <<Fin:1, 0:3, Opcode:4, Mask:1, 127:7, Len:64>>.

-spec split_feed(client | server, binary(), pos_integer()) -> [nhttp_ws:ws_message()].
split_feed(Role, Frame, At) ->
    {Head, Tail} = split_binary(Frame, At),
    {ok, [], Dec1} = nhttp_ws:feed(Head, nhttp_ws:decoder_new(Role)),
    {ok, Msgs, _Dec2} = nhttp_ws:feed(Tail, Dec1),
    Msgs.

-spec feed_bytes(binary(), nhttp_ws:ws_decoder()) -> [nhttp_ws:ws_message()].
feed_bytes(Wire, Dec0) ->
    {Msgs, _Dec} = lists:foldl(
        fun(Byte, {Acc, D0}) ->
            {ok, New, D1} = nhttp_ws:feed(<<Byte>>, D0),
            {Acc ++ New, D1}
        end,
        {[], Dec0},
        binary_to_list(Wire)
    ),
    Msgs.

-spec feed_all([binary()], nhttp_ws:ws_decoder(), [[nhttp_ws:ws_message()]]) ->
    [nhttp_ws:ws_message()].
feed_all([], _Dec, Acc) ->
    lists:append(lists:reverse(Acc));
feed_all([Chunk | Rest], Dec, Acc) ->
    {ok, Msgs, Dec1} = nhttp_ws:feed(Chunk, Dec),
    feed_all(Rest, Dec1, [Msgs | Acc]).

-spec fixed_chunks(binary(), pos_integer()) -> [binary()].
fixed_chunks(Bin, Size) when byte_size(Bin) =< Size ->
    [Bin];
fixed_chunks(Bin, Size) ->
    <<Head:Size/binary, Rest/binary>> = Bin,
    [Head | fixed_chunks(Rest, Size)].

-doc """
The chunked feed against one read of the same frame, each the best of a few
runs. Both unmask and scan every byte once, so the ratio stays near 1 on any
runner. A decoder that rescans its buffer on each read gives a ratio in the
hundreds for 1024 chunks.
""".
-spec assert_feed_time(nhttp_ws:ws_message()) -> ok.
assert_feed_time(Msg) ->
    Wire = iolist_to_binary(nhttp_ws:encode_masked(Msg)),
    Chunked = lists:min([time_feed(fixed_chunks(Wire, ?KIB16), Msg) || _ <- runs()]),
    Single = lists:min([time_feed([Wire], Msg) || _ <- runs()]),
    ct:pal("~p chunks ~p us, one read ~p us", [element(1, Msg), Chunked, Single]),
    ?assert(Chunked < ?MAX_CHUNKED_RATIO * Single, {Chunked, Single, ?MAX_CHUNKED_RATIO}).

-spec runs() -> [pos_integer()].
runs() ->
    lists:seq(1, ?TIMING_RUNS).

-spec time_feed([binary()], nhttp_ws:ws_message()) -> non_neg_integer().
time_feed(Chunks, Msg) ->
    true = erlang:garbage_collect(),
    {Us, Msgs} = timer:tc(fun() -> feed_all(Chunks, nhttp_ws:decoder_new(server), []) end),
    ?assert([Msg] =:= Msgs),
    Us.
