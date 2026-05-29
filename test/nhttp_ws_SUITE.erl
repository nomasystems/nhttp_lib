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
    frag_error_no_start/1,
    frag_server_decoder/1,
    frag_message_too_large_start/1,
    frag_message_too_large_continuation/1,
    frag_single_frame_too_large/1,
    frag_max_message_size_infinity/1,
    session_accessors/1,
    session_send_envelope/1,
    session_send_async_envelope/1,
    session_send_gone_when_pid_dead/1,
    session_send_timeout_when_no_reply/1,
    session_info_envelope/1,
    session_close_envelope/1,
    session_broadcast_to_session/1,
    session_broadcast_to_pid/1,
    session_is_alive/1
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
        {group, session}
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
            frag_error_no_start,
            frag_server_decoder,
            frag_message_too_large_start,
            frag_message_too_large_continuation,
            frag_single_frame_too_large,
            frag_max_message_size_infinity
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
            session_is_alive
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
    {more, 1, Dec1} = nhttp_ws:decode_with_state(First, Dec0),
    Cont = <<16#80, 2, "lo">>,
    {ok, {text, <<"Hello">>}, <<>>, _Dec2} = nhttp_ws:decode_with_state(Cont, Dec1).

frag_binary(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    First = <<16#02, 2, "AB">>,
    {more, 1, Dec1} = nhttp_ws:decode_with_state(First, Dec0),
    Cont = <<16#80, 2, "CD">>,
    {ok, {binary, <<"ABCD">>}, <<>>, _Dec2} = nhttp_ws:decode_with_state(Cont, Dec1).

frag_with_control(_Config) ->
    Dec0 = nhttp_ws:decoder_new(client),
    First = <<16#01, 3, "Hel">>,
    {more, 1, Dec1} = nhttp_ws:decode_with_state(First, Dec0),
    Ping = <<16#89, 0>>,
    {ok, ping, <<>>, Dec2} = nhttp_ws:decode_with_state(Ping, Dec1),
    Cont = <<16#80, 2, "lo">>,
    {ok, {text, <<"Hello">>}, <<>>, _Dec3} = nhttp_ws:decode_with_state(Cont, Dec2).

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
    {more, 1, Dec1} = nhttp_ws:decode_with_state(First, Dec0),
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
                gen_server:reply(From, {error, would_block})
        end
    end),
    Sess = make_session(h2, Probe, 5),
    ?assertEqual({error, would_block}, nhttp_ws:send_async(Sess, {binary, <<"x">>})),
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
    ?assertEqual(ok, nhttp_ws:close(Sess, 1001, <<"bye">>, #{force => true})),
    Expected = {'$gen_cast', {ws_close, Ref, undefined, 1001, <<"bye">>, #{force => true}}},
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
