-module(nhttp_ws_frame_SUITE).

-moduledoc "Per-frame WebSocket codec test suite (RFC 6455).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, encode},
        {group, decode_raw},
        {group, frame_cap},
        {group, helpers}
    ].

groups() ->
    [
        {encode, [parallel], [
            encode_unmasked_default,
            encode_with_mask_false,
            encode_with_mask_true,
            encode_masked_text,
            encode_close_with_code
        ]},
        {decode_raw, [parallel], [
            decode_raw_client,
            decode_raw_server,
            decode_raw_more,
            decode_raw_invalid_mask,
            decode_raw_reserved_bits_masked,
            decode_raw_reserved_bits_unmasked
        ]},
        {frame_cap, [parallel], [
            cap_refuses_declared_64bit,
            cap_infinity_keeps_more,
            cap_absent_keeps_more,
            cap_refuses_declared_16bit,
            cap_accepts_length_at_cap,
            cap_refuses_length_one_above,
            cap_refuses_complete_frame,
            cap_truncated_header_16_untouched,
            cap_truncated_header_64_untouched,
            cap_floor_allows_control_frame,
            cap_refuses_unmasked_64bit,
            cap_decode_refuses,
            cap_decode_unmasked_refuses
        ]},
        {helpers, [parallel], [
            validate_control_frame_ok,
            validate_control_frame_too_large,
            validate_control_frame_fragmented,
            opcode_to_message_fragmented_rejected,
            opcode_to_message_unknown_opcode,
            opcode_to_complete_message_unknown
        ]}
    ].

%%%-----------------------------------------------------------------------------
%%% ENCODE TESTS
%%%-----------------------------------------------------------------------------

encode_unmasked_default(_Config) ->
    Bin = iolist_to_binary(nhttp_ws_frame:encode({text, <<"hi">>})),
    <<_Fin:1, _Rsv:3, _Op:4, 0:1, _Len:7, _/binary>> = Bin,
    ok.

encode_with_mask_false(_Config) ->
    A = iolist_to_binary(nhttp_ws_frame:encode({text, <<"x">>}, #{mask => false})),
    B = iolist_to_binary(nhttp_ws_frame:encode({text, <<"x">>})),
    ?assertEqual(A, B).

encode_with_mask_true(_Config) ->
    Bin = iolist_to_binary(nhttp_ws_frame:encode({text, <<"x">>}, #{mask => true})),
    <<_:1, _:3, _:4, 1:1, _:7, _:32/binary-unit:1, _/binary>> = Bin,
    ok.

encode_masked_text(_Config) ->
    Bin = iolist_to_binary(nhttp_ws_frame:encode_masked({text, <<"hello">>})),
    {ok, Msg, <<>>} = nhttp_ws_frame:decode(Bin),
    ?assertEqual({text, <<"hello">>}, Msg).

encode_close_with_code(_Config) ->
    Bin = iolist_to_binary(nhttp_ws_frame:encode({close, 1000, <<"bye">>})),
    {ok, Msg, <<>>} = nhttp_ws_frame:decode_unmasked(Bin),
    ?assertEqual({close, 1000, <<"bye">>}, Msg).

%%%-----------------------------------------------------------------------------
%%% DECODE_RAW TESTS
%%%-----------------------------------------------------------------------------

decode_raw_client(_Config) ->
    Bin = iolist_to_binary(nhttp_ws_frame:encode({binary, <<1, 2, 3>>})),
    ?assertMatch({ok, 1, 2, <<1, 2, 3>>, <<>>}, nhttp_ws_frame:decode_raw(Bin, client)).

decode_raw_server(_Config) ->
    Bin = iolist_to_binary(nhttp_ws_frame:encode_masked({binary, <<4, 5>>})),
    {ok, 1, 2, Payload, <<>>} = nhttp_ws_frame:decode_raw(Bin, server),
    ?assertEqual(<<4, 5>>, Payload).

decode_raw_more(_Config) ->
    ?assertMatch({more, _}, nhttp_ws_frame:decode_raw(<<>>, client)),
    ?assertMatch({more, _}, nhttp_ws_frame:decode_raw(<<>>, server)).

decode_raw_invalid_mask(_Config) ->
    Unmasked = iolist_to_binary(nhttp_ws_frame:encode({text, <<"x">>})),
    ?assertEqual({error, unmasked_client_frame}, nhttp_ws_frame:decode_raw(Unmasked, server)).

decode_raw_reserved_bits_masked(_Config) ->
    Frame = <<1:1, 4:3, 1:4, 1:1, 0:7, 0:32>>,
    ?assertEqual({error, reserved_bits_set}, nhttp_ws_frame:decode_raw(Frame, server)).

decode_raw_reserved_bits_unmasked(_Config) ->
    Frame = <<1:1, 4:3, 1:4, 0:1, 0:7>>,
    ?assertEqual({error, reserved_bits_set}, nhttp_ws_frame:decode_raw(Frame, client)).

%%%-----------------------------------------------------------------------------
%%% FRAME LENGTH CAP TESTS (RFC 6455 Section 10.4)
%%%
%%% Section 10.4 requires an implementation to protect itself against "a
%%% single big frame (e.g., of size 2**60)". A declared length above the
%%% caller's cap is refused when the length is read, before the caller
%%% buffers the payload. Section 5.5 bounds a control frame at 125 bytes,
%%% so the effective cap never drops below 125.
%%%-----------------------------------------------------------------------------

cap_refuses_declared_64bit(_Config) ->
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws_frame:decode_raw(exabyte_header(), server, #{max_frame_size => 1024})
    ).

cap_infinity_keeps_more(_Config) ->
    ?assertEqual(
        {more, 1 bsl 60},
        nhttp_ws_frame:decode_raw(exabyte_header(), server, #{max_frame_size => infinity})
    ).

cap_absent_keeps_more(_Config) ->
    ?assertEqual({more, 1 bsl 60}, nhttp_ws_frame:decode_raw(exabyte_header(), server, #{})),
    ?assertEqual({more, 1 bsl 60}, nhttp_ws_frame:decode_raw(exabyte_header(), server)).

cap_refuses_declared_16bit(_Config) ->
    Header = <<16#82, 16#FE, 1000:16>>,
    ?assertEqual(
        {error, {frame_too_large, 1000}},
        nhttp_ws_frame:decode_raw(Header, server, #{max_frame_size => 200})
    ).

cap_accepts_length_at_cap(_Config) ->
    Header = <<16#82, 16#FE, 1000:16>>,
    ?assertEqual(
        {more, 1004},
        nhttp_ws_frame:decode_raw(Header, server, #{max_frame_size => 1000})
    ).

cap_refuses_length_one_above(_Config) ->
    Header = <<16#82, 16#FE, 1001:16>>,
    ?assertEqual(
        {error, {frame_too_large, 1001}},
        nhttp_ws_frame:decode_raw(Header, server, #{max_frame_size => 1000})
    ).

cap_refuses_complete_frame(_Config) ->
    Frame = iolist_to_binary(nhttp_ws_frame:encode_masked({binary, binary:copy(<<0>>, 200)})),
    ?assertEqual(
        {error, {frame_too_large, 200}},
        nhttp_ws_frame:decode_raw(Frame, server, #{max_frame_size => 125})
    ).

cap_truncated_header_16_untouched(_Config) ->
    ?assertEqual(
        {more, 2},
        nhttp_ws_frame:decode_raw(<<16#82, 16#FE>>, server, #{max_frame_size => 125})
    ).

cap_truncated_header_64_untouched(_Config) ->
    ?assertEqual(
        {more, 6},
        nhttp_ws_frame:decode_raw(<<16#82, 16#FF, 0, 0>>, server, #{max_frame_size => 125})
    ).

cap_floor_allows_control_frame(_Config) ->
    Payload = binary:copy(<<7>>, 125),
    Frame = iolist_to_binary(nhttp_ws_frame:encode_masked({ping, Payload})),
    ?assertEqual(
        {ok, 1, 9, Payload, <<>>},
        nhttp_ws_frame:decode_raw(Frame, server, #{max_frame_size => 10})
    ).

cap_refuses_unmasked_64bit(_Config) ->
    Header = <<1:1, 0:3, 2:4, 0:1, 127:7, 0:1, (1 bsl 60):63>>,
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws_frame:decode_raw(Header, client, #{max_frame_size => 1024})
    ).

cap_decode_refuses(_Config) ->
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws_frame:decode(exabyte_header(), #{max_frame_size => 1024})
    ).

cap_decode_unmasked_refuses(_Config) ->
    Header = <<1:1, 0:3, 2:4, 0:1, 127:7, 0:1, (1 bsl 60):63>>,
    ?assertEqual(
        {error, {frame_too_large, 1 bsl 60}},
        nhttp_ws_frame:decode_unmasked(Header, #{max_frame_size => 1024})
    ).

exabyte_header() ->
    <<1:1, 0:3, 2:4, 1:1, 127:7, 0:1, (1 bsl 60):63, 0, 0, 0, 0>>.

%%%-----------------------------------------------------------------------------
%%% HELPER TESTS
%%%-----------------------------------------------------------------------------

validate_control_frame_ok(_Config) ->
    ?assertEqual(ok, nhttp_ws_frame:validate_control_frame(1, 1, <<"data">>)),
    ?assertEqual(ok, nhttp_ws_frame:validate_control_frame(1, 9, <<"ping">>)).

validate_control_frame_too_large(_Config) ->
    Big = binary:copy(<<0>>, 126),
    ?assertEqual(
        {error, control_frame_too_large},
        nhttp_ws_frame:validate_control_frame(1, 9, Big)
    ).

validate_control_frame_fragmented(_Config) ->
    ?assertEqual(
        {error, fragmented_control_frame},
        nhttp_ws_frame:validate_control_frame(0, 9, <<>>)
    ).

opcode_to_message_fragmented_rejected(_Config) ->
    ?assertEqual(
        {error, fragmentation_not_supported},
        nhttp_ws_frame:opcode_to_message(0, 1, <<"chunk">>)
    ).

opcode_to_message_unknown_opcode(_Config) ->
    ?assertMatch(
        {error, {unknown_opcode, 7}},
        nhttp_ws_frame:opcode_to_message(1, 7, <<>>)
    ).

opcode_to_complete_message_unknown(_Config) ->
    ?assertMatch(
        {error, {unknown_opcode, 7}},
        nhttp_ws_frame:opcode_to_complete_message(7, <<>>)
    ).
