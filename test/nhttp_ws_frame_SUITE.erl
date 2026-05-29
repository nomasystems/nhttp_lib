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
            decode_raw_invalid_mask
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
