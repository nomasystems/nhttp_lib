%%%-----------------------------------------------------------------------------
-module(nhttp_ws_props).

-moduledoc """
WebSocket codec property tests (RFC 6455).

Properties:

- `decode_unmasked/1` recovers the original message from `encode/1`
  (server → client direction). M2.
- `decode/1` recovers the original message from `encode_masked/1`
  (client → server direction). M2.
- Trailing bytes after the frame are returned as `Rest` unchanged.
- Both decoders are total: arbitrary binary inputs return `{ok, _, _}`,
  `{more, _}` or `{error, _}` and never crash.

Control-frame validation (J3) and fragment-size enforcement (J4) are
covered by the dedicated CT cases in `nhttp_ws_SUITE`.

These properties are run via `nhttp_props_SUITE`.
""".

-include_lib("triq/include/triq.hrl").



-spec prop_unmasked_roundtrip() -> triq:property().
prop_unmasked_roundtrip() ->
    ?FORALL(
        Msg,
        ws_message_gen(),
        begin
            Encoded = iolist_to_binary(nhttp_ws:encode(Msg)),
            case nhttp_ws:decode_unmasked(Encoded) of
                {ok, Decoded, <<>>} -> Decoded =:= Msg;
                _ -> false
            end
        end
    ).

-spec prop_masked_roundtrip() -> triq:property().
prop_masked_roundtrip() ->
    ?FORALL(
        Msg,
        ws_message_gen(),
        begin
            Encoded = iolist_to_binary(nhttp_ws:encode_masked(Msg)),
            case nhttp_ws:decode(Encoded) of
                {ok, Decoded, <<>>} -> Decoded =:= Msg;
                _ -> false
            end
        end
    ).

-spec prop_unmasked_trailing_bytes() -> triq:property().
prop_unmasked_trailing_bytes() ->
    ?FORALL(
        {Msg, Trailer},
        {ws_message_gen(), binary()},
        begin
            Encoded = iolist_to_binary(nhttp_ws:encode(Msg)),
            Combined = <<Encoded/binary, Trailer/binary>>,
            case nhttp_ws:decode_unmasked(Combined) of
                {ok, Decoded, Rest} -> Decoded =:= Msg andalso Rest =:= Trailer;
                _ -> false
            end
        end
    ).

-spec prop_text_invalid_utf8_rejected() -> triq:property().
prop_text_invalid_utf8_rejected() ->
    ?FORALL(
        Payload,
        invalid_utf8_gen(),
        begin
            Frame = iolist_to_binary(nhttp_ws:encode({text, Payload})),
            case nhttp_ws:decode_unmasked(Frame) of
                {error, invalid_utf8} -> true;
                _ -> false
            end
        end
    ).

-spec prop_close_code_rejected() -> triq:property().
prop_close_code_rejected() ->
    ?FORALL(
        Code,
        invalid_close_code_gen(),
        begin
            Frame = iolist_to_binary(nhttp_ws:encode({close, Code, <<>>})),
            case nhttp_ws:decode_unmasked(Frame) of
                {error, invalid_close_code} -> true;
                _ -> false
            end
        end
    ).

-spec prop_close_code_accepted() -> triq:property().
prop_close_code_accepted() ->
    ?FORALL(
        {Code, Reason},
        {valid_close_code_gen(), valid_close_reason_gen()},
        begin
            Frame = iolist_to_binary(nhttp_ws:encode({close, Code, Reason})),
            case nhttp_ws:decode_unmasked(Frame) of
                {ok, {close, Code, Reason}, <<>>} -> true;
                _ -> false
            end
        end
    ).

-spec invalid_utf8_gen() -> triq_dom:domain().
invalid_utf8_gen() ->
    oneof([
        return(<<16#FF>>),
        return(<<16#C0, 16#80>>),
        return(<<16#C2>>),
        return(<<16#E0, 16#80, 16#80>>),
        return(<<16#ED, 16#A0, 16#80>>),
        return(<<16#F4, 16#90, 16#80, 16#80>>),
        return(<<16#80>>),
        ?LET(B, non_empty(binary()), <<16#FF, B/binary>>),
        ?LET(B, binary(), <<B/binary, 16#C2>>)
    ]).

-spec invalid_close_code_gen() -> triq_dom:domain().
invalid_close_code_gen() ->
    oneof([
        int(0, 999),
        return(1004),
        return(1005),
        return(1006),
        return(1015),
        int(1016, 2999),
        int(5000, 65535)
    ]).

-spec prop_ws_fragmentation_reassembly() -> triq:property().
prop_ws_fragmentation_reassembly() ->
    ?FORALL(
        {Kind, Payload, NumChunks, Controls},
        {oneof([text, binary]), valid_utf8_gen(), int(1, 8), list(control_frame_gen())},
        begin
            Chunks = split_into_n(Payload, NumChunks),
            Opcode =
                case Kind of
                    text -> 1;
                    binary -> 2
                end,
            Frames = build_fragmented_frames(Opcode, Chunks, Controls),
            Dec = nhttp_ws:decoder_new(server),
            ExpectedMessages = expected_messages(Kind, Payload, Controls),
            decode_frames(Frames, Dec, []) =:= ExpectedMessages
        end
    ).

-spec prop_ws_continuation_without_start_rejected() -> triq:property().
prop_ws_continuation_without_start_rejected() ->
    ?FORALL(
        {Fin, Payload},
        {oneof([0, 1]), valid_utf8_gen()},
        begin
            Frame = encode_masked_raw(Fin, 0, Payload),
            Dec = nhttp_ws:decoder_new(server),
            case nhttp_ws:decode_with_state(Frame, Dec) of
                {error, _} -> true;
                _ -> false
            end
        end
    ).

-spec prop_ws_new_message_mid_fragmentation_rejected() -> triq:property().
prop_ws_new_message_mid_fragmentation_rejected() ->
    ?FORALL(
        {StartPayload, IntruderOpcode, IntruderPayload},
        {valid_utf8_gen(), oneof([1, 2]), valid_utf8_gen()},
        begin
            Start = encode_masked_raw(0, 1, StartPayload),
            Intruder = encode_masked_raw(1, IntruderOpcode, IntruderPayload),
            Dec0 = nhttp_ws:decoder_new(server),
            case nhttp_ws:decode_with_state(Start, Dec0) of
                {more, _, Dec1} ->
                    case nhttp_ws:decode_with_state(Intruder, Dec1) of
                        {error, expected_continuation} -> true;
                        _ -> false
                    end;
                _ ->
                    false
            end
        end
    ).

-spec prop_ws_max_message_size_cumulative() -> triq:property().
prop_ws_max_message_size_cumulative() ->
    ?FORALL(
        {Max, OverflowSize, NumChunks},
        {int(1, 1000), int(1, 100), int(2, 8)},
        begin
            TotalSize = Max + OverflowSize,
            Payload = binary:copy(<<"x">>, TotalSize),
            Chunks = split_into_n(Payload, NumChunks),
            Frames = build_fragmented_frames(2, Chunks, []),
            Dec = nhttp_ws:decoder_new(server, #{max_message_size => Max}),
            decode_frames_until_error(Frames, Dec) =:= {error, message_too_large}
        end
    ).

-spec control_frame_gen() -> triq_dom:domain().
control_frame_gen() ->
    oneof([
        return(ping),
        ?LET(D, control_payload_gen(), {ping, D}),
        return(pong),
        ?LET(D, control_payload_gen(), {pong, D})
    ]).

-spec expected_messages(text | binary, binary(), [nhttp_ws_frame:ws_message()]) ->
    [nhttp_ws_frame:ws_message()].
expected_messages(text, Payload, Controls) ->
    Controls ++ [{text, Payload}];
expected_messages(binary, Payload, Controls) ->
    Controls ++ [{binary, Payload}].

-spec build_fragmented_frames(1 | 2, [binary()], [nhttp_ws_frame:ws_message()]) -> [binary()].
build_fragmented_frames(Opcode, [Chunk], Controls) ->
    [encode_masked(C) || C <- Controls] ++ [encode_masked_raw(1, Opcode, Chunk)];
build_fragmented_frames(Opcode, [First | Rest], Controls) ->
    [encode_masked_raw(0, Opcode, First) | build_middle_frames(Rest, Controls)].

-spec build_middle_frames([binary()], [nhttp_ws_frame:ws_message()]) -> [binary()].
build_middle_frames([Last], Controls) ->
    [encode_masked(C) || C <- Controls] ++ [encode_masked_raw(1, 0, Last)];
build_middle_frames([Chunk | Rest], Controls) ->
    [encode_masked_raw(0, 0, Chunk) | build_middle_frames(Rest, Controls)].

-spec encode_masked(nhttp_ws_frame:ws_message()) -> binary().
encode_masked(Msg) ->
    iolist_to_binary(nhttp_ws_frame:encode_masked(Msg)).

-spec encode_masked_raw(0 | 1, 0..15, binary()) -> binary().
encode_masked_raw(Fin, Opcode, Payload) ->
    Len = byte_size(Payload),
    MaskKey = crypto:strong_rand_bytes(4),
    Masked = apply_mask(MaskKey, Payload),
    Header =
        case Len of
            _ when Len < 126 ->
                <<Fin:1, 0:3, Opcode:4, 1:1, Len:7, MaskKey/binary>>;
            _ when Len < 65536 ->
                <<Fin:1, 0:3, Opcode:4, 1:1, 126:7, Len:16, MaskKey/binary>>;
            _ ->
                <<Fin:1, 0:3, Opcode:4, 1:1, 127:7, 0:1, Len:63, MaskKey/binary>>
        end,
    <<Header/binary, Masked/binary>>.

-spec apply_mask(binary(), binary()) -> binary().
apply_mask(MaskKey, Data) ->
    apply_mask(MaskKey, Data, 0, <<>>).

-spec apply_mask(binary(), binary(), non_neg_integer(), binary()) -> binary().
apply_mask(_MaskKey, <<>>, _I, Acc) ->
    Acc;
apply_mask(MaskKey, <<B, Rest/binary>>, I, Acc) ->
    K = binary:at(MaskKey, I rem 4),
    apply_mask(MaskKey, Rest, I + 1, <<Acc/binary, (B bxor K):8>>).

-spec split_into_n(binary(), pos_integer()) -> [binary()].
split_into_n(Bin, N) when N =< 1 ->
    [Bin];
split_into_n(Bin, N) ->
    Size = byte_size(Bin),
    case Size of
        0 ->
            [<<>> || _ <- lists:seq(1, N)];
        _ ->
            ChunkSize = max(1, Size div N),
            split_chunks(Bin, ChunkSize, N)
    end.

-spec split_chunks(binary(), pos_integer(), pos_integer()) -> [binary()].
split_chunks(Bin, _ChunkSize, 1) ->
    [Bin];
split_chunks(Bin, ChunkSize, N) when byte_size(Bin) =< ChunkSize ->
    [Bin | [<<>> || _ <- lists:seq(2, N)]];
split_chunks(Bin, ChunkSize, N) ->
    <<Head:ChunkSize/binary, Rest/binary>> = Bin,
    [Head | split_chunks(Rest, ChunkSize, N - 1)].

-spec decode_frames([binary()], nhttp_ws:ws_decoder(), [nhttp_ws_frame:ws_message()]) ->
    [nhttp_ws_frame:ws_message()] | error.
decode_frames([], _Dec, Acc) ->
    lists:reverse(Acc);
decode_frames([Frame | Rest], Dec, Acc) ->
    case nhttp_ws:decode_with_state(Frame, Dec) of
        {ok, Msg, _LeftOver, Dec1} -> decode_frames(Rest, Dec1, [Msg | Acc]);
        {more, _, Dec1} -> decode_frames(Rest, Dec1, Acc);
        {error, _} -> error
    end.

-spec decode_frames_until_error([binary()], nhttp_ws:ws_decoder()) ->
    {error, term()} | no_error.
decode_frames_until_error([], _Dec) ->
    no_error;
decode_frames_until_error([Frame | Rest], Dec) ->
    case nhttp_ws:decode_with_state(Frame, Dec) of
        {ok, _Msg, _Rest, Dec1} -> decode_frames_until_error(Rest, Dec1);
        {more, _, Dec1} -> decode_frames_until_error(Rest, Dec1);
        {error, _} = Err -> Err
    end.

-spec prop_decode_never_crashes() -> triq:property().
prop_decode_never_crashes() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            try nhttp_ws:decode(Bin) of
                {ok, _, _} -> true;
                {more, _} -> true;
                {error, _} -> true
            catch
                _:_ -> false
            end
        end
    ).

-spec prop_decode_unmasked_never_crashes() -> triq:property().
prop_decode_unmasked_never_crashes() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            try nhttp_ws:decode_unmasked(Bin) of
                {ok, _, _} -> true;
                {more, _} -> true;
                {error, _} -> true
            catch
                _:_ -> false
            end
        end
    ).


-spec ws_message_gen() -> triq_dom:domain().
ws_message_gen() ->
    oneof([
        ?LET(D, valid_utf8_gen(), {text, D}),
        ?LET(D, binary(), {binary, D}),
        return(ping),
        ?LET(D, control_payload_gen(), {ping, D}),
        return(pong),
        ?LET(D, control_payload_gen(), {pong, D}),
        return(close),
        ?LET(
            {Code, Reason},
            {valid_close_code_gen(), valid_close_reason_gen()},
            {close, Code, Reason}
        )
    ]).

-spec control_payload_gen() -> triq_dom:domain().
control_payload_gen() ->
    ?LET(
        N,
        int(1, 125),
        binary(N)
    ).

-spec valid_close_code_gen() -> triq_dom:domain().
valid_close_code_gen() ->
    oneof([
        int(1000, 1003),
        int(1007, 1011),
        int(1012, 1014),
        int(3000, 4999)
    ]).

-spec valid_close_reason_gen() -> triq_dom:domain().
valid_close_reason_gen() ->
    ?LET(
        Chars,
        list(int(16#20, 16#7E)),
        list_to_binary(lists:sublist(Chars, 123))
    ).

-spec valid_utf8_gen() -> triq_dom:domain().
valid_utf8_gen() ->
    ?LET(Chars, list(unicode_codepoint_gen()), unicode:characters_to_binary(Chars)).

-spec unicode_codepoint_gen() -> triq_dom:domain().
unicode_codepoint_gen() ->
    oneof([
        int(16#20, 16#7E),
        int(16#A1, 16#FF),
        int(16#100, 16#D7FF),
        int(16#E000, 16#FFFD),
        int(16#10000, 16#10FFFF)
    ]).
