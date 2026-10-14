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
- `nhttp_ws:feed/2` over any split of the wire into chunks returns the
  messages that `decode_with_state/2` returns over the whole buffer.
- `nhttp_ws:feed/2` refuses invalid UTF-8 on the call whose chunk carries the
  invalid byte.

Control-frame validation (J3) and fragment-size enforcement (J4) are
covered by the dedicated CT cases in `nhttp_ws_SUITE`.

These properties are run via `nhttp_props_SUITE`.
""".

-include_lib("triq/include/triq.hrl").

-define(FEED_NUMTESTS, 1000).


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
                {continue, _, Dec1} ->
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

-spec prop_ws_frame_cap_bounds_more() -> triq:property().
prop_ws_frame_cap_bounds_more() ->
    ?FORALL(
        {Len, Cap},
        {declared_length_gen(), int(1, 4096)},
        begin
            Header = masked_header(Len),
            EffCap = max(Cap, 125),
            case nhttp_ws_frame:decode_raw(Header, server, #{max_frame_size => Cap}) of
                {more, N} -> N =< EffCap + byte_size(Header);
                {error, {frame_too_large, Declared}} -> Declared =:= Len andalso Len > EffCap;
                {error, _} -> false;
                {ok, _Fin, _Opcode, _Payload, _Rest} -> Len =:= 0
            end
        end
    ).

-spec declared_length_gen() -> triq_dom:domain().
declared_length_gen() ->
    oneof([
        int(0, 125),
        int(126, 65535),
        ?LET(N, int(16, 62), 1 bsl N),
        ?LET(N, int(16, 62), (1 bsl N) - 1)
    ]).

-spec masked_header(non_neg_integer()) -> binary().
masked_header(Len) when Len < 126 ->
    <<1:1, 0:3, 2:4, 1:1, Len:7, 0:32>>;
masked_header(Len) when Len < 65536 ->
    <<1:1, 0:3, 2:4, 1:1, 126:7, Len:16, 0:32>>;
masked_header(Len) ->
    <<1:1, 0:3, 2:4, 1:1, 127:7, 0:1, Len:63, 0:32>>.

-spec prop_ws_incremental_utf8_matches_whole() -> triq:property().
prop_ws_incremental_utf8_matches_whole() ->
    ?FORALL(
        {Payload, NumChunks},
        {oneof([valid_utf8_gen(), invalid_utf8_gen(), binary()]), int(1, 8)},
        begin
            Chunks = split_into_n(Payload, NumChunks),
            scan_chunks(Chunks, <<>>) =:= whole_utf8_verdict(Payload)
        end
    ).

-spec scan_chunks([binary()], binary()) -> valid | invalid.
scan_chunks([], <<>>) ->
    valid;
scan_chunks([], _Carry) ->
    invalid;
scan_chunks([Chunk | Rest], <<>>) ->
    scan_chunks_next(nhttp_ws_frame:scan_utf8(Chunk), Rest);
scan_chunks([Chunk | Rest], Carry) ->
    scan_chunks_next(nhttp_ws_frame:scan_utf8(Carry, Chunk), Rest).

-spec scan_chunks_next({ok, binary()} | {error, invalid_utf8}, [binary()]) -> valid | invalid.
scan_chunks_next({ok, Carry}, Rest) -> scan_chunks(Rest, Carry);
scan_chunks_next({error, invalid_utf8}, _Rest) -> invalid.

-spec whole_utf8_verdict(binary()) -> valid | invalid.
whole_utf8_verdict(Payload) ->
    case nhttp_ws_frame:opcode_to_complete_message(1, Payload) of
        {ok, _} -> valid;
        {error, invalid_utf8} -> invalid
    end.

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
        {continue, _, Dec1} -> decode_frames(Rest, Dec1, Acc);
        {error, _} -> error
    end.

-spec decode_frames_until_error([binary()], nhttp_ws:ws_decoder()) ->
    {error, term()} | no_error.
decode_frames_until_error([], _Dec) ->
    no_error;
decode_frames_until_error([Frame | Rest], Dec) ->
    case nhttp_ws:decode_with_state(Frame, Dec) of
        {ok, _Msg, _Rest, Dec1} -> decode_frames_until_error(Rest, Dec1);
        {continue, _, Dec1} -> decode_frames_until_error(Rest, Dec1);
        {error, _} = Err -> Err
    end.

-spec prop_ws_feed_matches_whole_buffer() -> triq:property().
prop_ws_feed_matches_whole_buffer() ->
    triq:numtests(
        ?FEED_NUMTESTS,
        ?FORALL(
            {Role, Units, Base, Split},
            {role_gen(), units_gen(), key_base_gen(), split_gen()},
            begin
                Frames = lists:append([F || {F, _} <- Units]),
                Expected = lists:append([M || {_, M} <- Units]),
                Wire = iolist_to_binary(wire(Role, Frames, Base)),
                Whole = whole_buffer(Wire, nhttp_ws:decoder_new(Role)),
                Fed = feed_chunks(chunks(Wire, Split), nhttp_ws:decoder_new(Role)),
                ?WHENFAIL(
                    ct:pal("expected ~P~nwhole ~P~nfed ~P", [Expected, 8, Whole, 8, Fed, 8]),
                    Whole =:= Expected andalso Fed =:= Whole
                )
            end
        )
    ).

-spec prop_ws_feed_refuses_invalid_utf8_on_the_carrying_call() -> triq:property().
prop_ws_feed_refuses_invalid_utf8_on_the_carrying_call() ->
    triq:numtests(
        ?FEED_NUMTESTS,
        ?FORALL(
            {Role, Units, Before, Bad, After, Pieces, Base, Split},
            {
                role_gen(),
                units_gen(),
                feed_text_gen(),
                invalid_lead_byte_gen(),
                valid_utf8_gen(),
                int(1, 4),
                key_base_gen(),
                split_gen()
            },
            begin
                Prefix = lists:append([F || {F, _} <- Units]),
                Text = fragment_frames(text, <<Before/binary, Bad, After/binary>>, Pieces, []),
                Wires = wire(Role, Prefix ++ Text, Base),
                {PrefixWires, TextWires} = lists:split(length(Prefix), Wires),
                Offset =
                    iolist_size(PrefixWires) +
                        bad_byte_offset(TextWires, Text, byte_size(Before)),
                Chunks = chunks(iolist_to_binary(Wires), Split),
                refused_at(Chunks, Offset, 0, nhttp_ws:decoder_new(Role))
            end
        )
    ).

-type frame() :: {0 | 1, 0..15, binary()}.

-spec role_gen() -> triq_dom:domain().
role_gen() ->
    oneof([server, client]).

-spec key_base_gen() -> triq_dom:domain().
key_base_gen() ->
    int(0, 16#FFFFFFFF).

-spec units_gen() -> triq_dom:domain().
units_gen() ->
    ?LET(N, int(0, 6), vector(N, unit_gen())).

-spec unit_gen() -> triq_dom:domain().
unit_gen() ->
    frequency([
        {4, ?LET(Msg, feed_message_gen(), {[message_frame(Msg)], [Msg]})},
        {1, fragmented_unit_gen()}
    ]).

-spec fragmented_unit_gen() -> triq_dom:domain().
fragmented_unit_gen() ->
    ?LET(
        {Kind, Payload, Pieces, Controls},
        {oneof([text, binary]), feed_text_gen(), int(2, 5), list({int(1, 4), control_frame_gen()})},
        begin
            Placed = [{min(Pos, Pieces - 1), C} || {Pos, C} <- Controls],
            Interleaved = [C || {_, C} <- lists:keysort(1, Placed)],
            {fragment_frames(Kind, Payload, Pieces, Placed), Interleaved ++ [{Kind, Payload}]}
        end
    ).

-spec feed_message_gen() -> triq_dom:domain().
feed_message_gen() ->
    frequency([
        {8, ws_message_gen()},
        {1, ?LET(D, large_text_gen(), {text, D})},
        {1, ?LET(D, large_binary_gen(), {binary, D})}
    ]).

-spec feed_text_gen() -> triq_dom:domain().
feed_text_gen() ->
    frequency([{6, valid_utf8_gen()}, {1, large_text_gen()}]).

-spec large_text_gen() -> triq_dom:domain().
large_text_gen() ->
    ?LET(
        {Chars, Len},
        {non_empty(list(unicode_codepoint_gen())), large_length_gen()},
        repeat_to(unicode:characters_to_binary(Chars), Len)
    ).

-spec large_binary_gen() -> triq_dom:domain().
large_binary_gen() ->
    ?LET({Unit, Len}, {non_empty(binary()), large_length_gen()}, repeat_to(Unit, Len)).

-doc "Lengths that select the 16 bit and the 64 bit length encodings (RFC 6455 5.2).".
-spec large_length_gen() -> triq_dom:domain().
large_length_gen() ->
    oneof([int(126, 400), int(65536, 65800)]).

-spec invalid_lead_byte_gen() -> triq_dom:domain().
invalid_lead_byte_gen() ->
    oneof([int(16#80, 16#BF), return(16#C0), return(16#C1), int(16#F5, 16#FF)]).

-spec split_gen() -> triq_dom:domain().
split_gen() ->
    oneof([
        whole,
        {fixed, int(1, 4)},
        {fixed, int(5, 200)},
        {fraction, int(1, 100)},
        {random, int(1, 64), int(1, 1 bsl 30)},
        {random, int(1, 20000), int(1, 1 bsl 30)}
    ]).

-spec repeat_to(binary(), pos_integer()) -> binary().
repeat_to(Unit, Len) ->
    binary:copy(Unit, Len div byte_size(Unit) + 1).

-spec message_frame(nhttp_ws_frame:ws_message()) -> frame().
message_frame({text, D}) -> {1, 1, D};
message_frame({binary, D}) -> {1, 2, D};
message_frame(close) -> {1, 8, <<>>};
message_frame({close, Code, Reason}) -> {1, 8, <<Code:16, Reason/binary>>};
message_frame(ping) -> {1, 9, <<>>};
message_frame({ping, D}) -> {1, 9, D};
message_frame(pong) -> {1, 10, <<>>};
message_frame({pong, D}) -> {1, 10, D}.

-spec fragment_frames(
    text | binary, binary(), pos_integer(), [{pos_integer(), nhttp_ws_frame:ws_message()}]
) -> [frame()].
fragment_frames(Kind, Payload, Pieces, Placed) ->
    Split = split_into_n(Payload, Pieces),
    Last = length(Split),
    lists:append([
        [
            {fin(I, Last), fragment_opcode(Kind, I), Piece}
            | [message_frame(C) || {P, C} <- Placed, P =:= I]
        ]
     || {I, Piece} <- lists:zip(lists:seq(1, Last), Split)
    ]).

-spec fin(pos_integer(), pos_integer()) -> 0 | 1.
fin(Last, Last) -> 1;
fin(_I, _Last) -> 0.

-spec fragment_opcode(text | binary, pos_integer()) -> 0..2.
fragment_opcode(text, 1) -> 1;
fragment_opcode(binary, 1) -> 2;
fragment_opcode(_Kind, _I) -> 0.

-doc "Encode frames for the peer of a decoder in `Role`: masked toward a server.".
-spec wire(client | server, [frame()], non_neg_integer()) -> [binary()].
wire(Role, Frames, Base) ->
    [
        frame_wire(Role, Frame, <<((Base + I) band 16#FFFFFFFF):32>>)
     || {I, Frame} <- lists:enumerate(Frames)
    ].

-spec frame_wire(client | server, frame(), binary()) -> binary().
frame_wire(server, {Fin, Opcode, Payload}, Key) ->
    Header = frame_header(Fin, Opcode, 1, byte_size(Payload)),
    <<Header/binary, Key/binary, (xor_mask(Key, Payload))/binary>>;
frame_wire(client, {Fin, Opcode, Payload}, _Key) ->
    <<(frame_header(Fin, Opcode, 0, byte_size(Payload)))/binary, Payload/binary>>.

-spec frame_header(0 | 1, 0..15, 0 | 1, non_neg_integer()) -> binary().
frame_header(Fin, Opcode, Mask, Len) when Len < 126 ->
    <<Fin:1, 0:3, Opcode:4, Mask:1, Len:7>>;
frame_header(Fin, Opcode, Mask, Len) when Len < 65536 ->
    <<Fin:1, 0:3, Opcode:4, Mask:1, 126:7, Len:16>>;
frame_header(Fin, Opcode, Mask, Len) ->
    <<Fin:1, 0:3, Opcode:4, Mask:1, 127:7, Len:64>>.

-spec xor_mask(binary(), binary()) -> binary().
xor_mask(Key, Payload) ->
    Len = byte_size(Payload),
    crypto:exor(Payload, binary:part(binary:copy(Key, Len div 4 + 1), 0, Len)).

-spec chunks(binary(), term()) -> [binary()].
chunks(Wire, whole) ->
    [Wire];
chunks(Wire, {fixed, Size}) ->
    fixed_chunks(Wire, Size);
chunks(Wire, {fraction, Percent}) ->
    fixed_chunks(Wire, max(1, byte_size(Wire) * Percent div 100));
chunks(Wire, {random, Max, Seed}) ->
    random_chunks(Wire, Max, rand:seed_s(exsss, Seed)).

-spec fixed_chunks(binary(), pos_integer()) -> [binary()].
fixed_chunks(Bin, Size) when byte_size(Bin) =< Size ->
    [Bin];
fixed_chunks(Bin, Size) ->
    <<Head:Size/binary, Rest/binary>> = Bin,
    [Head | fixed_chunks(Rest, Size)].

-spec random_chunks(binary(), pos_integer(), rand:state()) -> [binary()].
random_chunks(Bin, Max, S0) ->
    {Size, S1} = rand:uniform_s(Max, S0),
    case Bin of
        <<Head:Size/binary, Rest/binary>> when Rest =/= <<>> -> [Head | random_chunks(Rest, Max, S1)];
        _ -> [Bin]
    end.

-spec whole_buffer(binary(), nhttp_ws:ws_decoder()) -> [nhttp_ws_frame:ws_message() | {error, term()}].
whole_buffer(Wire, Dec) ->
    case nhttp_ws:decode_with_state(Wire, Dec) of
        {ok, Msg, Rest, Dec1} -> [Msg | whole_buffer(Rest, Dec1)];
        {continue, Rest, Dec1} -> whole_buffer(Rest, Dec1);
        {more, _, _} -> [];
        {error, Reason} -> [{error, Reason}]
    end.

-spec feed_chunks([binary()], nhttp_ws:ws_decoder()) ->
    [nhttp_ws_frame:ws_message() | {error, term()}].
feed_chunks([], _Dec) ->
    [];
feed_chunks([Chunk | Rest], Dec) ->
    case nhttp_ws:feed(Chunk, Dec) of
        {ok, Msgs, Dec1} -> Msgs ++ feed_chunks(Rest, Dec1);
        {error, Reason, Msgs} -> Msgs ++ [{error, Reason}]
    end.

-doc "Wire offset of payload byte `K` of a message sent as `Frames`.".
-spec bad_byte_offset([binary()], [frame()], non_neg_integer()) -> non_neg_integer().
bad_byte_offset([Wire | Wires], [{_, _, Payload} | Frames], K) when K >= byte_size(Payload) ->
    byte_size(Wire) + bad_byte_offset(Wires, Frames, K - byte_size(Payload));
bad_byte_offset([Wire | _], [{_, _, Payload} | _], K) ->
    byte_size(Wire) - byte_size(Payload) + K.

-doc """
Every call before the chunk that carries wire byte `Offset` succeeds, and the
call that carries it refuses the text as UTF-8.
""".
-spec refused_at([binary()], non_neg_integer(), non_neg_integer(), nhttp_ws:ws_decoder()) ->
    boolean().
refused_at([], _Offset, _Pos, _Dec) ->
    false;
refused_at([Chunk | Rest], Offset, Pos, Dec) ->
    End = Pos + byte_size(Chunk),
    case {nhttp_ws:feed(Chunk, Dec), Offset < End} of
        {{ok, _Msgs, Dec1}, false} -> refused_at(Rest, Offset, End, Dec1);
        {{error, invalid_utf8, _Msgs}, true} -> true;
        {Other, Carries} ->
            ct:pal("chunk at ~p carries the byte: ~p, result ~P", [Pos, Carries, Other, 8]),
            false
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
