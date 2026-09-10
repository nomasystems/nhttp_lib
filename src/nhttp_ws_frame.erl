-module(nhttp_ws_frame).

-moduledoc """
WebSocket per-frame codec (RFC 6455).

Pure encode and decode for a single WebSocket frame. Stateless. For
continuation reassembly and interleaved control frames, layer
`nhttp_ws` on top of this module.

Server-to-client frames are unmasked, client-to-server frames must be
masked (RFC 6455 §5.1).

## Declared length cap

A frame header declares up to 2^63-1 payload bytes, and a decoder that
trusts that number asks its caller to buffer it. RFC 6455 §10.4 names
the threat: "a malicious endpoint can try to exhaust its peer's memory
... by sending either a single big frame (e.g., of size 2**60)".

Every decode function takes a `t:frame_limits/0` map. When the declared
length is above `max_frame_size`, the decoder returns
`{error, {frame_too_large, DeclaredLength}}` at the moment the length is
read, before any payload is buffered. The caller closes with status 1009
(§7.4.1). The arities without a limits map do not cap.

The effective cap never drops below 125 bytes, because §5.5 makes that
length legal for every control frame and §5.5.1 uses it for the close
code and reason.
""".

-compile({inline, [{decode_complete, 6}, {decode_unmasked_complete, 5}, {effective_cap, 1}]}).

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    decode/1,
    decode/2,
    decode_raw/2,
    decode_raw/3,
    decode_unmasked/1,
    decode_unmasked/2,
    encode/1,
    encode/2,
    encode_masked/1,
    opcode_to_complete_message/2,
    opcode_to_message/3,
    scan_utf8/1,
    scan_utf8/2,
    validate_control_frame/3
]).

-export_type([
    close_code/0,
    decode_result/0,
    encode_opts/0,
    frame_limits/0,
    frame_too_large/0,
    raw_decode_result/0,
    ws_message/0,
    ws_opcode/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type close_code() :: 0..65535.

-type ws_message() ::
    {text, binary()}
    | {binary, binary()}
    | ping
    | {ping, binary()}
    | pong
    | {pong, binary()}
    | close
    | {close, Code :: close_code(), Reason :: binary()}.

-type ws_opcode() :: text | binary | close | ping | pong | continuation.

-type decode_result() ::
    {ok, ws_message(), Rest :: binary()}
    | {more, MinBytes :: pos_integer()}
    | {error, term()}.

-type raw_decode_result() ::
    {ok, Fin :: 0 | 1, Opcode :: 0..15, Payload :: binary(), Rest :: binary()}
    | {more, MinBytes :: pos_integer()}
    | {error, term()}.

-type encode_opts() :: #{mask => boolean()}.

-type frame_limits() :: #{max_frame_size => pos_integer() | infinity}.

-type frame_cap() :: pos_integer() | infinity.

-type frame_too_large() :: {frame_too_large, DeclaredLength :: pos_integer()}.

%%%-----------------------------------------------------------------------------
%% MACROS
%%%-----------------------------------------------------------------------------
-define(MAX_CONTROL_PAYLOAD, 125).
-define(OP_TEXT, 1).
-define(OP_BINARY, 2).
-define(OP_CLOSE, 8).
-define(OP_PING, 9).
-define(OP_PONG, 10).

%%%-----------------------------------------------------------------------------
%% ENCODE
%%%-----------------------------------------------------------------------------
-doc "Encode a WebSocket message as an unmasked frame (server-to-client).".
-spec encode(ws_message()) -> iodata().
encode(Message) ->
    encode_for(Message, fun encode_frame/2).

-doc """
Encode a WebSocket message with options. The only option is
`mask => boolean()`, which defaults to `false` (server-to-client).
""".
-spec encode(ws_message(), encode_opts()) -> iodata().
encode(Message, Opts) ->
    case maps:get(mask, Opts, false) of
        true -> encode_for(Message, fun encode_masked_frame/2);
        false -> encode_for(Message, fun encode_frame/2)
    end.

-doc "Encode a WebSocket message as a masked frame (client-to-server).".
-spec encode_masked(ws_message()) -> iodata().
encode_masked(Message) ->
    encode_for(Message, fun encode_masked_frame/2).

%%%-----------------------------------------------------------------------------
%% DECODE
%%%-----------------------------------------------------------------------------
-doc """
Decode a masked WebSocket frame (client-to-server) with no cap on the
declared payload length. Equivalent to `decode(Data, #{})`.
""".
-spec decode(binary()) -> decode_result().
decode(Data) ->
    decode_message_masked(Data, infinity).

-doc """
Decode a masked WebSocket frame (client-to-server).
Returns `{ok, Message, Rest}` on success, `{more, MinBytes}` if more
data is needed, or `{error, Reason}` on protocol violation.
A declared payload length above `max_frame_size` returns
`{error, {frame_too_large, DeclaredLength}}` before any payload is
buffered (RFC 6455 §10.4).
""".
-spec decode(binary(), frame_limits()) -> decode_result().
decode(Data, Limits) ->
    decode_message_masked(Data, effective_cap(Limits)).

-doc """
Decode a raw frame with no cap on the declared payload length.
Equivalent to `decode_raw(Data, Role, #{})`.
""".
-spec decode_raw(binary(), client | server) -> raw_decode_result().
decode_raw(Data, client) ->
    decode_raw_unmasked(Data, infinity);
decode_raw(Data, server) ->
    decode_raw_masked(Data, infinity).

-doc """
Decode a raw frame, returning Fin, Opcode, Payload, Rest separately.
Used by the stateful message-level decoder for continuation reassembly.
The role argument selects masked (server) or unmasked (client) parsing.
A declared payload length above `max_frame_size` returns
`{error, {frame_too_large, DeclaredLength}}` before any payload is
buffered (RFC 6455 §10.4).
""".
-spec decode_raw(binary(), client | server, frame_limits()) -> raw_decode_result().
decode_raw(Data, client, Limits) ->
    decode_raw_unmasked(Data, effective_cap(Limits));
decode_raw(Data, server, Limits) ->
    decode_raw_masked(Data, effective_cap(Limits)).

-doc """
Decode an unmasked WebSocket frame (server-to-client) with no cap on the
declared payload length. Equivalent to `decode_unmasked(Data, #{})`.
""".
-spec decode_unmasked(binary()) -> decode_result().
decode_unmasked(Data) ->
    decode_message_unmasked(Data, infinity).

-doc """
Decode an unmasked WebSocket frame (server-to-client).
RFC 6455 §5.1: a server MUST NOT mask frames sent to clients.
A declared payload length above `max_frame_size` returns
`{error, {frame_too_large, DeclaredLength}}` before any payload is
buffered (RFC 6455 §10.4).
""".
-spec decode_unmasked(binary(), frame_limits()) -> decode_result().
decode_unmasked(Data, Limits) ->
    decode_message_unmasked(Data, effective_cap(Limits)).

%%%-----------------------------------------------------------------------------
%% SHARED HELPERS (USED BY STATEFUL MESSAGE-LEVEL DECODER)
%%%-----------------------------------------------------------------------------
-doc """
Map a complete (FIN=1) frame's opcode and payload to a `ws_message/0`.
Text payloads are validated as UTF-8 (RFC 6455 §5.6 / §8.1).
Close payloads are validated against the reserved-code ranges of
RFC 6455 §7.4.1 and the reason is checked as UTF-8.
""".
-spec opcode_to_complete_message(0..15, binary()) -> {ok, ws_message()} | {error, term()}.
opcode_to_complete_message(?OP_TEXT, Data) ->
    case is_valid_utf8(Data) of
        true -> {ok, {text, Data}};
        false -> {error, invalid_utf8}
    end;
opcode_to_complete_message(?OP_BINARY, Data) ->
    {ok, {binary, Data}};
opcode_to_complete_message(?OP_CLOSE, <<>>) ->
    {ok, close};
opcode_to_complete_message(?OP_CLOSE, <<_:8>>) ->
    {error, invalid_close_payload};
opcode_to_complete_message(?OP_CLOSE, <<Code:16, Reason/binary>>) ->
    case is_valid_close_code(Code) of
        false ->
            {error, invalid_close_code};
        true ->
            case is_valid_utf8(Reason) of
                true -> {ok, {close, Code, Reason}};
                false -> {error, invalid_close_reason}
            end
    end;
opcode_to_complete_message(?OP_PING, <<>>) ->
    {ok, ping};
opcode_to_complete_message(?OP_PING, Data) ->
    {ok, {ping, Data}};
opcode_to_complete_message(?OP_PONG, <<>>) ->
    {ok, pong};
opcode_to_complete_message(?OP_PONG, Data) ->
    {ok, {pong, Data}};
opcode_to_complete_message(Opcode, _) ->
    {error, {unknown_opcode, Opcode}}.

-doc """
Map a frame's Fin bit, opcode and payload to a `ws_message/0`. Rejects
fragmented frames (Fin=0). Fragmentation must be handled by the
stateful message-level decoder.
""".
-spec opcode_to_message(0 | 1, 0..15, binary()) -> {ok, ws_message()} | {error, term()}.
opcode_to_message(1, Opcode, Data) ->
    opcode_to_complete_message(Opcode, Data);
opcode_to_message(0, _Opcode, _Data) ->
    {error, fragmentation_not_supported}.

-doc """
Scan a run of text for UTF-8 validity (RFC 3629) and return the trailing
bytes that do not yet form a character.
A fragmented text message can split a character across two frames, so a
fragment is not valid or invalid on its own: it ends in a carry, which the
next fragment starts with. The run is refused as soon as no continuation
can complete it, which puts the refusal on the fragment that breaks rather
than on the whole reassembled message.
A carry left at the end of a message is a truncated character, so the
caller must require an empty one on the final fragment.
""".
-spec scan_utf8(binary()) -> {ok, Carry :: binary()} | {error, invalid_utf8}.
scan_utf8(<<_/utf8, Rest/binary>>) ->
    scan_utf8(Rest);
scan_utf8(<<>>) ->
    {ok, <<>>};
scan_utf8(Rest) ->
    case is_utf8_prefix(Rest) of
        true -> {ok, Rest};
        false -> {error, invalid_utf8}
    end.

-doc """
Scan a run of text that continues an unfinished character.
`Carry` comes from the previous fragment and is at most three bytes. Only
the bytes needed to finish that character are copied; the rest of the
payload is scanned where it lies.
""".
-spec scan_utf8(Carry :: binary(), binary()) -> {ok, Carry :: binary()} | {error, invalid_utf8}.
scan_utf8(Carry, Payload) when byte_size(Payload) =< 3 ->
    scan_utf8(<<Carry/binary, Payload/binary>>);
scan_utf8(Carry, <<Head:3/binary, Rest/binary>>) ->
    maybe
        {ok, <<>>} ?= scan_utf8(<<Carry/binary, Head/binary>>),
        scan_utf8(Rest)
    else
        {ok, NewCarry} -> scan_utf8(NewCarry, Rest);
        {error, _} = Err -> Err
    end.

-doc """
Validate that a control frame is not fragmented and not too large
(RFC 6455 §5.5: control frame payloads MUST be <= 125 bytes).
""".
-spec validate_control_frame(0 | 1, 0..15, binary()) ->
    ok | {error, control_frame_too_large | fragmented_control_frame}.
validate_control_frame(_Fin, Opcode, _Data) when Opcode < 8 ->
    ok;
validate_control_frame(_Fin, _Opcode, Data) when byte_size(Data) > 125 ->
    {error, control_frame_too_large};
validate_control_frame(0, _Opcode, _Data) ->
    {error, fragmented_control_frame};
validate_control_frame(_, _, _) ->
    ok.

%%%-----------------------------------------------------------------------------
%% INTERNAL: ENCODE
%%%-----------------------------------------------------------------------------
-spec encode_for(ws_message(), fun((0..15, iodata()) -> iodata())) -> iodata().
encode_for({text, Data}, F) -> F(?OP_TEXT, Data);
encode_for({binary, Data}, F) -> F(?OP_BINARY, Data);
encode_for(ping, F) -> F(?OP_PING, <<>>);
encode_for({ping, Data}, F) -> F(?OP_PING, Data);
encode_for(pong, F) -> F(?OP_PONG, <<>>);
encode_for({pong, Data}, F) -> F(?OP_PONG, Data);
encode_for(close, F) -> F(?OP_CLOSE, <<>>);
encode_for({close, Code, Reason}, F) -> F(?OP_CLOSE, <<Code:16, Reason/binary>>).

-spec encode_frame(0..15, iodata()) -> iodata().
encode_frame(Opcode, Data) ->
    Len = iolist_size(Data),
    encode_frame_with_length(Opcode, Data, Len).

-spec encode_frame_with_length(0..15, iodata(), non_neg_integer()) -> iodata().
encode_frame_with_length(Opcode, Data, Len) when Len < 126 ->
    [<<1:1, 0:3, Opcode:4, 0:1, Len:7>>, Data];
encode_frame_with_length(Opcode, Data, Len) when Len < 65536 ->
    [<<1:1, 0:3, Opcode:4, 0:1, 126:7, Len:16>>, Data];
encode_frame_with_length(Opcode, Data, Len) ->
    [<<1:1, 0:3, Opcode:4, 0:1, 127:7, 0:1, Len:63>>, Data].

-spec encode_masked_frame(0..15, iodata()) -> iodata().
encode_masked_frame(Opcode, Data) ->
    Bin = iolist_to_binary(Data),
    Len = byte_size(Bin),
    MaskKey = crypto:strong_rand_bytes(4),
    Masked = unmask(MaskKey, Bin),
    [encode_masked_header(Opcode, Len, MaskKey), Masked].

-spec encode_masked_header(0..15, non_neg_integer(), binary()) -> binary().
encode_masked_header(Opcode, Len, MaskKey) when Len < 126 ->
    <<1:1, 0:3, Opcode:4, 1:1, Len:7, MaskKey/binary>>;
encode_masked_header(Opcode, Len, MaskKey) when Len < 65536 ->
    <<1:1, 0:3, Opcode:4, 1:1, 126:7, Len:16, MaskKey/binary>>;
encode_masked_header(Opcode, Len, MaskKey) ->
    <<1:1, 0:3, Opcode:4, 1:1, 127:7, 0:1, Len:63, MaskKey/binary>>.

%%%-----------------------------------------------------------------------------
%% INTERNAL: DECODE
%%%-----------------------------------------------------------------------------
-spec decode_complete(0 | 1, 0..7, 0..15, binary(), binary(), binary()) -> decode_result().
decode_complete(_Fin, Rsv, _Opcode, _MaskKey, _Data, _Rest) when Rsv =/= 0 ->
    {error, reserved_bits_set};
decode_complete(Fin, 0, Opcode, MaskKey, Data, Rest) ->
    Unmasked = unmask(MaskKey, Data),
    case validate_control_frame(Fin, Opcode, Unmasked) of
        ok ->
            case opcode_to_message(Fin, Opcode, Unmasked) of
                {ok, Message} -> {ok, Message, Rest};
                {error, Reason} -> {error, Reason}
            end;
        {error, _} = Err ->
            Err
    end.

-spec decode_message_masked(binary(), frame_cap()) -> decode_result().
decode_message_masked(<<_:8, _Mask:1, 126:7, Len:16, _/binary>>, Cap) when Len > Cap ->
    {error, {frame_too_large, Len}};
decode_message_masked(<<_:8, _Mask:1, 127:7, _:1, Len:63, _/binary>>, Cap) when Len > Cap ->
    {error, {frame_too_large, Len}};
decode_message_masked(
    <<Fin:1, Rsv:3, Opcode:4, 1:1, Len:7, MaskKey:4/binary, Data:Len/binary, Rest/binary>>, _Cap
) when Len < 126 ->
    decode_complete(Fin, Rsv, Opcode, MaskKey, Data, Rest);
decode_message_masked(
    <<Fin:1, Rsv:3, Opcode:4, 1:1, 126:7, Len:16, MaskKey:4/binary, Data:Len/binary, Rest/binary>>,
    _Cap
) ->
    decode_complete(Fin, Rsv, Opcode, MaskKey, Data, Rest);
decode_message_masked(
    <<Fin:1, Rsv:3, Opcode:4, 1:1, 127:7, 0:1, Len:63, MaskKey:4/binary, Data:Len/binary,
        Rest/binary>>,
    _Cap
) ->
    decode_complete(Fin, Rsv, Opcode, MaskKey, Data, Rest);
decode_message_masked(<<_Fin:1, _Rsv:3, _Opcode:4, 0:1, _Len:7, _Rest/binary>>, _Cap) ->
    {error, unmasked_client_frame};
decode_message_masked(Binary, _Cap) when byte_size(Binary) < 2 ->
    {more, 2};
decode_message_masked(<<_:8, 1:1, Len:7, Rest/binary>>, _Cap) when Len < 126 ->
    Needed = 4 + Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_message_masked(<<_:8, 1:1, 126:7, Rest/binary>>, _Cap) when byte_size(Rest) < 2 ->
    {more, 2 - byte_size(Rest)};
decode_message_masked(<<_:8, 1:1, 126:7, Len:16, Rest/binary>>, _Cap) ->
    Needed = 4 + Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_message_masked(<<_:8, 1:1, 127:7, Rest/binary>>, _Cap) when byte_size(Rest) < 8 ->
    {more, 8 - byte_size(Rest)};
decode_message_masked(<<_:8, 1:1, 127:7, _:1, Len:63, Rest/binary>>, _Cap) ->
    Needed = 4 + Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_message_masked(_, _Cap) ->
    {error, invalid_frame}.

-spec decode_message_unmasked(binary(), frame_cap()) -> decode_result().
decode_message_unmasked(<<_:8, _Mask:1, 126:7, Len:16, _/binary>>, Cap) when Len > Cap ->
    {error, {frame_too_large, Len}};
decode_message_unmasked(<<_:8, _Mask:1, 127:7, _:1, Len:63, _/binary>>, Cap) when Len > Cap ->
    {error, {frame_too_large, Len}};
decode_message_unmasked(
    <<Fin:1, Rsv:3, Opcode:4, 0:1, Len:7, Data:Len/binary, Rest/binary>>, _Cap
) when
    Len < 126
->
    decode_unmasked_complete(Fin, Rsv, Opcode, Data, Rest);
decode_message_unmasked(
    <<Fin:1, Rsv:3, Opcode:4, 0:1, 126:7, Len:16, Data:Len/binary, Rest/binary>>, _Cap
) ->
    decode_unmasked_complete(Fin, Rsv, Opcode, Data, Rest);
decode_message_unmasked(
    <<Fin:1, Rsv:3, Opcode:4, 0:1, 127:7, 0:1, Len:63, Data:Len/binary, Rest/binary>>, _Cap
) ->
    decode_unmasked_complete(Fin, Rsv, Opcode, Data, Rest);
decode_message_unmasked(<<_:8, 1:1, _:7, _/binary>>, _Cap) ->
    {error, masked_server_frame};
decode_message_unmasked(Binary, _Cap) when byte_size(Binary) < 2 ->
    {more, 2};
decode_message_unmasked(<<_:8, 0:1, Len:7, Rest/binary>>, _Cap) when Len < 126 ->
    Needed = Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_message_unmasked(<<_:8, 0:1, 126:7, Rest/binary>>, _Cap) when byte_size(Rest) < 2 ->
    {more, 2 - byte_size(Rest)};
decode_message_unmasked(<<_:8, 0:1, 126:7, Len:16, Rest/binary>>, _Cap) ->
    Needed = Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_message_unmasked(<<_:8, 0:1, 127:7, Rest/binary>>, _Cap) when byte_size(Rest) < 8 ->
    {more, 8 - byte_size(Rest)};
decode_message_unmasked(<<_:8, 0:1, 127:7, _:1, Len:63, Rest/binary>>, _Cap) ->
    Needed = Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_message_unmasked(_, _Cap) ->
    {error, invalid_frame}.

-spec decode_raw_masked(binary(), frame_cap()) -> raw_decode_result().
decode_raw_masked(<<_:8, _Mask:1, 126:7, Len:16, _/binary>>, Cap) when Len > Cap ->
    {error, {frame_too_large, Len}};
decode_raw_masked(<<_:8, _Mask:1, 127:7, _:1, Len:63, _/binary>>, Cap) when Len > Cap ->
    {error, {frame_too_large, Len}};
decode_raw_masked(<<_Fin:1, Rsv:3, _Opcode:4, _/binary>>, _Cap) when Rsv =/= 0 ->
    {error, reserved_bits_set};
decode_raw_masked(
    <<Fin:1, 0:3, Opcode:4, 1:1, Len:7, MaskKey:4/binary, Data:Len/binary, Rest/binary>>, _Cap
) when Len < 126 ->
    {ok, Fin, Opcode, unmask(MaskKey, Data), Rest};
decode_raw_masked(
    <<Fin:1, 0:3, Opcode:4, 1:1, 126:7, Len:16, MaskKey:4/binary, Data:Len/binary, Rest/binary>>,
    _Cap
) ->
    {ok, Fin, Opcode, unmask(MaskKey, Data), Rest};
decode_raw_masked(
    <<Fin:1, 0:3, Opcode:4, 1:1, 127:7, 0:1, Len:63, MaskKey:4/binary, Data:Len/binary,
        Rest/binary>>,
    _Cap
) ->
    {ok, Fin, Opcode, unmask(MaskKey, Data), Rest};
decode_raw_masked(<<_:8, 0:1, _:7, _/binary>>, _Cap) ->
    {error, unmasked_client_frame};
decode_raw_masked(Binary, _Cap) when byte_size(Binary) < 2 ->
    {more, 2};
decode_raw_masked(<<_:8, 1:1, Len:7, Rest/binary>>, _Cap) when Len < 126 ->
    Needed = 4 + Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_raw_masked(<<_:8, 1:1, 126:7, Rest/binary>>, _Cap) when byte_size(Rest) < 2 ->
    {more, 2 - byte_size(Rest)};
decode_raw_masked(<<_:8, 1:1, 126:7, Len:16, Rest/binary>>, _Cap) ->
    Needed = 4 + Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_raw_masked(<<_:8, 1:1, 127:7, Rest/binary>>, _Cap) when byte_size(Rest) < 8 ->
    {more, 8 - byte_size(Rest)};
decode_raw_masked(<<_:8, 1:1, 127:7, _:1, Len:63, Rest/binary>>, _Cap) ->
    Needed = 4 + Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_raw_masked(_, _Cap) ->
    {error, invalid_frame}.

-spec decode_raw_unmasked(binary(), frame_cap()) -> raw_decode_result().
decode_raw_unmasked(<<_:8, _Mask:1, 126:7, Len:16, _/binary>>, Cap) when Len > Cap ->
    {error, {frame_too_large, Len}};
decode_raw_unmasked(<<_:8, _Mask:1, 127:7, _:1, Len:63, _/binary>>, Cap) when Len > Cap ->
    {error, {frame_too_large, Len}};
decode_raw_unmasked(<<_:1, Rsv:3, _:4, _/binary>>, _Cap) when Rsv =/= 0 ->
    {error, reserved_bits_set};
decode_raw_unmasked(<<Fin:1, 0:3, Opcode:4, 0:1, Len:7, Data:Len/binary, Rest/binary>>, _Cap) when
    Len < 126
->
    {ok, Fin, Opcode, Data, Rest};
decode_raw_unmasked(
    <<Fin:1, 0:3, Opcode:4, 0:1, 126:7, Len:16, Data:Len/binary, Rest/binary>>, _Cap
) ->
    {ok, Fin, Opcode, Data, Rest};
decode_raw_unmasked(
    <<Fin:1, 0:3, Opcode:4, 0:1, 127:7, 0:1, Len:63, Data:Len/binary, Rest/binary>>, _Cap
) ->
    {ok, Fin, Opcode, Data, Rest};
decode_raw_unmasked(<<_:8, 1:1, _:7, _/binary>>, _Cap) ->
    {error, masked_server_frame};
decode_raw_unmasked(Binary, _Cap) when byte_size(Binary) < 2 ->
    {more, 2};
decode_raw_unmasked(<<_:8, 0:1, Len:7, Rest/binary>>, _Cap) when Len < 126 ->
    Needed = Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_raw_unmasked(<<_:8, 0:1, 126:7, Rest/binary>>, _Cap) when byte_size(Rest) < 2 ->
    {more, 2 - byte_size(Rest)};
decode_raw_unmasked(<<_:8, 0:1, 126:7, Len:16, Rest/binary>>, _Cap) ->
    Needed = Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_raw_unmasked(<<_:8, 0:1, 127:7, Rest/binary>>, _Cap) when byte_size(Rest) < 8 ->
    {more, 8 - byte_size(Rest)};
decode_raw_unmasked(<<_:8, 0:1, 127:7, _:1, Len:63, Rest/binary>>, _Cap) ->
    Needed = Len - byte_size(Rest),
    case Needed > 0 of
        true -> {more, Needed};
        false -> {error, decode_failed}
    end;
decode_raw_unmasked(_, _Cap) ->
    {error, invalid_frame}.

-spec decode_unmasked_complete(0 | 1, 0..7, 0..15, binary(), binary()) -> decode_result().
decode_unmasked_complete(_Fin, Rsv, _Opcode, _Data, _Rest) when Rsv =/= 0 ->
    {error, reserved_bits_set};
decode_unmasked_complete(Fin, 0, Opcode, Data, Rest) ->
    case validate_control_frame(Fin, Opcode, Data) of
        ok ->
            case opcode_to_message(Fin, Opcode, Data) of
                {ok, Message} -> {ok, Message, Rest};
                {error, Reason} -> {error, Reason}
            end;
        {error, _} = Err ->
            Err
    end.

-spec effective_cap(frame_limits()) -> frame_cap().
effective_cap(Limits) ->
    case maps:get(max_frame_size, Limits, infinity) of
        infinity -> infinity;
        Cap -> max(Cap, ?MAX_CONTROL_PAYLOAD)
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL: VALIDATION
%%%-----------------------------------------------------------------------------
-doc """
Whether the bytes are a proper prefix of a UTF-8 character, so a
continuation can still complete them. The constraints on the second byte
are the ones that make an overlong encoding (`E0 80`), a surrogate half
(`ED A0`) and a scalar above U+10FFFF (`F4 90`) refusals here rather than
one byte later.
""".
-spec is_utf8_prefix(binary()) -> boolean().
is_utf8_prefix(<<B>>) when B >= 16#C2, B =< 16#F4 -> true;
is_utf8_prefix(<<16#E0, B>>) when B >= 16#A0, B =< 16#BF -> true;
is_utf8_prefix(<<16#ED, B>>) when B >= 16#80, B =< 16#9F -> true;
is_utf8_prefix(<<A, B>>) when A >= 16#E1, A =< 16#EF, A =/= 16#ED, B >= 16#80, B =< 16#BF ->
    true;
is_utf8_prefix(<<16#F0, B>>) when B >= 16#90, B =< 16#BF -> true;
is_utf8_prefix(<<16#F4, B>>) when B >= 16#80, B =< 16#8F -> true;
is_utf8_prefix(<<A, B>>) when A >= 16#F1, A =< 16#F3, B >= 16#80, B =< 16#BF -> true;
is_utf8_prefix(<<A, B, C>>) when A >= 16#F0, A =< 16#F4, C >= 16#80, C =< 16#BF ->
    is_utf8_prefix(<<A, B>>);
is_utf8_prefix(_) ->
    false.

-spec is_valid_close_code(close_code()) -> boolean().
is_valid_close_code(Code) when Code >= 1000, Code =< 1003 -> true;
is_valid_close_code(Code) when Code >= 1007, Code =< 1014 -> true;
is_valid_close_code(Code) when Code >= 3000, Code =< 4999 -> true;
is_valid_close_code(_) -> false.

-spec is_valid_utf8(binary()) -> boolean().
is_valid_utf8(<<_/utf8, Rest/binary>>) -> is_valid_utf8(Rest);
is_valid_utf8(<<>>) -> true;
is_valid_utf8(_) -> false.

%%%-----------------------------------------------------------------------------
%% INTERNAL: MASK
%%%-----------------------------------------------------------------------------
-spec unmask(MaskKey :: binary(), Data :: binary()) -> binary().
unmask(<<Key:32>>, Data) when byte_size(Data) >= 64 ->
    LongKey = binary:copy(<<Key:32>>, 16),
    <<LongKeyInt:512>> = LongKey,
    unmask_loop(Key, LongKeyInt, Data, <<>>);
unmask(<<Key:32>>, Data) ->
    unmask_loop(Key, 0, Data, <<>>).

-spec unmask_loop(integer(), integer(), binary(), binary()) -> binary().
unmask_loop(Key, LongKey, Data, Acc) ->
    case Data of
        <<Chunk:512, Rest/binary>> when LongKey =/= 0 ->
            unmask_loop(Key, LongKey, Rest, <<Acc/binary, (Chunk bxor LongKey):512>>);
        <<Chunk:32, Rest/binary>> ->
            unmask_loop(Key, LongKey, Rest, <<Acc/binary, (Chunk bxor Key):32>>);
        <<A:24>> ->
            <<B:24, _:8>> = <<Key:32>>,
            <<Acc/binary, (A bxor B):24>>;
        <<A:16>> ->
            <<B:16, _:16>> = <<Key:32>>,
            <<Acc/binary, (A bxor B):16>>;
        <<A:8>> ->
            <<B:8, _:24>> = <<Key:32>>,
            <<Acc/binary, (A bxor B):8>>;
        <<>> ->
            Acc
    end.
