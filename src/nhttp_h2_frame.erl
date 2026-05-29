-module(nhttp_h2_frame).

-moduledoc """
HTTP/2 binary frame encoding and decoding.

This module implements RFC 9113 Section 4-6 binary framing layer.
It provides zero-copy parsing using binary pattern matching and
efficient encoding using iolists.

## Decoding

```erlang
case nhttp_h2_frame:decode(Data) of
    {ok, Frame, Rest} -> handle_frame(Frame), decode(Rest);
    {more, MinBytes} -> wait_for_data(MinBytes);
    {error, Error} -> handle_error(Error)
end.
```

## Encoding

```erlang
{ok, Frame} = nhttp_h2_frame:headers(StreamId, fin, fin, HeaderBlock),
ok = ssl:send(Socket, Frame).
```
""".

%%%-----------------------------------------------------------------------------
%% INLINE DIRECTIVES (PERFORMANCE OPTIMIZATION)
%%%-----------------------------------------------------------------------------
-compile({inline, [fin_to_end_stream/1]}).
-compile({inline, [fin_to_end_headers/1]}).
-compile({inline, [end_stream_to_fin/1]}).
-compile({inline, [end_headers_to_fin/1]}).

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-export([
    decode/1,
    decode/2,
    decode_all/1,
    decode_settings_payload/1
]).

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-export([
    continuation/3,
    data/3,
    goaway/3,
    headers/4,
    headers/5,
    ping/1,
    ping_ack/1,
    priority/2,
    push_promise/4,
    rst_stream/2,
    settings/1,
    settings_ack/0,
    window_update/1,
    window_update/2
]).

%%%-----------------------------------------------------------------------------
%% UTILITIES
%%%-----------------------------------------------------------------------------
-export([
    headers_with_continuation/4,
    preface/0,
    split_at/2
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    decode_all_result/0,
    decode_error/0,
    decode_result/0,
    t/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type decode_all_result() ::
    {ok, [t()], BytesConsumed :: non_neg_integer()}
    | {error, decode_error()}.

-type decode_error() ::
    {connection_error, nhttp_h2:error_code(), Reason :: binary()}
    | {stream_error, nhttp_lib:stream_id(), nhttp_h2:error_code(), Reason :: binary()}.

-type decode_result() ::
    {ok, t(), BytesConsumed :: pos_integer()}
    | {more, MinBytes :: pos_integer()}
    | {error, decode_error()}.

-type t() ::
    {data, nhttp_lib:stream_id(), nhttp_h2:fin(), Payload :: binary()}
    | {headers, nhttp_lib:stream_id(), nhttp_h2:fin(), nhttp_h2:fin(), HeaderBlock :: binary()}
    | {headers, nhttp_lib:stream_id(), nhttp_h2:fin(), nhttp_h2:fin(), nhttp_h2:priority(),
        HeaderBlock :: binary()}
    | {priority, nhttp_lib:stream_id(), nhttp_h2:priority()}
    | {rst_stream, nhttp_lib:stream_id(), nhttp_h2:error_code()}
    | {settings, nhttp_h2:settings()}
    | settings_ack
    | {push_promise, nhttp_lib:stream_id(), nhttp_h2:fin(),
        PromisedStreamId :: nhttp_lib:stream_id(), HeaderBlock :: binary()}
    | {ping, OpaqueData :: binary()}
    | {ping_ack, OpaqueData :: binary()}
    | {goaway, LastStreamId :: nhttp_lib:stream_id(), nhttp_h2:error_code(), DebugData :: binary()}
    | {window_update, Increment :: pos_integer()}
    | {window_update, nhttp_lib:stream_id(), Increment :: pos_integer()}
    | {continuation, nhttp_lib:stream_id(), nhttp_h2:fin(), HeaderBlock :: binary()}
    | {unknown, Type :: non_neg_integer()}
    | preface.

%%%-----------------------------------------------------------------------------
%% FRAME TYPE IDENTIFIERS (RFC 9113 SECTION 6)
%%%-----------------------------------------------------------------------------
-define(FRAME_DATA, 16#00).
-define(FRAME_HEADERS, 16#01).
-define(FRAME_PRIORITY, 16#02).
-define(FRAME_RST_STREAM, 16#03).
-define(FRAME_SETTINGS, 16#04).
-define(FRAME_PUSH_PROMISE, 16#05).
-define(FRAME_PING, 16#06).
-define(FRAME_GOAWAY, 16#07).
-define(FRAME_WINDOW_UPDATE, 16#08).
-define(FRAME_CONTINUATION, 16#09).

%%%-----------------------------------------------------------------------------
%% FLAG BITS (RFC 9113 SECTION 6)
%%%-----------------------------------------------------------------------------
-define(FLAG_END_STREAM, 16#01).
-define(FLAG_ACK, 16#01).
-define(FLAG_END_HEADERS, 16#04).
-define(FLAG_PADDED, 16#08).
-define(FLAG_PRIORITY, 16#20).

%%%-----------------------------------------------------------------------------
%% SETTINGS IDENTIFIERS (RFC 9113 SECTION 6.5.2)
%%%-----------------------------------------------------------------------------
-define(SETTINGS_HEADER_TABLE_SIZE, 16#01).
-define(SETTINGS_ENABLE_PUSH, 16#02).
-define(SETTINGS_MAX_CONCURRENT_STREAMS, 16#03).
-define(SETTINGS_INITIAL_WINDOW_SIZE, 16#04).
-define(SETTINGS_MAX_FRAME_SIZE, 16#05).
-define(SETTINGS_MAX_HEADER_LIST_SIZE, 16#06).
-define(SETTINGS_ENABLE_CONNECT_PROTOCOL, 16#08).

%%%-----------------------------------------------------------------------------
%% DEFAULT VALUES (RFC 9113 SECTION 6.5.2)
%%%-----------------------------------------------------------------------------
-define(DEFAULT_MAX_FRAME_SIZE, 16384).

%%%-----------------------------------------------------------------------------
%% LIMITS (RFC 9113)
%%%-----------------------------------------------------------------------------
-define(MIN_MAX_FRAME_SIZE, 16#4000).
-define(MAX_FRAME_SIZE_LIMIT, 16#ffffff).
-define(MAX_WINDOW_SIZE, 16#7fffffff).

%%%-----------------------------------------------------------------------------
%% FRAME STRUCTURE
%%%-----------------------------------------------------------------------------
-define(FRAME_HEADER_SIZE, 9).

%%%-----------------------------------------------------------------------------
%% CONNECTION PREFACE (RFC 9113 SECTION 3.4)
%%%-----------------------------------------------------------------------------
-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(PREFACE_LEN, 24).

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-doc "Decode a single frame from binary data. Returns {ok, Frame, BytesConsumed} where BytesConsumed is the number of bytes consumed from the input. Use split_at/2 to get the remaining buffer. Uses default max frame size (16384 bytes).".
-spec decode(Data :: binary()) -> decode_result().
decode(<<Data/binary>>) ->
    decode(Data, ?DEFAULT_MAX_FRAME_SIZE).

-doc "Decode a single frame with custom max frame size. The max frame size should come from peer's SETTINGS_MAX_FRAME_SIZE.".
-spec decode(Data :: binary(), MaxFrameSize :: pos_integer()) -> decode_result().
decode(<<"PRI ", _/binary>> = Data, _MaxFrameSize) when byte_size(Data) >= ?PREFACE_LEN ->
    decode_frame(Data, 0);
decode(<<"PRI ", _/binary>> = Data, _MaxFrameSize) ->
    {more, ?PREFACE_LEN - byte_size(Data)};
decode(<<Data/binary>>, _MaxFrameSize) when byte_size(Data) < ?FRAME_HEADER_SIZE ->
    {more, ?FRAME_HEADER_SIZE - byte_size(Data)};
decode(<<Len:24, _:48, _/binary>> = Data, _MaxFrameSize) when
    byte_size(Data) < Len + ?FRAME_HEADER_SIZE
->
    {more, Len + ?FRAME_HEADER_SIZE - byte_size(Data)};
decode(<<Len:24, _:48, _/binary>>, MaxFrameSize) when Len > MaxFrameSize ->
    {error,
        {connection_error, frame_size_error,
            <<"Frame size exceeds SETTINGS_MAX_FRAME_SIZE (RFC 9113 Section 4.2)">>}};
decode(<<Data/binary>>, _MaxFrameSize) ->
    decode_frame(Data, 0).

-doc "Decode all complete frames from binary data. Returns {ok, Frames, BytesConsumed} with list of decoded frames.".
-spec decode_all(binary()) -> decode_all_result().
decode_all(<<Data/binary>>) ->
    decode_all_loop(Data, ?DEFAULT_MAX_FRAME_SIZE, 0, []).

-doc "Decode settings payload (for use in connection layer).".
-spec decode_settings_payload(binary()) -> {ok, nhttp_h2:settings()} | {error, decode_error()}.
decode_settings_payload(Payload) ->
    decode_settings_payload(Payload, #{}).

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc "Encode a CONTINUATION frame.".
-spec continuation(StreamId, EndHeaders, HeaderBlock) -> {ok, iodata()} when
    StreamId :: nhttp_lib:stream_id(),
    EndHeaders :: nhttp_h2:fin(),
    HeaderBlock :: iodata().
continuation(StreamId, EndHeaders, HeaderBlock) ->
    Len = iolist_size(HeaderBlock),
    Flags = fin_to_end_headers(EndHeaders),
    {ok, [<<Len:24, ?FRAME_CONTINUATION:8, Flags:8, 0:1, StreamId:31>>, HeaderBlock]}.

-doc "Encode a DATA frame.".
-spec data(StreamId, EndStream, Payload) -> {ok, iodata()} when
    StreamId :: nhttp_lib:stream_id(),
    EndStream :: nhttp_h2:fin(),
    Payload :: iodata().
data(StreamId, EndStream, Payload) ->
    Len = iolist_size(Payload),
    Flags = fin_to_end_stream(EndStream),
    {ok, [<<Len:24, ?FRAME_DATA:8, Flags:8, 0:1, StreamId:31>>, Payload]}.

-doc "Encode a GOAWAY frame.".
-spec goaway(LastStreamId, ErrorCode, DebugData) -> {ok, iodata()} when
    LastStreamId :: nhttp_lib:stream_id(),
    ErrorCode :: nhttp_h2:error_code(),
    DebugData :: iodata().
goaway(LastStreamId, ErrorCode, DebugData) ->
    Len = iolist_size(DebugData) + 8,
    Code = error_code_to_int(ErrorCode),
    {ok, [<<Len:24, ?FRAME_GOAWAY:8, 0:8, 0:32, 0:1, LastStreamId:31, Code:32>>, DebugData]}.

-doc "Encode a HEADERS frame without priority.".
-spec headers(StreamId, EndStream, EndHeaders, HeaderBlock) -> {ok, iodata()} when
    StreamId :: nhttp_lib:stream_id(),
    EndStream :: nhttp_h2:fin(),
    EndHeaders :: nhttp_h2:fin(),
    HeaderBlock :: iodata().
headers(StreamId, EndStream, EndHeaders, HeaderBlock) ->
    Len = iolist_size(HeaderBlock),
    Flags = fin_to_end_stream(EndStream) bor fin_to_end_headers(EndHeaders),
    {ok, [<<Len:24, ?FRAME_HEADERS:8, Flags:8, 0:1, StreamId:31>>, HeaderBlock]}.

-doc "Encode a HEADERS frame with priority.".
-spec headers(StreamId, EndStream, EndHeaders, Priority, HeaderBlock) -> {ok, iodata()} when
    StreamId :: nhttp_lib:stream_id(),
    EndStream :: nhttp_h2:fin(),
    EndHeaders :: nhttp_h2:fin(),
    Priority :: nhttp_h2:priority(),
    HeaderBlock :: iodata().
headers(StreamId, EndStream, EndHeaders, Priority, HeaderBlock) ->
    #{exclusive := Exclusive, stream_dependency := DepStreamId, weight := Weight} = Priority,
    Len = iolist_size(HeaderBlock) + 5,
    Flags = fin_to_end_stream(EndStream) bor fin_to_end_headers(EndHeaders) bor ?FLAG_PRIORITY,
    E = bool_to_bit(Exclusive),
    {ok, [
        <<Len:24, ?FRAME_HEADERS:8, Flags:8, 0:1, StreamId:31, E:1, DepStreamId:31,
            (Weight - 1):8>>,
        HeaderBlock
    ]}.

-doc "Encode a PING frame.".
-spec ping(OpaqueData :: binary()) -> {ok, binary()}.
ping(OpaqueData) when byte_size(OpaqueData) =:= 8 ->
    {ok, <<8:24, ?FRAME_PING:8, 0:8, 0:32, OpaqueData:8/binary>>}.

-doc "Encode a PING acknowledgment.".
-spec ping_ack(OpaqueData :: binary()) -> {ok, binary()}.
ping_ack(OpaqueData) when byte_size(OpaqueData) =:= 8 ->
    {ok, <<8:24, ?FRAME_PING:8, ?FLAG_ACK:8, 0:32, OpaqueData:8/binary>>}.

-doc "Encode a PRIORITY frame.".
-spec priority(StreamId, Priority) -> {ok, iodata()} when
    StreamId :: nhttp_lib:stream_id(),
    Priority :: nhttp_h2:priority().
priority(StreamId, Priority) ->
    #{exclusive := Exclusive, stream_dependency := DepStreamId, weight := Weight} = Priority,
    E = bool_to_bit(Exclusive),
    {ok, <<5:24, ?FRAME_PRIORITY:8, 0:8, 0:1, StreamId:31, E:1, DepStreamId:31, (Weight - 1):8>>}.

-doc "Encode a PUSH_PROMISE frame.".
-spec push_promise(StreamId, PromisedStreamId, EndHeaders, HeaderBlock) -> {ok, iodata()} when
    StreamId :: nhttp_lib:stream_id(),
    PromisedStreamId :: nhttp_lib:stream_id(),
    EndHeaders :: nhttp_h2:fin(),
    HeaderBlock :: iodata().
push_promise(StreamId, PromisedStreamId, EndHeaders, HeaderBlock) ->
    Len = iolist_size(HeaderBlock) + 4,
    Flags = fin_to_end_headers(EndHeaders),
    {ok, [
        <<Len:24, ?FRAME_PUSH_PROMISE:8, Flags:8, 0:1, StreamId:31, 0:1, PromisedStreamId:31>>,
        HeaderBlock
    ]}.

-doc "Encode a RST_STREAM frame.".
-spec rst_stream(StreamId, ErrorCode) -> {ok, binary()} when
    StreamId :: nhttp_lib:stream_id(),
    ErrorCode :: nhttp_h2:error_code().
rst_stream(StreamId, ErrorCode) ->
    Code = error_code_to_int(ErrorCode),
    {ok, <<4:24, ?FRAME_RST_STREAM:8, 0:8, 0:1, StreamId:31, Code:32>>}.

-doc "Encode a SETTINGS frame.".
-spec settings(Settings :: nhttp_h2:settings()) -> {ok, iodata()}.
settings(Settings) ->
    Payload = maps:fold(fun encode_setting/3, [], Settings),
    Len = iolist_size(Payload),
    {ok, [<<Len:24, ?FRAME_SETTINGS:8, 0:8, 0:32>>, Payload]}.

-doc "Encode a SETTINGS acknowledgment.".
-spec settings_ack() -> {ok, binary()}.
settings_ack() ->
    {ok, <<0:24, ?FRAME_SETTINGS:8, ?FLAG_ACK:8, 0:32>>}.

-doc "Encode a connection-level WINDOW_UPDATE frame.".
-spec window_update(Increment :: pos_integer()) -> {ok, binary()}.
window_update(Increment) when Increment > 0, Increment =< ?MAX_WINDOW_SIZE ->
    {ok, <<4:24, ?FRAME_WINDOW_UPDATE:8, 0:8, 0:32, 0:1, Increment:31>>}.

-doc "Encode a stream-level WINDOW_UPDATE frame.".
-spec window_update(StreamId, Increment) -> {ok, binary()} when
    StreamId :: nhttp_lib:stream_id(),
    Increment :: pos_integer().
window_update(StreamId, Increment) when Increment > 0, Increment =< ?MAX_WINDOW_SIZE ->
    {ok, <<4:24, ?FRAME_WINDOW_UPDATE:8, 0:8, 0:1, StreamId:31, 0:1, Increment:31>>}.

%%%-----------------------------------------------------------------------------
%% UTILITIES
%%%-----------------------------------------------------------------------------
-doc "Split header block into HEADERS + CONTINUATION frames if needed.".
-spec headers_with_continuation(StreamId, EndStream, HeaderBlock, MaxFrameSize) ->
    {ok, iodata()}
when
    StreamId :: nhttp_lib:stream_id(),
    EndStream :: nhttp_h2:fin(),
    HeaderBlock :: iodata(),
    MaxFrameSize :: pos_integer().
headers_with_continuation(StreamId, EndStream, HeaderBlock, MaxFrameSize) ->
    Bin = iolist_to_binary(HeaderBlock),
    case Bin of
        <<First:MaxFrameSize/binary, Rest/binary>> when byte_size(Rest) > 0 ->
            {ok, HeadersFrame} = headers(StreamId, EndStream, nofin, First),
            {ok, [HeadersFrame | continuation_frames(StreamId, Rest, MaxFrameSize)]};
        _ ->
            headers(StreamId, EndStream, fin, Bin)
    end.

-doc "HTTP/2 connection preface magic string.".
-spec preface() -> {ok, binary()}.
preface() ->
    {ok, ?PREFACE}.

-doc "Split buffer at position, returning the remainder. This is the intentional single allocation point for callers.".
-spec split_at(binary(), non_neg_integer()) -> binary().
split_at(<<Bin/binary>>, Pos) ->
    <<_:Pos/binary, Rest/binary>> = Bin,
    Rest.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec bit_to_bool(0 | 1) -> boolean().
bit_to_bool(1) -> true;
bit_to_bool(0) -> false.

-spec bool_to_bit(boolean()) -> 0 | 1.
bool_to_bit(true) -> 1;
bool_to_bit(false) -> 0.

-spec continuation_frames(nhttp_lib:stream_id(), binary(), pos_integer()) -> iodata().
continuation_frames(StreamId, <<Data/binary>>, MaxFrameSize) ->
    continuation_frames_loop(StreamId, Data, MaxFrameSize, byte_size(Data), []).

-spec continuation_frames_loop(
    nhttp_lib:stream_id(), binary(), pos_integer(), non_neg_integer(), iodata()
) -> iodata().
continuation_frames_loop(StreamId, <<Data/binary>>, _MaxFrameSize, Remaining, Acc) when
    Remaining =< 0
->
    lists:reverse([encode_continuation_bin(StreamId, fin, Data) | Acc]);
continuation_frames_loop(StreamId, <<Data/binary>>, MaxFrameSize, Remaining, Acc) when
    Remaining =< MaxFrameSize
->
    lists:reverse([encode_continuation_bin(StreamId, fin, Data) | Acc]);
continuation_frames_loop(StreamId, <<Data/binary>>, MaxFrameSize, Remaining, Acc) ->
    <<Chunk:MaxFrameSize/binary, Rest/binary>> = Data,
    Frame = encode_continuation_bin(StreamId, nofin, Chunk),
    continuation_frames_loop(StreamId, Rest, MaxFrameSize, Remaining - MaxFrameSize, [Frame | Acc]).

-spec decode_all_loop(binary(), pos_integer(), non_neg_integer(), [t()]) ->
    decode_all_result().
decode_all_loop(<<Data/binary>>, MaxFrameSize, TotalConsumed, Acc) ->
    case decode(Data, MaxFrameSize) of
        {ok, Frame, Consumed} ->
            <<_:Consumed/binary, Rest/binary>> = Data,
            decode_all_loop(Rest, MaxFrameSize, TotalConsumed + Consumed, [Frame | Acc]);
        {more, _} ->
            {ok, lists:reverse(Acc), TotalConsumed};
        {error, _} = Error ->
            Error
    end.

-spec decode_frame(binary(), non_neg_integer()) -> decode_result().
decode_frame(<<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", _/binary>>, Skip) ->
    {ok, preface, Skip + ?PREFACE_LEN};
decode_frame(<<"PRI ", _/binary>>, _Skip) ->
    {error,
        {connection_error, protocol_error, <<"Invalid connection preface (RFC 9113 Section 3.4)">>}};
decode_frame(<<_Len:24, ?FRAME_DATA:8, _:8, _:1, 0:31, _/binary>>, _Skip) ->
    {error,
        {connection_error, protocol_error,
            <<"DATA frame MUST be associated with a stream (RFC 9113 Section 6.1)">>}};
decode_frame(<<0:24, ?FRAME_DATA:8, Flags:8, _:32, _/binary>>, _Skip) when
    Flags band ?FLAG_PADDED =/= 0
->
    {error,
        {connection_error, frame_size_error,
            <<"DATA frame with padding MUST have length > 0 (RFC 9113 Section 6.1)">>}};
decode_frame(
    <<Len:24, ?FRAME_DATA:8, Flags:8, _:1, StreamId:31, PadLen:8, Rest1/binary>>, Skip
) when
    Flags band ?FLAG_PADDED =/= 0
->
    DataLen = Len - PadLen - 1,
    maybe
        true ?= PadLen < Len,
        <<Data:DataLen/binary, Padding:PadLen/binary, _/binary>> = Rest1,
        true ?= is_zero_padding(Padding),
        EndStream = end_stream_to_fin(Flags),
        {ok, {data, StreamId, EndStream, Data}, Skip + ?FRAME_HEADER_SIZE + Len}
    else
        false ->
            {error,
                {connection_error, protocol_error,
                    <<"Padding length exceeds frame payload (RFC 9113 Section 6.1)">>}}
    end;
decode_frame(<<Len:24, ?FRAME_DATA:8, Flags:8, _:1, StreamId:31, Data:Len/binary, _/binary>>, Skip) ->
    EndStream = end_stream_to_fin(Flags),
    {ok, {data, StreamId, EndStream, Data}, Skip + ?FRAME_HEADER_SIZE + Len};
decode_frame(<<_:24, ?FRAME_HEADERS:8, _:8, _:1, 0:31, _/binary>>, _Skip) ->
    {error,
        {connection_error, protocol_error,
            <<"HEADERS frame MUST be associated with a stream (RFC 9113 Section 6.2)">>}};
decode_frame(<<0:24, ?FRAME_HEADERS:8, Flags:8, _:32, _/binary>>, _Skip) when
    Flags band ?FLAG_PADDED =/= 0
->
    {error,
        {connection_error, frame_size_error,
            <<"HEADERS frame with padding MUST have length > 0 (RFC 9113 Section 6.2)">>}};
decode_frame(<<Len:24, ?FRAME_HEADERS:8, Flags:8, _:32, _/binary>>, _Skip) when
    Flags band ?FLAG_PRIORITY =/= 0, Len < 5
->
    {error,
        {connection_error, frame_size_error,
            <<"HEADERS frame with priority MUST have length >= 5 (RFC 9113 Section 6.2)">>}};
decode_frame(<<Len:24, ?FRAME_HEADERS:8, Flags:8, _:32, _/binary>>, _Skip) when
    Flags band ?FLAG_PADDED =/= 0, Flags band ?FLAG_PRIORITY =/= 0, Len < 6
->
    {error,
        {connection_error, frame_size_error,
            <<"HEADERS frame with padding and priority MUST have length >= 6 (RFC 9113 Section 6.2)">>}};
decode_frame(
    <<Len:24, ?FRAME_HEADERS:8, Flags:8, _:1, StreamId:31, HeaderBlock:Len/binary, _/binary>>, Skip
) when
    Flags band ?FLAG_PADDED =:= 0, Flags band ?FLAG_PRIORITY =:= 0
->
    EndStream = end_stream_to_fin(Flags),
    EndHeaders = end_headers_to_fin(Flags),
    {ok, {headers, StreamId, EndStream, EndHeaders, HeaderBlock}, Skip + ?FRAME_HEADER_SIZE + Len};
decode_frame(
    <<Len0:24, ?FRAME_HEADERS:8, Flags:8, _:1, StreamId:31, PadLen:8, Rest0/binary>>, Skip
) when
    Flags band ?FLAG_PADDED =/= 0, Flags band ?FLAG_PRIORITY =:= 0
->
    DataLen = Len0 - PadLen - 1,
    maybe
        true ?= PadLen < Len0,
        <<HeaderBlock:DataLen/binary, Padding:PadLen/binary, _/binary>> = Rest0,
        true ?= is_zero_padding(Padding),
        EndStream = end_stream_to_fin(Flags),
        EndHeaders = end_headers_to_fin(Flags),
        {ok, {headers, StreamId, EndStream, EndHeaders, HeaderBlock},
            Skip + ?FRAME_HEADER_SIZE + Len0}
    else
        false ->
            {error,
                {connection_error, protocol_error,
                    <<"Padding length exceeds frame payload (RFC 9113 Section 6.2)">>}}
    end;
decode_frame(
    <<_Len0:24, ?FRAME_HEADERS:8, Flags:8, _:1, StreamId:31, _E:1, StreamId:31, _:8, _/binary>>,
    _Skip
) when
    Flags band ?FLAG_PADDED =:= 0, Flags band ?FLAG_PRIORITY =/= 0
->
    {error,
        {connection_error, protocol_error,
            <<"HEADERS frame cannot depend on itself (RFC 9113 Section 5.3.1)">>}};
decode_frame(
    <<Len0:24, ?FRAME_HEADERS:8, Flags:8, _:1, StreamId:31, E:1, DepStreamId:31, Weight:8,
        Rest0/binary>>,
    Skip
) when
    Flags band ?FLAG_PADDED =:= 0, Flags band ?FLAG_PRIORITY =/= 0
->
    DataLen = Len0 - 5,
    <<HeaderBlock:DataLen/binary, _/binary>> = Rest0,
    EndStream = end_stream_to_fin(Flags),
    EndHeaders = end_headers_to_fin(Flags),
    Priority = #{
        exclusive => bit_to_bool(E), stream_dependency => DepStreamId, weight => Weight + 1
    },
    {ok, {headers, StreamId, EndStream, EndHeaders, Priority, HeaderBlock},
        Skip + ?FRAME_HEADER_SIZE + Len0};
decode_frame(
    <<_Len0:24, ?FRAME_HEADERS:8, Flags:8, _:1, StreamId:31, _:8, _:1, StreamId:31, _/binary>>,
    _Skip
) when
    Flags band ?FLAG_PADDED =/= 0, Flags band ?FLAG_PRIORITY =/= 0
->
    {error,
        {connection_error, protocol_error,
            <<"HEADERS frame cannot depend on itself (RFC 9113 Section 5.3.1)">>}};
decode_frame(
    <<Len0:24, ?FRAME_HEADERS:8, Flags:8, _:1, StreamId:31, PadLen:8, E:1, DepStreamId:31, Weight:8,
        Rest0/binary>>,
    Skip
) when
    Flags band ?FLAG_PADDED =/= 0, Flags band ?FLAG_PRIORITY =/= 0
->
    DataLen = Len0 - PadLen - 6,
    maybe
        true ?= PadLen < Len0 - 5,
        <<HeaderBlock:DataLen/binary, Padding:PadLen/binary, _/binary>> = Rest0,
        true ?= is_zero_padding(Padding),
        EndStream = end_stream_to_fin(Flags),
        EndHeaders = end_headers_to_fin(Flags),
        Priority = #{
            exclusive => bit_to_bool(E), stream_dependency => DepStreamId, weight => Weight + 1
        },
        {ok, {headers, StreamId, EndStream, EndHeaders, Priority, HeaderBlock},
            Skip + ?FRAME_HEADER_SIZE + Len0}
    else
        false ->
            {error,
                {connection_error, protocol_error,
                    <<"Padding length exceeds frame payload (RFC 9113 Section 6.2)">>}}
    end;
decode_frame(<<5:24, ?FRAME_PRIORITY:8, _:8, _:1, 0:31, _/binary>>, _Skip) ->
    {error,
        {connection_error, protocol_error,
            <<"PRIORITY frame MUST be associated with a stream (RFC 9113 Section 6.3)">>}};
decode_frame(
    <<5:24, ?FRAME_PRIORITY:8, _:8, _:1, StreamId:31, _:1, StreamId:31, _:8, _/binary>>, _Skip
) ->
    {error,
        {stream_error, StreamId, protocol_error,
            <<"PRIORITY frame cannot depend on itself (RFC 9113 Section 5.3.1)">>}};
decode_frame(
    <<5:24, ?FRAME_PRIORITY:8, _:8, _:1, StreamId:31, E:1, DepStreamId:31, Weight:8, _/binary>>,
    Skip
) ->
    Priority = #{
        exclusive => bit_to_bool(E), stream_dependency => DepStreamId, weight => Weight + 1
    },
    {ok, {priority, StreamId, Priority}, Skip + ?FRAME_HEADER_SIZE + 5};
decode_frame(
    <<Len:24, ?FRAME_PRIORITY:8, _:8, _:1, StreamId:31, _:Len/binary, _/binary>>, _Skip
) when
    Len =/= 5
->
    {error,
        {stream_error, StreamId, frame_size_error,
            <<"PRIORITY frame MUST be 5 bytes (RFC 9113 Section 6.3)">>}};
decode_frame(<<4:24, ?FRAME_RST_STREAM:8, _:8, _:1, 0:31, _/binary>>, _Skip) ->
    {error,
        {connection_error, protocol_error,
            <<"RST_STREAM frame MUST be associated with a stream (RFC 9113 Section 6.4)">>}};
decode_frame(<<4:24, ?FRAME_RST_STREAM:8, _:8, _:1, StreamId:31, ErrorCode:32, _/binary>>, Skip) ->
    {ok, {rst_stream, StreamId, int_to_error_code(ErrorCode)}, Skip + ?FRAME_HEADER_SIZE + 4};
decode_frame(<<Len:24, ?FRAME_RST_STREAM:8, _:8, _:32, _/binary>>, _Skip) when Len =/= 4 ->
    {error,
        {connection_error, frame_size_error,
            <<"RST_STREAM frame MUST be 4 bytes (RFC 9113 Section 6.4)">>}};
decode_frame(<<_:24, ?FRAME_SETTINGS:8, _:8, _:1, StreamId:31, _/binary>>, _Skip) when
    StreamId =/= 0
->
    {error,
        {connection_error, protocol_error,
            <<"SETTINGS frame MUST NOT be associated with a stream (RFC 9113 Section 6.5)">>}};
decode_frame(<<0:24, ?FRAME_SETTINGS:8, Flags:8, _:1, 0:31, _/binary>>, Skip) when
    Flags band ?FLAG_ACK =/= 0
->
    {ok, settings_ack, Skip + ?FRAME_HEADER_SIZE};
decode_frame(<<Len:24, ?FRAME_SETTINGS:8, Flags:8, _:1, 0:31, _/binary>>, _Skip) when
    Flags band ?FLAG_ACK =/= 0, Len =/= 0
->
    {error,
        {connection_error, frame_size_error,
            <<"SETTINGS ACK frame MUST have length 0 (RFC 9113 Section 6.5)">>}};
decode_frame(<<Len:24, ?FRAME_SETTINGS:8, _:8, _:1, 0:31, _/binary>>, _Skip) when Len rem 6 =/= 0 ->
    {error,
        {connection_error, frame_size_error,
            <<"SETTINGS frame length MUST be multiple of 6 (RFC 9113 Section 6.5)">>}};
decode_frame(<<Len:24, ?FRAME_SETTINGS:8, _:8, _:1, 0:31, Payload:Len/binary, _/binary>>, Skip) ->
    case decode_settings_payload(Payload, #{}) of
        {ok, Settings} -> {ok, {settings, Settings}, Skip + ?FRAME_HEADER_SIZE + Len};
        {error, _} = Error -> Error
    end;
decode_frame(<<_:24, ?FRAME_PUSH_PROMISE:8, _:8, _:1, 0:31, _/binary>>, _Skip) ->
    {error,
        {connection_error, protocol_error,
            <<"PUSH_PROMISE frame MUST be associated with a stream (RFC 9113 Section 6.6)">>}};
decode_frame(<<Len:24, ?FRAME_PUSH_PROMISE:8, _:8, _:32, _/binary>>, _Skip) when Len < 4 ->
    {error,
        {connection_error, frame_size_error,
            <<"PUSH_PROMISE frame MUST have length >= 4 (RFC 9113 Section 6.6)">>}};
decode_frame(<<Len:24, ?FRAME_PUSH_PROMISE:8, Flags:8, _:32, _/binary>>, _Skip) when
    Flags band ?FLAG_PADDED =/= 0, Len < 5
->
    {error,
        {connection_error, frame_size_error,
            <<"PUSH_PROMISE frame with padding MUST have length >= 5 (RFC 9113 Section 6.6)">>}};
decode_frame(
    <<Len0:24, ?FRAME_PUSH_PROMISE:8, Flags:8, _:1, StreamId:31, _:1, PromisedStreamId:31,
        Rest0/binary>>,
    Skip
) when
    Flags band ?FLAG_PADDED =:= 0
->
    DataLen = Len0 - 4,
    <<HeaderBlock:DataLen/binary, _/binary>> = Rest0,
    EndHeaders = end_headers_to_fin(Flags),
    {ok, {push_promise, StreamId, EndHeaders, PromisedStreamId, HeaderBlock},
        Skip + ?FRAME_HEADER_SIZE + Len0};
decode_frame(
    <<Len0:24, ?FRAME_PUSH_PROMISE:8, Flags:8, _:1, StreamId:31, PadLen:8, _:1, PromisedStreamId:31,
        Rest0/binary>>,
    Skip
) when
    Flags band ?FLAG_PADDED =/= 0
->
    DataLen = Len0 - PadLen - 5,
    maybe
        true ?= PadLen < Len0 - 4,
        <<HeaderBlock:DataLen/binary, Padding:PadLen/binary, _/binary>> = Rest0,
        true ?= is_zero_padding(Padding),
        EndHeaders = end_headers_to_fin(Flags),
        {ok, {push_promise, StreamId, EndHeaders, PromisedStreamId, HeaderBlock},
            Skip + ?FRAME_HEADER_SIZE + Len0}
    else
        false ->
            {error,
                {connection_error, protocol_error,
                    <<"Padding length exceeds frame payload (RFC 9113 Section 6.6)">>}}
    end;
decode_frame(<<8:24, ?FRAME_PING:8, _:8, _:1, StreamId:31, _/binary>>, _Skip) when StreamId =/= 0 ->
    {error,
        {connection_error, protocol_error,
            <<"PING frame MUST NOT be associated with a stream (RFC 9113 Section 6.7)">>}};
decode_frame(<<Len:24, ?FRAME_PING:8, _:8, _:32, _/binary>>, _Skip) when Len =/= 8 ->
    {error,
        {connection_error, frame_size_error,
            <<"PING frame MUST be 8 bytes (RFC 9113 Section 6.7)">>}};
decode_frame(<<8:24, ?FRAME_PING:8, Flags:8, _:1, 0:31, OpaqueData:8/binary, _/binary>>, Skip) when
    Flags band ?FLAG_ACK =/= 0
->
    {ok, {ping_ack, OpaqueData}, Skip + ?FRAME_HEADER_SIZE + 8};
decode_frame(<<8:24, ?FRAME_PING:8, _:8, _:1, 0:31, OpaqueData:8/binary, _/binary>>, Skip) ->
    {ok, {ping, OpaqueData}, Skip + ?FRAME_HEADER_SIZE + 8};
decode_frame(<<_:24, ?FRAME_GOAWAY:8, _:8, _:1, StreamId:31, _/binary>>, _Skip) when
    StreamId =/= 0
->
    {error,
        {connection_error, protocol_error,
            <<"GOAWAY frame MUST NOT be associated with a stream (RFC 9113 Section 6.8)">>}};
decode_frame(<<Len:24, ?FRAME_GOAWAY:8, _:8, _:32, _/binary>>, _Skip) when Len < 8 ->
    {error,
        {connection_error, frame_size_error,
            <<"GOAWAY frame MUST have length >= 8 (RFC 9113 Section 6.8)">>}};
decode_frame(
    <<Len0:24, ?FRAME_GOAWAY:8, _:8, _:1, 0:31, _:1, LastStreamId:31, ErrorCode:32, Rest0/binary>>,
    Skip
) ->
    DebugLen = Len0 - 8,
    <<DebugData:DebugLen/binary, _/binary>> = Rest0,
    {ok, {goaway, LastStreamId, int_to_error_code(ErrorCode), DebugData},
        Skip + ?FRAME_HEADER_SIZE + Len0};
decode_frame(<<Len:24, ?FRAME_WINDOW_UPDATE:8, _:8, _:32, _/binary>>, _Skip) when Len =/= 4 ->
    {error,
        {connection_error, frame_size_error,
            <<"WINDOW_UPDATE frame MUST be 4 bytes (RFC 9113 Section 6.9)">>}};
decode_frame(<<4:24, ?FRAME_WINDOW_UPDATE:8, _:8, _:1, 0:31, _:1, 0:31, _/binary>>, _Skip) ->
    {error,
        {connection_error, protocol_error,
            <<"WINDOW_UPDATE increment MUST NOT be 0 (RFC 9113 Section 6.9)">>}};
decode_frame(<<4:24, ?FRAME_WINDOW_UPDATE:8, _:8, _:1, 0:31, _:1, Increment:31, _/binary>>, Skip) ->
    {ok, {window_update, Increment}, Skip + ?FRAME_HEADER_SIZE + 4};
decode_frame(<<4:24, ?FRAME_WINDOW_UPDATE:8, _:8, _:1, StreamId:31, _:1, 0:31, _/binary>>, _Skip) ->
    {error,
        {stream_error, StreamId, protocol_error,
            <<"WINDOW_UPDATE increment MUST NOT be 0 (RFC 9113 Section 6.9)">>}};
decode_frame(
    <<4:24, ?FRAME_WINDOW_UPDATE:8, _:8, _:1, StreamId:31, _:1, Increment:31, _/binary>>, Skip
) ->
    {ok, {window_update, StreamId, Increment}, Skip + ?FRAME_HEADER_SIZE + 4};
decode_frame(<<_:24, ?FRAME_CONTINUATION:8, _:8, _:1, 0:31, _/binary>>, _Skip) ->
    {error,
        {connection_error, protocol_error,
            <<"CONTINUATION frame MUST be associated with a stream (RFC 9113 Section 6.10)">>}};
decode_frame(
    <<Len:24, ?FRAME_CONTINUATION:8, Flags:8, _:1, StreamId:31, HeaderBlock:Len/binary, _/binary>>,
    Skip
) ->
    EndHeaders = end_headers_to_fin(Flags),
    {ok, {continuation, StreamId, EndHeaders, HeaderBlock}, Skip + ?FRAME_HEADER_SIZE + Len};
decode_frame(<<Len:24, Type:8, _:8, _:32, _:Len/binary, _/binary>>, Skip) when
    Type > ?FRAME_CONTINUATION
->
    {ok, {unknown, Type}, Skip + ?FRAME_HEADER_SIZE + Len};
decode_frame(_, _Skip) ->
    {more, ?FRAME_HEADER_SIZE}.

-spec decode_settings_payload(binary(), nhttp_h2:settings()) ->
    {ok, nhttp_h2:settings()} | {error, decode_error()}.
decode_settings_payload(<<>>, Settings) ->
    {ok, Settings};
decode_settings_payload(<<?SETTINGS_HEADER_TABLE_SIZE:16, Value:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{header_table_size => Value});
decode_settings_payload(<<?SETTINGS_ENABLE_PUSH:16, 0:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{enable_push => false});
decode_settings_payload(<<?SETTINGS_ENABLE_PUSH:16, 1:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{enable_push => true});
decode_settings_payload(<<?SETTINGS_ENABLE_PUSH:16, _:32, _/binary>>, _Settings) ->
    {error,
        {connection_error, protocol_error,
            <<"SETTINGS_ENABLE_PUSH MUST be 0 or 1 (RFC 9113 Section 6.5.2)">>}};
decode_settings_payload(<<?SETTINGS_MAX_CONCURRENT_STREAMS:16, Value:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{max_concurrent_streams => Value});
decode_settings_payload(<<?SETTINGS_INITIAL_WINDOW_SIZE:16, Value:32, _/binary>>, _Settings) when
    Value > ?MAX_WINDOW_SIZE
->
    {error,
        {connection_error, flow_control_error,
            <<"SETTINGS_INITIAL_WINDOW_SIZE exceeds maximum (RFC 9113 Section 6.5.2)">>}};
decode_settings_payload(<<?SETTINGS_INITIAL_WINDOW_SIZE:16, Value:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{initial_window_size => Value});
decode_settings_payload(<<?SETTINGS_MAX_FRAME_SIZE:16, Value:32, _/binary>>, _Settings) when
    Value < ?MIN_MAX_FRAME_SIZE
->
    {error,
        {connection_error, protocol_error,
            <<"SETTINGS_MAX_FRAME_SIZE below minimum (RFC 9113 Section 6.5.2)">>}};
decode_settings_payload(<<?SETTINGS_MAX_FRAME_SIZE:16, Value:32, _/binary>>, _Settings) when
    Value > ?MAX_FRAME_SIZE_LIMIT
->
    {error,
        {connection_error, protocol_error,
            <<"SETTINGS_MAX_FRAME_SIZE exceeds maximum (RFC 9113 Section 6.5.2)">>}};
decode_settings_payload(<<?SETTINGS_MAX_FRAME_SIZE:16, Value:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{max_frame_size => Value});
decode_settings_payload(<<?SETTINGS_MAX_HEADER_LIST_SIZE:16, Value:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{max_header_list_size => Value});
decode_settings_payload(<<?SETTINGS_ENABLE_CONNECT_PROTOCOL:16, 0:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{enable_connect_protocol => false});
decode_settings_payload(<<?SETTINGS_ENABLE_CONNECT_PROTOCOL:16, 1:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings#{enable_connect_protocol => true});
decode_settings_payload(<<?SETTINGS_ENABLE_CONNECT_PROTOCOL:16, _:32, _/binary>>, _Settings) ->
    {error,
        {connection_error, protocol_error,
            <<"SETTINGS_ENABLE_CONNECT_PROTOCOL MUST be 0 or 1 (RFC 8441 Section 3)">>}};
decode_settings_payload(<<_:16, _:32, Rest/binary>>, Settings) ->
    decode_settings_payload(Rest, Settings).

-spec encode_continuation_bin(nhttp_lib:stream_id(), nhttp_h2:fin(), binary()) -> iodata().
encode_continuation_bin(StreamId, EndHeaders, <<HeaderBlock/binary>>) ->
    Len = byte_size(HeaderBlock),
    Flags = fin_to_end_headers(EndHeaders),
    [<<Len:24, ?FRAME_CONTINUATION:8, Flags:8, 0:1, StreamId:31>>, HeaderBlock].

-spec encode_setting(atom(), term(), iodata()) -> iodata().
encode_setting(header_table_size, Value, Acc) ->
    [<<?SETTINGS_HEADER_TABLE_SIZE:16, Value:32>> | Acc];
encode_setting(enable_push, true, Acc) ->
    [<<?SETTINGS_ENABLE_PUSH:16, 1:32>> | Acc];
encode_setting(enable_push, false, Acc) ->
    [<<?SETTINGS_ENABLE_PUSH:16, 0:32>> | Acc];
encode_setting(max_concurrent_streams, infinity, Acc) ->
    Acc;
encode_setting(max_concurrent_streams, Value, Acc) ->
    [<<?SETTINGS_MAX_CONCURRENT_STREAMS:16, Value:32>> | Acc];
encode_setting(initial_window_size, Value, Acc) ->
    [<<?SETTINGS_INITIAL_WINDOW_SIZE:16, Value:32>> | Acc];
encode_setting(max_frame_size, Value, Acc) ->
    [<<?SETTINGS_MAX_FRAME_SIZE:16, Value:32>> | Acc];
encode_setting(max_header_list_size, infinity, Acc) ->
    Acc;
encode_setting(max_header_list_size, Value, Acc) ->
    [<<?SETTINGS_MAX_HEADER_LIST_SIZE:16, Value:32>> | Acc];
encode_setting(enable_connect_protocol, true, Acc) ->
    [<<?SETTINGS_ENABLE_CONNECT_PROTOCOL:16, 1:32>> | Acc];
encode_setting(enable_connect_protocol, false, Acc) ->
    [<<?SETTINGS_ENABLE_CONNECT_PROTOCOL:16, 0:32>> | Acc];
encode_setting(_, _, Acc) ->
    Acc.

-spec end_headers_to_fin(non_neg_integer()) -> nhttp_h2:fin().
end_headers_to_fin(Flags) when Flags band ?FLAG_END_HEADERS =/= 0 -> fin;
end_headers_to_fin(_) -> nofin.

-spec end_stream_to_fin(non_neg_integer()) -> nhttp_h2:fin().
end_stream_to_fin(Flags) when Flags band ?FLAG_END_STREAM =/= 0 -> fin;
end_stream_to_fin(_) -> nofin.

-spec error_code_to_int(nhttp_h2:error_code()) -> non_neg_integer().
error_code_to_int(no_error) -> 16#00;
error_code_to_int(protocol_error) -> 16#01;
error_code_to_int(internal_error) -> 16#02;
error_code_to_int(flow_control_error) -> 16#03;
error_code_to_int(settings_timeout) -> 16#04;
error_code_to_int(stream_closed) -> 16#05;
error_code_to_int(frame_size_error) -> 16#06;
error_code_to_int(refused_stream) -> 16#07;
error_code_to_int(cancel) -> 16#08;
error_code_to_int(compression_error) -> 16#09;
error_code_to_int(connect_error) -> 16#0a;
error_code_to_int(enhance_your_calm) -> 16#0b;
error_code_to_int(inadequate_security) -> 16#0c;
error_code_to_int(http_1_1_required) -> 16#0d.

-spec fin_to_end_headers(nhttp_h2:fin()) -> 0 | 4.
fin_to_end_headers(fin) -> ?FLAG_END_HEADERS;
fin_to_end_headers(nofin) -> 0.

-spec fin_to_end_stream(nhttp_h2:fin()) -> 0 | 1.
fin_to_end_stream(fin) -> ?FLAG_END_STREAM;
fin_to_end_stream(nofin) -> 0.

-spec int_to_error_code(non_neg_integer()) -> nhttp_h2:error_code().
int_to_error_code(16#00) -> no_error;
int_to_error_code(16#01) -> protocol_error;
int_to_error_code(16#02) -> internal_error;
int_to_error_code(16#03) -> flow_control_error;
int_to_error_code(16#04) -> settings_timeout;
int_to_error_code(16#05) -> stream_closed;
int_to_error_code(16#06) -> frame_size_error;
int_to_error_code(16#07) -> refused_stream;
int_to_error_code(16#08) -> cancel;
int_to_error_code(16#09) -> compression_error;
int_to_error_code(16#0a) -> connect_error;
int_to_error_code(16#0b) -> enhance_your_calm;
int_to_error_code(16#0c) -> inadequate_security;
int_to_error_code(16#0d) -> http_1_1_required;
int_to_error_code(_) -> internal_error.

-spec is_zero_padding(binary()) -> boolean().
is_zero_padding(Padding) ->
    Padding =:= <<0:(byte_size(Padding) * 8)>>.
