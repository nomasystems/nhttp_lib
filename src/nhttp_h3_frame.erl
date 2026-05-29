-module(nhttp_h3_frame).

-moduledoc """
HTTP/3 binary frame encoding and decoding.

Implements RFC 9114 Section 7. Each HTTP/3 frame consists of:

    Type (varint) | Length (varint) | Payload (Length bytes)

Unlike HTTP/2's fixed 9-byte header, HTTP/3 uses QUIC variable-length
integers for both type and length fields.

Frame types 0x02, 0x06, 0x08, 0x09 are forbidden in HTTP/3 (reserved
from HTTP/2). Receiving them is a connection error (H3_FRAME_UNEXPECTED).

Unknown frame types in the grease range (0x1f * N + 0x21) must be
silently ignored. All other unknown types must also be ignored per
RFC 9114 Section 9.
""".

%%%-----------------------------------------------------------------------------
%% API EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    cancel_push/1,
    data/1,
    decode/1,
    goaway/1,
    headers/1,
    max_push_id/1,
    push_promise/2,
    settings/1
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    decode_error/0,
    decode_result/0,
    t/0,
    h3_settings/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type t() ::
    {data, binary()}
    | {headers, binary()}
    | {cancel_push, PushId :: non_neg_integer()}
    | {settings, h3_settings()}
    | {push_promise, PushId :: non_neg_integer(), FieldSection :: binary()}
    | {goaway, Id :: non_neg_integer()}
    | {max_push_id, PushId :: non_neg_integer()}
    | {unknown, Type :: non_neg_integer(), Payload :: binary()}.

-type h3_settings() :: #{
    max_field_section_size => non_neg_integer() | infinity,
    qpack_max_table_capacity => non_neg_integer(),
    qpack_blocked_streams => non_neg_integer(),
    enable_connect_protocol => boolean()
}.

-type decode_result() ::
    {ok, t(), Rest :: binary()}
    | {more, pos_integer()}
    | {error, decode_error()}.

-type decode_error() ::
    h3_frame_unexpected
    | h3_frame_error
    | h3_settings_error.

%%%-----------------------------------------------------------------------------
%% FRAME TYPE IDENTIFIERS (RFC 9114 SECTION 7.2)
%%%-----------------------------------------------------------------------------
-define(FRAME_DATA, 16#00).
-define(FRAME_HEADERS, 16#01).
-define(FRAME_CANCEL_PUSH, 16#03).
-define(FRAME_SETTINGS, 16#04).
-define(FRAME_PUSH_PROMISE, 16#05).
-define(FRAME_GOAWAY, 16#07).
-define(FRAME_MAX_PUSH_ID, 16#0D).

%%%-----------------------------------------------------------------------------
%% FORBIDDEN H2 FRAME TYPES (RFC 9114 SECTION 7.2.8)
%%%-----------------------------------------------------------------------------
-define(H2_FRAME_PRIORITY, 16#02).
-define(H2_FRAME_PING, 16#06).
-define(H2_FRAME_WINDOW_UPDATE, 16#08).
-define(H2_FRAME_CONTINUATION, 16#09).

%%%-----------------------------------------------------------------------------
%% H3 SETTINGS IDENTIFIERS (RFC 9114 SECTION 7.2.4.1)
%%%-----------------------------------------------------------------------------
-define(SETTINGS_MAX_FIELD_SECTION_SIZE, 16#06).
-define(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 16#01).
-define(SETTINGS_QPACK_BLOCKED_STREAMS, 16#07).
-define(SETTINGS_ENABLE_CONNECT_PROTOCOL, 16#08).

-define(H2_SETTINGS_ENABLE_PUSH, 16#02).
-define(H2_SETTINGS_MAX_CONCURRENT_STREAMS, 16#03).
-define(H2_SETTINGS_INITIAL_WINDOW_SIZE, 16#04).
-define(H2_SETTINGS_MAX_FRAME_SIZE, 16#05).

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-doc "Decode a single HTTP/3 frame. Returns the unparsed tail on success.".
-spec decode(binary()) -> decode_result().
decode(Bin) ->
    maybe
        {ok, Type, Rest0} ?= varint_decode(Bin),
        {ok, Length, Rest1} ?= varint_decode(Rest0),
        true ?= byte_size(Rest1) >= Length,
        <<Payload:Length/binary, Rest/binary>> = Rest1,
        case decode_frame(Type, Payload) of
            {ok, Frame} -> {ok, Frame, Rest};
            {error, _} = E -> E
        end
    else
        {error, incomplete_binary} ->
            {more, 1};
        false ->
            {more, 1}
    end.

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc "Encode a CANCEL_PUSH frame.".
-spec cancel_push(non_neg_integer()) -> {ok, iodata()}.
cancel_push(PushId) ->
    PushIdBin = nquic_varint:encode(PushId),
    Len = byte_size(PushIdBin),
    TypeBin = nquic_varint:encode(?FRAME_CANCEL_PUSH),
    LenBin = nquic_varint:encode(Len),
    {ok, [TypeBin, LenBin, PushIdBin]}.

-doc "Encode a DATA frame.".
-spec data(iodata()) -> {ok, iodata()}.
data(Payload) ->
    Len = iolist_size(Payload),
    TypeBin = nquic_varint:encode(?FRAME_DATA),
    LenBin = nquic_varint:encode(Len),
    {ok, [TypeBin, LenBin, Payload]}.

-doc "Encode a GOAWAY frame.".
-spec goaway(non_neg_integer()) -> {ok, iodata()}.
goaway(Id) ->
    IdBin = nquic_varint:encode(Id),
    Len = byte_size(IdBin),
    TypeBin = nquic_varint:encode(?FRAME_GOAWAY),
    LenBin = nquic_varint:encode(Len),
    {ok, [TypeBin, LenBin, IdBin]}.

-doc "Encode a HEADERS frame (payload is raw QPACK-encoded bytes).".
-spec headers(iodata()) -> {ok, iodata()}.
headers(FieldSection) ->
    Len = iolist_size(FieldSection),
    TypeBin = nquic_varint:encode(?FRAME_HEADERS),
    LenBin = nquic_varint:encode(Len),
    {ok, [TypeBin, LenBin, FieldSection]}.

-doc "Encode a MAX_PUSH_ID frame.".
-spec max_push_id(non_neg_integer()) -> {ok, iodata()}.
max_push_id(PushId) ->
    PushIdBin = nquic_varint:encode(PushId),
    Len = byte_size(PushIdBin),
    TypeBin = nquic_varint:encode(?FRAME_MAX_PUSH_ID),
    LenBin = nquic_varint:encode(Len),
    {ok, [TypeBin, LenBin, PushIdBin]}.

-doc "Encode a PUSH_PROMISE frame.".
-spec push_promise(non_neg_integer(), iodata()) -> {ok, iodata()}.
push_promise(PushId, FieldSection) ->
    PushIdBin = nquic_varint:encode(PushId),
    Len = byte_size(PushIdBin) + iolist_size(FieldSection),
    TypeBin = nquic_varint:encode(?FRAME_PUSH_PROMISE),
    LenBin = nquic_varint:encode(Len),
    {ok, [TypeBin, LenBin, PushIdBin, FieldSection]}.

-doc "Encode a SETTINGS frame.".
-spec settings(h3_settings()) -> {ok, iodata()}.
settings(Settings) ->
    Payload = encode_settings_payload(Settings),
    Len = iolist_size(Payload),
    TypeBin = nquic_varint:encode(?FRAME_SETTINGS),
    LenBin = nquic_varint:encode(Len),
    {ok, [TypeBin, LenBin, Payload]}.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec apply_setting(non_neg_integer(), non_neg_integer(), h3_settings()) ->
    {ok, h3_settings()} | {error, decode_error()}.
apply_setting(?SETTINGS_QPACK_MAX_TABLE_CAPACITY, Value, Settings) ->
    {ok, Settings#{qpack_max_table_capacity => Value}};
apply_setting(?H2_SETTINGS_ENABLE_PUSH, _Value, _Settings) ->
    {error, h3_settings_error};
apply_setting(?H2_SETTINGS_MAX_CONCURRENT_STREAMS, _Value, _Settings) ->
    {error, h3_settings_error};
apply_setting(?H2_SETTINGS_INITIAL_WINDOW_SIZE, _Value, _Settings) ->
    {error, h3_settings_error};
apply_setting(?H2_SETTINGS_MAX_FRAME_SIZE, _Value, _Settings) ->
    {error, h3_settings_error};
apply_setting(?SETTINGS_MAX_FIELD_SECTION_SIZE, Value, Settings) ->
    {ok, Settings#{max_field_section_size => Value}};
apply_setting(?SETTINGS_QPACK_BLOCKED_STREAMS, Value, Settings) ->
    {ok, Settings#{qpack_blocked_streams => Value}};
apply_setting(?SETTINGS_ENABLE_CONNECT_PROTOCOL, 0, Settings) ->
    {ok, Settings#{enable_connect_protocol => false}};
apply_setting(?SETTINGS_ENABLE_CONNECT_PROTOCOL, 1, Settings) ->
    {ok, Settings#{enable_connect_protocol => true}};
apply_setting(?SETTINGS_ENABLE_CONNECT_PROTOCOL, _Value, _Settings) ->
    {error, h3_settings_error};
apply_setting(_Id, _Value, Settings) ->
    {ok, Settings}.

-spec decode_frame(non_neg_integer(), binary()) ->
    {ok, t()} | {error, decode_error()}.
decode_frame(?FRAME_DATA, Payload) ->
    {ok, {data, Payload}};
decode_frame(?FRAME_HEADERS, Payload) ->
    {ok, {headers, Payload}};
decode_frame(?FRAME_CANCEL_PUSH, Payload) ->
    case nquic_varint:decode(Payload) of
        {ok, PushId, <<>>} -> {ok, {cancel_push, PushId}};
        {ok, _, _} -> {error, h3_frame_error};
        {error, incomplete_binary} -> {ok, {cancel_push, 0}}
    end;
decode_frame(?FRAME_SETTINGS, Payload) ->
    case decode_settings_payload(Payload, #{}) of
        {ok, Settings} -> {ok, {settings, Settings}};
        {error, _} = E -> E
    end;
decode_frame(?FRAME_PUSH_PROMISE, Payload) ->
    case nquic_varint:decode(Payload) of
        {ok, PushId, FieldSection} -> {ok, {push_promise, PushId, FieldSection}};
        {error, incomplete_binary} -> {error, h3_frame_error}
    end;
decode_frame(?FRAME_GOAWAY, Payload) ->
    case nquic_varint:decode(Payload) of
        {ok, Id, <<>>} -> {ok, {goaway, Id}};
        {ok, _, _} -> {error, h3_frame_error};
        {error, incomplete_binary} -> {error, h3_frame_error}
    end;
decode_frame(?FRAME_MAX_PUSH_ID, Payload) ->
    case nquic_varint:decode(Payload) of
        {ok, PushId, <<>>} -> {ok, {max_push_id, PushId}};
        {ok, _, _} -> {error, h3_frame_error};
        {error, incomplete_binary} -> {error, h3_frame_error}
    end;
decode_frame(Type, _Payload) when
    Type =:= ?H2_FRAME_PRIORITY;
    Type =:= ?H2_FRAME_PING;
    Type =:= ?H2_FRAME_WINDOW_UPDATE;
    Type =:= ?H2_FRAME_CONTINUATION
->
    {error, h3_frame_unexpected};
decode_frame(Type, Payload) ->
    {ok, {unknown, Type, Payload}}.

-spec decode_settings_payload(binary(), h3_settings()) ->
    {ok, h3_settings()} | {error, decode_error()}.
decode_settings_payload(<<>>, Settings) ->
    {ok, Settings};
decode_settings_payload(Bin, Settings) ->
    case nquic_varint:decode(Bin) of
        {ok, Id, Rest0} ->
            case nquic_varint:decode(Rest0) of
                {ok, Value, Rest1} ->
                    case apply_setting(Id, Value, Settings) of
                        {ok, Settings1} -> decode_settings_payload(Rest1, Settings1);
                        {error, _} = E -> E
                    end;
                {error, incomplete_binary} ->
                    {error, h3_frame_error}
            end;
        {error, incomplete_binary} ->
            {error, h3_frame_error}
    end.

-spec encode_setting(atom(), non_neg_integer() | boolean() | infinity, iodata()) -> iodata().
encode_setting(qpack_max_table_capacity, Value, Acc) ->
    Id = nquic_varint:encode(?SETTINGS_QPACK_MAX_TABLE_CAPACITY),
    Val = nquic_varint:encode(Value),
    [Id, Val | Acc];
encode_setting(max_field_section_size, infinity, Acc) ->
    Acc;
encode_setting(max_field_section_size, Value, Acc) ->
    Id = nquic_varint:encode(?SETTINGS_MAX_FIELD_SECTION_SIZE),
    Val = nquic_varint:encode(Value),
    [Id, Val | Acc];
encode_setting(qpack_blocked_streams, Value, Acc) ->
    Id = nquic_varint:encode(?SETTINGS_QPACK_BLOCKED_STREAMS),
    Val = nquic_varint:encode(Value),
    [Id, Val | Acc];
encode_setting(enable_connect_protocol, true, Acc) ->
    Id = nquic_varint:encode(?SETTINGS_ENABLE_CONNECT_PROTOCOL),
    Val = nquic_varint:encode(1),
    [Id, Val | Acc];
encode_setting(enable_connect_protocol, false, Acc) ->
    Id = nquic_varint:encode(?SETTINGS_ENABLE_CONNECT_PROTOCOL),
    Val = nquic_varint:encode(0),
    [Id, Val | Acc];
encode_setting(_, _, Acc) ->
    Acc.

-spec encode_settings_payload(h3_settings()) -> iodata().
encode_settings_payload(Settings) ->
    maps:fold(fun encode_setting/3, [], Settings).

-spec varint_decode(binary()) -> {ok, non_neg_integer(), binary()} | {error, incomplete_binary}.
varint_decode(Bin) ->
    nquic_varint:decode(Bin).
