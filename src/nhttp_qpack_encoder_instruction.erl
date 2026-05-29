-module(nhttp_qpack_encoder_instruction).

-moduledoc """
Encoder instructions wire format (RFC 9204 Section 4.3).

Encoder instructions flow from encoder to decoder on the encoder
unidirectional stream. They modify the decoder's copy of the dynamic
table.

Four instruction types are defined:

  * Set Dynamic Table Capacity (Section 4.3.1)
  * Insert with Name Reference (Section 4.3.2)
  * Insert with Literal Name (Section 4.3.3)
  * Duplicate (Section 4.3.4)
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([decode/1]).

-export([
    encode_duplicate/1,
    encode_insert_literal_name/3,
    encode_insert_name_ref/4,
    encode_set_capacity/1
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([decode_error/0, t/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type t() ::
    {set_capacity, non_neg_integer()}
    | {insert_name_ref, static | dynamic, non_neg_integer(), binary()}
    | {insert_literal_name, binary(), binary()}
    | {duplicate, non_neg_integer()}.

-type decode_error() :: incomplete | invalid_huffman | nhttp_int:decode_error().

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a single encoder instruction from a binary.

Returns the decoded instruction and unconsumed bytes, or an error
if the data is incomplete or contains invalid Huffman coding.
""".
-spec decode(binary()) ->
    {ok, t(), bitstring()} | {error, decode_error()}.
decode(<<>>) ->
    {error, incomplete};
decode(<<2#1:1, _/bits>> = Bin) ->
    decode_insert_name_ref(Bin);
decode(<<2#01:2, _/bits>> = Bin) ->
    decode_insert_literal_name(Bin);
decode(<<2#001:3, _/bits>> = Bin) ->
    decode_set_capacity(Bin);
decode(<<2#000:3, _/bits>> = Bin) ->
    decode_duplicate(Bin).

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc """
Encode a Duplicate instruction.
Wire format: `000` prefix + 5-bit prefixed integer (relative index).
""".
-spec encode_duplicate(non_neg_integer()) -> iolist().
encode_duplicate(Index) ->
    [nhttp_int:enc5(Index, 2#000)].

-doc """
Encode an Insert with Literal Name instruction.
Wire format: `01` + H-bit + 5-bit prefixed name string + value
string literal. The Huffman flag applies to both name and value.
""".
-spec encode_insert_literal_name(binary(), binary(), boolean()) -> iolist().
encode_insert_literal_name(Name, Value, true) ->
    HuffName = nhttp_huffman:encode(Name),
    [
        nhttp_int:enc5(byte_size(HuffName), 2#011),
        HuffName
        | nhttp_str:encode(Value, true)
    ];
encode_insert_literal_name(Name, Value, false) ->
    [
        nhttp_int:enc5(byte_size(Name), 2#010),
        Name
        | nhttp_str:encode(Value, false)
    ].

-doc """
Encode an Insert with Name Reference instruction.
Wire format: `1` + T-bit (1=static, 0=dynamic) + 6-bit prefixed
integer (name index) + value string literal.
""".
-spec encode_insert_name_ref(
    static | dynamic, non_neg_integer(), binary(), boolean()
) -> iolist().
encode_insert_name_ref(static, NameIndex, Value, Huffman) ->
    [nhttp_int:enc6(NameIndex, 2#11) | nhttp_str:encode(Value, Huffman)];
encode_insert_name_ref(dynamic, NameIndex, Value, Huffman) ->
    [nhttp_int:enc6(NameIndex, 2#10) | nhttp_str:encode(Value, Huffman)].

-doc """
Encode a Set Dynamic Table Capacity instruction.
Wire format: `001` prefix + 5-bit prefixed integer.
""".
-spec encode_set_capacity(non_neg_integer()) -> iolist().
encode_set_capacity(Capacity) ->
    [nhttp_int:enc5(Capacity, 2#001)].

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec dec5_safe(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec5_safe(Bits) ->
    nhttp_int:dec5(Bits).

-spec dec6_safe(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec6_safe(Bits) ->
    nhttp_int:dec6(Bits).

-spec decode_duplicate(binary()) ->
    {ok, t(), bitstring()} | {error, decode_error()}.
decode_duplicate(<<2#000:3, Rest/bits>>) ->
    maybe
        {ok, Index, Rest2} ?= dec5_safe(Rest),
        {ok, {duplicate, Index}, Rest2}
    end.

-spec decode_insert_literal_name(binary()) ->
    {ok, t(), bitstring()} | {error, decode_error()}.
decode_insert_literal_name(<<2#01:2, H:1, Rest/bits>>) ->
    maybe
        {ok, NameLen, Rest2} ?= dec5_safe(Rest),
        {ok, NameData, Rest3} ?= extract_bytes(NameLen, Rest2),
        {ok, Name} ?= decode_name(H, NameData),
        {ok, Value, Rest4} ?= nhttp_str:decode(Rest3),
        {ok, {insert_literal_name, Name, Value}, Rest4}
    end.

-spec decode_insert_name_ref(binary()) ->
    {ok, t(), bitstring()} | {error, decode_error()}.
decode_insert_name_ref(<<1:1, T:1, Rest/bits>>) ->
    maybe
        {ok, NameIndex, Rest2} ?= dec6_safe(Rest),
        {ok, Value, Rest3} ?= nhttp_str:decode(Rest2),
        TableType = table_type(T),
        {ok, {insert_name_ref, TableType, NameIndex, Value}, Rest3}
    end.

-spec decode_name(0 | 1, binary()) ->
    {ok, binary()} | {error, invalid_huffman}.
decode_name(0, Data) ->
    {ok, Data};
decode_name(1, Data) ->
    case nhttp_huffman:decode(Data) of
        {ok, Decoded} -> {ok, Decoded};
        _ -> {error, invalid_huffman}
    end.

-spec decode_set_capacity(binary()) ->
    {ok, t(), bitstring()} | {error, decode_error()}.
decode_set_capacity(<<2#001:3, Rest/bits>>) ->
    maybe
        {ok, Capacity, Rest2} ?= dec5_safe(Rest),
        {ok, {set_capacity, Capacity}, Rest2}
    end.

-spec extract_bytes(non_neg_integer(), bitstring()) ->
    {ok, binary(), bitstring()} | {error, incomplete}.
extract_bytes(Len, Bin) ->
    case Bin of
        <<Data:Len/binary, Rest/bits>> -> {ok, Data, Rest};
        _ -> {error, incomplete}
    end.

-spec table_type(0 | 1) -> static | dynamic.
table_type(1) -> static;
table_type(0) -> dynamic.
