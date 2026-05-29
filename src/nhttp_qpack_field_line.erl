-module(nhttp_qpack_field_line).

-moduledoc """
QPACK field line representations (RFC 9204 Section 4.5).

Handles the field section prefix and five field line representation
types used within encoded field sections on request and push streams.

The prefix carries the Required Insert Count and Base values needed
to interpret dynamic table references. The five representation types
encode header field lines as indexed references or literal values.

Representation types:
  * Indexed Field Line (Section 4.5.2)
  * Indexed Field Line with Post-Base Index (Section 4.5.3)
  * Literal Field Line with Name Reference (Section 4.5.4)
  * Literal Field Line with Post-Base Name Reference (Section 4.5.5)
  * Literal Field Line with Literal Name (Section 4.5.6)
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([decode_prefix/3, encode_prefix/3]).

-export([decode_representation/1, encode_representation/2]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([decode_error/0, prefix/0, representation/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type representation() ::
    {indexed, static | dynamic, non_neg_integer()}
    | {indexed_post_base, non_neg_integer()}
    | {literal_name_ref, static | dynamic, non_neg_integer(), binary(), boolean()}
    | {literal_post_base_name_ref, non_neg_integer(), binary(), boolean()}
    | {literal, binary(), binary(), boolean()}.

-type prefix() :: #{
    required_insert_count := non_neg_integer(),
    base := non_neg_integer()
}.

-type decode_error() ::
    incomplete
    | invalid_huffman
    | invalid_required_insert_count.

%%%-----------------------------------------------------------------------------
%% PREFIX ENCODING
%%%-----------------------------------------------------------------------------
-doc """
Encode a field section prefix.

The prefix consists of the Required Insert Count (with modular
encoding per Section 4.5.1.1) and the sign bit plus Delta Base.
MaxEntries is `floor(MaxTableCapacity / 32)`.
""".
-spec encode_prefix(
    non_neg_integer(), non_neg_integer(), non_neg_integer()
) -> iolist().
encode_prefix(RequiredInsertCount, Base, MaxEntries) ->
    EncodedRIC = encode_ric(RequiredInsertCount, MaxEntries),
    RICBytes = nhttp_int:enc8(EncodedRIC),
    {Sign, DeltaBase} = encode_base(RequiredInsertCount, Base),
    DeltaBytes = nhttp_int:enc7(DeltaBase, Sign),
    [RICBytes, DeltaBytes].

%%%-----------------------------------------------------------------------------
%% PREFIX DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a field section prefix from binary data.
MaxEntries is `floor(MaxTableCapacity / 32)`. TotalInserts is the
total number of inserts into the dynamic table so far.
""".
-spec decode_prefix(
    binary(), non_neg_integer(), non_neg_integer()
) ->
    {ok, prefix(), bitstring()} | {error, decode_error()}.
decode_prefix(Bin, MaxEntries, TotalInserts) ->
    maybe
        {ok, EncodedRIC, Rest1} ?=
            map_int_error(nhttp_int:dec8(Bin)),
        {ok, RIC} ?=
            decode_ric(EncodedRIC, MaxEntries, TotalInserts),
        {ok, {Sign, DeltaBase}, Rest2} ?=
            decode_sign_delta(Rest1),
        Base = compute_base(RIC, Sign, DeltaBase),
        {ok, #{required_insert_count => RIC, base => Base}, Rest2}
    end.

%%%-----------------------------------------------------------------------------
%% REPRESENTATION ENCODING
%%%-----------------------------------------------------------------------------
-doc """
Encode a single field line representation.
The Huffman flag controls whether string values (and literal names)
are Huffman-coded.
""".
-spec encode_representation(representation(), boolean()) -> iolist().
encode_representation({indexed, static, Index}, _Huffman) ->
    [nhttp_int:enc6(Index, 2#11)];
encode_representation({indexed, dynamic, Index}, _Huffman) ->
    [nhttp_int:enc6(Index, 2#10)];
encode_representation({indexed_post_base, Index}, _Huffman) ->
    [nhttp_int:enc4(Index, 2#0001)];
encode_representation(
    {literal_name_ref, Table, Index, Value, NI}, Huffman
) ->
    N = bool_to_bit(NI),
    T = table_bit(Table),
    Prefix = 2#0100 bor (N bsl 1) bor T,
    [
        nhttp_int:enc4(Index, Prefix)
        | nhttp_str:encode(Value, Huffman)
    ];
encode_representation(
    {literal_post_base_name_ref, Index, Value, NI}, Huffman
) ->
    N = bool_to_bit(NI),
    [
        nhttp_int:enc3(Index, N)
        | nhttp_str:encode(Value, Huffman)
    ];
encode_representation({literal, Name, Value, NI}, Huffman) ->
    encode_literal(Name, Value, NI, Huffman).

%%%-----------------------------------------------------------------------------
%% REPRESENTATION DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a single field line representation from binary data.
Dispatches based on the leading bit pattern to determine which of
the five representation types is encoded.
""".
-spec decode_representation(binary()) ->
    {ok, representation(), bitstring()} | {error, decode_error()}.
decode_representation(<<1:1, _/bits>> = Bin) ->
    decode_indexed(Bin);
decode_representation(<<2#01:2, _/bits>> = Bin) ->
    decode_literal_name_ref(Bin);
decode_representation(<<2#001:3, _/bits>> = Bin) ->
    decode_literal(Bin);
decode_representation(<<2#0001:4, _/bits>> = Bin) ->
    decode_indexed_post_base(Bin);
decode_representation(<<2#0000:4, _/bits>> = Bin) ->
    decode_literal_post_base_name_ref(Bin);
decode_representation(_) ->
    {error, incomplete}.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS - PREFIX
%%%-----------------------------------------------------------------------------
-spec adjust_ric(
    integer(), non_neg_integer(), pos_integer()
) ->
    {ok, pos_integer()}
    | {error, invalid_required_insert_count}.
adjust_ric(RIC, MaxValue, FullRange) when RIC > MaxValue ->
    case RIC =< FullRange of
        true ->
            {error, invalid_required_insert_count};
        false ->
            validate_ric(RIC - FullRange)
    end;
adjust_ric(RIC, _MaxValue, _FullRange) ->
    validate_ric(RIC).

-spec compute_base(
    non_neg_integer(), 0 | 1, non_neg_integer()
) -> non_neg_integer().
compute_base(RIC, 0, DeltaBase) ->
    RIC + DeltaBase;
compute_base(RIC, 1, DeltaBase) ->
    RIC - DeltaBase - 1.

-spec decode_ric(
    non_neg_integer(), non_neg_integer(), non_neg_integer()
) ->
    {ok, non_neg_integer()}
    | {error, invalid_required_insert_count}.
decode_ric(0, _MaxEntries, _TotalInserts) ->
    {ok, 0};
decode_ric(_Encoded, 0, _TotalInserts) ->
    {error, invalid_required_insert_count};
decode_ric(Encoded, MaxEntries, TotalInserts) ->
    FullRange = 2 * MaxEntries,
    case Encoded > FullRange of
        true ->
            {error, invalid_required_insert_count};
        false ->
            MaxValue = TotalInserts + MaxEntries,
            MaxWrapped = (MaxValue div FullRange) * FullRange,
            RIC = MaxWrapped + Encoded - 1,
            adjust_ric(RIC, MaxValue, FullRange)
    end.

-spec decode_sign_delta(bitstring()) ->
    {ok, {0 | 1, non_neg_integer()}, bitstring()}
    | {error, decode_error()}.
decode_sign_delta(<<S:1, Rest/bits>>) ->
    maybe
        {ok, DeltaBase, Rest2} ?=
            map_int_error(nhttp_int:dec7(Rest)),
        {ok, {S, DeltaBase}, Rest2}
    end;
decode_sign_delta(_) ->
    {error, incomplete}.

-spec encode_base(
    non_neg_integer(), non_neg_integer()
) -> {0 | 1, non_neg_integer()}.
encode_base(RIC, Base) when Base >= RIC ->
    {0, Base - RIC};
encode_base(RIC, Base) ->
    {1, RIC - Base - 1}.

-spec encode_ric(
    non_neg_integer(), non_neg_integer()
) -> non_neg_integer().
encode_ric(0, _MaxEntries) ->
    0;
encode_ric(RIC, MaxEntries) ->
    (RIC rem (2 * MaxEntries)) + 1.

-spec validate_ric(integer()) ->
    {ok, pos_integer()}
    | {error, invalid_required_insert_count}.
validate_ric(RIC) when RIC > 0 ->
    {ok, RIC};
validate_ric(_) ->
    {error, invalid_required_insert_count}.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS - REPRESENTATION ENCODING
%%%-----------------------------------------------------------------------------
-spec encode_literal(
    binary(), binary(), boolean(), boolean()
) -> iolist().
encode_literal(Name, Value, NeverIndexed, true) ->
    N = bool_to_bit(NeverIndexed),
    HuffName = nhttp_huffman:encode(Name),
    Prefix = (2#0010 bor N) bsl 1 bor 1,
    [
        nhttp_int:enc3(byte_size(HuffName), Prefix),
        HuffName
        | nhttp_str:encode(Value, true)
    ];
encode_literal(Name, Value, NeverIndexed, false) ->
    N = bool_to_bit(NeverIndexed),
    Prefix = (2#0010 bor N) bsl 1,
    [
        nhttp_int:enc3(byte_size(Name), Prefix),
        Name
        | nhttp_str:encode(Value, false)
    ].

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS - REPRESENTATION DECODING
%%%-----------------------------------------------------------------------------
-spec decode_indexed(bitstring()) ->
    {ok, representation(), bitstring()}
    | {error, decode_error()}.
decode_indexed(<<1:1, T:1, Rest/bits>>) ->
    maybe
        {ok, Index, Rest2} ?=
            map_int_error(nhttp_int:dec6(Rest)),
        Table = bit_to_table(T),
        {ok, {indexed, Table, Index}, Rest2}
    end.

-spec decode_indexed_post_base(bitstring()) ->
    {ok, representation(), bitstring()}
    | {error, decode_error()}.
decode_indexed_post_base(<<2#0001:4, Rest/bits>>) ->
    maybe
        {ok, Index, Rest2} ?=
            map_int_error(nhttp_int:dec4(Rest)),
        {ok, {indexed_post_base, Index}, Rest2}
    end.

-spec decode_literal(bitstring()) ->
    {ok, representation(), bitstring()}
    | {error, decode_error()}.
decode_literal(<<2#001:3, N:1, H:1, Rest/bits>>) ->
    maybe
        {ok, NameLen, Rest2} ?=
            map_int_error(nhttp_int:dec3(Rest)),
        {ok, NameData, Rest3} ?=
            extract_bytes(NameLen, Rest2),
        {ok, Name} ?= decode_name(H, NameData),
        {ok, Value, Rest4} ?=
            map_str_error(nhttp_str:decode(Rest3)),
        NeverIndexed = bit_to_bool(N),
        {ok, {literal, Name, Value, NeverIndexed}, Rest4}
    end.

-spec decode_literal_name_ref(bitstring()) ->
    {ok, representation(), bitstring()}
    | {error, decode_error()}.
decode_literal_name_ref(<<2#01:2, N:1, T:1, Rest/bits>>) ->
    maybe
        {ok, Index, Rest2} ?=
            map_int_error(nhttp_int:dec4(Rest)),
        {ok, Value, Rest3} ?=
            map_str_error(nhttp_str:decode(Rest2)),
        Table = bit_to_table(T),
        NeverIndexed = bit_to_bool(N),
        {ok, {literal_name_ref, Table, Index, Value, NeverIndexed}, Rest3}
    end.

-spec decode_literal_post_base_name_ref(bitstring()) ->
    {ok, representation(), bitstring()}
    | {error, decode_error()}.
decode_literal_post_base_name_ref(
    <<2#0000:4, N:1, Rest/bits>>
) ->
    maybe
        {ok, Index, Rest2} ?=
            map_int_error(nhttp_int:dec3(Rest)),
        {ok, Value, Rest3} ?=
            map_str_error(nhttp_str:decode(Rest2)),
        NeverIndexed = bit_to_bool(N),
        {ok, {literal_post_base_name_ref, Index, Value, NeverIndexed}, Rest3}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS - HELPERS
%%%-----------------------------------------------------------------------------
-spec bit_to_bool(0 | 1) -> boolean().
bit_to_bool(1) -> true;
bit_to_bool(0) -> false.

-spec bit_to_table(0 | 1) -> static | dynamic.
bit_to_table(1) -> static;
bit_to_table(0) -> dynamic.

-spec bool_to_bit(boolean()) -> 0 | 1.
bool_to_bit(true) -> 1;
bool_to_bit(false) -> 0.

-spec decode_name(0 | 1, binary()) ->
    {ok, binary()} | {error, invalid_huffman}.
decode_name(0, Data) ->
    {ok, Data};
decode_name(1, Data) ->
    case nhttp_huffman:decode(Data) of
        {ok, Decoded} -> {ok, Decoded};
        _ -> {error, invalid_huffman}
    end.

-spec extract_bytes(non_neg_integer(), bitstring()) ->
    {ok, binary(), bitstring()} | {error, incomplete}.
extract_bytes(Len, Bin) ->
    case Bin of
        <<Data:Len/binary, Rest/bits>> -> {ok, Data, Rest};
        _ -> {error, incomplete}
    end.

-spec map_int_error
    ({ok, non_neg_integer(), bitstring()}) ->
        {ok, non_neg_integer(), bitstring()};
    ({error, nhttp_int:decode_error()}) ->
        {error, incomplete}.
map_int_error({ok, _, _} = Ok) -> Ok;
map_int_error({error, _}) -> {error, incomplete}.

-spec map_str_error
    ({ok, binary(), bitstring()}) ->
        {ok, binary(), bitstring()};
    ({error, nhttp_str:decode_error()}) ->
        {error, decode_error()}.
map_str_error({ok, _, _} = Ok) -> Ok;
map_str_error({error, incomplete}) -> {error, incomplete};
map_str_error({error, invalid_huffman}) -> {error, invalid_huffman}.

-spec table_bit(static | dynamic) -> 0 | 1.
table_bit(static) -> 1;
table_bit(dynamic) -> 0.
