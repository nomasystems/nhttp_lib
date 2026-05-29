-module(nhttp_str).

-moduledoc """
String literal codec for HPACK and QPACK.

Implements the string literal representation shared by HPACK (RFC 7541
Section 5.2) and QPACK (RFC 9204 Section 4.1.2). A string literal is
encoded as:

    H (1 bit) | Length (7-bit prefixed integer) | Data (Length bytes)

When H=1 the data is Huffman-coded using the static table from
RFC 7541 Appendix B. When H=0 the data is the raw octets.
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([decode/1]).

-export([encode/2]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([decode_error/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type decode_error() :: incomplete | invalid_huffman.

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a string literal from a bitstring.

Reads the H-bit, decodes the 7-bit-prefixed length, extracts that many
bytes, and optionally Huffman-decodes the result. Returns the decoded
string and the unconsumed remainder.
""".
-spec decode(bitstring()) ->
    {ok, binary(), bitstring()} | {error, decode_error()}.
decode(<<>>) ->
    {error, incomplete};
decode(<<H:1, Rest0/bits>>) ->
    maybe
        {ok, Length, Rest1} ?= dec7_map_error(Rest0),
        case Rest1 of
            <<Data:Length/binary, Rest/bits>> ->
                decode_data(H, Data, Rest);
            _ ->
                {error, incomplete}
        end
    end;
decode(_) ->
    {error, incomplete}.

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc """
Encode a binary as a string literal.
When `Huffman` is `true`, the string is Huffman-encoded and the H-bit
is set. When `false`, the raw bytes are written with H=0.
""".
-spec encode(binary(), boolean()) -> iolist().
encode(Str, true) ->
    Encoded = nhttp_huffman:encode(Str),
    [nhttp_int:enc7(byte_size(Encoded), 2#1), Encoded];
encode(Str, false) ->
    [nhttp_int:enc7(byte_size(Str), 2#0), Str].

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec dec7_map_error(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec7_map_error(Bits) ->
    case nhttp_int:dec7(Bits) of
        {ok, _, _} = Ok -> Ok;
        {error, incomplete} -> {error, incomplete};
        {error, overflow} -> {error, incomplete}
    end.

-spec decode_data(0 | 1, binary(), bitstring()) ->
    {ok, binary(), bitstring()} | {error, invalid_huffman}.
decode_data(0, Data, Rest) ->
    {ok, Data, Rest};
decode_data(1, Data, Rest) ->
    case nhttp_huffman:decode(Data) of
        {ok, Decoded} -> {ok, Decoded, Rest};
        {error, _} -> {error, invalid_huffman}
    end.
