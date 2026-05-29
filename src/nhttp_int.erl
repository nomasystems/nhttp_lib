-module(nhttp_int).

-moduledoc """
Prefixed integer codec for HPACK and QPACK.

Implements the variable-length integer encoding defined in
RFC 7541 Section 5.1 (HPACK) and RFC 9204 Section 4.1.1 (QPACK).
Both protocols use the same encoding scheme with different prefix sizes.

A prefixed integer uses N bits of the first byte (the prefix). When the
value fits in those N bits, encoding is a single byte. Larger values
set all N prefix bits to 1 and encode the remainder in subsequent bytes
using a 7-bit-per-byte continuation scheme.

This module provides per-prefix-size encode and decode functions for
prefix sizes 3 through 8 bits.
""".

%%%-----------------------------------------------------------------------------
%% INLINE DIRECTIVES
%%%-----------------------------------------------------------------------------
-compile({inline, [dec3/1, dec4/1, dec5/1, dec6/1, dec7/1, dec8/1]}).

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([dec3/1, dec4/1, dec5/1, dec6/1, dec7/1, dec8/1]).

-export([enc3/2, enc4/2, enc5/2, enc6/2, enc7/2, enc8/1]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([decode_error/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type decode_error() :: incomplete | overflow.

%%%-----------------------------------------------------------------------------
%% CONSTANTS
%%%-----------------------------------------------------------------------------
-define(MAX_INT, 16#7FFFFFFF).

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-doc "Decode a 3-bit prefixed integer.".
-spec dec3(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec3(<<2#111:3, Rest/bits>>) ->
    dec_big(Rest, 7, 0);
dec3(<<Int:3, Rest/bits>>) ->
    {ok, Int, Rest};
dec3(_) ->
    {error, incomplete}.

-doc "Decode a 4-bit prefixed integer.".
-spec dec4(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec4(<<2#1111:4, Rest/bits>>) ->
    dec_big(Rest, 15, 0);
dec4(<<Int:4, Rest/bits>>) ->
    {ok, Int, Rest};
dec4(_) ->
    {error, incomplete}.

-doc "Decode a 5-bit prefixed integer.".
-spec dec5(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec5(<<2#11111:5, Rest/bits>>) ->
    dec_big(Rest, 31, 0);
dec5(<<Int:5, Rest/bits>>) ->
    {ok, Int, Rest};
dec5(_) ->
    {error, incomplete}.

-doc "Decode a 6-bit prefixed integer.".
-spec dec6(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec6(<<2#111111:6, Rest/bits>>) ->
    dec_big(Rest, 63, 0);
dec6(<<Int:6, Rest/bits>>) ->
    {ok, Int, Rest};
dec6(_) ->
    {error, incomplete}.

-doc "Decode a 7-bit prefixed integer.".
-spec dec7(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec7(<<2#1111111:7, Rest/bits>>) ->
    dec_big(Rest, 127, 0);
dec7(<<Int:7, Rest/bits>>) ->
    {ok, Int, Rest};
dec7(_) ->
    {error, incomplete}.

-doc "Decode an 8-bit prefixed integer (full byte prefix, no upper bits).".
-spec dec8(bitstring()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec8(<<2#11111111:8, Rest/bits>>) ->
    dec_big(Rest, 255, 0);
dec8(<<Int:8, Rest/bits>>) ->
    {ok, Int, Rest};
dec8(_) ->
    {error, incomplete}.

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc "Encode a 3-bit prefixed integer. Prefix occupies the upper 5 bits.".
-spec enc3(non_neg_integer(), 0..31) -> binary().
enc3(Int, Prefix) when Int < 7 ->
    <<Prefix:5, Int:3>>;
enc3(Int, Prefix) ->
    enc_big(Int - 7, <<Prefix:5, 2#111:3>>).

-doc "Encode a 4-bit prefixed integer. Prefix occupies the upper 4 bits.".
-spec enc4(non_neg_integer(), 0..15) -> binary().
enc4(Int, Prefix) when Int < 15 ->
    <<Prefix:4, Int:4>>;
enc4(Int, Prefix) ->
    enc_big(Int - 15, <<Prefix:4, 2#1111:4>>).

-doc "Encode a 5-bit prefixed integer. Prefix occupies the upper 3 bits.".
-spec enc5(non_neg_integer(), 0..7) -> binary().
enc5(Int, Prefix) when Int < 31 ->
    <<Prefix:3, Int:5>>;
enc5(Int, Prefix) ->
    enc_big(Int - 31, <<Prefix:3, 2#11111:5>>).

-doc "Encode a 6-bit prefixed integer. Prefix occupies the upper 2 bits.".
-spec enc6(non_neg_integer(), 0..3) -> binary().
enc6(Int, Prefix) when Int < 63 ->
    <<Prefix:2, Int:6>>;
enc6(Int, Prefix) ->
    enc_big(Int - 63, <<Prefix:2, 2#111111:6>>).

-doc "Encode a 7-bit prefixed integer. Prefix occupies the upper 1 bit.".
-spec enc7(non_neg_integer(), 0..1) -> binary().
enc7(Int, Prefix) when Int < 127 ->
    <<Prefix:1, Int:7>>;
enc7(Int, Prefix) ->
    enc_big(Int - 127, <<Prefix:1, 2#1111111:7>>).

-doc "Encode an 8-bit prefixed integer (full byte prefix, no upper bits).".
-spec enc8(non_neg_integer()) -> binary().
enc8(Int) when Int < 255 ->
    <<Int:8>>;
enc8(Int) ->
    enc_big(Int - 255, <<2#11111111:8>>).

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec dec_big(bitstring(), non_neg_integer(), non_neg_integer()) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
dec_big(<<0:1, Value:7, Rest/bits>>, Int, M) ->
    Result = Int + (Value bsl M),
    case Result > ?MAX_INT of
        true -> {error, overflow};
        false -> {ok, Result, Rest}
    end;
dec_big(<<1:1, Value:7, Rest/bits>>, Int, M) ->
    Partial = Int + (Value bsl M),
    case Partial > ?MAX_INT of
        true -> {error, overflow};
        false -> dec_big(Rest, Partial, M + 7)
    end;
dec_big(<<>>, _, _) ->
    {error, incomplete};
dec_big(_, _, _) ->
    {error, incomplete}.

-spec enc_big(non_neg_integer(), binary()) -> binary().
enc_big(Int, Acc) when Int < 128 ->
    <<Acc/binary, Int:8>>;
enc_big(Int, Acc) ->
    enc_big(Int bsr 7, <<Acc/binary, 1:1, Int:7>>).
