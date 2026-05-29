-module(nhttp_huffman).

-moduledoc """
Static Huffman encoder/decoder for HPACK (RFC 7541 Appendix B).

This module implements the static Huffman table used by HPACK for
HTTP/2 header compression. The code table is optimized for HTTP
header values with common ASCII characters having shorter codes.

Decoding uses a generated 4-bit (nibble) finite state machine: each
state is a function clause that consumes one nibble of the input and
emits decoded bytes, which the BEAM compiles to a per-state jump table.
The encode function uses bit accumulation with proper EOS padding.
""".

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-export([encode/1]).

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-export([decode/1]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-export_type([decode_error/0]).

-type decode_error() :: invalid_huffman.

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc """
Encode a binary using the HPACK Huffman table.

The encoded binary is padded with EOS (all 1s) to the next byte boundary
as required by RFC 7541 Section 5.2.
""".
-spec encode(Data :: binary()) -> binary().
encode(Data) ->
    encode(Data, <<>>).

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a complete Huffman-encoded binary.

The input is a whole number of octets terminated by EOS padding (1-7
all-ones bits) to the byte boundary, as required by RFC 7541 Section
5.2. Returns `{ok, Decoded}`, or `{error, invalid_huffman}` if the
encoding is invalid (a non-all-ones or over-long pad, or an invalid
code).
""".
-spec decode(Data :: binary()) ->
    {ok, Decoded :: binary()} | {error, decode_error()}.
decode(Data) ->
    finalize_padding(s0(Data, <<>>)).

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------

-spec finalize_padding({ok, binary(), bitstring()} | {error, invalid_huffman}) ->
    {ok, binary()} | {error, invalid_huffman}.
finalize_padding({ok, Decoded, <<>>}) ->
    {ok, Decoded};
finalize_padding({ok, Decoded, Pad}) ->
    PadBits = bit_size(Pad),
    case PadBits =< 7 andalso Pad =:= <<((1 bsl PadBits) - 1):PadBits>> of
        true -> {ok, Decoded};
        false -> {error, invalid_huffman}
    end;
finalize_padding({error, invalid_huffman} = Error) ->
    Error.

s0(<<0:4, R/bits>>, A) -> s1(R, A);
s0(<<1:4, R/bits>>, A) -> s2(R, A);
s0(<<2:4, R/bits>>, A) -> s3(R, A);
s0(<<3:4, R/bits>>, A) -> s4(R, A);
s0(<<4:4, R/bits>>, A) -> s5(R, A);
s0(<<5:4, R/bits>>, A) -> s6(R, A);
s0(<<6:4, R/bits>>, A) -> s7(R, A);
s0(<<7:4, R/bits>>, A) -> s8(R, A);
s0(<<8:4, R/bits>>, A) -> s9(R, A);
s0(<<9:4, R/bits>>, A) -> s10(R, A);
s0(<<10:4, R/bits>>, A) -> s11(R, A);
s0(<<11:4, R/bits>>, A) -> s12(R, A);
s0(<<12:4, R/bits>>, A) -> s13(R, A);
s0(<<13:4, R/bits>>, A) -> s14(R, A);
s0(<<14:4, R/bits>>, A) -> s15(R, A);
s0(<<15:4, R/bits>>, A) -> s16(R, A);
s0(<<Rest/bits>>, A) -> {ok, A, Rest}.

s1(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 48>>);
s1(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 48>>);
s1(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 48>>);
s1(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 48>>);
s1(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 48>>);
s1(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 48>>);
s1(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 48>>);
s1(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 48>>);
s1(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 49>>);
s1(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 49>>);
s1(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 49>>);
s1(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 49>>);
s1(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 49>>);
s1(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 49>>);
s1(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 49>>);
s1(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 49>>);
s1(<<_/bits>>, _) -> {error, invalid_huffman}.

s2(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 50>>);
s2(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 50>>);
s2(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 50>>);
s2(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 50>>);
s2(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 50>>);
s2(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 50>>);
s2(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 50>>);
s2(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 50>>);
s2(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 97>>);
s2(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 97>>);
s2(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 97>>);
s2(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 97>>);
s2(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 97>>);
s2(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 97>>);
s2(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 97>>);
s2(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 97>>);
s2(<<_/bits>>, _) -> {error, invalid_huffman}.

s3(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 99>>);
s3(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 99>>);
s3(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 99>>);
s3(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 99>>);
s3(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 99>>);
s3(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 99>>);
s3(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 99>>);
s3(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 99>>);
s3(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 101>>);
s3(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 101>>);
s3(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 101>>);
s3(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 101>>);
s3(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 101>>);
s3(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 101>>);
s3(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 101>>);
s3(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 101>>);
s3(<<_/bits>>, _) -> {error, invalid_huffman}.

s4(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 105>>);
s4(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 105>>);
s4(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 105>>);
s4(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 105>>);
s4(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 105>>);
s4(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 105>>);
s4(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 105>>);
s4(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 105>>);
s4(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 111>>);
s4(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 111>>);
s4(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 111>>);
s4(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 111>>);
s4(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 111>>);
s4(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 111>>);
s4(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 111>>);
s4(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 111>>);
s4(<<_/bits>>, _) -> {error, invalid_huffman}.

s5(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 115>>);
s5(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 115>>);
s5(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 115>>);
s5(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 115>>);
s5(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 115>>);
s5(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 115>>);
s5(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 115>>);
s5(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 115>>);
s5(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 116>>);
s5(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 116>>);
s5(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 116>>);
s5(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 116>>);
s5(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 116>>);
s5(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 116>>);
s5(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 116>>);
s5(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 116>>);
s5(<<_/bits>>, _) -> {error, invalid_huffman}.

s6(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 32>>);
s6(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 32>>);
s6(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 32>>);
s6(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 32>>);
s6(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 37>>);
s6(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 37>>);
s6(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 37>>);
s6(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 37>>);
s6(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 45>>);
s6(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 45>>);
s6(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 45>>);
s6(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 45>>);
s6(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 46>>);
s6(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 46>>);
s6(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 46>>);
s6(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 46>>);
s6(<<_/bits>>, _) -> {error, invalid_huffman}.

s7(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 47>>);
s7(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 47>>);
s7(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 47>>);
s7(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 47>>);
s7(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 51>>);
s7(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 51>>);
s7(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 51>>);
s7(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 51>>);
s7(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 52>>);
s7(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 52>>);
s7(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 52>>);
s7(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 52>>);
s7(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 53>>);
s7(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 53>>);
s7(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 53>>);
s7(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 53>>);
s7(<<_/bits>>, _) -> {error, invalid_huffman}.

s8(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 54>>);
s8(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 54>>);
s8(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 54>>);
s8(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 54>>);
s8(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 55>>);
s8(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 55>>);
s8(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 55>>);
s8(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 55>>);
s8(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 56>>);
s8(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 56>>);
s8(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 56>>);
s8(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 56>>);
s8(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 57>>);
s8(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 57>>);
s8(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 57>>);
s8(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 57>>);
s8(<<_/bits>>, _) -> {error, invalid_huffman}.

s9(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 61>>);
s9(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 61>>);
s9(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 61>>);
s9(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 61>>);
s9(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 65>>);
s9(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 65>>);
s9(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 65>>);
s9(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 65>>);
s9(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 95>>);
s9(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 95>>);
s9(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 95>>);
s9(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 95>>);
s9(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 98>>);
s9(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 98>>);
s9(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 98>>);
s9(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 98>>);
s9(<<_/bits>>, _) -> {error, invalid_huffman}.

s10(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 100>>);
s10(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 100>>);
s10(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 100>>);
s10(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 100>>);
s10(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 102>>);
s10(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 102>>);
s10(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 102>>);
s10(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 102>>);
s10(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 103>>);
s10(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 103>>);
s10(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 103>>);
s10(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 103>>);
s10(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 104>>);
s10(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 104>>);
s10(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 104>>);
s10(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 104>>);
s10(<<_/bits>>, _) -> {error, invalid_huffman}.

s11(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 108>>);
s11(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 108>>);
s11(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 108>>);
s11(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 108>>);
s11(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 109>>);
s11(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 109>>);
s11(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 109>>);
s11(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 109>>);
s11(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 110>>);
s11(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 110>>);
s11(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 110>>);
s11(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 110>>);
s11(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 112>>);
s11(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 112>>);
s11(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 112>>);
s11(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 112>>);
s11(<<_/bits>>, _) -> {error, invalid_huffman}.

s12(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 114>>);
s12(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 114>>);
s12(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 114>>);
s12(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 114>>);
s12(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 117>>);
s12(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 117>>);
s12(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 117>>);
s12(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 117>>);
s12(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 58>>);
s12(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 58>>);
s12(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 66>>);
s12(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 66>>);
s12(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 67>>);
s12(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 67>>);
s12(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 68>>);
s12(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 68>>);
s12(<<_/bits>>, _) -> {error, invalid_huffman}.

s13(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 69>>);
s13(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 69>>);
s13(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 70>>);
s13(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 70>>);
s13(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 71>>);
s13(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 71>>);
s13(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 72>>);
s13(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 72>>);
s13(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 73>>);
s13(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 73>>);
s13(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 74>>);
s13(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 74>>);
s13(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 75>>);
s13(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 75>>);
s13(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 76>>);
s13(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 76>>);
s13(<<_/bits>>, _) -> {error, invalid_huffman}.

s14(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 77>>);
s14(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 77>>);
s14(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 78>>);
s14(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 78>>);
s14(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 79>>);
s14(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 79>>);
s14(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 80>>);
s14(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 80>>);
s14(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 81>>);
s14(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 81>>);
s14(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 82>>);
s14(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 82>>);
s14(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 83>>);
s14(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 83>>);
s14(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 84>>);
s14(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 84>>);
s14(<<_/bits>>, _) -> {error, invalid_huffman}.

s15(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 85>>);
s15(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 85>>);
s15(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 86>>);
s15(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 86>>);
s15(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 87>>);
s15(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 87>>);
s15(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 89>>);
s15(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 89>>);
s15(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 106>>);
s15(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 106>>);
s15(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 107>>);
s15(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 107>>);
s15(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 113>>);
s15(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 113>>);
s15(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 118>>);
s15(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 118>>);
s15(<<_/bits>>, _) -> {error, invalid_huffman}.

s16(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 119>>);
s16(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 119>>);
s16(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 120>>);
s16(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 120>>);
s16(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 121>>);
s16(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 121>>);
s16(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 122>>);
s16(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 122>>);
s16(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 38>>);
s16(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 42>>);
s16(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 44>>);
s16(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 59>>);
s16(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 88>>);
s16(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 90>>);
s16(<<14:4, R/bits>>, A) -> s31(R, A);
s16(<<15:4, R/bits>>, A) -> s32(R, A);
s16(<<Rest/bits>>, A) -> {ok, A, Rest}.

s17(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 48>>);
s17(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 48>>);
s17(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 48>>);
s17(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 48>>);
s17(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 49>>);
s17(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 49>>);
s17(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 49>>);
s17(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 49>>);
s17(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 50>>);
s17(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 50>>);
s17(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 50>>);
s17(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 50>>);
s17(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 97>>);
s17(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 97>>);
s17(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 97>>);
s17(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 97>>);
s17(<<_/bits>>, _) -> {error, invalid_huffman}.

s18(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 99>>);
s18(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 99>>);
s18(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 99>>);
s18(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 99>>);
s18(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 101>>);
s18(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 101>>);
s18(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 101>>);
s18(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 101>>);
s18(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 105>>);
s18(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 105>>);
s18(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 105>>);
s18(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 105>>);
s18(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 111>>);
s18(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 111>>);
s18(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 111>>);
s18(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 111>>);
s18(<<_/bits>>, _) -> {error, invalid_huffman}.

s19(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 115>>);
s19(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 115>>);
s19(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 115>>);
s19(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 115>>);
s19(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 116>>);
s19(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 116>>);
s19(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 116>>);
s19(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 116>>);
s19(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 32>>);
s19(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 32>>);
s19(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 37>>);
s19(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 37>>);
s19(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 45>>);
s19(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 45>>);
s19(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 46>>);
s19(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 46>>);
s19(<<_/bits>>, _) -> {error, invalid_huffman}.

s20(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 47>>);
s20(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 47>>);
s20(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 51>>);
s20(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 51>>);
s20(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 52>>);
s20(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 52>>);
s20(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 53>>);
s20(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 53>>);
s20(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 54>>);
s20(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 54>>);
s20(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 55>>);
s20(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 55>>);
s20(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 56>>);
s20(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 56>>);
s20(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 57>>);
s20(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 57>>);
s20(<<_/bits>>, _) -> {error, invalid_huffman}.

s21(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 61>>);
s21(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 61>>);
s21(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 65>>);
s21(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 65>>);
s21(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 95>>);
s21(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 95>>);
s21(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 98>>);
s21(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 98>>);
s21(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 100>>);
s21(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 100>>);
s21(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 102>>);
s21(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 102>>);
s21(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 103>>);
s21(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 103>>);
s21(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 104>>);
s21(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 104>>);
s21(<<_/bits>>, _) -> {error, invalid_huffman}.

s22(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 108>>);
s22(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 108>>);
s22(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 109>>);
s22(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 109>>);
s22(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 110>>);
s22(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 110>>);
s22(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 112>>);
s22(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 112>>);
s22(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 114>>);
s22(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 114>>);
s22(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 117>>);
s22(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 117>>);
s22(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 58>>);
s22(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 66>>);
s22(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 67>>);
s22(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 68>>);
s22(<<_/bits>>, _) -> {error, invalid_huffman}.

s23(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 69>>);
s23(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 70>>);
s23(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 71>>);
s23(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 72>>);
s23(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 73>>);
s23(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 74>>);
s23(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 75>>);
s23(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 76>>);
s23(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 77>>);
s23(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 78>>);
s23(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 79>>);
s23(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 80>>);
s23(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 81>>);
s23(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 82>>);
s23(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 83>>);
s23(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 84>>);
s23(<<_/bits>>, _) -> {error, invalid_huffman}.

s24(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 85>>);
s24(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 86>>);
s24(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 87>>);
s24(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 89>>);
s24(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 106>>);
s24(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 107>>);
s24(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 113>>);
s24(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 118>>);
s24(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 119>>);
s24(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 120>>);
s24(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 121>>);
s24(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 122>>);
s24(<<12:4, R/bits>>, A) -> s33(R, A);
s24(<<13:4, R/bits>>, A) -> s34(R, A);
s24(<<14:4, R/bits>>, A) -> s35(R, A);
s24(<<15:4, R/bits>>, A) -> s36(R, A);
s24(<<Rest/bits>>, A) -> {ok, A, Rest}.

s25(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 48>>);
s25(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 48>>);
s25(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 49>>);
s25(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 49>>);
s25(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 50>>);
s25(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 50>>);
s25(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 97>>);
s25(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 97>>);
s25(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 99>>);
s25(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 99>>);
s25(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 101>>);
s25(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 101>>);
s25(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 105>>);
s25(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 105>>);
s25(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 111>>);
s25(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 111>>);
s25(<<_/bits>>, _) -> {error, invalid_huffman}.

s26(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 115>>);
s26(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 115>>);
s26(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 116>>);
s26(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 116>>);
s26(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 32>>);
s26(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 37>>);
s26(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 45>>);
s26(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 46>>);
s26(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 47>>);
s26(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 51>>);
s26(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 52>>);
s26(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 53>>);
s26(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 54>>);
s26(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 55>>);
s26(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 56>>);
s26(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 57>>);
s26(<<_/bits>>, _) -> {error, invalid_huffman}.

s27(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 61>>);
s27(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 65>>);
s27(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 95>>);
s27(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 98>>);
s27(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 100>>);
s27(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 102>>);
s27(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 103>>);
s27(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 104>>);
s27(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 108>>);
s27(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 109>>);
s27(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 110>>);
s27(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 112>>);
s27(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 114>>);
s27(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 117>>);
s27(<<14:4, R/bits>>, A) -> s37(R, A);
s27(<<15:4, R/bits>>, A) -> s38(R, A);
s27(<<_/bits>>, _) -> {error, invalid_huffman}.

s28(<<0:4, R/bits>>, A) -> s39(R, A);
s28(<<1:4, R/bits>>, A) -> s40(R, A);
s28(<<2:4, R/bits>>, A) -> s41(R, A);
s28(<<3:4, R/bits>>, A) -> s42(R, A);
s28(<<4:4, R/bits>>, A) -> s43(R, A);
s28(<<5:4, R/bits>>, A) -> s44(R, A);
s28(<<6:4, R/bits>>, A) -> s45(R, A);
s28(<<7:4, R/bits>>, A) -> s46(R, A);
s28(<<8:4, R/bits>>, A) -> s47(R, A);
s28(<<9:4, R/bits>>, A) -> s48(R, A);
s28(<<10:4, R/bits>>, A) -> s49(R, A);
s28(<<11:4, R/bits>>, A) -> s50(R, A);
s28(<<12:4, R/bits>>, A) -> s51(R, A);
s28(<<13:4, R/bits>>, A) -> s52(R, A);
s28(<<14:4, R/bits>>, A) -> s53(R, A);
s28(<<15:4, R/bits>>, A) -> s54(R, A);
s28(<<Rest/bits>>, A) -> {ok, A, Rest}.

s29(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 48>>);
s29(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 49>>);
s29(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 50>>);
s29(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 97>>);
s29(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 99>>);
s29(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 101>>);
s29(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 105>>);
s29(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 111>>);
s29(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 115>>);
s29(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 116>>);
s29(<<10:4, R/bits>>, A) -> s55(R, A);
s29(<<11:4, R/bits>>, A) -> s56(R, A);
s29(<<12:4, R/bits>>, A) -> s57(R, A);
s29(<<13:4, R/bits>>, A) -> s58(R, A);
s29(<<14:4, R/bits>>, A) -> s59(R, A);
s29(<<15:4, R/bits>>, A) -> s60(R, A);
s29(<<_/bits>>, _) -> {error, invalid_huffman}.

s30(<<0:4, R/bits>>, A) -> s61(R, A);
s30(<<1:4, R/bits>>, A) -> s62(R, A);
s30(<<2:4, R/bits>>, A) -> s63(R, A);
s30(<<3:4, R/bits>>, A) -> s64(R, A);
s30(<<4:4, R/bits>>, A) -> s65(R, A);
s30(<<5:4, R/bits>>, A) -> s66(R, A);
s30(<<6:4, R/bits>>, A) -> s67(R, A);
s30(<<7:4, R/bits>>, A) -> s68(R, A);
s30(<<8:4, R/bits>>, A) -> s69(R, A);
s30(<<9:4, R/bits>>, A) -> s70(R, A);
s30(<<10:4, R/bits>>, A) -> s71(R, A);
s30(<<11:4, R/bits>>, A) -> s72(R, A);
s30(<<12:4, R/bits>>, A) -> s73(R, A);
s30(<<13:4, R/bits>>, A) -> s74(R, A);
s30(<<14:4, R/bits>>, A) -> s75(R, A);
s30(<<15:4, R/bits>>, A) -> s76(R, A);
s30(<<Rest/bits>>, A) -> {ok, A, Rest}.

s31(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 33>>);
s31(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 33>>);
s31(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 33>>);
s31(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 33>>);
s31(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 34>>);
s31(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 34>>);
s31(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 34>>);
s31(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 34>>);
s31(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 40>>);
s31(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 40>>);
s31(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 40>>);
s31(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 40>>);
s31(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 41>>);
s31(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 41>>);
s31(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 41>>);
s31(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 41>>);
s31(<<_/bits>>, _) -> {error, invalid_huffman}.

s32(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 63>>);
s32(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 63>>);
s32(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 63>>);
s32(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 63>>);
s32(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 39>>);
s32(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 39>>);
s32(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 43>>);
s32(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 43>>);
s32(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 124>>);
s32(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 124>>);
s32(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 35>>);
s32(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 62>>);
s32(<<12:4, R/bits>>, A) -> s77(R, A);
s32(<<13:4, R/bits>>, A) -> s78(R, A);
s32(<<14:4, R/bits>>, A) -> s79(R, A);
s32(<<15:4, R/bits>>, A) -> s80(R, A);
s32(<<_/bits>>, _) -> {error, invalid_huffman}.

s33(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 38>>);
s33(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 38>>);
s33(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 38>>);
s33(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 38>>);
s33(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 38>>);
s33(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 38>>);
s33(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 38>>);
s33(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 38>>);
s33(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 42>>);
s33(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 42>>);
s33(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 42>>);
s33(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 42>>);
s33(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 42>>);
s33(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 42>>);
s33(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 42>>);
s33(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 42>>);
s33(<<_/bits>>, _) -> {error, invalid_huffman}.

s34(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 44>>);
s34(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 44>>);
s34(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 44>>);
s34(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 44>>);
s34(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 44>>);
s34(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 44>>);
s34(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 44>>);
s34(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 44>>);
s34(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 59>>);
s34(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 59>>);
s34(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 59>>);
s34(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 59>>);
s34(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 59>>);
s34(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 59>>);
s34(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 59>>);
s34(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 59>>);
s34(<<_/bits>>, _) -> {error, invalid_huffman}.

s35(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 88>>);
s35(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 88>>);
s35(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 88>>);
s35(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 88>>);
s35(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 88>>);
s35(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 88>>);
s35(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 88>>);
s35(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 88>>);
s35(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 90>>);
s35(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 90>>);
s35(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 90>>);
s35(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 90>>);
s35(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 90>>);
s35(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 90>>);
s35(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 90>>);
s35(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 90>>);
s35(<<_/bits>>, _) -> {error, invalid_huffman}.

s36(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 33>>);
s36(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 33>>);
s36(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 34>>);
s36(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 34>>);
s36(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 40>>);
s36(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 40>>);
s36(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 41>>);
s36(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 41>>);
s36(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 63>>);
s36(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 63>>);
s36(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 39>>);
s36(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 43>>);
s36(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 124>>);
s36(<<13:4, R/bits>>, A) -> s81(R, A);
s36(<<14:4, R/bits>>, A) -> s82(R, A);
s36(<<15:4, R/bits>>, A) -> s83(R, A);
s36(<<Rest/bits>>, A) -> {ok, A, Rest}.

s37(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 58>>);
s37(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 58>>);
s37(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 58>>);
s37(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 58>>);
s37(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 58>>);
s37(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 58>>);
s37(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 58>>);
s37(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 58>>);
s37(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 66>>);
s37(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 66>>);
s37(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 66>>);
s37(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 66>>);
s37(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 66>>);
s37(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 66>>);
s37(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 66>>);
s37(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 66>>);
s37(<<_/bits>>, _) -> {error, invalid_huffman}.

s38(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 67>>);
s38(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 67>>);
s38(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 67>>);
s38(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 67>>);
s38(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 67>>);
s38(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 67>>);
s38(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 67>>);
s38(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 67>>);
s38(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 68>>);
s38(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 68>>);
s38(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 68>>);
s38(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 68>>);
s38(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 68>>);
s38(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 68>>);
s38(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 68>>);
s38(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 68>>);
s38(<<_/bits>>, _) -> {error, invalid_huffman}.

s39(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 69>>);
s39(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 69>>);
s39(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 69>>);
s39(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 69>>);
s39(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 69>>);
s39(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 69>>);
s39(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 69>>);
s39(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 69>>);
s39(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 70>>);
s39(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 70>>);
s39(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 70>>);
s39(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 70>>);
s39(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 70>>);
s39(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 70>>);
s39(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 70>>);
s39(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 70>>);
s39(<<_/bits>>, _) -> {error, invalid_huffman}.

s40(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 71>>);
s40(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 71>>);
s40(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 71>>);
s40(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 71>>);
s40(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 71>>);
s40(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 71>>);
s40(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 71>>);
s40(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 71>>);
s40(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 72>>);
s40(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 72>>);
s40(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 72>>);
s40(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 72>>);
s40(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 72>>);
s40(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 72>>);
s40(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 72>>);
s40(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 72>>);
s40(<<_/bits>>, _) -> {error, invalid_huffman}.

s41(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 73>>);
s41(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 73>>);
s41(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 73>>);
s41(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 73>>);
s41(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 73>>);
s41(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 73>>);
s41(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 73>>);
s41(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 73>>);
s41(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 74>>);
s41(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 74>>);
s41(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 74>>);
s41(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 74>>);
s41(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 74>>);
s41(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 74>>);
s41(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 74>>);
s41(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 74>>);
s41(<<_/bits>>, _) -> {error, invalid_huffman}.

s42(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 75>>);
s42(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 75>>);
s42(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 75>>);
s42(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 75>>);
s42(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 75>>);
s42(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 75>>);
s42(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 75>>);
s42(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 75>>);
s42(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 76>>);
s42(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 76>>);
s42(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 76>>);
s42(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 76>>);
s42(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 76>>);
s42(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 76>>);
s42(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 76>>);
s42(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 76>>);
s42(<<_/bits>>, _) -> {error, invalid_huffman}.

s43(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 77>>);
s43(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 77>>);
s43(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 77>>);
s43(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 77>>);
s43(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 77>>);
s43(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 77>>);
s43(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 77>>);
s43(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 77>>);
s43(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 78>>);
s43(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 78>>);
s43(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 78>>);
s43(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 78>>);
s43(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 78>>);
s43(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 78>>);
s43(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 78>>);
s43(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 78>>);
s43(<<_/bits>>, _) -> {error, invalid_huffman}.

s44(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 79>>);
s44(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 79>>);
s44(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 79>>);
s44(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 79>>);
s44(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 79>>);
s44(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 79>>);
s44(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 79>>);
s44(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 79>>);
s44(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 80>>);
s44(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 80>>);
s44(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 80>>);
s44(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 80>>);
s44(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 80>>);
s44(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 80>>);
s44(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 80>>);
s44(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 80>>);
s44(<<_/bits>>, _) -> {error, invalid_huffman}.

s45(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 81>>);
s45(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 81>>);
s45(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 81>>);
s45(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 81>>);
s45(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 81>>);
s45(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 81>>);
s45(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 81>>);
s45(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 81>>);
s45(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 82>>);
s45(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 82>>);
s45(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 82>>);
s45(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 82>>);
s45(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 82>>);
s45(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 82>>);
s45(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 82>>);
s45(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 82>>);
s45(<<_/bits>>, _) -> {error, invalid_huffman}.

s46(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 83>>);
s46(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 83>>);
s46(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 83>>);
s46(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 83>>);
s46(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 83>>);
s46(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 83>>);
s46(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 83>>);
s46(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 83>>);
s46(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 84>>);
s46(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 84>>);
s46(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 84>>);
s46(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 84>>);
s46(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 84>>);
s46(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 84>>);
s46(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 84>>);
s46(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 84>>);
s46(<<_/bits>>, _) -> {error, invalid_huffman}.

s47(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 85>>);
s47(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 85>>);
s47(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 85>>);
s47(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 85>>);
s47(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 85>>);
s47(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 85>>);
s47(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 85>>);
s47(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 85>>);
s47(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 86>>);
s47(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 86>>);
s47(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 86>>);
s47(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 86>>);
s47(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 86>>);
s47(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 86>>);
s47(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 86>>);
s47(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 86>>);
s47(<<_/bits>>, _) -> {error, invalid_huffman}.

s48(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 87>>);
s48(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 87>>);
s48(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 87>>);
s48(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 87>>);
s48(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 87>>);
s48(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 87>>);
s48(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 87>>);
s48(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 87>>);
s48(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 89>>);
s48(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 89>>);
s48(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 89>>);
s48(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 89>>);
s48(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 89>>);
s48(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 89>>);
s48(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 89>>);
s48(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 89>>);
s48(<<_/bits>>, _) -> {error, invalid_huffman}.

s49(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 106>>);
s49(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 106>>);
s49(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 106>>);
s49(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 106>>);
s49(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 106>>);
s49(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 106>>);
s49(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 106>>);
s49(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 106>>);
s49(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 107>>);
s49(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 107>>);
s49(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 107>>);
s49(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 107>>);
s49(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 107>>);
s49(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 107>>);
s49(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 107>>);
s49(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 107>>);
s49(<<_/bits>>, _) -> {error, invalid_huffman}.

s50(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 113>>);
s50(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 113>>);
s50(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 113>>);
s50(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 113>>);
s50(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 113>>);
s50(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 113>>);
s50(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 113>>);
s50(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 113>>);
s50(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 118>>);
s50(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 118>>);
s50(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 118>>);
s50(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 118>>);
s50(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 118>>);
s50(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 118>>);
s50(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 118>>);
s50(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 118>>);
s50(<<_/bits>>, _) -> {error, invalid_huffman}.

s51(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 119>>);
s51(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 119>>);
s51(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 119>>);
s51(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 119>>);
s51(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 119>>);
s51(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 119>>);
s51(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 119>>);
s51(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 119>>);
s51(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 120>>);
s51(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 120>>);
s51(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 120>>);
s51(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 120>>);
s51(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 120>>);
s51(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 120>>);
s51(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 120>>);
s51(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 120>>);
s51(<<_/bits>>, _) -> {error, invalid_huffman}.

s52(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 121>>);
s52(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 121>>);
s52(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 121>>);
s52(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 121>>);
s52(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 121>>);
s52(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 121>>);
s52(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 121>>);
s52(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 121>>);
s52(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 122>>);
s52(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 122>>);
s52(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 122>>);
s52(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 122>>);
s52(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 122>>);
s52(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 122>>);
s52(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 122>>);
s52(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 122>>);
s52(<<_/bits>>, _) -> {error, invalid_huffman}.

s53(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 38>>);
s53(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 38>>);
s53(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 38>>);
s53(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 38>>);
s53(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 42>>);
s53(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 42>>);
s53(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 42>>);
s53(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 42>>);
s53(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 44>>);
s53(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 44>>);
s53(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 44>>);
s53(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 44>>);
s53(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 59>>);
s53(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 59>>);
s53(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 59>>);
s53(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 59>>);
s53(<<_/bits>>, _) -> {error, invalid_huffman}.

s54(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 88>>);
s54(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 88>>);
s54(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 88>>);
s54(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 88>>);
s54(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 90>>);
s54(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 90>>);
s54(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 90>>);
s54(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 90>>);
s54(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 33>>);
s54(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 34>>);
s54(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 40>>);
s54(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 41>>);
s54(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 63>>);
s54(<<13:4, R/bits>>, A) -> s84(R, A);
s54(<<14:4, R/bits>>, A) -> s85(R, A);
s54(<<15:4, R/bits>>, A) -> s86(R, A);
s54(<<Rest/bits>>, A) -> {ok, A, Rest}.

s55(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 32>>);
s55(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 32>>);
s55(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 32>>);
s55(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 32>>);
s55(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 32>>);
s55(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 32>>);
s55(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 32>>);
s55(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 32>>);
s55(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 37>>);
s55(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 37>>);
s55(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 37>>);
s55(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 37>>);
s55(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 37>>);
s55(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 37>>);
s55(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 37>>);
s55(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 37>>);
s55(<<_/bits>>, _) -> {error, invalid_huffman}.

s56(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 45>>);
s56(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 45>>);
s56(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 45>>);
s56(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 45>>);
s56(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 45>>);
s56(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 45>>);
s56(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 45>>);
s56(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 45>>);
s56(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 46>>);
s56(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 46>>);
s56(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 46>>);
s56(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 46>>);
s56(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 46>>);
s56(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 46>>);
s56(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 46>>);
s56(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 46>>);
s56(<<_/bits>>, _) -> {error, invalid_huffman}.

s57(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 47>>);
s57(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 47>>);
s57(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 47>>);
s57(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 47>>);
s57(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 47>>);
s57(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 47>>);
s57(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 47>>);
s57(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 47>>);
s57(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 51>>);
s57(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 51>>);
s57(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 51>>);
s57(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 51>>);
s57(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 51>>);
s57(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 51>>);
s57(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 51>>);
s57(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 51>>);
s57(<<_/bits>>, _) -> {error, invalid_huffman}.

s58(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 52>>);
s58(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 52>>);
s58(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 52>>);
s58(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 52>>);
s58(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 52>>);
s58(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 52>>);
s58(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 52>>);
s58(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 52>>);
s58(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 53>>);
s58(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 53>>);
s58(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 53>>);
s58(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 53>>);
s58(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 53>>);
s58(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 53>>);
s58(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 53>>);
s58(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 53>>);
s58(<<_/bits>>, _) -> {error, invalid_huffman}.

s59(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 54>>);
s59(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 54>>);
s59(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 54>>);
s59(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 54>>);
s59(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 54>>);
s59(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 54>>);
s59(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 54>>);
s59(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 54>>);
s59(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 55>>);
s59(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 55>>);
s59(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 55>>);
s59(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 55>>);
s59(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 55>>);
s59(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 55>>);
s59(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 55>>);
s59(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 55>>);
s59(<<_/bits>>, _) -> {error, invalid_huffman}.

s60(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 56>>);
s60(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 56>>);
s60(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 56>>);
s60(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 56>>);
s60(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 56>>);
s60(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 56>>);
s60(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 56>>);
s60(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 56>>);
s60(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 57>>);
s60(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 57>>);
s60(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 57>>);
s60(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 57>>);
s60(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 57>>);
s60(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 57>>);
s60(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 57>>);
s60(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 57>>);
s60(<<_/bits>>, _) -> {error, invalid_huffman}.

s61(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 61>>);
s61(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 61>>);
s61(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 61>>);
s61(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 61>>);
s61(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 61>>);
s61(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 61>>);
s61(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 61>>);
s61(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 61>>);
s61(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 65>>);
s61(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 65>>);
s61(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 65>>);
s61(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 65>>);
s61(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 65>>);
s61(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 65>>);
s61(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 65>>);
s61(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 65>>);
s61(<<_/bits>>, _) -> {error, invalid_huffman}.

s62(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 95>>);
s62(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 95>>);
s62(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 95>>);
s62(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 95>>);
s62(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 95>>);
s62(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 95>>);
s62(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 95>>);
s62(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 95>>);
s62(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 98>>);
s62(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 98>>);
s62(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 98>>);
s62(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 98>>);
s62(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 98>>);
s62(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 98>>);
s62(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 98>>);
s62(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 98>>);
s62(<<_/bits>>, _) -> {error, invalid_huffman}.

s63(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 100>>);
s63(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 100>>);
s63(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 100>>);
s63(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 100>>);
s63(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 100>>);
s63(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 100>>);
s63(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 100>>);
s63(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 100>>);
s63(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 102>>);
s63(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 102>>);
s63(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 102>>);
s63(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 102>>);
s63(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 102>>);
s63(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 102>>);
s63(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 102>>);
s63(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 102>>);
s63(<<_/bits>>, _) -> {error, invalid_huffman}.

s64(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 103>>);
s64(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 103>>);
s64(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 103>>);
s64(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 103>>);
s64(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 103>>);
s64(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 103>>);
s64(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 103>>);
s64(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 103>>);
s64(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 104>>);
s64(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 104>>);
s64(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 104>>);
s64(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 104>>);
s64(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 104>>);
s64(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 104>>);
s64(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 104>>);
s64(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 104>>);
s64(<<_/bits>>, _) -> {error, invalid_huffman}.

s65(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 108>>);
s65(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 108>>);
s65(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 108>>);
s65(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 108>>);
s65(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 108>>);
s65(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 108>>);
s65(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 108>>);
s65(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 108>>);
s65(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 109>>);
s65(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 109>>);
s65(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 109>>);
s65(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 109>>);
s65(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 109>>);
s65(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 109>>);
s65(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 109>>);
s65(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 109>>);
s65(<<_/bits>>, _) -> {error, invalid_huffman}.

s66(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 110>>);
s66(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 110>>);
s66(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 110>>);
s66(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 110>>);
s66(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 110>>);
s66(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 110>>);
s66(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 110>>);
s66(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 110>>);
s66(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 112>>);
s66(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 112>>);
s66(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 112>>);
s66(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 112>>);
s66(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 112>>);
s66(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 112>>);
s66(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 112>>);
s66(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 112>>);
s66(<<_/bits>>, _) -> {error, invalid_huffman}.

s67(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 114>>);
s67(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 114>>);
s67(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 114>>);
s67(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 114>>);
s67(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 114>>);
s67(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 114>>);
s67(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 114>>);
s67(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 114>>);
s67(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 117>>);
s67(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 117>>);
s67(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 117>>);
s67(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 117>>);
s67(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 117>>);
s67(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 117>>);
s67(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 117>>);
s67(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 117>>);
s67(<<_/bits>>, _) -> {error, invalid_huffman}.

s68(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 58>>);
s68(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 58>>);
s68(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 58>>);
s68(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 58>>);
s68(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 66>>);
s68(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 66>>);
s68(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 66>>);
s68(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 66>>);
s68(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 67>>);
s68(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 67>>);
s68(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 67>>);
s68(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 67>>);
s68(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 68>>);
s68(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 68>>);
s68(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 68>>);
s68(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 68>>);
s68(<<_/bits>>, _) -> {error, invalid_huffman}.

s69(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 69>>);
s69(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 69>>);
s69(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 69>>);
s69(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 69>>);
s69(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 70>>);
s69(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 70>>);
s69(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 70>>);
s69(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 70>>);
s69(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 71>>);
s69(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 71>>);
s69(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 71>>);
s69(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 71>>);
s69(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 72>>);
s69(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 72>>);
s69(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 72>>);
s69(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 72>>);
s69(<<_/bits>>, _) -> {error, invalid_huffman}.

s70(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 73>>);
s70(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 73>>);
s70(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 73>>);
s70(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 73>>);
s70(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 74>>);
s70(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 74>>);
s70(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 74>>);
s70(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 74>>);
s70(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 75>>);
s70(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 75>>);
s70(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 75>>);
s70(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 75>>);
s70(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 76>>);
s70(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 76>>);
s70(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 76>>);
s70(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 76>>);
s70(<<_/bits>>, _) -> {error, invalid_huffman}.

s71(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 77>>);
s71(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 77>>);
s71(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 77>>);
s71(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 77>>);
s71(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 78>>);
s71(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 78>>);
s71(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 78>>);
s71(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 78>>);
s71(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 79>>);
s71(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 79>>);
s71(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 79>>);
s71(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 79>>);
s71(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 80>>);
s71(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 80>>);
s71(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 80>>);
s71(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 80>>);
s71(<<_/bits>>, _) -> {error, invalid_huffman}.

s72(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 81>>);
s72(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 81>>);
s72(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 81>>);
s72(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 81>>);
s72(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 82>>);
s72(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 82>>);
s72(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 82>>);
s72(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 82>>);
s72(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 83>>);
s72(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 83>>);
s72(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 83>>);
s72(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 83>>);
s72(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 84>>);
s72(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 84>>);
s72(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 84>>);
s72(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 84>>);
s72(<<_/bits>>, _) -> {error, invalid_huffman}.

s73(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 85>>);
s73(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 85>>);
s73(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 85>>);
s73(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 85>>);
s73(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 86>>);
s73(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 86>>);
s73(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 86>>);
s73(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 86>>);
s73(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 87>>);
s73(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 87>>);
s73(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 87>>);
s73(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 87>>);
s73(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 89>>);
s73(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 89>>);
s73(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 89>>);
s73(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 89>>);
s73(<<_/bits>>, _) -> {error, invalid_huffman}.

s74(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 106>>);
s74(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 106>>);
s74(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 106>>);
s74(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 106>>);
s74(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 107>>);
s74(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 107>>);
s74(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 107>>);
s74(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 107>>);
s74(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 113>>);
s74(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 113>>);
s74(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 113>>);
s74(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 113>>);
s74(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 118>>);
s74(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 118>>);
s74(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 118>>);
s74(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 118>>);
s74(<<_/bits>>, _) -> {error, invalid_huffman}.

s75(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 119>>);
s75(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 119>>);
s75(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 119>>);
s75(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 119>>);
s75(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 120>>);
s75(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 120>>);
s75(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 120>>);
s75(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 120>>);
s75(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 121>>);
s75(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 121>>);
s75(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 121>>);
s75(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 121>>);
s75(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 122>>);
s75(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 122>>);
s75(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 122>>);
s75(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 122>>);
s75(<<_/bits>>, _) -> {error, invalid_huffman}.

s76(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 38>>);
s76(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 38>>);
s76(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 42>>);
s76(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 42>>);
s76(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 44>>);
s76(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 44>>);
s76(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 59>>);
s76(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 59>>);
s76(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 88>>);
s76(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 88>>);
s76(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 90>>);
s76(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 90>>);
s76(<<12:4, R/bits>>, A) -> s87(R, A);
s76(<<13:4, R/bits>>, A) -> s88(R, A);
s76(<<14:4, R/bits>>, A) -> s89(R, A);
s76(<<15:4, R/bits>>, A) -> s90(R, A);
s76(<<Rest/bits>>, A) -> {ok, A, Rest}.

s77(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 0>>);
s77(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 0>>);
s77(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 0>>);
s77(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 0>>);
s77(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 0>>);
s77(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 0>>);
s77(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 0>>);
s77(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 0>>);
s77(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 36>>);
s77(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 36>>);
s77(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 36>>);
s77(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 36>>);
s77(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 36>>);
s77(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 36>>);
s77(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 36>>);
s77(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 36>>);
s77(<<_/bits>>, _) -> {error, invalid_huffman}.

s78(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 64>>);
s78(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 64>>);
s78(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 64>>);
s78(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 64>>);
s78(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 64>>);
s78(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 64>>);
s78(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 64>>);
s78(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 64>>);
s78(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 91>>);
s78(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 91>>);
s78(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 91>>);
s78(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 91>>);
s78(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 91>>);
s78(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 91>>);
s78(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 91>>);
s78(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 91>>);
s78(<<_/bits>>, _) -> {error, invalid_huffman}.

s79(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 93>>);
s79(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 93>>);
s79(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 93>>);
s79(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 93>>);
s79(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 93>>);
s79(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 93>>);
s79(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 93>>);
s79(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 93>>);
s79(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 126>>);
s79(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 126>>);
s79(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 126>>);
s79(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 126>>);
s79(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 126>>);
s79(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 126>>);
s79(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 126>>);
s79(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 126>>);
s79(<<_/bits>>, _) -> {error, invalid_huffman}.

s80(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 94>>);
s80(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 94>>);
s80(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 94>>);
s80(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 94>>);
s80(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 125>>);
s80(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 125>>);
s80(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 125>>);
s80(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 125>>);
s80(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 60>>);
s80(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 60>>);
s80(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 96>>);
s80(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 96>>);
s80(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 123>>);
s80(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 123>>);
s80(<<14:4, R/bits>>, A) -> s91(R, A);
s80(<<15:4, R/bits>>, A) -> s92(R, A);
s80(<<_/bits>>, _) -> {error, invalid_huffman}.

s81(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 35>>);
s81(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 35>>);
s81(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 35>>);
s81(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 35>>);
s81(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 35>>);
s81(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 35>>);
s81(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 35>>);
s81(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 35>>);
s81(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 62>>);
s81(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 62>>);
s81(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 62>>);
s81(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 62>>);
s81(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 62>>);
s81(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 62>>);
s81(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 62>>);
s81(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 62>>);
s81(<<_/bits>>, _) -> {error, invalid_huffman}.

s82(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 0>>);
s82(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 0>>);
s82(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 0>>);
s82(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 0>>);
s82(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 36>>);
s82(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 36>>);
s82(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 36>>);
s82(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 36>>);
s82(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 64>>);
s82(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 64>>);
s82(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 64>>);
s82(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 64>>);
s82(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 91>>);
s82(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 91>>);
s82(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 91>>);
s82(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 91>>);
s82(<<_/bits>>, _) -> {error, invalid_huffman}.

s83(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 93>>);
s83(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 93>>);
s83(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 93>>);
s83(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 93>>);
s83(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 126>>);
s83(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 126>>);
s83(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 126>>);
s83(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 126>>);
s83(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 94>>);
s83(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 94>>);
s83(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 125>>);
s83(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 125>>);
s83(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 60>>);
s83(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 96>>);
s83(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 123>>);
s83(<<15:4, R/bits>>, A) -> s93(R, A);
s83(<<_/bits>>, _) -> {error, invalid_huffman}.

s84(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 39>>);
s84(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 39>>);
s84(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 39>>);
s84(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 39>>);
s84(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 39>>);
s84(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 39>>);
s84(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 39>>);
s84(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 39>>);
s84(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 43>>);
s84(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 43>>);
s84(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 43>>);
s84(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 43>>);
s84(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 43>>);
s84(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 43>>);
s84(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 43>>);
s84(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 43>>);
s84(<<_/bits>>, _) -> {error, invalid_huffman}.

s85(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 124>>);
s85(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 124>>);
s85(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 124>>);
s85(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 124>>);
s85(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 124>>);
s85(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 124>>);
s85(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 124>>);
s85(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 124>>);
s85(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 35>>);
s85(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 35>>);
s85(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 35>>);
s85(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 35>>);
s85(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 62>>);
s85(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 62>>);
s85(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 62>>);
s85(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 62>>);
s85(<<_/bits>>, _) -> {error, invalid_huffman}.

s86(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 0>>);
s86(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 0>>);
s86(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 36>>);
s86(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 36>>);
s86(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 64>>);
s86(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 64>>);
s86(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 91>>);
s86(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 91>>);
s86(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 93>>);
s86(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 93>>);
s86(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 126>>);
s86(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 126>>);
s86(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 94>>);
s86(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 125>>);
s86(<<14:4, R/bits>>, A) -> s94(R, A);
s86(<<15:4, R/bits>>, A) -> s95(R, A);
s86(<<_/bits>>, _) -> {error, invalid_huffman}.

s87(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 33>>);
s87(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 33>>);
s87(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 33>>);
s87(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 33>>);
s87(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 33>>);
s87(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 33>>);
s87(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 33>>);
s87(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 33>>);
s87(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 34>>);
s87(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 34>>);
s87(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 34>>);
s87(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 34>>);
s87(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 34>>);
s87(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 34>>);
s87(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 34>>);
s87(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 34>>);
s87(<<_/bits>>, _) -> {error, invalid_huffman}.

s88(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 40>>);
s88(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 40>>);
s88(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 40>>);
s88(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 40>>);
s88(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 40>>);
s88(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 40>>);
s88(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 40>>);
s88(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 40>>);
s88(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 41>>);
s88(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 41>>);
s88(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 41>>);
s88(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 41>>);
s88(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 41>>);
s88(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 41>>);
s88(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 41>>);
s88(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 41>>);
s88(<<_/bits>>, _) -> {error, invalid_huffman}.

s89(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 63>>);
s89(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 63>>);
s89(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 63>>);
s89(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 63>>);
s89(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 63>>);
s89(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 63>>);
s89(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 63>>);
s89(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 63>>);
s89(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 39>>);
s89(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 39>>);
s89(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 39>>);
s89(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 39>>);
s89(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 43>>);
s89(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 43>>);
s89(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 43>>);
s89(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 43>>);
s89(<<_/bits>>, _) -> {error, invalid_huffman}.

s90(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 124>>);
s90(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 124>>);
s90(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 124>>);
s90(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 124>>);
s90(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 35>>);
s90(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 35>>);
s90(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 62>>);
s90(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 62>>);
s90(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 0>>);
s90(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 36>>);
s90(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 64>>);
s90(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 91>>);
s90(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 93>>);
s90(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 126>>);
s90(<<14:4, R/bits>>, A) -> s96(R, A);
s90(<<15:4, R/bits>>, A) -> s97(R, A);
s90(<<_/bits>>, _) -> {error, invalid_huffman}.

s91(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 92>>);
s91(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 92>>);
s91(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 195>>);
s91(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 195>>);
s91(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 208>>);
s91(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 208>>);
s91(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 128>>);
s91(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 130>>);
s91(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 131>>);
s91(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 162>>);
s91(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 184>>);
s91(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 194>>);
s91(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 224>>);
s91(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 226>>);
s91(<<14:4, R/bits>>, A) -> s98(R, A);
s91(<<15:4, R/bits>>, A) -> s99(R, A);
s91(<<_/bits>>, _) -> {error, invalid_huffman}.

s92(<<0:4, R/bits>>, A) -> s100(R, A);
s92(<<1:4, R/bits>>, A) -> s101(R, A);
s92(<<2:4, R/bits>>, A) -> s102(R, A);
s92(<<3:4, R/bits>>, A) -> s103(R, A);
s92(<<4:4, R/bits>>, A) -> s104(R, A);
s92(<<5:4, R/bits>>, A) -> s105(R, A);
s92(<<6:4, R/bits>>, A) -> s106(R, A);
s92(<<7:4, R/bits>>, A) -> s107(R, A);
s92(<<8:4, R/bits>>, A) -> s108(R, A);
s92(<<9:4, R/bits>>, A) -> s109(R, A);
s92(<<10:4, R/bits>>, A) -> s110(R, A);
s92(<<11:4, R/bits>>, A) -> s111(R, A);
s92(<<12:4, R/bits>>, A) -> s112(R, A);
s92(<<13:4, R/bits>>, A) -> s113(R, A);
s92(<<14:4, R/bits>>, A) -> s114(R, A);
s92(<<15:4, R/bits>>, A) -> s115(R, A);
s92(<<_/bits>>, _) -> {error, invalid_huffman}.

s93(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 92>>);
s93(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 195>>);
s93(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 208>>);
s93(<<3:4, R/bits>>, A) -> s116(R, A);
s93(<<4:4, R/bits>>, A) -> s117(R, A);
s93(<<5:4, R/bits>>, A) -> s118(R, A);
s93(<<6:4, R/bits>>, A) -> s119(R, A);
s93(<<7:4, R/bits>>, A) -> s120(R, A);
s93(<<8:4, R/bits>>, A) -> s121(R, A);
s93(<<9:4, R/bits>>, A) -> s122(R, A);
s93(<<10:4, R/bits>>, A) -> s123(R, A);
s93(<<11:4, R/bits>>, A) -> s124(R, A);
s93(<<12:4, R/bits>>, A) -> s125(R, A);
s93(<<13:4, R/bits>>, A) -> s126(R, A);
s93(<<14:4, R/bits>>, A) -> s127(R, A);
s93(<<15:4, R/bits>>, A) -> s128(R, A);
s93(<<_/bits>>, _) -> {error, invalid_huffman}.

s94(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 60>>);
s94(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 60>>);
s94(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 60>>);
s94(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 60>>);
s94(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 60>>);
s94(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 60>>);
s94(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 60>>);
s94(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 60>>);
s94(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 96>>);
s94(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 96>>);
s94(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 96>>);
s94(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 96>>);
s94(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 96>>);
s94(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 96>>);
s94(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 96>>);
s94(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 96>>);
s94(<<_/bits>>, _) -> {error, invalid_huffman}.

s95(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 123>>);
s95(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 123>>);
s95(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 123>>);
s95(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 123>>);
s95(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 123>>);
s95(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 123>>);
s95(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 123>>);
s95(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 123>>);
s95(<<8:4, R/bits>>, A) -> s129(R, A);
s95(<<9:4, R/bits>>, A) -> s130(R, A);
s95(<<10:4, R/bits>>, A) -> s131(R, A);
s95(<<11:4, R/bits>>, A) -> s132(R, A);
s95(<<12:4, R/bits>>, A) -> s133(R, A);
s95(<<13:4, R/bits>>, A) -> s134(R, A);
s95(<<14:4, R/bits>>, A) -> s135(R, A);
s95(<<15:4, R/bits>>, A) -> s136(R, A);
s95(<<_/bits>>, _) -> {error, invalid_huffman}.

s96(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 94>>);
s96(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 94>>);
s96(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 94>>);
s96(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 94>>);
s96(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 94>>);
s96(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 94>>);
s96(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 94>>);
s96(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 94>>);
s96(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 125>>);
s96(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 125>>);
s96(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 125>>);
s96(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 125>>);
s96(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 125>>);
s96(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 125>>);
s96(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 125>>);
s96(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 125>>);
s96(<<_/bits>>, _) -> {error, invalid_huffman}.

s97(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 60>>);
s97(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 60>>);
s97(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 60>>);
s97(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 60>>);
s97(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 96>>);
s97(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 96>>);
s97(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 96>>);
s97(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 96>>);
s97(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 123>>);
s97(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 123>>);
s97(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 123>>);
s97(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 123>>);
s97(<<12:4, R/bits>>, A) -> s137(R, A);
s97(<<13:4, R/bits>>, A) -> s138(R, A);
s97(<<14:4, R/bits>>, A) -> s139(R, A);
s97(<<15:4, R/bits>>, A) -> s140(R, A);
s97(<<_/bits>>, _) -> {error, invalid_huffman}.

s98(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 153>>);
s98(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 153>>);
s98(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 153>>);
s98(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 153>>);
s98(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 153>>);
s98(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 153>>);
s98(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 153>>);
s98(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 153>>);
s98(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 161>>);
s98(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 161>>);
s98(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 161>>);
s98(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 161>>);
s98(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 161>>);
s98(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 161>>);
s98(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 161>>);
s98(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 161>>);
s98(<<_/bits>>, _) -> {error, invalid_huffman}.

s99(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 167>>);
s99(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 167>>);
s99(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 167>>);
s99(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 167>>);
s99(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 167>>);
s99(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 167>>);
s99(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 167>>);
s99(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 167>>);
s99(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 172>>);
s99(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 172>>);
s99(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 172>>);
s99(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 172>>);
s99(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 172>>);
s99(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 172>>);
s99(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 172>>);
s99(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 172>>);
s99(<<_/bits>>, _) -> {error, invalid_huffman}.

s100(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 176>>);
s100(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 176>>);
s100(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 176>>);
s100(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 176>>);
s100(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 176>>);
s100(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 176>>);
s100(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 176>>);
s100(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 176>>);
s100(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 177>>);
s100(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 177>>);
s100(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 177>>);
s100(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 177>>);
s100(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 177>>);
s100(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 177>>);
s100(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 177>>);
s100(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 177>>);
s100(<<_/bits>>, _) -> {error, invalid_huffman}.

s101(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 179>>);
s101(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 179>>);
s101(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 179>>);
s101(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 179>>);
s101(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 179>>);
s101(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 179>>);
s101(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 179>>);
s101(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 179>>);
s101(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 209>>);
s101(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 209>>);
s101(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 209>>);
s101(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 209>>);
s101(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 209>>);
s101(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 209>>);
s101(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 209>>);
s101(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 209>>);
s101(<<_/bits>>, _) -> {error, invalid_huffman}.

s102(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 216>>);
s102(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 216>>);
s102(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 216>>);
s102(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 216>>);
s102(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 216>>);
s102(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 216>>);
s102(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 216>>);
s102(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 216>>);
s102(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 217>>);
s102(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 217>>);
s102(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 217>>);
s102(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 217>>);
s102(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 217>>);
s102(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 217>>);
s102(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 217>>);
s102(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 217>>);
s102(<<_/bits>>, _) -> {error, invalid_huffman}.

s103(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 227>>);
s103(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 227>>);
s103(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 227>>);
s103(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 227>>);
s103(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 227>>);
s103(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 227>>);
s103(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 227>>);
s103(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 227>>);
s103(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 229>>);
s103(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 229>>);
s103(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 229>>);
s103(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 229>>);
s103(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 229>>);
s103(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 229>>);
s103(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 229>>);
s103(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 229>>);
s103(<<_/bits>>, _) -> {error, invalid_huffman}.

s104(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 230>>);
s104(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 230>>);
s104(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 230>>);
s104(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 230>>);
s104(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 230>>);
s104(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 230>>);
s104(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 230>>);
s104(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 230>>);
s104(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 129>>);
s104(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 129>>);
s104(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 129>>);
s104(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 129>>);
s104(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 132>>);
s104(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 132>>);
s104(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 132>>);
s104(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 132>>);
s104(<<_/bits>>, _) -> {error, invalid_huffman}.

s105(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 133>>);
s105(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 133>>);
s105(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 133>>);
s105(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 133>>);
s105(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 134>>);
s105(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 134>>);
s105(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 134>>);
s105(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 134>>);
s105(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 136>>);
s105(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 136>>);
s105(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 136>>);
s105(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 136>>);
s105(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 146>>);
s105(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 146>>);
s105(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 146>>);
s105(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 146>>);
s105(<<_/bits>>, _) -> {error, invalid_huffman}.

s106(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 154>>);
s106(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 154>>);
s106(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 154>>);
s106(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 154>>);
s106(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 156>>);
s106(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 156>>);
s106(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 156>>);
s106(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 156>>);
s106(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 160>>);
s106(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 160>>);
s106(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 160>>);
s106(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 160>>);
s106(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 163>>);
s106(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 163>>);
s106(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 163>>);
s106(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 163>>);
s106(<<_/bits>>, _) -> {error, invalid_huffman}.

s107(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 164>>);
s107(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 164>>);
s107(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 164>>);
s107(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 164>>);
s107(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 169>>);
s107(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 169>>);
s107(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 169>>);
s107(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 169>>);
s107(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 170>>);
s107(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 170>>);
s107(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 170>>);
s107(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 170>>);
s107(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 173>>);
s107(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 173>>);
s107(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 173>>);
s107(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 173>>);
s107(<<_/bits>>, _) -> {error, invalid_huffman}.

s108(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 178>>);
s108(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 178>>);
s108(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 178>>);
s108(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 178>>);
s108(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 181>>);
s108(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 181>>);
s108(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 181>>);
s108(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 181>>);
s108(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 185>>);
s108(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 185>>);
s108(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 185>>);
s108(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 185>>);
s108(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 186>>);
s108(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 186>>);
s108(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 186>>);
s108(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 186>>);
s108(<<_/bits>>, _) -> {error, invalid_huffman}.

s109(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 187>>);
s109(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 187>>);
s109(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 187>>);
s109(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 187>>);
s109(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 189>>);
s109(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 189>>);
s109(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 189>>);
s109(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 189>>);
s109(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 190>>);
s109(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 190>>);
s109(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 190>>);
s109(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 190>>);
s109(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 196>>);
s109(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 196>>);
s109(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 196>>);
s109(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 196>>);
s109(<<_/bits>>, _) -> {error, invalid_huffman}.

s110(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 198>>);
s110(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 198>>);
s110(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 198>>);
s110(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 198>>);
s110(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 228>>);
s110(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 228>>);
s110(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 228>>);
s110(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 228>>);
s110(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 232>>);
s110(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 232>>);
s110(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 232>>);
s110(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 232>>);
s110(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 233>>);
s110(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 233>>);
s110(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 233>>);
s110(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 233>>);
s110(<<_/bits>>, _) -> {error, invalid_huffman}.

s111(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 1>>);
s111(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 1>>);
s111(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 135>>);
s111(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 135>>);
s111(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 137>>);
s111(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 137>>);
s111(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 138>>);
s111(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 138>>);
s111(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 139>>);
s111(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 139>>);
s111(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 140>>);
s111(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 140>>);
s111(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 141>>);
s111(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 141>>);
s111(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 143>>);
s111(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 143>>);
s111(<<_/bits>>, _) -> {error, invalid_huffman}.

s112(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 147>>);
s112(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 147>>);
s112(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 149>>);
s112(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 149>>);
s112(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 150>>);
s112(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 150>>);
s112(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 151>>);
s112(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 151>>);
s112(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 152>>);
s112(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 152>>);
s112(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 155>>);
s112(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 155>>);
s112(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 157>>);
s112(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 157>>);
s112(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 158>>);
s112(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 158>>);
s112(<<_/bits>>, _) -> {error, invalid_huffman}.

s113(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 165>>);
s113(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 165>>);
s113(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 166>>);
s113(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 166>>);
s113(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 168>>);
s113(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 168>>);
s113(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 174>>);
s113(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 174>>);
s113(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 175>>);
s113(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 175>>);
s113(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 180>>);
s113(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 180>>);
s113(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 182>>);
s113(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 182>>);
s113(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 183>>);
s113(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 183>>);
s113(<<_/bits>>, _) -> {error, invalid_huffman}.

s114(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 188>>);
s114(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 188>>);
s114(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 191>>);
s114(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 191>>);
s114(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 197>>);
s114(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 197>>);
s114(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 231>>);
s114(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 231>>);
s114(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 239>>);
s114(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 239>>);
s114(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 9>>);
s114(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 142>>);
s114(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 144>>);
s114(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 145>>);
s114(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 148>>);
s114(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 159>>);
s114(<<_/bits>>, _) -> {error, invalid_huffman}.

s115(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 171>>);
s115(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 206>>);
s115(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 215>>);
s115(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 225>>);
s115(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 236>>);
s115(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 237>>);
s115(<<6:4, R/bits>>, A) -> s141(R, A);
s115(<<7:4, R/bits>>, A) -> s142(R, A);
s115(<<8:4, R/bits>>, A) -> s143(R, A);
s115(<<9:4, R/bits>>, A) -> s144(R, A);
s115(<<10:4, R/bits>>, A) -> s145(R, A);
s115(<<11:4, R/bits>>, A) -> s146(R, A);
s115(<<12:4, R/bits>>, A) -> s147(R, A);
s115(<<13:4, R/bits>>, A) -> s148(R, A);
s115(<<14:4, R/bits>>, A) -> s149(R, A);
s115(<<15:4, R/bits>>, A) -> s150(R, A);
s115(<<_/bits>>, _) -> {error, invalid_huffman}.

s116(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 128>>);
s116(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 128>>);
s116(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 128>>);
s116(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 128>>);
s116(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 128>>);
s116(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 128>>);
s116(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 128>>);
s116(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 128>>);
s116(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 130>>);
s116(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 130>>);
s116(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 130>>);
s116(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 130>>);
s116(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 130>>);
s116(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 130>>);
s116(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 130>>);
s116(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 130>>);
s116(<<_/bits>>, _) -> {error, invalid_huffman}.

s117(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 131>>);
s117(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 131>>);
s117(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 131>>);
s117(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 131>>);
s117(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 131>>);
s117(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 131>>);
s117(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 131>>);
s117(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 131>>);
s117(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 162>>);
s117(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 162>>);
s117(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 162>>);
s117(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 162>>);
s117(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 162>>);
s117(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 162>>);
s117(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 162>>);
s117(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 162>>);
s117(<<_/bits>>, _) -> {error, invalid_huffman}.

s118(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 184>>);
s118(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 184>>);
s118(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 184>>);
s118(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 184>>);
s118(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 184>>);
s118(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 184>>);
s118(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 184>>);
s118(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 184>>);
s118(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 194>>);
s118(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 194>>);
s118(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 194>>);
s118(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 194>>);
s118(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 194>>);
s118(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 194>>);
s118(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 194>>);
s118(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 194>>);
s118(<<_/bits>>, _) -> {error, invalid_huffman}.

s119(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 224>>);
s119(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 224>>);
s119(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 224>>);
s119(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 224>>);
s119(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 224>>);
s119(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 224>>);
s119(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 224>>);
s119(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 224>>);
s119(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 226>>);
s119(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 226>>);
s119(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 226>>);
s119(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 226>>);
s119(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 226>>);
s119(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 226>>);
s119(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 226>>);
s119(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 226>>);
s119(<<_/bits>>, _) -> {error, invalid_huffman}.

s120(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 153>>);
s120(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 153>>);
s120(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 153>>);
s120(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 153>>);
s120(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 161>>);
s120(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 161>>);
s120(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 161>>);
s120(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 161>>);
s120(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 167>>);
s120(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 167>>);
s120(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 167>>);
s120(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 167>>);
s120(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 172>>);
s120(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 172>>);
s120(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 172>>);
s120(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 172>>);
s120(<<_/bits>>, _) -> {error, invalid_huffman}.

s121(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 176>>);
s121(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 176>>);
s121(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 176>>);
s121(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 176>>);
s121(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 177>>);
s121(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 177>>);
s121(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 177>>);
s121(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 177>>);
s121(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 179>>);
s121(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 179>>);
s121(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 179>>);
s121(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 179>>);
s121(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 209>>);
s121(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 209>>);
s121(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 209>>);
s121(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 209>>);
s121(<<_/bits>>, _) -> {error, invalid_huffman}.

s122(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 216>>);
s122(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 216>>);
s122(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 216>>);
s122(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 216>>);
s122(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 217>>);
s122(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 217>>);
s122(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 217>>);
s122(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 217>>);
s122(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 227>>);
s122(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 227>>);
s122(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 227>>);
s122(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 227>>);
s122(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 229>>);
s122(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 229>>);
s122(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 229>>);
s122(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 229>>);
s122(<<_/bits>>, _) -> {error, invalid_huffman}.

s123(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 230>>);
s123(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 230>>);
s123(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 230>>);
s123(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 230>>);
s123(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 129>>);
s123(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 129>>);
s123(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 132>>);
s123(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 132>>);
s123(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 133>>);
s123(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 133>>);
s123(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 134>>);
s123(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 134>>);
s123(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 136>>);
s123(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 136>>);
s123(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 146>>);
s123(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 146>>);
s123(<<_/bits>>, _) -> {error, invalid_huffman}.

s124(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 154>>);
s124(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 154>>);
s124(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 156>>);
s124(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 156>>);
s124(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 160>>);
s124(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 160>>);
s124(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 163>>);
s124(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 163>>);
s124(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 164>>);
s124(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 164>>);
s124(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 169>>);
s124(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 169>>);
s124(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 170>>);
s124(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 170>>);
s124(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 173>>);
s124(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 173>>);
s124(<<_/bits>>, _) -> {error, invalid_huffman}.

s125(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 178>>);
s125(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 178>>);
s125(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 181>>);
s125(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 181>>);
s125(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 185>>);
s125(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 185>>);
s125(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 186>>);
s125(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 186>>);
s125(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 187>>);
s125(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 187>>);
s125(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 189>>);
s125(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 189>>);
s125(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 190>>);
s125(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 190>>);
s125(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 196>>);
s125(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 196>>);
s125(<<_/bits>>, _) -> {error, invalid_huffman}.

s126(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 198>>);
s126(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 198>>);
s126(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 228>>);
s126(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 228>>);
s126(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 232>>);
s126(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 232>>);
s126(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 233>>);
s126(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 233>>);
s126(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 1>>);
s126(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 135>>);
s126(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 137>>);
s126(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 138>>);
s126(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 139>>);
s126(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 140>>);
s126(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 141>>);
s126(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 143>>);
s126(<<_/bits>>, _) -> {error, invalid_huffman}.

s127(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 147>>);
s127(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 149>>);
s127(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 150>>);
s127(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 151>>);
s127(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 152>>);
s127(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 155>>);
s127(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 157>>);
s127(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 158>>);
s127(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 165>>);
s127(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 166>>);
s127(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 168>>);
s127(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 174>>);
s127(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 175>>);
s127(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 180>>);
s127(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 182>>);
s127(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 183>>);
s127(<<_/bits>>, _) -> {error, invalid_huffman}.

s128(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 188>>);
s128(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 191>>);
s128(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 197>>);
s128(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 231>>);
s128(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 239>>);
s128(<<5:4, R/bits>>, A) -> s151(R, A);
s128(<<6:4, R/bits>>, A) -> s152(R, A);
s128(<<7:4, R/bits>>, A) -> s153(R, A);
s128(<<8:4, R/bits>>, A) -> s154(R, A);
s128(<<9:4, R/bits>>, A) -> s155(R, A);
s128(<<10:4, R/bits>>, A) -> s156(R, A);
s128(<<11:4, R/bits>>, A) -> s157(R, A);
s128(<<12:4, R/bits>>, A) -> s158(R, A);
s128(<<13:4, R/bits>>, A) -> s159(R, A);
s128(<<14:4, R/bits>>, A) -> s160(R, A);
s128(<<15:4, R/bits>>, A) -> s161(R, A);
s128(<<_/bits>>, _) -> {error, invalid_huffman}.

s129(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 92>>);
s129(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 92>>);
s129(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 92>>);
s129(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 92>>);
s129(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 92>>);
s129(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 92>>);
s129(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 92>>);
s129(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 92>>);
s129(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 195>>);
s129(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 195>>);
s129(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 195>>);
s129(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 195>>);
s129(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 195>>);
s129(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 195>>);
s129(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 195>>);
s129(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 195>>);
s129(<<_/bits>>, _) -> {error, invalid_huffman}.

s130(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 208>>);
s130(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 208>>);
s130(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 208>>);
s130(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 208>>);
s130(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 208>>);
s130(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 208>>);
s130(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 208>>);
s130(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 208>>);
s130(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 128>>);
s130(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 128>>);
s130(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 128>>);
s130(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 128>>);
s130(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 130>>);
s130(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 130>>);
s130(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 130>>);
s130(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 130>>);
s130(<<_/bits>>, _) -> {error, invalid_huffman}.

s131(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 131>>);
s131(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 131>>);
s131(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 131>>);
s131(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 131>>);
s131(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 162>>);
s131(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 162>>);
s131(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 162>>);
s131(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 162>>);
s131(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 184>>);
s131(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 184>>);
s131(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 184>>);
s131(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 184>>);
s131(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 194>>);
s131(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 194>>);
s131(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 194>>);
s131(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 194>>);
s131(<<_/bits>>, _) -> {error, invalid_huffman}.

s132(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 224>>);
s132(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 224>>);
s132(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 224>>);
s132(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 224>>);
s132(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 226>>);
s132(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 226>>);
s132(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 226>>);
s132(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 226>>);
s132(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 153>>);
s132(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 153>>);
s132(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 161>>);
s132(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 161>>);
s132(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 167>>);
s132(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 167>>);
s132(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 172>>);
s132(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 172>>);
s132(<<_/bits>>, _) -> {error, invalid_huffman}.

s133(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 176>>);
s133(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 176>>);
s133(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 177>>);
s133(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 177>>);
s133(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 179>>);
s133(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 179>>);
s133(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 209>>);
s133(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 209>>);
s133(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 216>>);
s133(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 216>>);
s133(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 217>>);
s133(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 217>>);
s133(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 227>>);
s133(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 227>>);
s133(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 229>>);
s133(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 229>>);
s133(<<_/bits>>, _) -> {error, invalid_huffman}.

s134(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 230>>);
s134(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 230>>);
s134(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 129>>);
s134(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 132>>);
s134(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 133>>);
s134(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 134>>);
s134(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 136>>);
s134(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 146>>);
s134(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 154>>);
s134(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 156>>);
s134(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 160>>);
s134(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 163>>);
s134(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 164>>);
s134(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 169>>);
s134(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 170>>);
s134(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 173>>);
s134(<<_/bits>>, _) -> {error, invalid_huffman}.

s135(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 178>>);
s135(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 181>>);
s135(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 185>>);
s135(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 186>>);
s135(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 187>>);
s135(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 189>>);
s135(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 190>>);
s135(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 196>>);
s135(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 198>>);
s135(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 228>>);
s135(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 232>>);
s135(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 233>>);
s135(<<12:4, R/bits>>, A) -> s162(R, A);
s135(<<13:4, R/bits>>, A) -> s163(R, A);
s135(<<14:4, R/bits>>, A) -> s164(R, A);
s135(<<15:4, R/bits>>, A) -> s165(R, A);
s135(<<_/bits>>, _) -> {error, invalid_huffman}.

s136(<<0:4, R/bits>>, A) -> s166(R, A);
s136(<<1:4, R/bits>>, A) -> s167(R, A);
s136(<<2:4, R/bits>>, A) -> s168(R, A);
s136(<<3:4, R/bits>>, A) -> s169(R, A);
s136(<<4:4, R/bits>>, A) -> s170(R, A);
s136(<<5:4, R/bits>>, A) -> s171(R, A);
s136(<<6:4, R/bits>>, A) -> s172(R, A);
s136(<<7:4, R/bits>>, A) -> s173(R, A);
s136(<<8:4, R/bits>>, A) -> s174(R, A);
s136(<<9:4, R/bits>>, A) -> s175(R, A);
s136(<<10:4, R/bits>>, A) -> s176(R, A);
s136(<<11:4, R/bits>>, A) -> s177(R, A);
s136(<<12:4, R/bits>>, A) -> s178(R, A);
s136(<<13:4, R/bits>>, A) -> s179(R, A);
s136(<<14:4, R/bits>>, A) -> s180(R, A);
s136(<<15:4, R/bits>>, A) -> s181(R, A);
s136(<<_/bits>>, _) -> {error, invalid_huffman}.

s137(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 92>>);
s137(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 92>>);
s137(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 92>>);
s137(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 92>>);
s137(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 195>>);
s137(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 195>>);
s137(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 195>>);
s137(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 195>>);
s137(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 208>>);
s137(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 208>>);
s137(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 208>>);
s137(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 208>>);
s137(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 128>>);
s137(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 128>>);
s137(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 130>>);
s137(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 130>>);
s137(<<_/bits>>, _) -> {error, invalid_huffman}.

s138(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 131>>);
s138(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 131>>);
s138(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 162>>);
s138(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 162>>);
s138(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 184>>);
s138(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 184>>);
s138(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 194>>);
s138(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 194>>);
s138(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 224>>);
s138(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 224>>);
s138(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 226>>);
s138(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 226>>);
s138(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 153>>);
s138(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 161>>);
s138(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 167>>);
s138(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 172>>);
s138(<<_/bits>>, _) -> {error, invalid_huffman}.

s139(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 176>>);
s139(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 177>>);
s139(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 179>>);
s139(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 209>>);
s139(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 216>>);
s139(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 217>>);
s139(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 227>>);
s139(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 229>>);
s139(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 230>>);
s139(<<9:4, R/bits>>, A) -> s182(R, A);
s139(<<10:4, R/bits>>, A) -> s183(R, A);
s139(<<11:4, R/bits>>, A) -> s184(R, A);
s139(<<12:4, R/bits>>, A) -> s185(R, A);
s139(<<13:4, R/bits>>, A) -> s186(R, A);
s139(<<14:4, R/bits>>, A) -> s187(R, A);
s139(<<15:4, R/bits>>, A) -> s188(R, A);
s139(<<_/bits>>, _) -> {error, invalid_huffman}.

s140(<<0:4, R/bits>>, A) -> s189(R, A);
s140(<<1:4, R/bits>>, A) -> s190(R, A);
s140(<<2:4, R/bits>>, A) -> s191(R, A);
s140(<<3:4, R/bits>>, A) -> s192(R, A);
s140(<<4:4, R/bits>>, A) -> s193(R, A);
s140(<<5:4, R/bits>>, A) -> s194(R, A);
s140(<<6:4, R/bits>>, A) -> s195(R, A);
s140(<<7:4, R/bits>>, A) -> s196(R, A);
s140(<<8:4, R/bits>>, A) -> s197(R, A);
s140(<<9:4, R/bits>>, A) -> s198(R, A);
s140(<<10:4, R/bits>>, A) -> s199(R, A);
s140(<<11:4, R/bits>>, A) -> s200(R, A);
s140(<<12:4, R/bits>>, A) -> s201(R, A);
s140(<<13:4, R/bits>>, A) -> s202(R, A);
s140(<<14:4, R/bits>>, A) -> s203(R, A);
s140(<<15:4, R/bits>>, A) -> s204(R, A);
s140(<<_/bits>>, _) -> {error, invalid_huffman}.

s141(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 199>>);
s141(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 199>>);
s141(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 199>>);
s141(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 199>>);
s141(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 199>>);
s141(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 199>>);
s141(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 199>>);
s141(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 199>>);
s141(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 207>>);
s141(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 207>>);
s141(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 207>>);
s141(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 207>>);
s141(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 207>>);
s141(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 207>>);
s141(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 207>>);
s141(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 207>>);
s141(<<_/bits>>, _) -> {error, invalid_huffman}.

s142(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 234>>);
s142(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 234>>);
s142(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 234>>);
s142(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 234>>);
s142(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 234>>);
s142(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 234>>);
s142(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 234>>);
s142(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 234>>);
s142(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 235>>);
s142(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 235>>);
s142(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 235>>);
s142(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 235>>);
s142(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 235>>);
s142(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 235>>);
s142(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 235>>);
s142(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 235>>);
s142(<<_/bits>>, _) -> {error, invalid_huffman}.

s143(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 192>>);
s143(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 192>>);
s143(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 192>>);
s143(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 192>>);
s143(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 193>>);
s143(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 193>>);
s143(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 193>>);
s143(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 193>>);
s143(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 200>>);
s143(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 200>>);
s143(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 200>>);
s143(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 200>>);
s143(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 201>>);
s143(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 201>>);
s143(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 201>>);
s143(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 201>>);
s143(<<_/bits>>, _) -> {error, invalid_huffman}.

s144(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 202>>);
s144(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 202>>);
s144(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 202>>);
s144(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 202>>);
s144(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 205>>);
s144(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 205>>);
s144(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 205>>);
s144(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 205>>);
s144(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 210>>);
s144(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 210>>);
s144(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 210>>);
s144(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 210>>);
s144(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 213>>);
s144(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 213>>);
s144(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 213>>);
s144(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 213>>);
s144(<<_/bits>>, _) -> {error, invalid_huffman}.

s145(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 218>>);
s145(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 218>>);
s145(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 218>>);
s145(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 218>>);
s145(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 219>>);
s145(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 219>>);
s145(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 219>>);
s145(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 219>>);
s145(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 238>>);
s145(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 238>>);
s145(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 238>>);
s145(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 238>>);
s145(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 240>>);
s145(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 240>>);
s145(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 240>>);
s145(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 240>>);
s145(<<_/bits>>, _) -> {error, invalid_huffman}.

s146(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 242>>);
s146(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 242>>);
s146(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 242>>);
s146(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 242>>);
s146(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 243>>);
s146(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 243>>);
s146(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 243>>);
s146(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 243>>);
s146(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 255>>);
s146(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 255>>);
s146(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 255>>);
s146(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 255>>);
s146(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 203>>);
s146(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 203>>);
s146(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 204>>);
s146(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 204>>);
s146(<<_/bits>>, _) -> {error, invalid_huffman}.

s147(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 211>>);
s147(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 211>>);
s147(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 212>>);
s147(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 212>>);
s147(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 214>>);
s147(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 214>>);
s147(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 221>>);
s147(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 221>>);
s147(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 222>>);
s147(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 222>>);
s147(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 223>>);
s147(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 223>>);
s147(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 241>>);
s147(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 241>>);
s147(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 244>>);
s147(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 244>>);
s147(<<_/bits>>, _) -> {error, invalid_huffman}.

s148(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 245>>);
s148(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 245>>);
s148(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 246>>);
s148(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 246>>);
s148(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 247>>);
s148(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 247>>);
s148(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 248>>);
s148(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 248>>);
s148(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 250>>);
s148(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 250>>);
s148(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 251>>);
s148(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 251>>);
s148(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 252>>);
s148(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 252>>);
s148(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 253>>);
s148(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 253>>);
s148(<<_/bits>>, _) -> {error, invalid_huffman}.

s149(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 254>>);
s149(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 254>>);
s149(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 2>>);
s149(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 3>>);
s149(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 4>>);
s149(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 5>>);
s149(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 6>>);
s149(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 7>>);
s149(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 8>>);
s149(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 11>>);
s149(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 12>>);
s149(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 14>>);
s149(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 15>>);
s149(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 16>>);
s149(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 17>>);
s149(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 18>>);
s149(<<_/bits>>, _) -> {error, invalid_huffman}.

s150(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 19>>);
s150(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 20>>);
s150(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 21>>);
s150(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 23>>);
s150(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 24>>);
s150(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 25>>);
s150(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 26>>);
s150(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 27>>);
s150(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 28>>);
s150(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 29>>);
s150(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 30>>);
s150(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 31>>);
s150(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 127>>);
s150(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 220>>);
s150(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 249>>);
s150(<<15:4, R/bits>>, A) -> s205(R, A);
s150(<<_/bits>>, _) -> {error, invalid_huffman}.

s151(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 9>>);
s151(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 9>>);
s151(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 9>>);
s151(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 9>>);
s151(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 9>>);
s151(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 9>>);
s151(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 9>>);
s151(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 9>>);
s151(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 142>>);
s151(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 142>>);
s151(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 142>>);
s151(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 142>>);
s151(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 142>>);
s151(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 142>>);
s151(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 142>>);
s151(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 142>>);
s151(<<_/bits>>, _) -> {error, invalid_huffman}.

s152(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 144>>);
s152(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 144>>);
s152(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 144>>);
s152(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 144>>);
s152(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 144>>);
s152(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 144>>);
s152(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 144>>);
s152(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 144>>);
s152(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 145>>);
s152(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 145>>);
s152(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 145>>);
s152(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 145>>);
s152(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 145>>);
s152(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 145>>);
s152(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 145>>);
s152(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 145>>);
s152(<<_/bits>>, _) -> {error, invalid_huffman}.

s153(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 148>>);
s153(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 148>>);
s153(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 148>>);
s153(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 148>>);
s153(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 148>>);
s153(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 148>>);
s153(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 148>>);
s153(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 148>>);
s153(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 159>>);
s153(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 159>>);
s153(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 159>>);
s153(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 159>>);
s153(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 159>>);
s153(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 159>>);
s153(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 159>>);
s153(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 159>>);
s153(<<_/bits>>, _) -> {error, invalid_huffman}.

s154(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 171>>);
s154(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 171>>);
s154(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 171>>);
s154(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 171>>);
s154(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 171>>);
s154(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 171>>);
s154(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 171>>);
s154(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 171>>);
s154(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 206>>);
s154(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 206>>);
s154(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 206>>);
s154(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 206>>);
s154(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 206>>);
s154(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 206>>);
s154(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 206>>);
s154(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 206>>);
s154(<<_/bits>>, _) -> {error, invalid_huffman}.

s155(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 215>>);
s155(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 215>>);
s155(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 215>>);
s155(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 215>>);
s155(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 215>>);
s155(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 215>>);
s155(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 215>>);
s155(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 215>>);
s155(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 225>>);
s155(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 225>>);
s155(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 225>>);
s155(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 225>>);
s155(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 225>>);
s155(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 225>>);
s155(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 225>>);
s155(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 225>>);
s155(<<_/bits>>, _) -> {error, invalid_huffman}.

s156(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 236>>);
s156(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 236>>);
s156(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 236>>);
s156(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 236>>);
s156(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 236>>);
s156(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 236>>);
s156(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 236>>);
s156(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 236>>);
s156(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 237>>);
s156(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 237>>);
s156(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 237>>);
s156(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 237>>);
s156(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 237>>);
s156(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 237>>);
s156(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 237>>);
s156(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 237>>);
s156(<<_/bits>>, _) -> {error, invalid_huffman}.

s157(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 199>>);
s157(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 199>>);
s157(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 199>>);
s157(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 199>>);
s157(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 207>>);
s157(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 207>>);
s157(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 207>>);
s157(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 207>>);
s157(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 234>>);
s157(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 234>>);
s157(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 234>>);
s157(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 234>>);
s157(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 235>>);
s157(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 235>>);
s157(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 235>>);
s157(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 235>>);
s157(<<_/bits>>, _) -> {error, invalid_huffman}.

s158(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 192>>);
s158(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 192>>);
s158(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 193>>);
s158(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 193>>);
s158(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 200>>);
s158(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 200>>);
s158(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 201>>);
s158(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 201>>);
s158(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 202>>);
s158(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 202>>);
s158(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 205>>);
s158(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 205>>);
s158(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 210>>);
s158(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 210>>);
s158(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 213>>);
s158(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 213>>);
s158(<<_/bits>>, _) -> {error, invalid_huffman}.

s159(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 218>>);
s159(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 218>>);
s159(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 219>>);
s159(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 219>>);
s159(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 238>>);
s159(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 238>>);
s159(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 240>>);
s159(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 240>>);
s159(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 242>>);
s159(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 242>>);
s159(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 243>>);
s159(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 243>>);
s159(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 255>>);
s159(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 255>>);
s159(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 203>>);
s159(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 204>>);
s159(<<_/bits>>, _) -> {error, invalid_huffman}.

s160(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 211>>);
s160(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 212>>);
s160(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 214>>);
s160(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 221>>);
s160(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 222>>);
s160(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 223>>);
s160(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 241>>);
s160(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 244>>);
s160(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 245>>);
s160(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 246>>);
s160(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 247>>);
s160(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 248>>);
s160(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 250>>);
s160(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 251>>);
s160(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 252>>);
s160(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 253>>);
s160(<<_/bits>>, _) -> {error, invalid_huffman}.

s161(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 254>>);
s161(<<1:4, R/bits>>, A) -> s206(R, A);
s161(<<2:4, R/bits>>, A) -> s207(R, A);
s161(<<3:4, R/bits>>, A) -> s208(R, A);
s161(<<4:4, R/bits>>, A) -> s209(R, A);
s161(<<5:4, R/bits>>, A) -> s210(R, A);
s161(<<6:4, R/bits>>, A) -> s211(R, A);
s161(<<7:4, R/bits>>, A) -> s212(R, A);
s161(<<8:4, R/bits>>, A) -> s213(R, A);
s161(<<9:4, R/bits>>, A) -> s214(R, A);
s161(<<10:4, R/bits>>, A) -> s215(R, A);
s161(<<11:4, R/bits>>, A) -> s216(R, A);
s161(<<12:4, R/bits>>, A) -> s217(R, A);
s161(<<13:4, R/bits>>, A) -> s218(R, A);
s161(<<14:4, R/bits>>, A) -> s219(R, A);
s161(<<15:4, R/bits>>, A) -> s220(R, A);
s161(<<_/bits>>, _) -> {error, invalid_huffman}.

s162(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 1>>);
s162(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 1>>);
s162(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 1>>);
s162(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 1>>);
s162(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 1>>);
s162(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 1>>);
s162(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 1>>);
s162(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 1>>);
s162(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 135>>);
s162(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 135>>);
s162(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 135>>);
s162(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 135>>);
s162(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 135>>);
s162(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 135>>);
s162(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 135>>);
s162(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 135>>);
s162(<<_/bits>>, _) -> {error, invalid_huffman}.

s163(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 137>>);
s163(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 137>>);
s163(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 137>>);
s163(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 137>>);
s163(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 137>>);
s163(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 137>>);
s163(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 137>>);
s163(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 137>>);
s163(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 138>>);
s163(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 138>>);
s163(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 138>>);
s163(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 138>>);
s163(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 138>>);
s163(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 138>>);
s163(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 138>>);
s163(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 138>>);
s163(<<_/bits>>, _) -> {error, invalid_huffman}.

s164(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 139>>);
s164(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 139>>);
s164(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 139>>);
s164(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 139>>);
s164(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 139>>);
s164(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 139>>);
s164(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 139>>);
s164(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 139>>);
s164(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 140>>);
s164(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 140>>);
s164(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 140>>);
s164(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 140>>);
s164(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 140>>);
s164(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 140>>);
s164(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 140>>);
s164(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 140>>);
s164(<<_/bits>>, _) -> {error, invalid_huffman}.

s165(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 141>>);
s165(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 141>>);
s165(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 141>>);
s165(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 141>>);
s165(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 141>>);
s165(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 141>>);
s165(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 141>>);
s165(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 141>>);
s165(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 143>>);
s165(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 143>>);
s165(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 143>>);
s165(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 143>>);
s165(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 143>>);
s165(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 143>>);
s165(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 143>>);
s165(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 143>>);
s165(<<_/bits>>, _) -> {error, invalid_huffman}.

s166(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 147>>);
s166(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 147>>);
s166(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 147>>);
s166(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 147>>);
s166(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 147>>);
s166(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 147>>);
s166(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 147>>);
s166(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 147>>);
s166(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 149>>);
s166(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 149>>);
s166(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 149>>);
s166(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 149>>);
s166(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 149>>);
s166(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 149>>);
s166(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 149>>);
s166(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 149>>);
s166(<<_/bits>>, _) -> {error, invalid_huffman}.

s167(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 150>>);
s167(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 150>>);
s167(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 150>>);
s167(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 150>>);
s167(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 150>>);
s167(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 150>>);
s167(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 150>>);
s167(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 150>>);
s167(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 151>>);
s167(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 151>>);
s167(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 151>>);
s167(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 151>>);
s167(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 151>>);
s167(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 151>>);
s167(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 151>>);
s167(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 151>>);
s167(<<_/bits>>, _) -> {error, invalid_huffman}.

s168(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 152>>);
s168(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 152>>);
s168(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 152>>);
s168(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 152>>);
s168(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 152>>);
s168(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 152>>);
s168(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 152>>);
s168(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 152>>);
s168(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 155>>);
s168(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 155>>);
s168(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 155>>);
s168(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 155>>);
s168(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 155>>);
s168(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 155>>);
s168(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 155>>);
s168(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 155>>);
s168(<<_/bits>>, _) -> {error, invalid_huffman}.

s169(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 157>>);
s169(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 157>>);
s169(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 157>>);
s169(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 157>>);
s169(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 157>>);
s169(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 157>>);
s169(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 157>>);
s169(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 157>>);
s169(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 158>>);
s169(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 158>>);
s169(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 158>>);
s169(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 158>>);
s169(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 158>>);
s169(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 158>>);
s169(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 158>>);
s169(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 158>>);
s169(<<_/bits>>, _) -> {error, invalid_huffman}.

s170(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 165>>);
s170(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 165>>);
s170(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 165>>);
s170(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 165>>);
s170(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 165>>);
s170(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 165>>);
s170(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 165>>);
s170(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 165>>);
s170(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 166>>);
s170(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 166>>);
s170(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 166>>);
s170(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 166>>);
s170(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 166>>);
s170(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 166>>);
s170(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 166>>);
s170(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 166>>);
s170(<<_/bits>>, _) -> {error, invalid_huffman}.

s171(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 168>>);
s171(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 168>>);
s171(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 168>>);
s171(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 168>>);
s171(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 168>>);
s171(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 168>>);
s171(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 168>>);
s171(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 168>>);
s171(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 174>>);
s171(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 174>>);
s171(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 174>>);
s171(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 174>>);
s171(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 174>>);
s171(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 174>>);
s171(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 174>>);
s171(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 174>>);
s171(<<_/bits>>, _) -> {error, invalid_huffman}.

s172(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 175>>);
s172(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 175>>);
s172(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 175>>);
s172(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 175>>);
s172(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 175>>);
s172(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 175>>);
s172(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 175>>);
s172(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 175>>);
s172(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 180>>);
s172(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 180>>);
s172(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 180>>);
s172(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 180>>);
s172(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 180>>);
s172(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 180>>);
s172(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 180>>);
s172(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 180>>);
s172(<<_/bits>>, _) -> {error, invalid_huffman}.

s173(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 182>>);
s173(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 182>>);
s173(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 182>>);
s173(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 182>>);
s173(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 182>>);
s173(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 182>>);
s173(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 182>>);
s173(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 182>>);
s173(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 183>>);
s173(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 183>>);
s173(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 183>>);
s173(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 183>>);
s173(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 183>>);
s173(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 183>>);
s173(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 183>>);
s173(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 183>>);
s173(<<_/bits>>, _) -> {error, invalid_huffman}.

s174(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 188>>);
s174(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 188>>);
s174(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 188>>);
s174(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 188>>);
s174(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 188>>);
s174(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 188>>);
s174(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 188>>);
s174(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 188>>);
s174(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 191>>);
s174(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 191>>);
s174(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 191>>);
s174(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 191>>);
s174(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 191>>);
s174(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 191>>);
s174(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 191>>);
s174(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 191>>);
s174(<<_/bits>>, _) -> {error, invalid_huffman}.

s175(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 197>>);
s175(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 197>>);
s175(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 197>>);
s175(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 197>>);
s175(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 197>>);
s175(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 197>>);
s175(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 197>>);
s175(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 197>>);
s175(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 231>>);
s175(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 231>>);
s175(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 231>>);
s175(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 231>>);
s175(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 231>>);
s175(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 231>>);
s175(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 231>>);
s175(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 231>>);
s175(<<_/bits>>, _) -> {error, invalid_huffman}.

s176(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 239>>);
s176(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 239>>);
s176(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 239>>);
s176(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 239>>);
s176(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 239>>);
s176(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 239>>);
s176(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 239>>);
s176(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 239>>);
s176(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 9>>);
s176(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 9>>);
s176(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 9>>);
s176(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 9>>);
s176(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 142>>);
s176(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 142>>);
s176(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 142>>);
s176(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 142>>);
s176(<<_/bits>>, _) -> {error, invalid_huffman}.

s177(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 144>>);
s177(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 144>>);
s177(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 144>>);
s177(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 144>>);
s177(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 145>>);
s177(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 145>>);
s177(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 145>>);
s177(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 145>>);
s177(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 148>>);
s177(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 148>>);
s177(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 148>>);
s177(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 148>>);
s177(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 159>>);
s177(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 159>>);
s177(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 159>>);
s177(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 159>>);
s177(<<_/bits>>, _) -> {error, invalid_huffman}.

s178(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 171>>);
s178(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 171>>);
s178(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 171>>);
s178(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 171>>);
s178(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 206>>);
s178(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 206>>);
s178(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 206>>);
s178(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 206>>);
s178(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 215>>);
s178(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 215>>);
s178(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 215>>);
s178(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 215>>);
s178(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 225>>);
s178(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 225>>);
s178(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 225>>);
s178(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 225>>);
s178(<<_/bits>>, _) -> {error, invalid_huffman}.

s179(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 236>>);
s179(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 236>>);
s179(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 236>>);
s179(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 236>>);
s179(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 237>>);
s179(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 237>>);
s179(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 237>>);
s179(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 237>>);
s179(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 199>>);
s179(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 199>>);
s179(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 207>>);
s179(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 207>>);
s179(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 234>>);
s179(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 234>>);
s179(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 235>>);
s179(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 235>>);
s179(<<_/bits>>, _) -> {error, invalid_huffman}.

s180(<<0:4, R/bits>>, A) -> s0(R, <<A/binary, 192>>);
s180(<<1:4, R/bits>>, A) -> s0(R, <<A/binary, 193>>);
s180(<<2:4, R/bits>>, A) -> s0(R, <<A/binary, 200>>);
s180(<<3:4, R/bits>>, A) -> s0(R, <<A/binary, 201>>);
s180(<<4:4, R/bits>>, A) -> s0(R, <<A/binary, 202>>);
s180(<<5:4, R/bits>>, A) -> s0(R, <<A/binary, 205>>);
s180(<<6:4, R/bits>>, A) -> s0(R, <<A/binary, 210>>);
s180(<<7:4, R/bits>>, A) -> s0(R, <<A/binary, 213>>);
s180(<<8:4, R/bits>>, A) -> s0(R, <<A/binary, 218>>);
s180(<<9:4, R/bits>>, A) -> s0(R, <<A/binary, 219>>);
s180(<<10:4, R/bits>>, A) -> s0(R, <<A/binary, 238>>);
s180(<<11:4, R/bits>>, A) -> s0(R, <<A/binary, 240>>);
s180(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 242>>);
s180(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 243>>);
s180(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 255>>);
s180(<<15:4, R/bits>>, A) -> s221(R, A);
s180(<<_/bits>>, _) -> {error, invalid_huffman}.

s181(<<0:4, R/bits>>, A) -> s222(R, A);
s181(<<1:4, R/bits>>, A) -> s223(R, A);
s181(<<2:4, R/bits>>, A) -> s224(R, A);
s181(<<3:4, R/bits>>, A) -> s225(R, A);
s181(<<4:4, R/bits>>, A) -> s226(R, A);
s181(<<5:4, R/bits>>, A) -> s227(R, A);
s181(<<6:4, R/bits>>, A) -> s228(R, A);
s181(<<7:4, R/bits>>, A) -> s229(R, A);
s181(<<8:4, R/bits>>, A) -> s230(R, A);
s181(<<9:4, R/bits>>, A) -> s231(R, A);
s181(<<10:4, R/bits>>, A) -> s232(R, A);
s181(<<11:4, R/bits>>, A) -> s233(R, A);
s181(<<12:4, R/bits>>, A) -> s234(R, A);
s181(<<13:4, R/bits>>, A) -> s235(R, A);
s181(<<14:4, R/bits>>, A) -> s236(R, A);
s181(<<15:4, R/bits>>, A) -> s237(R, A);
s181(<<_/bits>>, _) -> {error, invalid_huffman}.

s182(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 129>>);
s182(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 129>>);
s182(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 129>>);
s182(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 129>>);
s182(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 129>>);
s182(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 129>>);
s182(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 129>>);
s182(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 129>>);
s182(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 132>>);
s182(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 132>>);
s182(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 132>>);
s182(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 132>>);
s182(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 132>>);
s182(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 132>>);
s182(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 132>>);
s182(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 132>>);
s182(<<_/bits>>, _) -> {error, invalid_huffman}.

s183(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 133>>);
s183(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 133>>);
s183(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 133>>);
s183(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 133>>);
s183(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 133>>);
s183(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 133>>);
s183(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 133>>);
s183(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 133>>);
s183(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 134>>);
s183(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 134>>);
s183(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 134>>);
s183(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 134>>);
s183(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 134>>);
s183(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 134>>);
s183(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 134>>);
s183(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 134>>);
s183(<<_/bits>>, _) -> {error, invalid_huffman}.

s184(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 136>>);
s184(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 136>>);
s184(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 136>>);
s184(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 136>>);
s184(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 136>>);
s184(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 136>>);
s184(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 136>>);
s184(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 136>>);
s184(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 146>>);
s184(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 146>>);
s184(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 146>>);
s184(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 146>>);
s184(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 146>>);
s184(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 146>>);
s184(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 146>>);
s184(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 146>>);
s184(<<_/bits>>, _) -> {error, invalid_huffman}.

s185(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 154>>);
s185(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 154>>);
s185(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 154>>);
s185(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 154>>);
s185(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 154>>);
s185(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 154>>);
s185(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 154>>);
s185(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 154>>);
s185(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 156>>);
s185(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 156>>);
s185(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 156>>);
s185(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 156>>);
s185(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 156>>);
s185(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 156>>);
s185(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 156>>);
s185(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 156>>);
s185(<<_/bits>>, _) -> {error, invalid_huffman}.

s186(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 160>>);
s186(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 160>>);
s186(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 160>>);
s186(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 160>>);
s186(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 160>>);
s186(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 160>>);
s186(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 160>>);
s186(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 160>>);
s186(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 163>>);
s186(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 163>>);
s186(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 163>>);
s186(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 163>>);
s186(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 163>>);
s186(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 163>>);
s186(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 163>>);
s186(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 163>>);
s186(<<_/bits>>, _) -> {error, invalid_huffman}.

s187(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 164>>);
s187(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 164>>);
s187(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 164>>);
s187(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 164>>);
s187(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 164>>);
s187(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 164>>);
s187(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 164>>);
s187(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 164>>);
s187(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 169>>);
s187(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 169>>);
s187(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 169>>);
s187(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 169>>);
s187(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 169>>);
s187(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 169>>);
s187(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 169>>);
s187(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 169>>);
s187(<<_/bits>>, _) -> {error, invalid_huffman}.

s188(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 170>>);
s188(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 170>>);
s188(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 170>>);
s188(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 170>>);
s188(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 170>>);
s188(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 170>>);
s188(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 170>>);
s188(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 170>>);
s188(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 173>>);
s188(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 173>>);
s188(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 173>>);
s188(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 173>>);
s188(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 173>>);
s188(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 173>>);
s188(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 173>>);
s188(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 173>>);
s188(<<_/bits>>, _) -> {error, invalid_huffman}.

s189(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 178>>);
s189(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 178>>);
s189(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 178>>);
s189(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 178>>);
s189(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 178>>);
s189(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 178>>);
s189(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 178>>);
s189(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 178>>);
s189(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 181>>);
s189(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 181>>);
s189(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 181>>);
s189(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 181>>);
s189(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 181>>);
s189(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 181>>);
s189(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 181>>);
s189(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 181>>);
s189(<<_/bits>>, _) -> {error, invalid_huffman}.

s190(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 185>>);
s190(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 185>>);
s190(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 185>>);
s190(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 185>>);
s190(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 185>>);
s190(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 185>>);
s190(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 185>>);
s190(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 185>>);
s190(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 186>>);
s190(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 186>>);
s190(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 186>>);
s190(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 186>>);
s190(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 186>>);
s190(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 186>>);
s190(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 186>>);
s190(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 186>>);
s190(<<_/bits>>, _) -> {error, invalid_huffman}.

s191(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 187>>);
s191(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 187>>);
s191(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 187>>);
s191(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 187>>);
s191(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 187>>);
s191(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 187>>);
s191(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 187>>);
s191(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 187>>);
s191(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 189>>);
s191(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 189>>);
s191(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 189>>);
s191(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 189>>);
s191(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 189>>);
s191(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 189>>);
s191(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 189>>);
s191(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 189>>);
s191(<<_/bits>>, _) -> {error, invalid_huffman}.

s192(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 190>>);
s192(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 190>>);
s192(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 190>>);
s192(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 190>>);
s192(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 190>>);
s192(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 190>>);
s192(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 190>>);
s192(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 190>>);
s192(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 196>>);
s192(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 196>>);
s192(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 196>>);
s192(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 196>>);
s192(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 196>>);
s192(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 196>>);
s192(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 196>>);
s192(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 196>>);
s192(<<_/bits>>, _) -> {error, invalid_huffman}.

s193(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 198>>);
s193(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 198>>);
s193(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 198>>);
s193(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 198>>);
s193(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 198>>);
s193(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 198>>);
s193(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 198>>);
s193(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 198>>);
s193(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 228>>);
s193(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 228>>);
s193(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 228>>);
s193(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 228>>);
s193(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 228>>);
s193(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 228>>);
s193(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 228>>);
s193(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 228>>);
s193(<<_/bits>>, _) -> {error, invalid_huffman}.

s194(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 232>>);
s194(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 232>>);
s194(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 232>>);
s194(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 232>>);
s194(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 232>>);
s194(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 232>>);
s194(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 232>>);
s194(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 232>>);
s194(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 233>>);
s194(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 233>>);
s194(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 233>>);
s194(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 233>>);
s194(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 233>>);
s194(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 233>>);
s194(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 233>>);
s194(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 233>>);
s194(<<_/bits>>, _) -> {error, invalid_huffman}.

s195(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 1>>);
s195(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 1>>);
s195(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 1>>);
s195(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 1>>);
s195(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 135>>);
s195(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 135>>);
s195(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 135>>);
s195(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 135>>);
s195(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 137>>);
s195(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 137>>);
s195(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 137>>);
s195(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 137>>);
s195(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 138>>);
s195(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 138>>);
s195(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 138>>);
s195(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 138>>);
s195(<<_/bits>>, _) -> {error, invalid_huffman}.

s196(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 139>>);
s196(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 139>>);
s196(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 139>>);
s196(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 139>>);
s196(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 140>>);
s196(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 140>>);
s196(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 140>>);
s196(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 140>>);
s196(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 141>>);
s196(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 141>>);
s196(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 141>>);
s196(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 141>>);
s196(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 143>>);
s196(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 143>>);
s196(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 143>>);
s196(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 143>>);
s196(<<_/bits>>, _) -> {error, invalid_huffman}.

s197(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 147>>);
s197(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 147>>);
s197(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 147>>);
s197(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 147>>);
s197(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 149>>);
s197(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 149>>);
s197(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 149>>);
s197(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 149>>);
s197(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 150>>);
s197(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 150>>);
s197(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 150>>);
s197(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 150>>);
s197(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 151>>);
s197(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 151>>);
s197(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 151>>);
s197(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 151>>);
s197(<<_/bits>>, _) -> {error, invalid_huffman}.

s198(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 152>>);
s198(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 152>>);
s198(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 152>>);
s198(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 152>>);
s198(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 155>>);
s198(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 155>>);
s198(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 155>>);
s198(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 155>>);
s198(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 157>>);
s198(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 157>>);
s198(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 157>>);
s198(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 157>>);
s198(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 158>>);
s198(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 158>>);
s198(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 158>>);
s198(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 158>>);
s198(<<_/bits>>, _) -> {error, invalid_huffman}.

s199(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 165>>);
s199(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 165>>);
s199(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 165>>);
s199(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 165>>);
s199(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 166>>);
s199(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 166>>);
s199(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 166>>);
s199(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 166>>);
s199(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 168>>);
s199(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 168>>);
s199(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 168>>);
s199(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 168>>);
s199(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 174>>);
s199(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 174>>);
s199(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 174>>);
s199(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 174>>);
s199(<<_/bits>>, _) -> {error, invalid_huffman}.

s200(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 175>>);
s200(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 175>>);
s200(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 175>>);
s200(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 175>>);
s200(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 180>>);
s200(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 180>>);
s200(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 180>>);
s200(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 180>>);
s200(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 182>>);
s200(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 182>>);
s200(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 182>>);
s200(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 182>>);
s200(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 183>>);
s200(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 183>>);
s200(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 183>>);
s200(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 183>>);
s200(<<_/bits>>, _) -> {error, invalid_huffman}.

s201(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 188>>);
s201(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 188>>);
s201(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 188>>);
s201(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 188>>);
s201(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 191>>);
s201(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 191>>);
s201(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 191>>);
s201(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 191>>);
s201(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 197>>);
s201(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 197>>);
s201(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 197>>);
s201(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 197>>);
s201(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 231>>);
s201(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 231>>);
s201(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 231>>);
s201(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 231>>);
s201(<<_/bits>>, _) -> {error, invalid_huffman}.

s202(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 239>>);
s202(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 239>>);
s202(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 239>>);
s202(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 239>>);
s202(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 9>>);
s202(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 9>>);
s202(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 142>>);
s202(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 142>>);
s202(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 144>>);
s202(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 144>>);
s202(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 145>>);
s202(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 145>>);
s202(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 148>>);
s202(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 148>>);
s202(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 159>>);
s202(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 159>>);
s202(<<_/bits>>, _) -> {error, invalid_huffman}.

s203(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 171>>);
s203(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 171>>);
s203(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 206>>);
s203(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 206>>);
s203(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 215>>);
s203(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 215>>);
s203(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 225>>);
s203(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 225>>);
s203(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 236>>);
s203(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 236>>);
s203(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 237>>);
s203(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 237>>);
s203(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 199>>);
s203(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 207>>);
s203(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 234>>);
s203(<<15:4, R/bits>>, A) -> s0(R, <<A/binary, 235>>);
s203(<<_/bits>>, _) -> {error, invalid_huffman}.

s204(<<0:4, R/bits>>, A) -> s238(R, A);
s204(<<1:4, R/bits>>, A) -> s239(R, A);
s204(<<2:4, R/bits>>, A) -> s240(R, A);
s204(<<3:4, R/bits>>, A) -> s241(R, A);
s204(<<4:4, R/bits>>, A) -> s242(R, A);
s204(<<5:4, R/bits>>, A) -> s243(R, A);
s204(<<6:4, R/bits>>, A) -> s244(R, A);
s204(<<7:4, R/bits>>, A) -> s245(R, A);
s204(<<8:4, R/bits>>, A) -> s246(R, A);
s204(<<9:4, R/bits>>, A) -> s247(R, A);
s204(<<10:4, R/bits>>, A) -> s248(R, A);
s204(<<11:4, R/bits>>, A) -> s249(R, A);
s204(<<12:4, R/bits>>, A) -> s250(R, A);
s204(<<13:4, R/bits>>, A) -> s251(R, A);
s204(<<14:4, R/bits>>, A) -> s252(R, A);
s204(<<15:4, R/bits>>, A) -> s253(R, A);
s204(<<_/bits>>, _) -> {error, invalid_huffman}.

s205(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 10>>);
s205(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 10>>);
s205(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 10>>);
s205(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 10>>);
s205(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 13>>);
s205(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 13>>);
s205(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 13>>);
s205(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 13>>);
s205(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 22>>);
s205(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 22>>);
s205(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 22>>);
s205(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 22>>);
s205(<<12:4, _/bits>>, _) -> {error, invalid_huffman};
s205(<<13:4, _/bits>>, _) -> {error, invalid_huffman};
s205(<<14:4, _/bits>>, _) -> {error, invalid_huffman};
s205(<<15:4, _/bits>>, _) -> {error, invalid_huffman};
s205(<<_/bits>>, _) -> {error, invalid_huffman}.

s206(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 2>>);
s206(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 2>>);
s206(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 2>>);
s206(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 2>>);
s206(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 2>>);
s206(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 2>>);
s206(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 2>>);
s206(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 2>>);
s206(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 3>>);
s206(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 3>>);
s206(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 3>>);
s206(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 3>>);
s206(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 3>>);
s206(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 3>>);
s206(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 3>>);
s206(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 3>>);
s206(<<_/bits>>, _) -> {error, invalid_huffman}.

s207(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 4>>);
s207(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 4>>);
s207(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 4>>);
s207(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 4>>);
s207(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 4>>);
s207(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 4>>);
s207(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 4>>);
s207(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 4>>);
s207(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 5>>);
s207(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 5>>);
s207(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 5>>);
s207(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 5>>);
s207(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 5>>);
s207(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 5>>);
s207(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 5>>);
s207(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 5>>);
s207(<<_/bits>>, _) -> {error, invalid_huffman}.

s208(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 6>>);
s208(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 6>>);
s208(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 6>>);
s208(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 6>>);
s208(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 6>>);
s208(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 6>>);
s208(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 6>>);
s208(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 6>>);
s208(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 7>>);
s208(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 7>>);
s208(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 7>>);
s208(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 7>>);
s208(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 7>>);
s208(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 7>>);
s208(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 7>>);
s208(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 7>>);
s208(<<_/bits>>, _) -> {error, invalid_huffman}.

s209(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 8>>);
s209(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 8>>);
s209(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 8>>);
s209(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 8>>);
s209(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 8>>);
s209(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 8>>);
s209(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 8>>);
s209(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 8>>);
s209(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 11>>);
s209(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 11>>);
s209(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 11>>);
s209(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 11>>);
s209(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 11>>);
s209(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 11>>);
s209(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 11>>);
s209(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 11>>);
s209(<<_/bits>>, _) -> {error, invalid_huffman}.

s210(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 12>>);
s210(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 12>>);
s210(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 12>>);
s210(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 12>>);
s210(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 12>>);
s210(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 12>>);
s210(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 12>>);
s210(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 12>>);
s210(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 14>>);
s210(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 14>>);
s210(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 14>>);
s210(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 14>>);
s210(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 14>>);
s210(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 14>>);
s210(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 14>>);
s210(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 14>>);
s210(<<_/bits>>, _) -> {error, invalid_huffman}.

s211(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 15>>);
s211(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 15>>);
s211(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 15>>);
s211(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 15>>);
s211(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 15>>);
s211(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 15>>);
s211(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 15>>);
s211(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 15>>);
s211(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 16>>);
s211(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 16>>);
s211(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 16>>);
s211(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 16>>);
s211(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 16>>);
s211(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 16>>);
s211(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 16>>);
s211(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 16>>);
s211(<<_/bits>>, _) -> {error, invalid_huffman}.

s212(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 17>>);
s212(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 17>>);
s212(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 17>>);
s212(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 17>>);
s212(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 17>>);
s212(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 17>>);
s212(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 17>>);
s212(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 17>>);
s212(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 18>>);
s212(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 18>>);
s212(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 18>>);
s212(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 18>>);
s212(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 18>>);
s212(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 18>>);
s212(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 18>>);
s212(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 18>>);
s212(<<_/bits>>, _) -> {error, invalid_huffman}.

s213(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 19>>);
s213(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 19>>);
s213(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 19>>);
s213(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 19>>);
s213(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 19>>);
s213(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 19>>);
s213(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 19>>);
s213(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 19>>);
s213(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 20>>);
s213(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 20>>);
s213(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 20>>);
s213(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 20>>);
s213(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 20>>);
s213(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 20>>);
s213(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 20>>);
s213(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 20>>);
s213(<<_/bits>>, _) -> {error, invalid_huffman}.

s214(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 21>>);
s214(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 21>>);
s214(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 21>>);
s214(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 21>>);
s214(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 21>>);
s214(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 21>>);
s214(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 21>>);
s214(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 21>>);
s214(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 23>>);
s214(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 23>>);
s214(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 23>>);
s214(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 23>>);
s214(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 23>>);
s214(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 23>>);
s214(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 23>>);
s214(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 23>>);
s214(<<_/bits>>, _) -> {error, invalid_huffman}.

s215(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 24>>);
s215(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 24>>);
s215(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 24>>);
s215(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 24>>);
s215(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 24>>);
s215(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 24>>);
s215(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 24>>);
s215(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 24>>);
s215(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 25>>);
s215(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 25>>);
s215(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 25>>);
s215(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 25>>);
s215(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 25>>);
s215(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 25>>);
s215(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 25>>);
s215(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 25>>);
s215(<<_/bits>>, _) -> {error, invalid_huffman}.

s216(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 26>>);
s216(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 26>>);
s216(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 26>>);
s216(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 26>>);
s216(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 26>>);
s216(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 26>>);
s216(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 26>>);
s216(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 26>>);
s216(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 27>>);
s216(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 27>>);
s216(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 27>>);
s216(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 27>>);
s216(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 27>>);
s216(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 27>>);
s216(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 27>>);
s216(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 27>>);
s216(<<_/bits>>, _) -> {error, invalid_huffman}.

s217(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 28>>);
s217(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 28>>);
s217(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 28>>);
s217(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 28>>);
s217(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 28>>);
s217(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 28>>);
s217(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 28>>);
s217(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 28>>);
s217(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 29>>);
s217(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 29>>);
s217(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 29>>);
s217(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 29>>);
s217(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 29>>);
s217(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 29>>);
s217(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 29>>);
s217(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 29>>);
s217(<<_/bits>>, _) -> {error, invalid_huffman}.

s218(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 30>>);
s218(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 30>>);
s218(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 30>>);
s218(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 30>>);
s218(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 30>>);
s218(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 30>>);
s218(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 30>>);
s218(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 30>>);
s218(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 31>>);
s218(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 31>>);
s218(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 31>>);
s218(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 31>>);
s218(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 31>>);
s218(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 31>>);
s218(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 31>>);
s218(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 31>>);
s218(<<_/bits>>, _) -> {error, invalid_huffman}.

s219(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 127>>);
s219(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 127>>);
s219(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 127>>);
s219(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 127>>);
s219(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 127>>);
s219(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 127>>);
s219(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 127>>);
s219(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 127>>);
s219(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 220>>);
s219(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 220>>);
s219(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 220>>);
s219(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 220>>);
s219(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 220>>);
s219(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 220>>);
s219(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 220>>);
s219(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 220>>);
s219(<<_/bits>>, _) -> {error, invalid_huffman}.

s220(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 249>>);
s220(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 249>>);
s220(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 249>>);
s220(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 249>>);
s220(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 249>>);
s220(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 249>>);
s220(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 249>>);
s220(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 249>>);
s220(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 10>>);
s220(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 10>>);
s220(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 13>>);
s220(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 13>>);
s220(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 22>>);
s220(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 22>>);
s220(<<14:4, _/bits>>, _) -> {error, invalid_huffman};
s220(<<15:4, _/bits>>, _) -> {error, invalid_huffman};
s220(<<_/bits>>, _) -> {error, invalid_huffman}.

s221(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 203>>);
s221(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 203>>);
s221(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 203>>);
s221(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 203>>);
s221(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 203>>);
s221(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 203>>);
s221(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 203>>);
s221(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 203>>);
s221(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 204>>);
s221(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 204>>);
s221(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 204>>);
s221(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 204>>);
s221(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 204>>);
s221(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 204>>);
s221(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 204>>);
s221(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 204>>);
s221(<<_/bits>>, _) -> {error, invalid_huffman}.

s222(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 211>>);
s222(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 211>>);
s222(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 211>>);
s222(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 211>>);
s222(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 211>>);
s222(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 211>>);
s222(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 211>>);
s222(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 211>>);
s222(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 212>>);
s222(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 212>>);
s222(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 212>>);
s222(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 212>>);
s222(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 212>>);
s222(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 212>>);
s222(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 212>>);
s222(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 212>>);
s222(<<_/bits>>, _) -> {error, invalid_huffman}.

s223(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 214>>);
s223(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 214>>);
s223(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 214>>);
s223(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 214>>);
s223(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 214>>);
s223(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 214>>);
s223(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 214>>);
s223(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 214>>);
s223(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 221>>);
s223(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 221>>);
s223(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 221>>);
s223(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 221>>);
s223(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 221>>);
s223(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 221>>);
s223(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 221>>);
s223(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 221>>);
s223(<<_/bits>>, _) -> {error, invalid_huffman}.

s224(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 222>>);
s224(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 222>>);
s224(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 222>>);
s224(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 222>>);
s224(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 222>>);
s224(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 222>>);
s224(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 222>>);
s224(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 222>>);
s224(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 223>>);
s224(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 223>>);
s224(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 223>>);
s224(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 223>>);
s224(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 223>>);
s224(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 223>>);
s224(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 223>>);
s224(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 223>>);
s224(<<_/bits>>, _) -> {error, invalid_huffman}.

s225(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 241>>);
s225(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 241>>);
s225(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 241>>);
s225(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 241>>);
s225(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 241>>);
s225(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 241>>);
s225(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 241>>);
s225(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 241>>);
s225(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 244>>);
s225(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 244>>);
s225(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 244>>);
s225(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 244>>);
s225(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 244>>);
s225(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 244>>);
s225(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 244>>);
s225(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 244>>);
s225(<<_/bits>>, _) -> {error, invalid_huffman}.

s226(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 245>>);
s226(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 245>>);
s226(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 245>>);
s226(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 245>>);
s226(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 245>>);
s226(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 245>>);
s226(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 245>>);
s226(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 245>>);
s226(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 246>>);
s226(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 246>>);
s226(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 246>>);
s226(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 246>>);
s226(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 246>>);
s226(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 246>>);
s226(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 246>>);
s226(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 246>>);
s226(<<_/bits>>, _) -> {error, invalid_huffman}.

s227(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 247>>);
s227(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 247>>);
s227(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 247>>);
s227(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 247>>);
s227(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 247>>);
s227(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 247>>);
s227(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 247>>);
s227(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 247>>);
s227(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 248>>);
s227(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 248>>);
s227(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 248>>);
s227(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 248>>);
s227(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 248>>);
s227(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 248>>);
s227(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 248>>);
s227(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 248>>);
s227(<<_/bits>>, _) -> {error, invalid_huffman}.

s228(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 250>>);
s228(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 250>>);
s228(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 250>>);
s228(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 250>>);
s228(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 250>>);
s228(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 250>>);
s228(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 250>>);
s228(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 250>>);
s228(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 251>>);
s228(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 251>>);
s228(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 251>>);
s228(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 251>>);
s228(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 251>>);
s228(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 251>>);
s228(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 251>>);
s228(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 251>>);
s228(<<_/bits>>, _) -> {error, invalid_huffman}.

s229(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 252>>);
s229(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 252>>);
s229(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 252>>);
s229(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 252>>);
s229(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 252>>);
s229(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 252>>);
s229(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 252>>);
s229(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 252>>);
s229(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 253>>);
s229(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 253>>);
s229(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 253>>);
s229(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 253>>);
s229(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 253>>);
s229(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 253>>);
s229(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 253>>);
s229(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 253>>);
s229(<<_/bits>>, _) -> {error, invalid_huffman}.

s230(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 254>>);
s230(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 254>>);
s230(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 254>>);
s230(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 254>>);
s230(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 254>>);
s230(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 254>>);
s230(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 254>>);
s230(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 254>>);
s230(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 2>>);
s230(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 2>>);
s230(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 2>>);
s230(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 2>>);
s230(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 3>>);
s230(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 3>>);
s230(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 3>>);
s230(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 3>>);
s230(<<_/bits>>, _) -> {error, invalid_huffman}.

s231(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 4>>);
s231(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 4>>);
s231(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 4>>);
s231(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 4>>);
s231(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 5>>);
s231(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 5>>);
s231(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 5>>);
s231(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 5>>);
s231(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 6>>);
s231(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 6>>);
s231(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 6>>);
s231(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 6>>);
s231(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 7>>);
s231(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 7>>);
s231(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 7>>);
s231(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 7>>);
s231(<<_/bits>>, _) -> {error, invalid_huffman}.

s232(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 8>>);
s232(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 8>>);
s232(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 8>>);
s232(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 8>>);
s232(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 11>>);
s232(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 11>>);
s232(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 11>>);
s232(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 11>>);
s232(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 12>>);
s232(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 12>>);
s232(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 12>>);
s232(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 12>>);
s232(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 14>>);
s232(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 14>>);
s232(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 14>>);
s232(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 14>>);
s232(<<_/bits>>, _) -> {error, invalid_huffman}.

s233(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 15>>);
s233(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 15>>);
s233(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 15>>);
s233(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 15>>);
s233(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 16>>);
s233(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 16>>);
s233(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 16>>);
s233(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 16>>);
s233(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 17>>);
s233(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 17>>);
s233(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 17>>);
s233(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 17>>);
s233(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 18>>);
s233(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 18>>);
s233(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 18>>);
s233(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 18>>);
s233(<<_/bits>>, _) -> {error, invalid_huffman}.

s234(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 19>>);
s234(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 19>>);
s234(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 19>>);
s234(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 19>>);
s234(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 20>>);
s234(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 20>>);
s234(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 20>>);
s234(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 20>>);
s234(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 21>>);
s234(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 21>>);
s234(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 21>>);
s234(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 21>>);
s234(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 23>>);
s234(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 23>>);
s234(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 23>>);
s234(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 23>>);
s234(<<_/bits>>, _) -> {error, invalid_huffman}.

s235(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 24>>);
s235(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 24>>);
s235(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 24>>);
s235(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 24>>);
s235(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 25>>);
s235(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 25>>);
s235(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 25>>);
s235(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 25>>);
s235(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 26>>);
s235(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 26>>);
s235(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 26>>);
s235(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 26>>);
s235(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 27>>);
s235(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 27>>);
s235(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 27>>);
s235(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 27>>);
s235(<<_/bits>>, _) -> {error, invalid_huffman}.

s236(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 28>>);
s236(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 28>>);
s236(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 28>>);
s236(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 28>>);
s236(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 29>>);
s236(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 29>>);
s236(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 29>>);
s236(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 29>>);
s236(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 30>>);
s236(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 30>>);
s236(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 30>>);
s236(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 30>>);
s236(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 31>>);
s236(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 31>>);
s236(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 31>>);
s236(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 31>>);
s236(<<_/bits>>, _) -> {error, invalid_huffman}.

s237(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 127>>);
s237(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 127>>);
s237(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 127>>);
s237(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 127>>);
s237(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 220>>);
s237(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 220>>);
s237(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 220>>);
s237(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 220>>);
s237(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 249>>);
s237(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 249>>);
s237(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 249>>);
s237(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 249>>);
s237(<<12:4, R/bits>>, A) -> s0(R, <<A/binary, 10>>);
s237(<<13:4, R/bits>>, A) -> s0(R, <<A/binary, 13>>);
s237(<<14:4, R/bits>>, A) -> s0(R, <<A/binary, 22>>);
s237(<<15:4, _/bits>>, _) -> {error, invalid_huffman};
s237(<<_/bits>>, _) -> {error, invalid_huffman}.

s238(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 192>>);
s238(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 192>>);
s238(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 192>>);
s238(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 192>>);
s238(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 192>>);
s238(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 192>>);
s238(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 192>>);
s238(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 192>>);
s238(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 193>>);
s238(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 193>>);
s238(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 193>>);
s238(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 193>>);
s238(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 193>>);
s238(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 193>>);
s238(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 193>>);
s238(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 193>>);
s238(<<_/bits>>, _) -> {error, invalid_huffman}.

s239(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 200>>);
s239(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 200>>);
s239(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 200>>);
s239(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 200>>);
s239(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 200>>);
s239(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 200>>);
s239(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 200>>);
s239(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 200>>);
s239(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 201>>);
s239(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 201>>);
s239(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 201>>);
s239(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 201>>);
s239(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 201>>);
s239(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 201>>);
s239(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 201>>);
s239(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 201>>);
s239(<<_/bits>>, _) -> {error, invalid_huffman}.

s240(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 202>>);
s240(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 202>>);
s240(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 202>>);
s240(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 202>>);
s240(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 202>>);
s240(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 202>>);
s240(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 202>>);
s240(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 202>>);
s240(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 205>>);
s240(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 205>>);
s240(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 205>>);
s240(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 205>>);
s240(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 205>>);
s240(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 205>>);
s240(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 205>>);
s240(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 205>>);
s240(<<_/bits>>, _) -> {error, invalid_huffman}.

s241(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 210>>);
s241(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 210>>);
s241(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 210>>);
s241(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 210>>);
s241(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 210>>);
s241(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 210>>);
s241(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 210>>);
s241(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 210>>);
s241(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 213>>);
s241(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 213>>);
s241(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 213>>);
s241(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 213>>);
s241(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 213>>);
s241(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 213>>);
s241(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 213>>);
s241(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 213>>);
s241(<<_/bits>>, _) -> {error, invalid_huffman}.

s242(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 218>>);
s242(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 218>>);
s242(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 218>>);
s242(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 218>>);
s242(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 218>>);
s242(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 218>>);
s242(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 218>>);
s242(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 218>>);
s242(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 219>>);
s242(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 219>>);
s242(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 219>>);
s242(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 219>>);
s242(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 219>>);
s242(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 219>>);
s242(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 219>>);
s242(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 219>>);
s242(<<_/bits>>, _) -> {error, invalid_huffman}.

s243(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 238>>);
s243(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 238>>);
s243(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 238>>);
s243(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 238>>);
s243(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 238>>);
s243(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 238>>);
s243(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 238>>);
s243(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 238>>);
s243(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 240>>);
s243(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 240>>);
s243(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 240>>);
s243(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 240>>);
s243(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 240>>);
s243(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 240>>);
s243(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 240>>);
s243(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 240>>);
s243(<<_/bits>>, _) -> {error, invalid_huffman}.

s244(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 242>>);
s244(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 242>>);
s244(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 242>>);
s244(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 242>>);
s244(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 242>>);
s244(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 242>>);
s244(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 242>>);
s244(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 242>>);
s244(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 243>>);
s244(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 243>>);
s244(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 243>>);
s244(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 243>>);
s244(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 243>>);
s244(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 243>>);
s244(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 243>>);
s244(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 243>>);
s244(<<_/bits>>, _) -> {error, invalid_huffman}.

s245(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 255>>);
s245(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 255>>);
s245(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 255>>);
s245(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 255>>);
s245(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 255>>);
s245(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 255>>);
s245(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 255>>);
s245(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 255>>);
s245(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 203>>);
s245(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 203>>);
s245(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 203>>);
s245(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 203>>);
s245(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 204>>);
s245(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 204>>);
s245(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 204>>);
s245(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 204>>);
s245(<<_/bits>>, _) -> {error, invalid_huffman}.

s246(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 211>>);
s246(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 211>>);
s246(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 211>>);
s246(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 211>>);
s246(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 212>>);
s246(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 212>>);
s246(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 212>>);
s246(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 212>>);
s246(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 214>>);
s246(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 214>>);
s246(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 214>>);
s246(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 214>>);
s246(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 221>>);
s246(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 221>>);
s246(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 221>>);
s246(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 221>>);
s246(<<_/bits>>, _) -> {error, invalid_huffman}.

s247(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 222>>);
s247(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 222>>);
s247(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 222>>);
s247(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 222>>);
s247(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 223>>);
s247(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 223>>);
s247(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 223>>);
s247(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 223>>);
s247(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 241>>);
s247(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 241>>);
s247(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 241>>);
s247(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 241>>);
s247(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 244>>);
s247(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 244>>);
s247(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 244>>);
s247(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 244>>);
s247(<<_/bits>>, _) -> {error, invalid_huffman}.

s248(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 245>>);
s248(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 245>>);
s248(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 245>>);
s248(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 245>>);
s248(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 246>>);
s248(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 246>>);
s248(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 246>>);
s248(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 246>>);
s248(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 247>>);
s248(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 247>>);
s248(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 247>>);
s248(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 247>>);
s248(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 248>>);
s248(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 248>>);
s248(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 248>>);
s248(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 248>>);
s248(<<_/bits>>, _) -> {error, invalid_huffman}.

s249(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 250>>);
s249(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 250>>);
s249(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 250>>);
s249(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 250>>);
s249(<<4:4, R/bits>>, A) -> s25(R, <<A/binary, 251>>);
s249(<<5:4, R/bits>>, A) -> s26(R, <<A/binary, 251>>);
s249(<<6:4, R/bits>>, A) -> s27(R, <<A/binary, 251>>);
s249(<<7:4, R/bits>>, A) -> s28(R, <<A/binary, 251>>);
s249(<<8:4, R/bits>>, A) -> s25(R, <<A/binary, 252>>);
s249(<<9:4, R/bits>>, A) -> s26(R, <<A/binary, 252>>);
s249(<<10:4, R/bits>>, A) -> s27(R, <<A/binary, 252>>);
s249(<<11:4, R/bits>>, A) -> s28(R, <<A/binary, 252>>);
s249(<<12:4, R/bits>>, A) -> s25(R, <<A/binary, 253>>);
s249(<<13:4, R/bits>>, A) -> s26(R, <<A/binary, 253>>);
s249(<<14:4, R/bits>>, A) -> s27(R, <<A/binary, 253>>);
s249(<<15:4, R/bits>>, A) -> s28(R, <<A/binary, 253>>);
s249(<<_/bits>>, _) -> {error, invalid_huffman}.

s250(<<0:4, R/bits>>, A) -> s25(R, <<A/binary, 254>>);
s250(<<1:4, R/bits>>, A) -> s26(R, <<A/binary, 254>>);
s250(<<2:4, R/bits>>, A) -> s27(R, <<A/binary, 254>>);
s250(<<3:4, R/bits>>, A) -> s28(R, <<A/binary, 254>>);
s250(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 2>>);
s250(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 2>>);
s250(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 3>>);
s250(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 3>>);
s250(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 4>>);
s250(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 4>>);
s250(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 5>>);
s250(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 5>>);
s250(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 6>>);
s250(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 6>>);
s250(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 7>>);
s250(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 7>>);
s250(<<_/bits>>, _) -> {error, invalid_huffman}.

s251(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 8>>);
s251(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 8>>);
s251(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 11>>);
s251(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 11>>);
s251(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 12>>);
s251(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 12>>);
s251(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 14>>);
s251(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 14>>);
s251(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 15>>);
s251(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 15>>);
s251(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 16>>);
s251(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 16>>);
s251(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 17>>);
s251(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 17>>);
s251(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 18>>);
s251(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 18>>);
s251(<<_/bits>>, _) -> {error, invalid_huffman}.

s252(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 19>>);
s252(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 19>>);
s252(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 20>>);
s252(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 20>>);
s252(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 21>>);
s252(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 21>>);
s252(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 23>>);
s252(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 23>>);
s252(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 24>>);
s252(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 24>>);
s252(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 25>>);
s252(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 25>>);
s252(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 26>>);
s252(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 26>>);
s252(<<14:4, R/bits>>, A) -> s29(R, <<A/binary, 27>>);
s252(<<15:4, R/bits>>, A) -> s30(R, <<A/binary, 27>>);
s252(<<_/bits>>, _) -> {error, invalid_huffman}.

s253(<<0:4, R/bits>>, A) -> s29(R, <<A/binary, 28>>);
s253(<<1:4, R/bits>>, A) -> s30(R, <<A/binary, 28>>);
s253(<<2:4, R/bits>>, A) -> s29(R, <<A/binary, 29>>);
s253(<<3:4, R/bits>>, A) -> s30(R, <<A/binary, 29>>);
s253(<<4:4, R/bits>>, A) -> s29(R, <<A/binary, 30>>);
s253(<<5:4, R/bits>>, A) -> s30(R, <<A/binary, 30>>);
s253(<<6:4, R/bits>>, A) -> s29(R, <<A/binary, 31>>);
s253(<<7:4, R/bits>>, A) -> s30(R, <<A/binary, 31>>);
s253(<<8:4, R/bits>>, A) -> s29(R, <<A/binary, 127>>);
s253(<<9:4, R/bits>>, A) -> s30(R, <<A/binary, 127>>);
s253(<<10:4, R/bits>>, A) -> s29(R, <<A/binary, 220>>);
s253(<<11:4, R/bits>>, A) -> s30(R, <<A/binary, 220>>);
s253(<<12:4, R/bits>>, A) -> s29(R, <<A/binary, 249>>);
s253(<<13:4, R/bits>>, A) -> s30(R, <<A/binary, 249>>);
s253(<<14:4, R/bits>>, A) -> s254(R, A);
s253(<<15:4, R/bits>>, A) -> s255(R, A);
s253(<<_/bits>>, _) -> {error, invalid_huffman}.

s254(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 10>>);
s254(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 10>>);
s254(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 10>>);
s254(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 10>>);
s254(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 10>>);
s254(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 10>>);
s254(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 10>>);
s254(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 10>>);
s254(<<8:4, R/bits>>, A) -> s17(R, <<A/binary, 13>>);
s254(<<9:4, R/bits>>, A) -> s18(R, <<A/binary, 13>>);
s254(<<10:4, R/bits>>, A) -> s19(R, <<A/binary, 13>>);
s254(<<11:4, R/bits>>, A) -> s20(R, <<A/binary, 13>>);
s254(<<12:4, R/bits>>, A) -> s21(R, <<A/binary, 13>>);
s254(<<13:4, R/bits>>, A) -> s22(R, <<A/binary, 13>>);
s254(<<14:4, R/bits>>, A) -> s23(R, <<A/binary, 13>>);
s254(<<15:4, R/bits>>, A) -> s24(R, <<A/binary, 13>>);
s254(<<_/bits>>, _) -> {error, invalid_huffman}.

s255(<<0:4, R/bits>>, A) -> s17(R, <<A/binary, 22>>);
s255(<<1:4, R/bits>>, A) -> s18(R, <<A/binary, 22>>);
s255(<<2:4, R/bits>>, A) -> s19(R, <<A/binary, 22>>);
s255(<<3:4, R/bits>>, A) -> s20(R, <<A/binary, 22>>);
s255(<<4:4, R/bits>>, A) -> s21(R, <<A/binary, 22>>);
s255(<<5:4, R/bits>>, A) -> s22(R, <<A/binary, 22>>);
s255(<<6:4, R/bits>>, A) -> s23(R, <<A/binary, 22>>);
s255(<<7:4, R/bits>>, A) -> s24(R, <<A/binary, 22>>);
s255(<<8:4, _/bits>>, _) -> {error, invalid_huffman};
s255(<<9:4, _/bits>>, _) -> {error, invalid_huffman};
s255(<<10:4, _/bits>>, _) -> {error, invalid_huffman};
s255(<<11:4, _/bits>>, _) -> {error, invalid_huffman};
s255(<<12:4, _/bits>>, _) -> {error, invalid_huffman};
s255(<<13:4, _/bits>>, _) -> {error, invalid_huffman};
s255(<<14:4, _/bits>>, _) -> {error, invalid_huffman};
s255(<<15:4, _/bits>>, _) -> {error, invalid_huffman};
s255(<<_/bits>>, _) -> {error, invalid_huffman}.

-spec encode(binary(), bitstring()) -> binary().
encode(<<>>, Acc) ->
    case bit_size(Acc) rem 8 of
        0 -> Acc;
        1 -> <<Acc/bits, 2#1111111:7>>;
        2 -> <<Acc/bits, 2#111111:6>>;
        3 -> <<Acc/bits, 2#11111:5>>;
        4 -> <<Acc/bits, 2#1111:4>>;
        5 -> <<Acc/bits, 2#111:3>>;
        6 -> <<Acc/bits, 2#11:2>>;
        7 -> <<Acc/bits, 2#1:1>>
    end;
encode(<<0, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111000:13>>);
encode(<<1, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111011000:23>>);
encode(<<2, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111100010:28>>);
encode(<<3, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111100011:28>>);
encode(<<4, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111100100:28>>);
encode(<<5, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111100101:28>>);
encode(<<6, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111100110:28>>);
encode(<<7, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111100111:28>>);
encode(<<8, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111101000:28>>);
encode(<<9, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111101010:24>>);
encode(<<10, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111111111100:30>>);
encode(<<11, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111101001:28>>);
encode(<<12, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111101010:28>>);
encode(<<13, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111111111101:30>>);
encode(<<14, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111101011:28>>);
encode(<<15, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111101100:28>>);
encode(<<16, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111101101:28>>);
encode(<<17, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111101110:28>>);
encode(<<18, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111101111:28>>);
encode(<<19, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111110000:28>>);
encode(<<20, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111110001:28>>);
encode(<<21, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111110010:28>>);
encode(<<22, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111111111110:30>>);
encode(<<23, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111110011:28>>);
encode(<<24, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111110100:28>>);
encode(<<25, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111110101:28>>);
encode(<<26, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111110110:28>>);
encode(<<27, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111110111:28>>);
encode(<<28, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111111000:28>>);
encode(<<29, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111111001:28>>);
encode(<<30, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111111010:28>>);
encode(<<31, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111111011:28>>);
encode(<<32, R/bits>>, A) ->
    encode(R, <<A/bits, 2#010100:6>>);
encode(<<33, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111000:10>>);
encode(<<34, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111001:10>>);
encode(<<35, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111010:12>>);
encode(<<36, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111001:13>>);
encode(<<37, R/bits>>, A) ->
    encode(R, <<A/bits, 2#010101:6>>);
encode(<<38, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111000:8>>);
encode(<<39, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111010:11>>);
encode(<<40, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111010:10>>);
encode(<<41, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111011:10>>);
encode(<<42, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111001:8>>);
encode(<<43, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111011:11>>);
encode(<<44, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111010:8>>);
encode(<<45, R/bits>>, A) ->
    encode(R, <<A/bits, 2#010110:6>>);
encode(<<46, R/bits>>, A) ->
    encode(R, <<A/bits, 2#010111:6>>);
encode(<<47, R/bits>>, A) ->
    encode(R, <<A/bits, 2#011000:6>>);
encode(<<48, R/bits>>, A) ->
    encode(R, <<A/bits, 2#00000:5>>);
encode(<<49, R/bits>>, A) ->
    encode(R, <<A/bits, 2#00001:5>>);
encode(<<50, R/bits>>, A) ->
    encode(R, <<A/bits, 2#00010:5>>);
encode(<<51, R/bits>>, A) ->
    encode(R, <<A/bits, 2#011001:6>>);
encode(<<52, R/bits>>, A) ->
    encode(R, <<A/bits, 2#011010:6>>);
encode(<<53, R/bits>>, A) ->
    encode(R, <<A/bits, 2#011011:6>>);
encode(<<54, R/bits>>, A) ->
    encode(R, <<A/bits, 2#011100:6>>);
encode(<<55, R/bits>>, A) ->
    encode(R, <<A/bits, 2#011101:6>>);
encode(<<56, R/bits>>, A) ->
    encode(R, <<A/bits, 2#011110:6>>);
encode(<<57, R/bits>>, A) ->
    encode(R, <<A/bits, 2#011111:6>>);
encode(<<58, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1011100:7>>);
encode(<<59, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111011:8>>);
encode(<<60, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111100:15>>);
encode(<<61, R/bits>>, A) ->
    encode(R, <<A/bits, 2#100000:6>>);
encode(<<62, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111011:12>>);
encode(<<63, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111100:10>>);
encode(<<64, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111010:13>>);
encode(<<65, R/bits>>, A) ->
    encode(R, <<A/bits, 2#100001:6>>);
encode(<<66, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1011101:7>>);
encode(<<67, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1011110:7>>);
encode(<<68, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1011111:7>>);
encode(<<69, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1100000:7>>);
encode(<<70, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1100001:7>>);
encode(<<71, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1100010:7>>);
encode(<<72, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1100011:7>>);
encode(<<73, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1100100:7>>);
encode(<<74, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1100101:7>>);
encode(<<75, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1100110:7>>);
encode(<<76, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1100111:7>>);
encode(<<77, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1101000:7>>);
encode(<<78, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1101001:7>>);
encode(<<79, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1101010:7>>);
encode(<<80, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1101011:7>>);
encode(<<81, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1101100:7>>);
encode(<<82, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1101101:7>>);
encode(<<83, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1101110:7>>);
encode(<<84, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1101111:7>>);
encode(<<85, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1110000:7>>);
encode(<<86, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1110001:7>>);
encode(<<87, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1110010:7>>);
encode(<<88, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111100:8>>);
encode(<<89, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1110011:7>>);
encode(<<90, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111101:8>>);
encode(<<91, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111011:13>>);
encode(<<92, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111110000:19>>);
encode(<<93, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111100:13>>);
encode(<<94, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111100:14>>);
encode(<<95, R/bits>>, A) ->
    encode(R, <<A/bits, 2#100010:6>>);
encode(<<96, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111101:15>>);
encode(<<97, R/bits>>, A) ->
    encode(R, <<A/bits, 2#00011:5>>);
encode(<<98, R/bits>>, A) ->
    encode(R, <<A/bits, 2#100011:6>>);
encode(<<99, R/bits>>, A) ->
    encode(R, <<A/bits, 2#00100:5>>);
encode(<<100, R/bits>>, A) ->
    encode(R, <<A/bits, 2#100100:6>>);
encode(<<101, R/bits>>, A) ->
    encode(R, <<A/bits, 2#00101:5>>);
encode(<<102, R/bits>>, A) ->
    encode(R, <<A/bits, 2#100101:6>>);
encode(<<103, R/bits>>, A) ->
    encode(R, <<A/bits, 2#100110:6>>);
encode(<<104, R/bits>>, A) ->
    encode(R, <<A/bits, 2#100111:6>>);
encode(<<105, R/bits>>, A) ->
    encode(R, <<A/bits, 2#00110:5>>);
encode(<<106, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1110100:7>>);
encode(<<107, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1110101:7>>);
encode(<<108, R/bits>>, A) ->
    encode(R, <<A/bits, 2#101000:6>>);
encode(<<109, R/bits>>, A) ->
    encode(R, <<A/bits, 2#101001:6>>);
encode(<<110, R/bits>>, A) ->
    encode(R, <<A/bits, 2#101010:6>>);
encode(<<111, R/bits>>, A) ->
    encode(R, <<A/bits, 2#00111:5>>);
encode(<<112, R/bits>>, A) ->
    encode(R, <<A/bits, 2#101011:6>>);
encode(<<113, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1110110:7>>);
encode(<<114, R/bits>>, A) ->
    encode(R, <<A/bits, 2#101100:6>>);
encode(<<115, R/bits>>, A) ->
    encode(R, <<A/bits, 2#01000:5>>);
encode(<<116, R/bits>>, A) ->
    encode(R, <<A/bits, 2#01001:5>>);
encode(<<117, R/bits>>, A) ->
    encode(R, <<A/bits, 2#101101:6>>);
encode(<<118, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1110111:7>>);
encode(<<119, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111000:7>>);
encode(<<120, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111001:7>>);
encode(<<121, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111010:7>>);
encode(<<122, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111011:7>>);
encode(<<123, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111110:15>>);
encode(<<124, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111100:11>>);
encode(<<125, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111101:14>>);
encode(<<126, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111101:13>>);
encode(<<127, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111111100:28>>);
encode(<<128, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111100110:20>>);
encode(<<129, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111010010:22>>);
encode(<<130, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111100111:20>>);
encode(<<131, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111101000:20>>);
encode(<<132, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111010011:22>>);
encode(<<133, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111010100:22>>);
encode(<<134, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111010101:22>>);
encode(<<135, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111011001:23>>);
encode(<<136, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111010110:22>>);
encode(<<137, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111011010:23>>);
encode(<<138, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111011011:23>>);
encode(<<139, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111011100:23>>);
encode(<<140, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111011101:23>>);
encode(<<141, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111011110:23>>);
encode(<<142, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111101011:24>>);
encode(<<143, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111011111:23>>);
encode(<<144, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111101100:24>>);
encode(<<145, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111101101:24>>);
encode(<<146, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111010111:22>>);
encode(<<147, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111100000:23>>);
encode(<<148, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111101110:24>>);
encode(<<149, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111100001:23>>);
encode(<<150, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111100010:23>>);
encode(<<151, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111100011:23>>);
encode(<<152, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111100100:23>>);
encode(<<153, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111011100:21>>);
encode(<<154, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111011000:22>>);
encode(<<155, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111100101:23>>);
encode(<<156, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111011001:22>>);
encode(<<157, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111100110:23>>);
encode(<<158, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111100111:23>>);
encode(<<159, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111101111:24>>);
encode(<<160, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111011010:22>>);
encode(<<161, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111011101:21>>);
encode(<<162, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111101001:20>>);
encode(<<163, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111011011:22>>);
encode(<<164, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111011100:22>>);
encode(<<165, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111101000:23>>);
encode(<<166, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111101001:23>>);
encode(<<167, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111011110:21>>);
encode(<<168, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111101010:23>>);
encode(<<169, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111011101:22>>);
encode(<<170, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111011110:22>>);
encode(<<171, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111110000:24>>);
encode(<<172, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111011111:21>>);
encode(<<173, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111011111:22>>);
encode(<<174, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111101011:23>>);
encode(<<175, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111101100:23>>);
encode(<<176, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111100000:21>>);
encode(<<177, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111100001:21>>);
encode(<<178, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111100000:22>>);
encode(<<179, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111100010:21>>);
encode(<<180, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111101101:23>>);
encode(<<181, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111100001:22>>);
encode(<<182, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111101110:23>>);
encode(<<183, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111101111:23>>);
encode(<<184, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111101010:20>>);
encode(<<185, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111100010:22>>);
encode(<<186, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111100011:22>>);
encode(<<187, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111100100:22>>);
encode(<<188, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111110000:23>>);
encode(<<189, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111100101:22>>);
encode(<<190, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111100110:22>>);
encode(<<191, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111110001:23>>);
encode(<<192, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111100000:26>>);
encode(<<193, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111100001:26>>);
encode(<<194, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111101011:20>>);
encode(<<195, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111110001:19>>);
encode(<<196, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111100111:22>>);
encode(<<197, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111110010:23>>);
encode(<<198, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111101000:22>>);
encode(<<199, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111101100:25>>);
encode(<<200, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111100010:26>>);
encode(<<201, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111100011:26>>);
encode(<<202, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111100100:26>>);
encode(<<203, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111011110:27>>);
encode(<<204, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111011111:27>>);
encode(<<205, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111100101:26>>);
encode(<<206, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111110001:24>>);
encode(<<207, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111101101:25>>);
encode(<<208, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111110010:19>>);
encode(<<209, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111100011:21>>);
encode(<<210, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111100110:26>>);
encode(<<211, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111100000:27>>);
encode(<<212, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111100001:27>>);
encode(<<213, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111100111:26>>);
encode(<<214, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111100010:27>>);
encode(<<215, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111110010:24>>);
encode(<<216, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111100100:21>>);
encode(<<217, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111100101:21>>);
encode(<<218, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111101000:26>>);
encode(<<219, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111101001:26>>);
encode(<<220, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111111101:28>>);
encode(<<221, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111100011:27>>);
encode(<<222, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111100100:27>>);
encode(<<223, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111100101:27>>);
encode(<<224, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111101100:20>>);
encode(<<225, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111110011:24>>);
encode(<<226, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111101101:20>>);
encode(<<227, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111100110:21>>);
encode(<<228, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111101001:22>>);
encode(<<229, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111100111:21>>);
encode(<<230, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111101000:21>>);
encode(<<231, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111110011:23>>);
encode(<<232, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111101010:22>>);
encode(<<233, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111101011:22>>);
encode(<<234, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111101110:25>>);
encode(<<235, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111101111:25>>);
encode(<<236, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111110100:24>>);
encode(<<237, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111110101:24>>);
encode(<<238, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111101010:26>>);
encode(<<239, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111110100:23>>);
encode(<<240, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111101011:26>>);
encode(<<241, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111100110:27>>);
encode(<<242, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111101100:26>>);
encode(<<243, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111101101:26>>);
encode(<<244, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111100111:27>>);
encode(<<245, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111101000:27>>);
encode(<<246, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111101001:27>>);
encode(<<247, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111101010:27>>);
encode(<<248, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111101011:27>>);
encode(<<249, R/bits>>, A) ->
    encode(R, <<A/bits, 2#1111111111111111111111111110:28>>);
encode(<<250, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111101100:27>>);
encode(<<251, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111101101:27>>);
encode(<<252, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111101110:27>>);
encode(<<253, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111101111:27>>);
encode(<<254, R/bits>>, A) ->
    encode(R, <<A/bits, 2#111111111111111111111110000:27>>);
encode(<<255, R/bits>>, A) ->
    encode(R, <<A/bits, 2#11111111111111111111101110:26>>).
