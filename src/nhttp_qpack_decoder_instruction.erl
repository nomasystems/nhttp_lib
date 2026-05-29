-module(nhttp_qpack_decoder_instruction).

-moduledoc """
Decoder instructions wire format (RFC 9204 Section 4.4).

Decoder instructions are sent from decoder to encoder on the decoder
unidirectional stream. They provide acknowledgments and state updates.

Three instruction types:
- Section Acknowledgment   (1xxxxxxx) - 7-bit stream ID
- Stream Cancellation      (01xxxxxx) - 6-bit stream ID
- Insert Count Increment   (00xxxxxx) - 6-bit increment
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    encode_insert_count_increment/1,
    encode_section_ack/1,
    encode_stream_cancellation/1
]).

-export([decode/1]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([decode_error/0, t/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type t() ::
    {section_ack, nhttp_lib:stream_id()}
    | {stream_cancellation, nhttp_lib:stream_id()}
    | {insert_count_increment, pos_integer()}.

-type decode_error() :: incomplete | zero_increment.

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc "Encode an Insert Count Increment instruction (RFC 9204 Section 4.4.3).".
-spec encode_insert_count_increment(pos_integer()) -> iolist().
encode_insert_count_increment(Increment) ->
    [nhttp_int:enc6(Increment, 2#00)].

-doc "Encode a Section Acknowledgment instruction (RFC 9204 Section 4.4.1).".
-spec encode_section_ack(nhttp_lib:stream_id()) -> iolist().
encode_section_ack(StreamId) ->
    [nhttp_int:enc7(StreamId, 2#1)].

-doc "Encode a Stream Cancellation instruction (RFC 9204 Section 4.4.2).".
-spec encode_stream_cancellation(nhttp_lib:stream_id()) -> iolist().
encode_stream_cancellation(StreamId) ->
    [nhttp_int:enc6(StreamId, 2#01)].

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a single decoder instruction from binary data.
Returns the decoded instruction and any unconsumed bytes.
""".
-spec decode(bitstring()) ->
    {ok, t(), bitstring()} | {error, decode_error()}.
decode(<<>>) ->
    {error, incomplete};
decode(<<1:1, Rest/bits>>) ->
    maybe
        {ok, StreamId, Rest2} ?= map_error(nhttp_int:dec7(Rest)),
        {ok, {section_ack, StreamId}, Rest2}
    end;
decode(<<2#01:2, Rest/bits>>) ->
    maybe
        {ok, StreamId, Rest2} ?= map_error(nhttp_int:dec6(Rest)),
        {ok, {stream_cancellation, StreamId}, Rest2}
    end;
decode(<<2#00:2, Rest/bits>>) ->
    maybe
        {ok, Increment, Rest2} ?= map_error(nhttp_int:dec6(Rest)),
        case Increment of
            0 -> {error, zero_increment};
            _ -> {ok, {insert_count_increment, Increment}, Rest2}
        end
    end;
decode(_) ->
    {error, incomplete}.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec map_error
    ({ok, non_neg_integer(), bitstring()}) -> {ok, non_neg_integer(), bitstring()};
    ({error, nhttp_int:decode_error()}) -> {error, decode_error()}.
map_error({ok, _, _} = Ok) -> Ok;
map_error({error, incomplete}) -> {error, incomplete};
map_error({error, overflow}) -> {error, incomplete}.
