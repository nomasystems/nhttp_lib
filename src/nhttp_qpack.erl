-module(nhttp_qpack).

-moduledoc """
QPACK header compression for HTTP/3 (RFC 9204).

Public API facade that delegates to the encoder and decoder state
machines. Provides a symmetric interface for encoding and decoding
field sections on request/push streams, and feeding control stream
data in both directions.

## Encoder usage

```erlang
{ok, Enc0} = nhttp_qpack:new_encoder(#{
    max_table_capacity => 4096,
    max_blocked_streams => 100
}),
Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
{ok, Enc1, EncStreamData, FieldData} =
    nhttp_qpack:encode_field_section(Enc0, 0, Headers).
```

## Decoder usage

```erlang
{ok, Dec0} = nhttp_qpack:new_decoder(#{
    max_table_capacity => 4096,
    max_blocked_streams => 100
}),
{ok, Dec1, DecStreamData, FieldLines} =
    nhttp_qpack:decode_field_section(Dec0, 0, FieldData).
```
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([encode_field_section/3, feed_decoder_stream/2, new_encoder/1, reconcile_peer_limits/3]).

-export([decode_field_section/3, feed_encoder_stream/2, new_decoder/1]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    decoder/0,

    decoder_config/0,
    encoder/0,

    encoder_config/0,

    field_line/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type encoder() :: nhttp_qpack_encoder:state().
-type decoder() :: nhttp_qpack_decoder:state().

-type encoder_config() :: nhttp_qpack_encoder:config().
-type decoder_config() :: nhttp_qpack_decoder:config().

-type field_line() :: {binary(), binary()}.

%%%-----------------------------------------------------------------------------
%% ENCODER API
%%%-----------------------------------------------------------------------------
-doc """
Encode a field section for the given stream.

Returns encoder stream data (to send on the encoder unidirectional
stream) and field section data (to send on the request stream).
""".
-spec encode_field_section(
    encoder(), nhttp_lib:stream_id(), [field_line()]
) ->
    {ok, encoder(), iodata(), iodata()}.
encode_field_section(Encoder, StreamId, Headers) ->
    nhttp_qpack_encoder:encode_field_section(
        Encoder, StreamId, Headers
    ).

-doc """
Feed decoder stream data into the encoder.
Processes section acknowledgments, stream cancellations, and insert
count increments from the decoder.
""".
-spec feed_decoder_stream(encoder(), binary()) ->
    {ok, encoder()} | {error, term()}.
feed_decoder_stream(Encoder, Data) ->
    nhttp_qpack_encoder:feed_decoder_stream(Encoder, Data).

-doc "Create a new QPACK encoder.".
-spec new_encoder(encoder_config()) -> {ok, encoder()}.
new_encoder(Config) ->
    nhttp_qpack_encoder:new(Config).

-doc """
Reconcile the encoder against the peer's advertised QPACK limits
(SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS).
Call once when the peer's HTTP/3 SETTINGS are received. See
`nhttp_qpack_encoder:reconcile_peer_limits/3`.
""".
-spec reconcile_peer_limits(non_neg_integer(), non_neg_integer(), encoder()) -> encoder().
reconcile_peer_limits(PeerMaxCap, PeerMaxBlocked, Encoder) ->
    nhttp_qpack_encoder:reconcile_peer_limits(PeerMaxCap, PeerMaxBlocked, Encoder).

%%%-----------------------------------------------------------------------------
%% DECODER API
%%%-----------------------------------------------------------------------------
-doc """
Decode an encoded field section from a request or push stream.
Returns `{ok, Decoder, DecoderStreamData, FieldLines}` on success,
`{blocked, Decoder}` when the field section references entries not
yet received on the encoder stream, or `{error, Reason}` on failure.
""".
-spec decode_field_section(
    decoder(), nhttp_lib:stream_id(), binary()
) ->
    {ok, decoder(), iodata(), [field_line()]}
    | {blocked, decoder()}
    | {error, term()}.
decode_field_section(Decoder, StreamId, Data) ->
    nhttp_qpack_decoder:decode_field_section(
        Decoder, StreamId, Data
    ).

-doc """
Feed encoder stream data into the decoder.
Processes encoder instructions (table insertions, capacity changes,
duplications) and unblocks any streams whose required insert count
is now satisfied.
Returns `{ok, Decoder, UnblockedResults}` where UnblockedResults
is a list of `{StreamId, DecoderStreamData, FieldLines}` tuples
for streams that became unblocked.
""".
-spec feed_encoder_stream(decoder(), binary()) ->
    {ok, decoder(), [{nhttp_lib:stream_id(), iodata(), [field_line()]}]}
    | {error, term()}.
feed_encoder_stream(Decoder, Data) ->
    nhttp_qpack_decoder:feed_encoder_stream(Decoder, Data).

-doc "Create a new QPACK decoder.".
-spec new_decoder(decoder_config()) -> {ok, decoder()}.
new_decoder(Config) ->
    nhttp_qpack_decoder:new(Config).
