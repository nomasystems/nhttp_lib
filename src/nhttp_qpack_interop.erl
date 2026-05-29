-module(nhttp_qpack_interop).

-moduledoc """
QPACK Interop Format (QIF) parser and encoded file handler.

Implements the offline interop testing format described at:
https://github.com/quicwg/base-drafts/wiki/QPACK-Offline-Interop

QIF is a plain-text format where each field line is on a separate line
with name and value separated by a TAB character. Empty lines delimit
field sections. Lines starting with '#' are comments.

The binary encoded output format is:

    File = Block*
    Block = StreamId(64bit) | Length(32bit) | QPACKData

StreamId 0 carries encoder stream data. StreamId 1+ carry request
stream field section data.
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    decode_from_file/2,
    encode_to_file/2,
    parse_qif/1,
    write_qif/1
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([block/0, interop_config/0, qif/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type qif() :: [[nhttp_qpack:field_line()]].

-type block() :: #{
    stream_id := nhttp_lib:stream_id(),
    data := binary()
}.

-type interop_config() :: #{
    max_table_capacity => non_neg_integer(),
    max_blocked_streams => non_neg_integer(),
    huffman => boolean()
}.

%%%-----------------------------------------------------------------------------
%% QIF PARSING
%%%-----------------------------------------------------------------------------
-doc """
Parse a QIF text file into a list of field sections.

Each field section is a list of `{Name, Value}` tuples. Sections are
separated by empty lines. Lines starting with '#' are comments.
""".
-spec parse_qif(binary()) -> {ok, qif()}.
parse_qif(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    {ok, parse_lines(Lines, [], [])}.

-doc """
Write field sections back to QIF text format.
""".
-spec write_qif(qif()) -> {ok, iodata()}.
write_qif(FieldSections) ->
    Parts = lists:map(fun format_section/1, FieldSections),
    {ok, Parts}.

%%%-----------------------------------------------------------------------------
%% BINARY INTEROP FORMAT
%%%-----------------------------------------------------------------------------
-doc """
Decode the binary interop file format using the QPACK decoder.
Reads blocks sequentially: StreamId=0 blocks are fed as encoder
stream data, other blocks are decoded as field sections. Returns
the decoded field sections in order.
""".
-spec decode_from_file(binary(), interop_config()) ->
    {ok, qif()} | {error, term()}.
decode_from_file(Bin, Config) ->
    DecConfig = #{
        max_table_capacity =>
            maps:get(max_table_capacity, Config, 4096),
        max_blocked_streams =>
            maps:get(max_blocked_streams, Config, 100)
    },
    {ok, Dec0} = nhttp_qpack:new_decoder(DecConfig),
    Blocks = decode_blocks(Bin, []),
    replay_blocks(Blocks, Dec0, []).

-doc """
Encode QIF field sections to the binary interop file format.
For each field section, emits encoder stream blocks (StreamId=0) and
a request stream block (StreamId=N). The decoder can replay these
blocks in order.
""".
-spec encode_to_file(qif(), interop_config()) ->
    {ok, iodata()} | {error, term()}.
encode_to_file(FieldSections, Config) ->
    EncConfig = #{
        max_table_capacity =>
            maps:get(max_table_capacity, Config, 4096),
        max_blocked_streams =>
            maps:get(max_blocked_streams, Config, 100),
        huffman =>
            maps:get(huffman, Config, false)
    },
    {ok, Enc0} = nhttp_qpack:new_encoder(EncConfig),
    encode_sections(FieldSections, Enc0, 1, []).

%%%-----------------------------------------------------------------------------
%% INTERNAL - QIF PARSING
%%%-----------------------------------------------------------------------------
-spec format_section([nhttp_qpack:field_line()]) -> iodata().
format_section(Section) ->
    Lines = [
        [Name, <<"\t">>, Value, <<"\n">>]
     || {Name, Value} <- Section
    ],
    [Lines, <<"\n">>].

-spec parse_lines(
    [binary()],
    [nhttp_qpack:field_line()],
    qif()
) -> qif().
parse_lines([], [], Acc) ->
    lists:reverse(Acc);
parse_lines([], Current, Acc) ->
    lists:reverse([lists:reverse(Current) | Acc]);
parse_lines([<<>> | Rest], [], Acc) ->
    parse_lines(Rest, [], Acc);
parse_lines([<<>> | Rest], Current, Acc) ->
    parse_lines(Rest, [], [lists:reverse(Current) | Acc]);
parse_lines([<<"#", _/binary>> | Rest], Current, Acc) ->
    parse_lines(Rest, Current, Acc);
parse_lines([Line | Rest], Current, Acc) ->
    case binary:split(Line, <<"\t">>) of
        [Name, Value] ->
            parse_lines(
                Rest, [{Name, Value} | Current], Acc
            );
        [_] ->
            parse_lines(Rest, Current, Acc)
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL - BINARY FORMAT ENCODING
%%%-----------------------------------------------------------------------------
-spec encode_sections(
    qif(),
    nhttp_qpack:encoder(),
    nhttp_lib:stream_id(),
    [iodata()]
) ->
    {ok, iodata()} | {error, term()}.
encode_sections([], _Enc, _StreamId, Acc) ->
    {ok, lists:reverse(Acc)};
encode_sections(
    [Headers | Rest], Enc, StreamId, Acc
) ->
    {ok, Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, StreamId, Headers),
    EncBin = iolist_to_binary(EncStream),
    FDBin = iolist_to_binary(FieldData),
    Acc1 = maybe_add_block(0, EncBin, Acc),
    Acc2 = maybe_add_block(StreamId, FDBin, Acc1),
    encode_sections(Rest, Enc1, StreamId + 4, Acc2).

-spec maybe_add_block(
    nhttp_lib:stream_id(), binary(), [iodata()]
) -> [iodata()].
maybe_add_block(_StreamId, <<>>, Acc) ->
    Acc;
maybe_add_block(StreamId, Data, Acc) ->
    Len = byte_size(Data),
    Block = <<StreamId:64/big, Len:32/big, Data/binary>>,
    [Block | Acc].

%%%-----------------------------------------------------------------------------
%% INTERNAL - BINARY FORMAT DECODING
%%%-----------------------------------------------------------------------------
-spec decode_blocks(binary(), [block()]) -> [block()].
decode_blocks(<<>>, Acc) ->
    lists:reverse(Acc);
decode_blocks(
    <<StreamId:64/big, Length:32/big, Data:Length/binary, Rest/binary>>,
    Acc
) ->
    Block = #{stream_id => StreamId, data => Data},
    decode_blocks(Rest, [Block | Acc]);
decode_blocks(_, Acc) ->
    lists:reverse(Acc).

-spec replay_blocks(
    [block()],
    nhttp_qpack:decoder(),
    qif()
) ->
    {ok, qif()} | {error, term()}.
replay_blocks([], _Dec, Acc) ->
    {ok, lists:reverse(Acc)};
replay_blocks(
    [#{stream_id := 0, data := Data} | Rest], Dec, Acc
) ->
    case nhttp_qpack:feed_encoder_stream(Dec, Data) of
        {ok, Dec1, _Unblocked} ->
            replay_blocks(Rest, Dec1, Acc);
        {error, _} = Err ->
            Err
    end;
replay_blocks(
    [#{stream_id := StreamId, data := Data} | Rest],
    Dec,
    Acc
) ->
    case nhttp_qpack:decode_field_section(Dec, StreamId, Data) of
        {ok, Dec1, _DecStream, FieldLines} ->
            replay_blocks(Rest, Dec1, [FieldLines | Acc]);
        {blocked, _Dec1} ->
            {error, {blocked, StreamId}};
        {error, _} = Err ->
            Err
    end.
