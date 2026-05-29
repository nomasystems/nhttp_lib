-module(nhttp_qpack_decoder).

-moduledoc """
QPACK decoder state machine (RFC 9204 Section 2.2).

Processes encoded field sections and encoder stream instructions.
Maintains the dynamic table, handles blocked streams, and emits
decoder instructions (section acknowledgments, insert count
increments) back to the encoder.

The decoder receives:
  * Encoded field sections on request/push streams via
    `decode_field_section/3`
  * Encoder stream data via `feed_encoder_stream/2`

When a field section references a dynamic table entry that has not
yet been inserted, the stream is blocked until the encoder stream
delivers the missing entries.
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    decode_field_section/3,
    feed_encoder_stream/2,
    new/1
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([config/0, state/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type config() :: #{
    max_table_capacity => non_neg_integer(),
    max_blocked_streams => non_neg_integer()
}.

-type field_line() :: {binary(), binary()}.

-type unblocked_result() :: {
    nhttp_lib:stream_id(), iodata(), [field_line()]
}.

%%%-----------------------------------------------------------------------------
%% RECORDS
%%%-----------------------------------------------------------------------------
-record(qpack_dec, {
    dynamic_table :: nhttp_qpack_dynamic_table:t(),
    max_table_capacity :: non_neg_integer(),
    max_entries :: non_neg_integer(),
    max_blocked_streams :: non_neg_integer(),
    known_sending_count :: non_neg_integer(),
    blocked_streams :: #{nhttp_lib:stream_id() => blocked_section()},
    encoder_stream_buf :: binary()
}).

-record(blocked_section, {
    required_insert_count :: pos_integer(),
    data :: binary(),
    stream_id :: nhttp_lib:stream_id()
}).

-type blocked_section() :: #blocked_section{}.

-opaque state() :: #qpack_dec{}.

%%%-----------------------------------------------------------------------------
%% API FUNCTIONS
%%%-----------------------------------------------------------------------------
-doc """
Decode an encoded field section from a request or push stream.

Returns `{ok, NewState, DecoderStreamData, FieldLines}` on success,
`{blocked, NewState}` when the required insert count exceeds the
current insert count, or `{error, Reason}` on failure.
""".
-spec decode_field_section(state(), nhttp_lib:stream_id(), binary()) ->
    {ok, state(), iodata(), [field_line()]}
    | {blocked, state()}
    | {error, term()}.
decode_field_section(State, StreamId, Data) ->
    #qpack_dec{
        dynamic_table = DynTable,
        max_entries = MaxEntries,
        blocked_streams = BlockedStreams,
        max_blocked_streams = MaxBlocked
    } = State,
    InsertCount = nhttp_qpack_dynamic_table:insert_count(DynTable),
    maybe
        {ok, Prefix, Rest} ?=
            nhttp_qpack_field_line:decode_prefix(
                Data, MaxEntries, InsertCount
            ),
        #{required_insert_count := RIC, base := Base} = Prefix,
        case RIC > InsertCount of
            true ->
                block_stream(
                    State,
                    StreamId,
                    RIC,
                    Data,
                    BlockedStreams,
                    MaxBlocked
                );
            false ->
                decode_field_lines(
                    State, StreamId, Rest, Base, RIC
                )
        end
    end.

-doc """
Feed encoder stream data into the decoder.
Processes encoder instructions (table insertions, capacity changes,
duplications) and unblocks any streams whose required insert count
is now satisfied.
Returns `{ok, NewState, UnblockedResults}` where UnblockedResults
is a list of `{StreamId, DecoderStreamData, FieldLines}` tuples
for streams that became unblocked.
""".
-spec feed_encoder_stream(state(), binary()) ->
    {ok, state(), [unblocked_result()]}
    | {error, term()}.
feed_encoder_stream(State, Data) ->
    #qpack_dec{encoder_stream_buf = Buf} = State,
    Combined = <<Buf/binary, Data/binary>>,
    process_encoder_instructions(
        State#qpack_dec{encoder_stream_buf = Combined}
    ).

-doc "Create a new QPACK decoder with the given configuration.".
-spec new(config()) -> {ok, state()}.
new(Config) ->
    MaxCap = maps:get(max_table_capacity, Config, 0),
    MaxBlocked = maps:get(max_blocked_streams, Config, 0),
    {ok, Table} = nhttp_qpack_dynamic_table:new(MaxCap),
    {ok, #qpack_dec{
        dynamic_table = Table,
        max_table_capacity = MaxCap,
        max_entries = MaxCap div 32,
        max_blocked_streams = MaxBlocked,
        known_sending_count = 0,
        blocked_streams = #{},
        encoder_stream_buf = <<>>
    }}.

%%%-----------------------------------------------------------------------------
%% INTERNAL - BLOCKING
%%%-----------------------------------------------------------------------------
-spec block_stream(
    state(),
    nhttp_lib:stream_id(),
    pos_integer(),
    binary(),
    #{nhttp_lib:stream_id() => blocked_section()},
    non_neg_integer()
) ->
    {blocked, state()} | {error, blocked_stream_limit}.
block_stream(
    _State,
    _StreamId,
    _RIC,
    _Data,
    BlockedStreams,
    MaxBlocked
) when
    map_size(BlockedStreams) >= MaxBlocked
->
    {error, blocked_stream_limit};
block_stream(
    State,
    StreamId,
    RIC,
    Data,
    BlockedStreams,
    _MaxBlocked
) ->
    Blocked = #blocked_section{
        required_insert_count = RIC,
        data = Data,
        stream_id = StreamId
    },
    NewBlocked = BlockedStreams#{StreamId => Blocked},
    {blocked, State#qpack_dec{blocked_streams = NewBlocked}}.

%%%-----------------------------------------------------------------------------
%% INTERNAL - FIELD LINE DECODING
%%%-----------------------------------------------------------------------------
-spec decode_field_lines(
    state(),
    nhttp_lib:stream_id(),
    bitstring(),
    non_neg_integer(),
    non_neg_integer()
) ->
    {ok, state(), iodata(), [field_line()]}
    | {error, term()}.
decode_field_lines(State, StreamId, Rest, Base, RIC) ->
    #qpack_dec{dynamic_table = DynTable} = State,
    case decode_representations(Rest, Base, DynTable, [], false) of
        {ok, FieldLines, UsedDynamic} ->
            DecoderData = make_decoder_data(
                StreamId, RIC, UsedDynamic, State
            ),
            NewState = update_known_sending_count(
                State, RIC, UsedDynamic
            ),
            {ok, NewState, DecoderData, FieldLines};
        {error, _} = Err ->
            Err
    end.

-spec decode_representations(
    bitstring(),
    non_neg_integer(),
    nhttp_qpack_dynamic_table:t(),
    [field_line()],
    boolean()
) ->
    {ok, [field_line()], boolean()} | {error, term()}.
decode_representations(<<>>, _Base, _DynTable, Acc, UsedDyn) ->
    {ok, lists:reverse(Acc), UsedDyn};
decode_representations(Bin, Base, DynTable, Acc, UsedDyn) ->
    maybe
        {ok, Rep, Rest} ?=
            nhttp_qpack_field_line:decode_representation(Bin),
        {ok, FieldLine, RefsDynamic} ?=
            resolve_representation(Rep, Base, DynTable),
        decode_representations(
            Rest,
            Base,
            DynTable,
            [FieldLine | Acc],
            UsedDyn orelse RefsDynamic
        )
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL - REPRESENTATION RESOLUTION
%%%-----------------------------------------------------------------------------
-spec resolve_representation(
    nhttp_qpack_field_line:representation(),
    non_neg_integer(),
    nhttp_qpack_dynamic_table:t()
) ->
    {ok, field_line(), boolean()} | {error, term()}.
resolve_representation(
    {indexed, static, Index}, _Base, _DynTable
) ->
    maybe
        {ok, Entry} ?= nhttp_qpack_static_table:lookup(Index),
        {ok, Entry, false}
    end;
resolve_representation(
    {indexed, dynamic, RelIndex}, Base, DynTable
) ->
    AbsIndex = Base - RelIndex - 1,
    maybe
        {ok, Entry} ?=
            nhttp_qpack_dynamic_table:lookup(AbsIndex, DynTable),
        {ok, Entry, true}
    end;
resolve_representation(
    {indexed_post_base, Index}, Base, DynTable
) ->
    AbsIndex = Base + Index,
    maybe
        {ok, Entry} ?=
            nhttp_qpack_dynamic_table:lookup(AbsIndex, DynTable),
        {ok, Entry, true}
    end;
resolve_representation(
    {literal_name_ref, static, Index, Value, _NI},
    _Base,
    _DynTable
) ->
    maybe
        {ok, {Name, _}} ?=
            nhttp_qpack_static_table:lookup(Index),
        {ok, {Name, Value}, false}
    end;
resolve_representation(
    {literal_name_ref, dynamic, RelIndex, Value, _NI},
    Base,
    DynTable
) ->
    AbsIndex = Base - RelIndex - 1,
    maybe
        {ok, {Name, _}} ?=
            nhttp_qpack_dynamic_table:lookup(AbsIndex, DynTable),
        {ok, {Name, Value}, true}
    end;
resolve_representation(
    {literal_post_base_name_ref, Index, Value, _NI},
    Base,
    DynTable
) ->
    AbsIndex = Base + Index,
    maybe
        {ok, {Name, _}} ?=
            nhttp_qpack_dynamic_table:lookup(AbsIndex, DynTable),
        {ok, {Name, Value}, true}
    end;
resolve_representation(
    {literal, Name, Value, _NI}, _Base, _DynTable
) ->
    {ok, {Name, Value}, false}.

%%%-----------------------------------------------------------------------------
%% INTERNAL - DECODER STREAM DATA
%%%-----------------------------------------------------------------------------
-spec make_decoder_data(
    nhttp_lib:stream_id(),
    non_neg_integer(),
    boolean(),
    state()
) -> iodata().
make_decoder_data(StreamId, _RIC, true, _State) ->
    nhttp_qpack_decoder_instruction:encode_section_ack(
        StreamId
    );
make_decoder_data(_StreamId, RIC, false, State) ->
    #qpack_dec{known_sending_count = KSC} = State,
    case RIC > KSC of
        true ->
            Increment = RIC - KSC,
            nhttp_qpack_decoder_instruction:encode_insert_count_increment(
                Increment
            );
        false ->
            []
    end.

-spec update_known_sending_count(
    state(), non_neg_integer(), boolean()
) -> state().
update_known_sending_count(State, _RIC, true) ->
    State;
update_known_sending_count(State, RIC, false) ->
    #qpack_dec{known_sending_count = KSC} = State,
    case RIC > KSC of
        true ->
            State#qpack_dec{known_sending_count = RIC};
        false ->
            State
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL - ENCODER STREAM PROCESSING
%%%-----------------------------------------------------------------------------
-spec apply_encoder_instruction(
    nhttp_qpack_encoder_instruction:t(), state()
) -> {ok, state()} | {error, term()}.
apply_encoder_instruction(
    {set_capacity, Cap},
    #qpack_dec{dynamic_table = DynTable} = State
) ->
    maybe
        {ok, NewTable} ?=
            nhttp_qpack_dynamic_table:set_capacity(Cap, DynTable),
        {ok, State#qpack_dec{dynamic_table = NewTable}}
    end;
apply_encoder_instruction(
    {insert_name_ref, static, Index, Value},
    #qpack_dec{dynamic_table = DynTable} = State
) ->
    maybe
        {ok, {Name, _}} ?=
            nhttp_qpack_static_table:lookup(Index),
        {ok, NewTable} ?=
            nhttp_qpack_dynamic_table:insert(
                Name, Value, DynTable
            ),
        {ok, State#qpack_dec{dynamic_table = NewTable}}
    end;
apply_encoder_instruction(
    {insert_name_ref, dynamic, RelIndex, Value},
    #qpack_dec{dynamic_table = DynTable} = State
) ->
    IC = nhttp_qpack_dynamic_table:insert_count(DynTable),
    AbsIndex = IC - RelIndex - 1,
    maybe
        {ok, {Name, _}} ?=
            nhttp_qpack_dynamic_table:lookup(
                AbsIndex, DynTable
            ),
        {ok, NewTable} ?=
            nhttp_qpack_dynamic_table:insert(
                Name, Value, DynTable
            ),
        {ok, State#qpack_dec{dynamic_table = NewTable}}
    end;
apply_encoder_instruction(
    {insert_literal_name, Name, Value},
    #qpack_dec{dynamic_table = DynTable} = State
) ->
    maybe
        {ok, NewTable} ?=
            nhttp_qpack_dynamic_table:insert(
                Name, Value, DynTable
            ),
        {ok, State#qpack_dec{dynamic_table = NewTable}}
    end;
apply_encoder_instruction(
    {duplicate, RelIndex},
    #qpack_dec{dynamic_table = DynTable} = State
) ->
    IC = nhttp_qpack_dynamic_table:insert_count(DynTable),
    AbsIndex = IC - RelIndex - 1,
    maybe
        {ok, {Name, Value}} ?=
            nhttp_qpack_dynamic_table:lookup(
                AbsIndex, DynTable
            ),
        {ok, NewTable} ?=
            nhttp_qpack_dynamic_table:insert(
                Name, Value, DynTable
            ),
        {ok, State#qpack_dec{dynamic_table = NewTable}}
    end.

-spec process_encoder_instructions(state()) ->
    {ok, state(), [unblocked_result()]} | {error, term()}.
process_encoder_instructions(State) ->
    #qpack_dec{encoder_stream_buf = Buf} = State,
    process_encoder_loop(State, Buf).

-spec process_encoder_loop(state(), binary()) ->
    {ok, state(), [unblocked_result()]} | {error, term()}.
process_encoder_loop(State, <<>>) ->
    State1 = State#qpack_dec{encoder_stream_buf = <<>>},
    try_unblock_streams(State1);
process_encoder_loop(State, Buf) ->
    case nhttp_qpack_encoder_instruction:decode(Buf) of
        {ok, Instruction, Rest} ->
            case apply_encoder_instruction(Instruction, State) of
                {ok, NewState} ->
                    RestBin = align_binary(Rest),
                    process_encoder_loop(NewState, RestBin);
                {error, _} = Err ->
                    Err
            end;
        {error, incomplete} ->
            State1 = State#qpack_dec{
                encoder_stream_buf = align_binary(Buf)
            },
            try_unblock_streams(State1);
        {error, _} = Err ->
            Err
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL - UNBLOCKING
%%%-----------------------------------------------------------------------------
-spec decode_unblocked(
    [blocked_section()], state(), [unblocked_result()]
) ->
    {ok, state(), [unblocked_result()]} | {error, term()}.
decode_unblocked([], State, Acc) ->
    {ok, State, lists:reverse(Acc)};
decode_unblocked(
    [
        #blocked_section{
            data = Data,
            stream_id = StreamId
        }
        | Rest
    ],
    State,
    Acc
) ->
    case decode_field_section(State, StreamId, Data) of
        {ok, NewState, DecoderData, FieldLines} ->
            Result = {StreamId, DecoderData, FieldLines},
            decode_unblocked(Rest, NewState, [Result | Acc]);
        {error, _} = Err ->
            Err;
        {blocked, _} ->
            decode_unblocked(Rest, State, Acc)
    end.

-spec partition_blocked(
    [{nhttp_lib:stream_id(), blocked_section()}],
    non_neg_integer(),
    [blocked_section()],
    #{nhttp_lib:stream_id() => blocked_section()}
) ->
    {[blocked_section()], #{nhttp_lib:stream_id() => blocked_section()}}.
partition_blocked([], _IC, Ready, StillBlocked) ->
    {Ready, StillBlocked};
partition_blocked(
    [{StreamId, Section} | Rest], IC, Ready, StillBlocked
) ->
    #blocked_section{required_insert_count = RIC} = Section,
    case RIC =< IC of
        true ->
            partition_blocked(
                Rest, IC, [Section | Ready], StillBlocked
            );
        false ->
            partition_blocked(
                Rest,
                IC,
                Ready,
                StillBlocked#{StreamId => Section}
            )
    end.

-spec try_unblock_streams(state()) ->
    {ok, state(), [unblocked_result()]} | {error, term()}.
try_unblock_streams(State) ->
    #qpack_dec{
        dynamic_table = DynTable,
        blocked_streams = BlockedStreams
    } = State,
    IC = nhttp_qpack_dynamic_table:insert_count(DynTable),
    {Ready, StillBlocked} = partition_blocked(
        maps:to_list(BlockedStreams), IC, [], #{}
    ),
    State1 = State#qpack_dec{blocked_streams = StillBlocked},
    decode_unblocked(Ready, State1, []).

%%%-----------------------------------------------------------------------------
%% INTERNAL - HELPERS
%%%-----------------------------------------------------------------------------
-spec align_binary(bitstring()) -> binary().
align_binary(Bin) when is_binary(Bin) ->
    Bin;
align_binary(Bits) ->
    BitSize = bit_size(Bits),
    PadBits = (8 - (BitSize rem 8)) rem 8,
    <<Bin:((BitSize + PadBits) div 8)/binary>> =
        <<Bits/bits, 0:PadBits>>,
    Bin.
