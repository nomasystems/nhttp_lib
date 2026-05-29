-module(nhttp_qpack_encoder).

-moduledoc """
QPACK encoder state machine (RFC 9204 Section 2.1).

Converts field sections into compressed representations using the QPACK
header compression format for HTTP/3. The encoder maintains a dynamic
table, generates encoder stream instructions for table modifications,
and produces encoded field section data for request streams.

The implementation uses a conservative encoding strategy following
Appendix C of RFC 9204: static table lookups are always preferred,
dynamic table entries are only referenced when safely below the Known
Received Count (no risk of blocking), and new entries are inserted
eagerly when table capacity allows.

## Usage

```erlang
{ok, Enc0} = nhttp_qpack_encoder:new(#{
    max_table_capacity => 4096,
    max_blocked_streams => 100
}),

Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
{ok, Enc1, EncStreamData, FieldData} =
    nhttp_qpack_encoder:encode_field_section(Enc0, 0, Headers),


DecoderData = ...,
{ok, Enc2} = nhttp_qpack_encoder:feed_decoder_stream(Enc1, DecoderData).
```
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    encode_field_section/3,
    feed_decoder_stream/2,
    new/1,
    reconcile_peer_limits/3
]).

-export_type([config/0, state/0]).

-type enc_rep() ::
    nhttp_qpack_field_line:representation()
    | {abs_indexed, non_neg_integer()}.

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type config() :: #{
    max_table_capacity => non_neg_integer(),
    configured_max_capacity => non_neg_integer(),
    max_blocked_streams => non_neg_integer(),
    configured_max_blocked => non_neg_integer(),
    huffman => boolean()
}.

%%%-----------------------------------------------------------------------------
%% RECORDS
%%%-----------------------------------------------------------------------------
-record(qpack_enc, {
    dynamic_table :: nhttp_qpack_dynamic_table:t(),
    max_table_capacity :: non_neg_integer(),
    configured_max_capacity :: non_neg_integer(),
    max_entries :: non_neg_integer(),
    max_blocked_streams :: non_neg_integer(),
    configured_max_blocked :: non_neg_integer(),
    known_received_count :: non_neg_integer(),
    blocked_stream_count :: non_neg_integer(),
    stream_refs :: #{nhttp_lib:stream_id() => non_neg_integer()},
    pending_capacity :: boolean(),
    huffman :: boolean()
}).

-record(enc_acc, {
    enc_instructions :: [iodata()],
    representations :: [enc_rep()],
    max_ref :: non_neg_integer(),
    min_ref :: non_neg_integer() | infinity,
    has_dynamic_ref :: boolean(),
    can_block :: boolean(),
    state :: #qpack_enc{}
}).

-opaque state() :: #qpack_enc{}.

%%%-----------------------------------------------------------------------------
%% API FUNCTIONS
%%%-----------------------------------------------------------------------------
-doc """
Encode a field section for the given stream.

Returns encoder stream data (instructions for the decoder's dynamic
table) and field section data (the prefix plus encoded representations
to send on the request stream).
""".
-spec encode_field_section(
    state(), nhttp_lib:stream_id(), [{binary(), binary()}]
) ->
    {ok, state(), iodata(), iodata()}.
encode_field_section(State0, StreamId, Headers) ->
    {CapInstr, State1} = maybe_emit_capacity(State0),
    CanBlock =
        State1#qpack_enc.blocked_stream_count < State1#qpack_enc.max_blocked_streams,
    Acc0 = #enc_acc{
        enc_instructions = CapInstr,
        representations = [],
        max_ref = 0,
        min_ref = infinity,
        has_dynamic_ref = false,
        can_block = CanBlock,
        state = State1
    },
    Acc1 = encode_headers(Headers, Acc0),
    #enc_acc{
        enc_instructions = EncInstrs,
        representations = Reps,
        max_ref = MaxRef,
        has_dynamic_ref = HasDynRef,
        state = State2
    } = Acc1,
    {RIC, Base} = compute_ric_base(HasDynRef, MaxRef),
    MaxEntries = State2#qpack_enc.max_entries,
    Huffman = State2#qpack_enc.huffman,
    Prefix = nhttp_qpack_field_line:encode_prefix(
        RIC, Base, MaxEntries
    ),
    FinalReps = resolve_reps(lists:reverse(Reps), Base),
    EncodedReps = encode_reps(FinalReps, Huffman),
    FieldSection = [Prefix | EncodedReps],
    EncStream = lists:reverse(EncInstrs),
    State3 = track_stream_ref(
        State2, StreamId, HasDynRef, MaxRef
    ),
    {ok, State3, EncStream, FieldSection}.

-doc """
Process decoder instructions received on the decoder stream.
Handles section acknowledgments, stream cancellations, and insert
count increments. Partial instructions are buffered (returns the
current state unchanged).
""".
-spec feed_decoder_stream(state(), binary()) ->
    {ok, state()} | {error, term()}.
feed_decoder_stream(State, Data) ->
    process_decoder_instructions(State, Data).

-doc "Create a new encoder with the given configuration.".
-spec new(config()) -> {ok, state()}.
new(Config) ->
    MaxCap = maps:get(max_table_capacity, Config, 0),
    ConfiguredCap = maps:get(configured_max_capacity, Config, MaxCap),
    MaxBlocked = maps:get(max_blocked_streams, Config, 0),
    ConfiguredBlocked = maps:get(configured_max_blocked, Config, MaxBlocked),
    Huffman = maps:get(huffman, Config, false),
    {ok, Table} = nhttp_qpack_dynamic_table:new(ConfiguredCap),
    {ok, #qpack_enc{
        dynamic_table = Table,
        max_table_capacity = MaxCap,
        configured_max_capacity = ConfiguredCap,
        max_entries = MaxCap div 32,
        max_blocked_streams = MaxBlocked,
        configured_max_blocked = ConfiguredBlocked,
        known_received_count = 0,
        blocked_stream_count = 0,
        stream_refs = #{},
        pending_capacity = MaxCap > 0,
        huffman = Huffman
    }}.

-doc """
Reconcile the encoder against the peer's advertised QPACK limits
(RFC 9204 Section 3.2.3). The peer is the decoder of the field
sections this encoder produces, so the effective dynamic-table
capacity is bounded by `min(configured ceiling, peer advertised)`, and
the encoder must never reference more than the peer's advertised
blocked-stream budget. `max_entries` for the field-section prefix is
fixed by the peer's advertised capacity (Section 4.5.1.1), independent
of how much of the table this encoder chooses to use.

Arms the Set Dynamic Table Capacity instruction so the next encode
announces the effective capacity on the encoder stream before any
reference to a dynamic entry. Capacity 0 (the QPACK default, e.g. a
peer that does not advertise the setting) leaves the encoder dormant:
all field lines stay static-or-literal and no encoder-stream
instructions are emitted.
""".
-spec reconcile_peer_limits(non_neg_integer(), non_neg_integer(), state()) -> state().
reconcile_peer_limits(PeerMaxCap, PeerMaxBlocked, State) ->
    EffectiveCap = min(State#qpack_enc.configured_max_capacity, PeerMaxCap),
    EffectiveBlocked = min(State#qpack_enc.configured_max_blocked, PeerMaxBlocked),
    State#qpack_enc{
        max_table_capacity = EffectiveCap,
        max_entries = PeerMaxCap div 32,
        max_blocked_streams = EffectiveBlocked,
        pending_capacity = EffectiveCap > 0
    }.

%%%-----------------------------------------------------------------------------
%% INTERNAL - CAPACITY INSTRUCTION
%%%-----------------------------------------------------------------------------
-spec maybe_emit_capacity(#qpack_enc{}) -> {[iodata()], #qpack_enc{}}.
maybe_emit_capacity(
    #qpack_enc{
        pending_capacity = true,
        max_table_capacity = Cap,
        dynamic_table = DynTable
    } = State
) ->
    Instr = nhttp_qpack_encoder_instruction:encode_set_capacity(
        Cap
    ),
    {ok, DynTable1} =
        nhttp_qpack_dynamic_table:set_capacity(Cap, DynTable),
    {[Instr], State#qpack_enc{
        pending_capacity = false,
        dynamic_table = DynTable1
    }};
maybe_emit_capacity(State) ->
    {[], State}.

%%%-----------------------------------------------------------------------------
%% INTERNAL - HEADER ENCODING LOOP
%%%-----------------------------------------------------------------------------
-spec can_insert(
    binary(), binary(), #qpack_enc{}, non_neg_integer() | infinity
) -> boolean().
can_insert(
    _Name, _Value, #qpack_enc{max_table_capacity = 0}, _MinRef
) ->
    false;
can_insert(
    Name, Value, #qpack_enc{dynamic_table = DynTable}, MinRef
) ->
    case nhttp_qpack_dynamic_table:insert(Name, Value, DynTable) of
        {ok, TrialTable} ->
            NewDC =
                nhttp_qpack_dynamic_table:drop_count(TrialTable),
            case MinRef of
                infinity -> true;
                _ -> NewDC =< MinRef
            end;
        {error, _} ->
            false
    end.

-spec do_insert_literal_name(
    binary(), binary(), #enc_acc{}
) -> #enc_acc{}.
do_insert_literal_name(Name, Value, Acc) ->
    #enc_acc{state = State} = Acc,
    Huffman = State#qpack_enc.huffman,
    DynTable = State#qpack_enc.dynamic_table,
    {ok, DynTable1} = nhttp_qpack_dynamic_table:insert(
        Name, Value, DynTable
    ),
    NewAbsIndex =
        nhttp_qpack_dynamic_table:insert_count(DynTable1) - 1,
    Instr =
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            Name, Value, Huffman
        ),
    State1 = State#qpack_enc{dynamic_table = DynTable1},
    Rep = {abs_indexed, NewAbsIndex},
    Acc1 = Acc#enc_acc{
        state = State1,
        enc_instructions = [
            Instr | Acc#enc_acc.enc_instructions
        ]
    },
    add_dynamic_rep(Acc1, Rep, NewAbsIndex).

-spec do_insert_name_ref(
    static | dynamic,
    non_neg_integer(),
    binary(),
    binary(),
    #enc_acc{}
) -> #enc_acc{}.
do_insert_name_ref(Table, NameIndex, Name, Value, Acc) ->
    #enc_acc{state = State} = Acc,
    Huffman = State#qpack_enc.huffman,
    DynTable = State#qpack_enc.dynamic_table,
    {ok, DynTable1} = nhttp_qpack_dynamic_table:insert(
        Name, Value, DynTable
    ),
    NewAbsIndex =
        nhttp_qpack_dynamic_table:insert_count(DynTable1) - 1,
    Instr =
        nhttp_qpack_encoder_instruction:encode_insert_name_ref(
            Table, NameIndex, Value, Huffman
        ),
    State1 = State#qpack_enc{dynamic_table = DynTable1},
    Rep = {abs_indexed, NewAbsIndex},
    Acc1 = Acc#enc_acc{
        state = State1,
        enc_instructions = [
            Instr | Acc#enc_acc.enc_instructions
        ]
    },
    add_dynamic_rep(Acc1, Rep, NewAbsIndex).

-spec encode_headers(
    [{binary(), binary()}], #enc_acc{}
) -> #enc_acc{}.
encode_headers([], Acc) ->
    Acc;
encode_headers([{Name, Value} | Rest], Acc) ->
    Acc1 = encode_one_header(Name, Value, Acc),
    encode_headers(Rest, Acc1).

-spec encode_one_header(binary(), binary(), #enc_acc{}) ->
    #enc_acc{}.
encode_one_header(Name, Value, Acc) ->
    case nhttp_qpack_static_table:find_name_value(Name, Value) of
        {ok, Index} ->
            add_rep(Acc, {indexed, static, Index});
        NameRes ->
            encode_non_static_full(Name, Value, NameRes, Acc)
    end.

-spec encode_non_static_full(
    binary(), binary(), {name, non_neg_integer()} | error, #enc_acc{}
) -> #enc_acc{}.
encode_non_static_full(
    Name, Value, NameRes, #enc_acc{state = #qpack_enc{max_table_capacity = 0}} = Acc
) ->
    encode_static_name_or_literal(NameRes, Name, Value, Acc);
encode_non_static_full(Name, Value, NameRes, Acc) ->
    #enc_acc{state = State} = Acc,
    DynTable = State#qpack_enc.dynamic_table,
    KRC = State#qpack_enc.known_received_count,
    case nhttp_qpack_dynamic_table:find(Name, Value, DynTable) of
        {ok, AbsIndex} when AbsIndex < KRC ->
            add_dynamic_rep(Acc, {abs_indexed, AbsIndex}, AbsIndex);
        _ ->
            encode_static_name_or_literal(NameRes, Name, Value, Acc)
    end.

-spec encode_static_name_or_literal(
    {name, non_neg_integer()} | error, binary(), binary(), #enc_acc{}
) -> #enc_acc{}.
encode_static_name_or_literal({name, NameIndex}, Name, Value, Acc) ->
    try_insert_with_static_name(NameIndex, Name, Value, Acc);
encode_static_name_or_literal(error, Name, Value, Acc) ->
    try_insert_literal(Name, Value, Acc).

-spec try_insert_literal(binary(), binary(), #enc_acc{}) ->
    #enc_acc{}.
try_insert_literal(Name, Value, Acc) ->
    #enc_acc{state = State, min_ref = MinRef, can_block = CanBlock} = Acc,
    case CanBlock andalso can_insert(Name, Value, State, MinRef) of
        true ->
            do_insert_literal_name(Name, Value, Acc);
        false ->
            Rep = {literal, Name, Value, false},
            add_rep(Acc, Rep)
    end.

-spec try_insert_with_static_name(
    non_neg_integer(), binary(), binary(), #enc_acc{}
) -> #enc_acc{}.
try_insert_with_static_name(NameIndex, Name, Value, Acc) ->
    #enc_acc{state = State, min_ref = MinRef, can_block = CanBlock} = Acc,
    case CanBlock andalso can_insert(Name, Value, State, MinRef) of
        true ->
            do_insert_name_ref(
                static, NameIndex, Name, Value, Acc
            );
        false ->
            Rep = {literal_name_ref, static, NameIndex, Value, false},
            add_rep(Acc, Rep)
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL - ACCUMULATOR HELPERS
%%%-----------------------------------------------------------------------------
-spec add_dynamic_rep(
    #enc_acc{}, enc_rep(), non_neg_integer()
) -> #enc_acc{}.
add_dynamic_rep(Acc, Rep, AbsIndex) ->
    NewMaxRef = max(Acc#enc_acc.max_ref, AbsIndex),
    NewMinRef =
        case Acc#enc_acc.min_ref of
            infinity -> AbsIndex;
            OldMin -> min(OldMin, AbsIndex)
        end,
    Acc#enc_acc{
        representations = [Rep | Acc#enc_acc.representations],
        max_ref = NewMaxRef,
        min_ref = NewMinRef,
        has_dynamic_ref = true
    }.

-spec add_rep(#enc_acc{}, enc_rep()) -> #enc_acc{}.
add_rep(Acc, Rep) ->
    Acc#enc_acc{
        representations = [Rep | Acc#enc_acc.representations]
    }.

%%%-----------------------------------------------------------------------------
%% INTERNAL - RIC / BASE / PREFIX
%%%-----------------------------------------------------------------------------
-spec compute_ric_base(boolean(), non_neg_integer()) ->
    {non_neg_integer(), non_neg_integer()}.
compute_ric_base(false, _MaxRef) ->
    {0, 0};
compute_ric_base(true, MaxRef) ->
    RIC = MaxRef + 1,
    Base = RIC,
    {RIC, Base}.

-spec encode_reps(
    [nhttp_qpack_field_line:representation()], boolean()
) -> [iodata()].
encode_reps(Reps, Huffman) ->
    [
        nhttp_qpack_field_line:encode_representation(R, Huffman)
     || R <- Reps
    ].

-spec resolve_rep(enc_rep(), non_neg_integer()) ->
    nhttp_qpack_field_line:representation().
resolve_rep({abs_indexed, AbsIndex}, Base) ->
    RelIndex = Base - AbsIndex - 1,
    {indexed, dynamic, RelIndex};
resolve_rep(Rep, _Base) ->
    Rep.

-spec resolve_reps([enc_rep()], non_neg_integer()) ->
    [nhttp_qpack_field_line:representation()].
resolve_reps(Reps, Base) ->
    [resolve_rep(R, Base) || R <- Reps].

%%%-----------------------------------------------------------------------------
%% INTERNAL - STREAM REFERENCE TRACKING
%%%-----------------------------------------------------------------------------
-spec track_stream_ref(
    #qpack_enc{},
    nhttp_lib:stream_id(),
    boolean(),
    non_neg_integer()
) -> #qpack_enc{}.
track_stream_ref(State, _StreamId, false, _MaxRef) ->
    State;
track_stream_ref(State, StreamId, true, MaxRef) ->
    #qpack_enc{
        stream_refs = Refs,
        blocked_stream_count = Blocked,
        known_received_count = KRC
    } = State,
    NewRefs = Refs#{StreamId => MaxRef},
    IsBlocking = (MaxRef >= KRC),
    NewBlocked =
        case IsBlocking of
            true -> Blocked + 1;
            false -> Blocked
        end,
    State#qpack_enc{
        stream_refs = NewRefs,
        blocked_stream_count = NewBlocked
    }.

%%%-----------------------------------------------------------------------------
%% INTERNAL - DECODER INSTRUCTION PROCESSING
%%%-----------------------------------------------------------------------------
-spec apply_decoder_instruction(
    nhttp_qpack_decoder_instruction:t(), #qpack_enc{}
) -> {ok, #qpack_enc{}} | {error, term()}.
apply_decoder_instruction({section_ack, StreamId}, State) ->
    apply_section_ack(StreamId, State);
apply_decoder_instruction(
    {stream_cancellation, StreamId}, State
) ->
    apply_stream_cancellation(StreamId, State);
apply_decoder_instruction(
    {insert_count_increment, Increment}, State
) ->
    apply_insert_count_increment(Increment, State).

-spec apply_insert_count_increment(
    pos_integer(), #qpack_enc{}
) -> {ok, #qpack_enc{}} | {error, increment_too_large}.
apply_insert_count_increment(Increment, State) ->
    #qpack_enc{
        known_received_count = KRC,
        dynamic_table = DynTable
    } = State,
    NewKRC = KRC + Increment,
    IC = nhttp_qpack_dynamic_table:insert_count(DynTable),
    case NewKRC > IC of
        true ->
            {error, increment_too_large};
        false ->
            {ok, State#qpack_enc{
                known_received_count = NewKRC
            }}
    end.

-spec apply_section_ack(nhttp_lib:stream_id(), #qpack_enc{}) ->
    {ok, #qpack_enc{}} | {error, unknown_stream}.
apply_section_ack(StreamId, State) ->
    #qpack_enc{
        stream_refs = Refs,
        known_received_count = KRC,
        blocked_stream_count = Blocked
    } = State,
    case Refs of
        #{StreamId := MaxRef} ->
            NewKRC = max(KRC, MaxRef + 1),
            NewRefs = maps:remove(StreamId, Refs),
            WasBlocking = (MaxRef >= KRC),
            NewBlocked =
                case WasBlocking of
                    true -> max(0, Blocked - 1);
                    false -> Blocked
                end,
            {ok, State#qpack_enc{
                stream_refs = NewRefs,
                known_received_count = NewKRC,
                blocked_stream_count = NewBlocked
            }};
        _ ->
            {error, unknown_stream}
    end.

-spec apply_stream_cancellation(
    nhttp_lib:stream_id(), #qpack_enc{}
) -> {ok, #qpack_enc{}}.
apply_stream_cancellation(StreamId, State) ->
    #qpack_enc{
        stream_refs = Refs,
        blocked_stream_count = Blocked,
        known_received_count = KRC
    } = State,
    case Refs of
        #{StreamId := MaxRef} ->
            NewRefs = maps:remove(StreamId, Refs),
            WasBlocking = (MaxRef >= KRC),
            NewBlocked =
                case WasBlocking of
                    true -> max(0, Blocked - 1);
                    false -> Blocked
                end,
            {ok, State#qpack_enc{
                stream_refs = NewRefs,
                blocked_stream_count = NewBlocked
            }};
        _ ->
            {ok, State}
    end.

-spec process_decoder_instructions(#qpack_enc{}, binary()) ->
    {ok, #qpack_enc{}} | {error, term()}.
process_decoder_instructions(State, <<>>) ->
    {ok, State};
process_decoder_instructions(State, Data) ->
    case nhttp_qpack_decoder_instruction:decode(Data) of
        {ok, Instruction, Rest} ->
            case apply_decoder_instruction(Instruction, State) of
                {ok, State2} ->
                    process_decoder_instructions(
                        State2, rest_to_binary(Rest)
                    );
                {error, _} = Error ->
                    Error
            end;
        {error, incomplete} ->
            {ok, State};
        {error, _} = Error ->
            Error
    end.

-spec rest_to_binary(bitstring()) -> binary().
rest_to_binary(Bin) when is_binary(Bin) ->
    Bin;
rest_to_binary(Bits) ->
    BitSize = bit_size(Bits),
    ByteSize = BitSize div 8,
    <<Bin:ByteSize/binary, _/bits>> = Bits,
    Bin.
