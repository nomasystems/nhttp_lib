-module(nhttp_hpack).

-moduledoc """
HPACK header compression for HTTP/2 (RFC 7541).

This module implements the HPACK header compression format used by
HTTP/2. It provides stateful encoding and decoding of header fields
using static and dynamic tables.

## Usage

```erlang
{ok, EncState0} = nhttp_hpack:new(),
{ok, DecState0} = nhttp_hpack:new(),

Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
{ok, HeaderBlock, EncState1} = nhttp_hpack:encode(Headers, EncState0),

{ok, DecodedHeaders, DecState1} = nhttp_hpack:decode(HeaderBlock, DecState0).
```

## Field names on encode

`encode/2` and `encode/3` write every field name in lowercase. RFC 9113 §8.2
requires that a field name is converted to lowercase when an HTTP/2 message is
constructed, and RFC 9113 §8.2.1 makes an uppercase name on the wire malformed.
The conversion is silent: the return type does not change, and the caller reads
no report of it.

A name that already holds no octet in `0x41-0x5A` costs one scan and no
allocation. The lowercase name is what the static table lookup reads, what the
literal representation writes and what the dynamic table holds, so the octets in
the table and the octets on the wire agree.

## Field validity on decode

Every field name and every field value that arrives as a literal is read
against the minimal rule of RFC 9113 §8.2.1. A block that carries such a
field returns `{invalid_field, Reason, NewState}`, which is apart from the
`{error, Reason}` of an HPACK failure: RFC 9113 §8.1.1 makes a malformed
field a stream error, where RFC 9113 §4.3 makes a decode failure a
connection error.

The block runs to its end either way. RFC 9113 §4.3 makes an endpoint
decompress a field block even when it discards the frames, so `NewState`
carries every dynamic table update that the block asks for. A decoder that
skips the update of a refused field falls out of step with the peer encoder,
and every later block on that connection then decodes to the wrong field.

An entry therefore holds the verdict on its name and the verdict on its
value, read once at insert. A field that arrives by index carries that
verdict out again and needs no second read of the octets. The name verdict
alone travels to a field that reuses the name by index, because such a field
takes a fresh value from the wire.
""".

%%%-----------------------------------------------------------------------------
%% INLINE DIRECTIVES
%%%-----------------------------------------------------------------------------
-compile(
    {inline, [
        check_field/2,
        check_name/1,
        check_value/1,
        fault/2,
        field_fault/1,
        first_bad/2,
        name_fault/1
    ]}
).

%%%-----------------------------------------------------------------------------
%% STATE MANAGEMENT
%%%-----------------------------------------------------------------------------
-export([
    is_empty/1,
    new/0,
    new/1,
    set_max_table_size/2,
    table_size/1
]).

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-export([decode/2, decode/3]).

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-export([encode/2, encode/3]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    decode_error/0,
    decode_opts/0,
    decode_result/0,
    encode_opts/0,
    field_error/0,
    headers/0,
    state/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type headers() :: [{Name :: binary(), Value :: binary()}].
-type encode_opts() :: #{
    huffman => boolean()
}.
-type decode_opts() :: #{
    max_list_size => pos_integer() | infinity
}.
-type decode_error() ::
    dynamic_table_size_exceeded
    | invalid_table_index
    | integer_overflow
    | invalid_huffman
    | incomplete_header_block
    | header_list_too_large
    | field_error().

-doc """
A field that breaks the minimal rule of RFC 9113 §8.2.1.

`uppercase_header_name` names the case that the RFC lists apart from the
other invalid name characters.
""".
-type field_error() ::
    uppercase_header_name
    | invalid_header_name
    | invalid_header_value.

-doc """
The outcome of a header block decode.

`{invalid_field, Reason, NewState}` reports a field that breaks RFC 9113
§8.2.1. The block decompressed, and `NewState` carries every dynamic table
update that the block asks for, because RFC 9113 §4.3 makes an endpoint
decompress a field block even when it discards the frames. The caller keeps
`NewState` and treats the message as malformed, a stream error of type
PROTOCOL_ERROR (RFC 9113 §8.1.1).

`{error, Reason}` reports a decode failure. The block did not decompress,
the state is unusable, and RFC 9113 §4.3 makes this a connection error of
type COMPRESSION_ERROR.
""".
-type decode_result() ::
    {ok, headers(), state()}
    | {invalid_field, field_error(), state()}
    | {error, decode_error()}.

%% The verdict of the RFC 9113 Section 8.2.1 read on one field, kept apart for
%% the name and for the value. An indexed name carries its name verdict into
%% the field that reuses it, where the value arrives fresh from the wire.
-type fault_reason() :: ok | field_error().
-type fault() :: ok | {fault_reason(), fault_reason()}.

%%%-----------------------------------------------------------------------------
%% CONSTANTS
%%%-----------------------------------------------------------------------------
-define(ENTRY_OVERHEAD, 32).

%%%-----------------------------------------------------------------------------
%% RECORDS
%%%-----------------------------------------------------------------------------
-record(hpack, {
    size = 0 :: non_neg_integer(),
    max_size = 4096 :: non_neg_integer(),
    configured_max_size = 4096 :: non_neg_integer(),
    next_seq = 0 :: non_neg_integer(),
    oldest_seq = 0 :: non_neg_integer(),
    entries = #{} :: #{non_neg_integer() => {pos_integer(), {binary(), binary()}, fault()}},
    full_index = #{} :: #{{binary(), binary()} => non_neg_integer()},
    name_index = #{} :: #{binary() => non_neg_integer()}
}).

-opaque state() :: #hpack{}.

%%%-----------------------------------------------------------------------------
%% STATE MANAGEMENT
%%%-----------------------------------------------------------------------------
-doc "Check if the dynamic table is empty.".
-spec is_empty(State :: state()) -> boolean().
is_empty(#hpack{size = 0}) ->
    true;
is_empty(_) ->
    false.

-doc "Create a new HPACK state with default max size (4096 bytes).".
-spec new() -> {ok, state()}.
new() ->
    {ok, #hpack{}}.

-doc "Create a new HPACK state with specified max size.".
-spec new(MaxSize :: non_neg_integer()) -> {ok, state()}.
new(MaxSize) ->
    {ok, #hpack{max_size = MaxSize, configured_max_size = MaxSize}}.

-doc "Update the maximum table size (from SETTINGS_HEADER_TABLE_SIZE). Immediately evicts entries if the new size is smaller than current table size.".
-spec set_max_table_size(MaxSize :: non_neg_integer(), State :: state()) -> {ok, state()}.
set_max_table_size(MaxSize, State) ->
    {ok, update_table_size(MaxSize, State#hpack{configured_max_size = MaxSize})}.

-doc "Get the current dynamic table size in bytes.".
-spec table_size(State :: state()) -> non_neg_integer().
table_size(#hpack{size = Size}) ->
    Size.

%%%-----------------------------------------------------------------------------
%% DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a header block.

See `decode/3` for the `invalid_field` return.
""".
-spec decode(Data :: binary(), State :: state()) -> decode_result().
decode(Data, State) ->
    decode(Data, State, #{}).

-doc """
Decode a header block, aborting with `{error, header_list_too_large}` once
the cumulative decoded list size exceeds `max_list_size`. The check matches
the RFC 9113 §10.5.1 octet count (name + value + 32 per entry).
""".
-spec decode(Data :: binary(), State :: state(), Opts :: decode_opts()) -> decode_result().
decode(Data, State, Opts) ->
    Limit = maps:get(max_list_size, Opts, infinity),
    decode_block(Data, State, [], 0, Limit, ok).

%%%-----------------------------------------------------------------------------
%% ENCODING
%%%-----------------------------------------------------------------------------
-doc "Encode headers without Huffman encoding.".
-spec encode(Headers :: headers(), State :: state()) -> {ok, iodata(), state()}.
encode(Headers, State) ->
    encode(Headers, State, #{huffman => false}).

-doc "Encode headers with options.".
-spec encode(Headers :: headers(), State :: state(), Opts :: encode_opts()) ->
    {ok, iodata(), state()}.
encode(Headers, State0, Opts) ->
    UseHuffman = maps:get(huffman, Opts, false),
    {Prefix, State1} = maybe_emit_table_size_update(State0),
    {Data, State2} = encode_headers(Headers, State1, UseHuffman, []),
    {ok, [Prefix | Data], State2}.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec clear_table(state()) -> state().
clear_table(State = #hpack{next_seq = NextSeq}) ->
    State#hpack{
        size = 0,
        oldest_seq = NextSeq,
        entries = #{},
        full_index = #{},
        name_index = #{}
    }.

-spec decode_block(
    binary(),
    state(),
    headers(),
    non_neg_integer(),
    pos_integer() | infinity,
    fault_reason()
) ->
    decode_result().
decode_block(
    <<2#001:3, Rest/bits>>,
    State = #hpack{configured_max_size = ConfigMax},
    Acc,
    Total,
    Limit,
    Bad
) ->
    maybe
        {ok, MaxSize, Rest2} ?= map_int_error(nhttp_int:dec5(Rest)),
        case MaxSize =< ConfigMax of
            true ->
                State2 = update_table_size(MaxSize, State),
                decode_block(Rest2, State2, Acc, Total, Limit, Bad);
            false ->
                {error, dynamic_table_size_exceeded}
        end
    end;
decode_block(Data, State, Acc, Total, Limit, Bad) ->
    decode_headers(Data, State, Acc, Total, Limit, Bad).

%% `Bad' carries the first field that broke RFC 9113 Section 8.2.1. The block
%% still runs to its end, because RFC 9113 Section 4.3 makes an endpoint
%% decompress a field block even when it discards the frames, and a skipped
%% dynamic table update leaves this decoder out of step with the peer encoder.
-spec decode_headers(
    binary(),
    state(),
    headers(),
    non_neg_integer(),
    pos_integer() | infinity,
    fault_reason()
) ->
    decode_result().
decode_headers(<<>>, State, Acc, _Total, _Limit, ok) ->
    {ok, lists:reverse(Acc), State};
decode_headers(<<>>, State, _Acc, _Total, _Limit, Bad) ->
    {invalid_field, Bad, State};
decode_headers(<<2#1:1, Rest/bits>>, State, Acc, Total, Limit, Bad) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec7(Rest)),
        {ok, {Name, Value}, Fault} ?= lookup(Index, State),
        NewBad = first_bad(Bad, field_fault(Fault)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest2, State, NewAcc, NewTotal, Limit, NewBad)
    end;
decode_headers(<<2#01:2, 2#000000:6, Rest/bits>>, State, Acc, Total, Limit, Bad) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        Fault = fault(check_name(Name), check_value(Value)),
        State2 = insert({Name, Value}, Fault, State),
        NewBad = first_bad(Bad, field_fault(Fault)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State2, NewAcc, NewTotal, Limit, NewBad)
    end;
decode_headers(<<2#01:2, Rest/bits>>, State, Acc, Total, Limit, Bad) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec6(Rest)),
        {ok, {Name, _}, NameFault} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        Fault = fault(name_fault(NameFault), check_value(Value)),
        State2 = insert({Name, Value}, Fault, State),
        NewBad = first_bad(Bad, field_fault(Fault)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State2, NewAcc, NewTotal, Limit, NewBad)
    end;
decode_headers(<<2#0000:4, 2#0000:4, Rest/bits>>, State, Acc, Total, Limit, Bad) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        NewBad = first_bad(Bad, check_field(Name, Value)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit, NewBad)
    end;
decode_headers(<<2#0000:4, Rest/bits>>, State, Acc, Total, Limit, Bad) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec4(Rest)),
        {ok, {Name, _}, NameFault} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        NewBad = first_bad(Bad, first_bad(name_fault(NameFault), check_value(Value))),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit, NewBad)
    end;
decode_headers(<<2#0001:4, 2#0000:4, Rest/bits>>, State, Acc, Total, Limit, Bad) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        NewBad = first_bad(Bad, check_field(Name, Value)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit, NewBad)
    end;
decode_headers(<<2#0001:4, Rest/bits>>, State, Acc, Total, Limit, Bad) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec4(Rest)),
        {ok, {Name, _}, NameFault} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        NewBad = first_bad(Bad, first_bad(name_fault(NameFault), check_value(Value))),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit, NewBad)
    end;
decode_headers(_, _, _, _, _, _) ->
    {error, incomplete_header_block}.

%% RFC 9113 Section 8.2: a field name is converted to lowercase when an
%% HTTP/2 message is constructed. The lowercased name feeds the table lookup,
%% the literal representation and the dynamic table insert, so the octets on
%% the wire and the octets in the table agree.
-spec encode_headers(headers(), state(), boolean(), [iodata()]) ->
    {[iodata()], state()}.
encode_headers([], State, _, Acc) ->
    {lists:reverse(Acc), State};
encode_headers([{Name0, Value} = Header0 | Tail], State, UseHuffman, Acc) ->
    {Name, _} = Header = lower_name(Header0, Name0, Value),
    case find(Header, State) of
        {field, Index} ->
            Encoded = nhttp_int:enc7(Index, 2#1),
            encode_headers(Tail, State, UseHuffman, [Encoded | Acc]);
        {name, Index} ->
            State2 = insert(Header, State),
            Encoded = [nhttp_int:enc6(Index, 2#01) | nhttp_str:encode(Value, UseHuffman)],
            encode_headers(Tail, State2, UseHuffman, [Encoded | Acc]);
        not_found ->
            State2 = insert(Header, State),
            Encoded = [
                <<2#01:2, 0:6>>
                | [nhttp_str:encode(Name, UseHuffman) | nhttp_str:encode(Value, UseHuffman)]
            ],
            encode_headers(Tail, State2, UseHuffman, [Encoded | Acc])
    end.

%% `lower_field_name/1' hands back the very binary it read when the name holds
%% no uppercase octet, so the tuple the caller wrote survives the common path
%% and the encoder allocates nothing for a name that is already on the wire form.
-spec lower_name({binary(), binary()}, binary(), binary()) -> {binary(), binary()}.
lower_name(Header, Name, Value) ->
    case nhttp_headers:lower_field_name(Name) of
        Name -> Header;
        Lower -> {Lower, Value}
    end.

-spec evict_to_size(non_neg_integer(), state()) -> state().
evict_to_size(TargetSize, State = #hpack{size = Size}) when Size =< TargetSize ->
    State;
evict_to_size(
    TargetSize,
    State = #hpack{
        size = Size,
        oldest_seq = OldestSeq,
        entries = Entries
    }
) ->
    case maps:get(OldestSeq, Entries, undefined) of
        undefined ->
            State;
        {EntrySize, _Header, _Fault} ->
            NewState = State#hpack{
                size = Size - EntrySize,
                oldest_seq = OldestSeq + 1,
                entries = maps:remove(OldestSeq, Entries)
            },
            evict_to_size(TargetSize, NewState)
    end.

-spec find({binary(), binary()}, state()) ->
    {field, pos_integer()} | {name, pos_integer()} | not_found.
find({<<":authority">>, <<>>}, _) -> {field, 1};
find({<<":authority">>, _}, _) -> {name, 1};
find({<<":method">>, <<"GET">>}, _) -> {field, 2};
find({<<":method">>, <<"POST">>}, _) -> {field, 3};
find({<<":method">>, _}, _) -> {name, 2};
find({<<":path">>, <<"/">>}, _) -> {field, 4};
find({<<":path">>, <<"/index.html">>}, _) -> {field, 5};
find({<<":path">>, _}, _) -> {name, 4};
find({<<":scheme">>, <<"http">>}, _) -> {field, 6};
find({<<":scheme">>, <<"https">>}, _) -> {field, 7};
find({<<":scheme">>, _}, _) -> {name, 6};
find({<<":status">>, <<"200">>}, _) -> {field, 8};
find({<<":status">>, <<"204">>}, _) -> {field, 9};
find({<<":status">>, <<"206">>}, _) -> {field, 10};
find({<<":status">>, <<"304">>}, _) -> {field, 11};
find({<<":status">>, <<"400">>}, _) -> {field, 12};
find({<<":status">>, <<"404">>}, _) -> {field, 13};
find({<<":status">>, <<"500">>}, _) -> {field, 14};
find({<<":status">>, _}, _) -> {name, 8};
find({<<"accept-charset">>, <<>>}, _) -> {field, 15};
find({<<"accept-charset">>, _}, _) -> {name, 15};
find({<<"accept-encoding">>, <<"gzip, deflate">>}, _) -> {field, 16};
find({<<"accept-encoding">>, _}, _) -> {name, 16};
find({<<"accept-language">>, <<>>}, _) -> {field, 17};
find({<<"accept-language">>, _}, _) -> {name, 17};
find({<<"accept-ranges">>, <<>>}, _) -> {field, 18};
find({<<"accept-ranges">>, _}, _) -> {name, 18};
find({<<"accept">>, <<>>}, _) -> {field, 19};
find({<<"accept">>, _}, _) -> {name, 19};
find({<<"access-control-allow-origin">>, <<>>}, _) -> {field, 20};
find({<<"access-control-allow-origin">>, _}, _) -> {name, 20};
find({<<"age">>, <<>>}, _) -> {field, 21};
find({<<"age">>, _}, _) -> {name, 21};
find({<<"allow">>, <<>>}, _) -> {field, 22};
find({<<"allow">>, _}, _) -> {name, 22};
find({<<"authorization">>, <<>>}, _) -> {field, 23};
find({<<"authorization">>, _}, _) -> {name, 23};
find({<<"cache-control">>, <<>>}, _) -> {field, 24};
find({<<"cache-control">>, _}, _) -> {name, 24};
find({<<"content-disposition">>, <<>>}, _) -> {field, 25};
find({<<"content-disposition">>, _}, _) -> {name, 25};
find({<<"content-encoding">>, <<>>}, _) -> {field, 26};
find({<<"content-encoding">>, _}, _) -> {name, 26};
find({<<"content-language">>, <<>>}, _) -> {field, 27};
find({<<"content-language">>, _}, _) -> {name, 27};
find({<<"content-length">>, <<>>}, _) -> {field, 28};
find({<<"content-length">>, _}, _) -> {name, 28};
find({<<"content-location">>, <<>>}, _) -> {field, 29};
find({<<"content-location">>, _}, _) -> {name, 29};
find({<<"content-range">>, <<>>}, _) -> {field, 30};
find({<<"content-range">>, _}, _) -> {name, 30};
find({<<"content-type">>, <<>>}, _) -> {field, 31};
find({<<"content-type">>, _}, _) -> {name, 31};
find({<<"cookie">>, <<>>}, _) -> {field, 32};
find({<<"cookie">>, _}, _) -> {name, 32};
find({<<"date">>, <<>>}, _) -> {field, 33};
find({<<"date">>, _}, _) -> {name, 33};
find({<<"etag">>, <<>>}, _) -> {field, 34};
find({<<"etag">>, _}, _) -> {name, 34};
find({<<"expect">>, <<>>}, _) -> {field, 35};
find({<<"expect">>, _}, _) -> {name, 35};
find({<<"expires">>, <<>>}, _) -> {field, 36};
find({<<"expires">>, _}, _) -> {name, 36};
find({<<"from">>, <<>>}, _) -> {field, 37};
find({<<"from">>, _}, _) -> {name, 37};
find({<<"host">>, <<>>}, _) -> {field, 38};
find({<<"host">>, _}, _) -> {name, 38};
find({<<"if-match">>, <<>>}, _) -> {field, 39};
find({<<"if-match">>, _}, _) -> {name, 39};
find({<<"if-modified-since">>, <<>>}, _) -> {field, 40};
find({<<"if-modified-since">>, _}, _) -> {name, 40};
find({<<"if-none-match">>, <<>>}, _) -> {field, 41};
find({<<"if-none-match">>, _}, _) -> {name, 41};
find({<<"if-range">>, <<>>}, _) -> {field, 42};
find({<<"if-range">>, _}, _) -> {name, 42};
find({<<"if-unmodified-since">>, <<>>}, _) -> {field, 43};
find({<<"if-unmodified-since">>, _}, _) -> {name, 43};
find({<<"last-modified">>, <<>>}, _) -> {field, 44};
find({<<"last-modified">>, _}, _) -> {name, 44};
find({<<"link">>, <<>>}, _) -> {field, 45};
find({<<"link">>, _}, _) -> {name, 45};
find({<<"location">>, <<>>}, _) -> {field, 46};
find({<<"location">>, _}, _) -> {name, 46};
find({<<"max-forwards">>, <<>>}, _) -> {field, 47};
find({<<"max-forwards">>, _}, _) -> {name, 47};
find({<<"proxy-authenticate">>, <<>>}, _) -> {field, 48};
find({<<"proxy-authenticate">>, _}, _) -> {name, 48};
find({<<"proxy-authorization">>, <<>>}, _) -> {field, 49};
find({<<"proxy-authorization">>, _}, _) -> {name, 49};
find({<<"range">>, <<>>}, _) -> {field, 50};
find({<<"range">>, _}, _) -> {name, 50};
find({<<"referer">>, <<>>}, _) -> {field, 51};
find({<<"referer">>, _}, _) -> {name, 51};
find({<<"refresh">>, <<>>}, _) -> {field, 52};
find({<<"refresh">>, _}, _) -> {name, 52};
find({<<"retry-after">>, <<>>}, _) -> {field, 53};
find({<<"retry-after">>, _}, _) -> {name, 53};
find({<<"server">>, <<>>}, _) -> {field, 54};
find({<<"server">>, _}, _) -> {name, 54};
find({<<"set-cookie">>, <<>>}, _) -> {field, 55};
find({<<"set-cookie">>, _}, _) -> {name, 55};
find({<<"strict-transport-security">>, <<>>}, _) -> {field, 56};
find({<<"strict-transport-security">>, _}, _) -> {name, 56};
find({<<"transfer-encoding">>, <<>>}, _) -> {field, 57};
find({<<"transfer-encoding">>, _}, _) -> {name, 57};
find({<<"user-agent">>, <<>>}, _) -> {field, 58};
find({<<"user-agent">>, _}, _) -> {name, 58};
find({<<"vary">>, <<>>}, _) -> {field, 59};
find({<<"vary">>, _}, _) -> {name, 59};
find({<<"via">>, <<>>}, _) -> {field, 60};
find({<<"via">>, _}, _) -> {name, 60};
find({<<"www-authenticate">>, <<>>}, _) -> {field, 61};
find({<<"www-authenticate">>, _}, _) -> {name, 61};
find(Header, State) -> find_dyn(Header, State).

-spec find_dyn({binary(), binary()}, state()) ->
    {field, pos_integer()} | {name, pos_integer()} | not_found.
find_dyn({Name, _Value} = Header, #hpack{
    next_seq = NextSeq,
    oldest_seq = OldestSeq,
    full_index = FullIndex,
    name_index = NameIndex
}) ->
    case maps:get(Header, FullIndex, undefined) of
        Seq when is_integer(Seq), Seq >= OldestSeq ->
            Index = 62 + (NextSeq - 1 - Seq),
            {field, Index};
        _ ->
            case maps:get(Name, NameIndex, undefined) of
                NameSeq when is_integer(NameSeq), NameSeq >= OldestSeq ->
                    Index = 62 + (NextSeq - 1 - NameSeq),
                    {name, Index};
                _ ->
                    not_found
            end
    end.

-spec insert({binary(), binary()}, state()) -> state().
insert(Header, State) ->
    insert(Header, ok, State).

-spec insert({binary(), binary()}, fault(), state()) -> state().
insert({Name, Value}, Fault, State = #hpack{max_size = MaxSize, next_seq = NextSeq}) ->
    EntrySize = byte_size(Name) + byte_size(Value) + ?ENTRY_OVERHEAD,
    case EntrySize > MaxSize of
        true ->
            clear_table(State);
        false ->
            TargetSize = MaxSize - EntrySize,
            State1 = evict_to_size(TargetSize, State),
            Header = {Name, Value},
            #hpack{
                size = Size1,
                entries = Entries1,
                full_index = FullIndex1,
                name_index = NameIndex1
            } = State1,
            State1#hpack{
                size = Size1 + EntrySize,
                next_seq = NextSeq + 1,
                entries = maps:put(NextSeq, {EntrySize, Header, Fault}, Entries1),
                full_index = maps:put(Header, NextSeq, FullIndex1),
                name_index = maps:put(Name, NextSeq, NameIndex1)
            }
    end.

-spec lookup(pos_integer(), state()) ->
    {ok, {binary(), binary()}, fault()} | {error, decode_error()}.
lookup(1, _) ->
    {ok, {<<":authority">>, <<>>}, ok};
lookup(2, _) ->
    {ok, {<<":method">>, <<"GET">>}, ok};
lookup(3, _) ->
    {ok, {<<":method">>, <<"POST">>}, ok};
lookup(4, _) ->
    {ok, {<<":path">>, <<"/">>}, ok};
lookup(5, _) ->
    {ok, {<<":path">>, <<"/index.html">>}, ok};
lookup(6, _) ->
    {ok, {<<":scheme">>, <<"http">>}, ok};
lookup(7, _) ->
    {ok, {<<":scheme">>, <<"https">>}, ok};
lookup(8, _) ->
    {ok, {<<":status">>, <<"200">>}, ok};
lookup(9, _) ->
    {ok, {<<":status">>, <<"204">>}, ok};
lookup(10, _) ->
    {ok, {<<":status">>, <<"206">>}, ok};
lookup(11, _) ->
    {ok, {<<":status">>, <<"304">>}, ok};
lookup(12, _) ->
    {ok, {<<":status">>, <<"400">>}, ok};
lookup(13, _) ->
    {ok, {<<":status">>, <<"404">>}, ok};
lookup(14, _) ->
    {ok, {<<":status">>, <<"500">>}, ok};
lookup(15, _) ->
    {ok, {<<"accept-charset">>, <<>>}, ok};
lookup(16, _) ->
    {ok, {<<"accept-encoding">>, <<"gzip, deflate">>}, ok};
lookup(17, _) ->
    {ok, {<<"accept-language">>, <<>>}, ok};
lookup(18, _) ->
    {ok, {<<"accept-ranges">>, <<>>}, ok};
lookup(19, _) ->
    {ok, {<<"accept">>, <<>>}, ok};
lookup(20, _) ->
    {ok, {<<"access-control-allow-origin">>, <<>>}, ok};
lookup(21, _) ->
    {ok, {<<"age">>, <<>>}, ok};
lookup(22, _) ->
    {ok, {<<"allow">>, <<>>}, ok};
lookup(23, _) ->
    {ok, {<<"authorization">>, <<>>}, ok};
lookup(24, _) ->
    {ok, {<<"cache-control">>, <<>>}, ok};
lookup(25, _) ->
    {ok, {<<"content-disposition">>, <<>>}, ok};
lookup(26, _) ->
    {ok, {<<"content-encoding">>, <<>>}, ok};
lookup(27, _) ->
    {ok, {<<"content-language">>, <<>>}, ok};
lookup(28, _) ->
    {ok, {<<"content-length">>, <<>>}, ok};
lookup(29, _) ->
    {ok, {<<"content-location">>, <<>>}, ok};
lookup(30, _) ->
    {ok, {<<"content-range">>, <<>>}, ok};
lookup(31, _) ->
    {ok, {<<"content-type">>, <<>>}, ok};
lookup(32, _) ->
    {ok, {<<"cookie">>, <<>>}, ok};
lookup(33, _) ->
    {ok, {<<"date">>, <<>>}, ok};
lookup(34, _) ->
    {ok, {<<"etag">>, <<>>}, ok};
lookup(35, _) ->
    {ok, {<<"expect">>, <<>>}, ok};
lookup(36, _) ->
    {ok, {<<"expires">>, <<>>}, ok};
lookup(37, _) ->
    {ok, {<<"from">>, <<>>}, ok};
lookup(38, _) ->
    {ok, {<<"host">>, <<>>}, ok};
lookup(39, _) ->
    {ok, {<<"if-match">>, <<>>}, ok};
lookup(40, _) ->
    {ok, {<<"if-modified-since">>, <<>>}, ok};
lookup(41, _) ->
    {ok, {<<"if-none-match">>, <<>>}, ok};
lookup(42, _) ->
    {ok, {<<"if-range">>, <<>>}, ok};
lookup(43, _) ->
    {ok, {<<"if-unmodified-since">>, <<>>}, ok};
lookup(44, _) ->
    {ok, {<<"last-modified">>, <<>>}, ok};
lookup(45, _) ->
    {ok, {<<"link">>, <<>>}, ok};
lookup(46, _) ->
    {ok, {<<"location">>, <<>>}, ok};
lookup(47, _) ->
    {ok, {<<"max-forwards">>, <<>>}, ok};
lookup(48, _) ->
    {ok, {<<"proxy-authenticate">>, <<>>}, ok};
lookup(49, _) ->
    {ok, {<<"proxy-authorization">>, <<>>}, ok};
lookup(50, _) ->
    {ok, {<<"range">>, <<>>}, ok};
lookup(51, _) ->
    {ok, {<<"referer">>, <<>>}, ok};
lookup(52, _) ->
    {ok, {<<"refresh">>, <<>>}, ok};
lookup(53, _) ->
    {ok, {<<"retry-after">>, <<>>}, ok};
lookup(54, _) ->
    {ok, {<<"server">>, <<>>}, ok};
lookup(55, _) ->
    {ok, {<<"set-cookie">>, <<>>}, ok};
lookup(56, _) ->
    {ok, {<<"strict-transport-security">>, <<>>}, ok};
lookup(57, _) ->
    {ok, {<<"transfer-encoding">>, <<>>}, ok};
lookup(58, _) ->
    {ok, {<<"user-agent">>, <<>>}, ok};
lookup(59, _) ->
    {ok, {<<"vary">>, <<>>}, ok};
lookup(60, _) ->
    {ok, {<<"via">>, <<>>}, ok};
lookup(61, _) ->
    {ok, {<<"www-authenticate">>, <<>>}, ok};
lookup(Index, #hpack{next_seq = NextSeq, oldest_seq = OldestSeq, entries = Entries}) when
    Index > 61
->
    Seq = NextSeq - 1 - (Index - 62),
    case Seq >= OldestSeq andalso Seq < NextSeq of
        true ->
            case maps:get(Seq, Entries, undefined) of
                {_, Header, Fault} -> {ok, Header, Fault};
                undefined -> {error, invalid_table_index}
            end;
        false ->
            {error, invalid_table_index}
    end;
lookup(0, _) ->
    {error, invalid_table_index}.

-spec map_int_error({ok, non_neg_integer(), bitstring()} | {error, nhttp_int:decode_error()}) ->
    {ok, non_neg_integer(), bitstring()} | {error, decode_error()}.
map_int_error({ok, _, _} = Ok) -> Ok;
map_int_error({error, incomplete}) -> {error, incomplete_header_block};
map_int_error({error, overflow}) -> {error, integer_overflow}.

-spec map_str_error({ok, binary(), bitstring()} | {error, nhttp_str:decode_error()}) ->
    {ok, binary(), bitstring()} | {error, decode_error()}.
map_str_error({ok, _, _} = Ok) -> Ok;
map_str_error({error, incomplete}) -> {error, incomplete_header_block};
map_str_error({error, invalid_huffman}) -> {error, invalid_huffman}.

-spec maybe_emit_table_size_update(state()) -> {iodata(), state()}.
maybe_emit_table_size_update(State = #hpack{max_size = MaxSize, configured_max_size = MaxSize}) ->
    {[], State};
maybe_emit_table_size_update(State0 = #hpack{configured_max_size = MaxSize}) ->
    State1 = update_table_size(MaxSize, State0#hpack{max_size = MaxSize}),
    {nhttp_int:enc5(MaxSize, 2#001), State1}.

-spec push_header(
    {binary(), binary()},
    headers(),
    non_neg_integer(),
    pos_integer() | infinity
) ->
    {ok, headers(), non_neg_integer()} | {error, header_list_too_large}.
push_header({Name, Value} = Header, Acc, Total, infinity) ->
    {ok, [Header | Acc], Total + byte_size(Name) + byte_size(Value) + 32};
push_header({Name, Value} = Header, Acc, Total, Limit) ->
    NewTotal = Total + byte_size(Name) + byte_size(Value) + 32,
    case NewTotal =< Limit of
        true -> {ok, [Header | Acc], NewTotal};
        false -> {error, header_list_too_large}
    end.

-spec update_table_size(non_neg_integer(), state()) -> state().
update_table_size(0, State) ->
    clear_table(State#hpack{max_size = 0});
update_table_size(MaxSize, State = #hpack{max_size = MaxSize}) ->
    State;
update_table_size(MaxSize, State) ->
    State1 = evict_to_size(MaxSize, State),
    State1#hpack{max_size = MaxSize}.

-spec check_field(binary(), binary()) -> fault_reason().
check_field(Name, Value) ->
    first_bad(check_name(Name), check_value(Value)).

-spec check_name(binary()) -> fault_reason().
check_name(Name) ->
    case nhttp_headers:validate_field_name(Name) of
        ok -> ok;
        {error, uppercase_field_name} -> uppercase_header_name;
        {error, _} -> invalid_header_name
    end.

-spec check_value(binary()) -> fault_reason().
check_value(Value) ->
    case nhttp_headers:validate_field_value(Value) of
        ok -> ok;
        {error, _} -> invalid_header_value
    end.

-spec first_bad(fault_reason(), fault_reason()) -> fault_reason().
first_bad(ok, Second) -> Second;
first_bad(First, _) -> First.

-spec fault(fault_reason(), fault_reason()) -> fault().
fault(ok, ok) -> ok;
fault(NameFault, ValueFault) -> {NameFault, ValueFault}.

%% The verdict on a name that a later field reuses by index. The value of that
%% entry does not travel with the name, so its verdict stays behind.
-spec name_fault(fault()) -> fault_reason().
name_fault(ok) -> ok;
name_fault({NameFault, _}) -> NameFault.

-spec field_fault(fault()) -> fault_reason().
field_fault(ok) -> ok;
field_fault({ok, ValueFault}) -> ValueFault;
field_fault({NameFault, _}) -> NameFault.
