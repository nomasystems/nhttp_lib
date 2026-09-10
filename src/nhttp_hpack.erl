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

An entry therefore holds the verdict on its field, read once at insert. A
field that arrives by index carries that verdict out again and needs no
second read of the octets. The verdict names the part that failed, so a
field that reuses the name by index drops a verdict against the value and
reads a fresh value from the wire.
""".

%%%-----------------------------------------------------------------------------
%% INLINE DIRECTIVES
%%%-----------------------------------------------------------------------------
-compile(
    {inline, [
        check_field/2,
        check_name/1,
        check_value/1,
        first_invalid/2,
        name_verdict/1
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

-type find_result() :: {field, pos_integer()} | {name, pos_integer()} | not_found.

-doc """
The outcome of the octet scan over one field (RFC 9113 §8.2.1).

`{invalid_value, _}` implies a valid name, because a bad name wins the
verdict of the field. A field that takes the name by index and the value
from the wire therefore reads `{invalid_value, _}` as `valid`.
""".
-type verdict() ::
    valid
    | {invalid_name, field_error()}
    | {invalid_value, field_error()}.

%%%-----------------------------------------------------------------------------
%% CONSTANTS
%%%-----------------------------------------------------------------------------
-define(ENTRY_OVERHEAD, 32).

%%%-----------------------------------------------------------------------------
%% RECORDS
%%%-----------------------------------------------------------------------------
-record(entry, {
    size :: pos_integer(),
    field :: {binary(), binary()},
    verdict = valid :: verdict()
}).

-record(hpack, {
    size = 0 :: non_neg_integer(),
    max_size = 4096 :: non_neg_integer(),
    configured_max_size = 4096 :: non_neg_integer(),
    next_seq = 0 :: non_neg_integer(),
    oldest_seq = 0 :: non_neg_integer(),
    entries = #{} :: #{non_neg_integer() => #entry{}},
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
    decode_block(Data, State, [], 0, Limit, valid).

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
-spec best({name, pos_integer()} | not_found, find_result()) -> find_result().
best(_Static, {field, _} = Field) -> Field;
best({name, _} = Static, _Dyn) -> Static;
best(not_found, Dyn) -> Dyn.

-spec check_field(binary(), binary()) -> verdict().
check_field(Name, Value) ->
    first_invalid(check_name(Name), check_value(Value)).

-spec check_name(binary()) -> verdict().
check_name(Name) ->
    case nhttp_headers:validate_field_name(Name) of
        ok -> valid;
        {error, uppercase_field_name} -> {invalid_name, uppercase_header_name};
        {error, _} -> {invalid_name, invalid_header_name}
    end.

-spec check_value(binary()) -> verdict().
check_value(Value) ->
    case nhttp_headers:validate_field_value(Value) of
        ok -> valid;
        {error, _} -> {invalid_value, invalid_header_value}
    end.

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
    verdict()
) ->
    decode_result().
decode_block(
    <<2#001:3, Rest/bits>>,
    State = #hpack{configured_max_size = ConfigMax},
    Acc,
    Total,
    Limit,
    Seen
) ->
    maybe
        {ok, MaxSize, Rest2} ?= map_int_error(nhttp_int:dec5(Rest)),
        case MaxSize =< ConfigMax of
            true ->
                State2 = update_table_size(MaxSize, State),
                decode_block(Rest2, State2, Acc, Total, Limit, Seen);
            false ->
                {error, dynamic_table_size_exceeded}
        end
    end;
decode_block(Data, State, Acc, Total, Limit, Seen) ->
    decode_headers(Data, State, Acc, Total, Limit, Seen).

-spec decode_headers(
    binary(),
    state(),
    headers(),
    non_neg_integer(),
    pos_integer() | infinity,
    verdict()
) ->
    decode_result().
decode_headers(<<>>, State, Acc, _Total, _Limit, valid) ->
    {ok, lists:reverse(Acc), State};
decode_headers(<<>>, State, _Acc, _Total, _Limit, {_, Error}) ->
    {invalid_field, Error, State};
decode_headers(<<2#1:1, Rest/bits>>, State, Acc, Total, Limit, Seen) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec7(Rest)),
        {ok, Field, Verdict} ?= lookup(Index, State),
        Seen2 = first_invalid(Seen, Verdict),
        {ok, NewAcc, NewTotal} ?= push_header(Field, Acc, Total, Limit),
        decode_headers(Rest2, State, NewAcc, NewTotal, Limit, Seen2)
    end;
decode_headers(<<2#01:2, 2#000000:6, Rest/bits>>, State, Acc, Total, Limit, Seen) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        Verdict = check_field(Name, Value),
        State2 = insert({Name, Value}, Verdict, State),
        Seen2 = first_invalid(Seen, Verdict),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State2, NewAcc, NewTotal, Limit, Seen2)
    end;
decode_headers(<<2#01:2, Rest/bits>>, State, Acc, Total, Limit, Seen) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec6(Rest)),
        {ok, {Name, _}, NameVerdict} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        Verdict = first_invalid(name_verdict(NameVerdict), check_value(Value)),
        State2 = insert({Name, Value}, Verdict, State),
        Seen2 = first_invalid(Seen, Verdict),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State2, NewAcc, NewTotal, Limit, Seen2)
    end;
decode_headers(<<2#0000:4, 2#0000:4, Rest/bits>>, State, Acc, Total, Limit, Seen) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        Seen2 = first_invalid(Seen, check_field(Name, Value)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit, Seen2)
    end;
decode_headers(<<2#0000:4, Rest/bits>>, State, Acc, Total, Limit, Seen) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec4(Rest)),
        {ok, {Name, _}, NameVerdict} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        Seen2 = first_invalid(Seen, first_invalid(name_verdict(NameVerdict), check_value(Value))),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit, Seen2)
    end;
decode_headers(<<2#0001:4, 2#0000:4, Rest/bits>>, State, Acc, Total, Limit, Seen) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        Seen2 = first_invalid(Seen, check_field(Name, Value)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit, Seen2)
    end;
decode_headers(<<2#0001:4, Rest/bits>>, State, Acc, Total, Limit, Seen) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec4(Rest)),
        {ok, {Name, _}, NameVerdict} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        Seen2 = first_invalid(Seen, first_invalid(name_verdict(NameVerdict), check_value(Value))),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit, Seen2)
    end;
decode_headers(_, _, _, _, _, _) ->
    {error, incomplete_header_block}.

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
        #entry{size = EntrySize} ->
            NewState = State#hpack{
                size = Size - EntrySize,
                oldest_seq = OldestSeq + 1,
                entries = maps:remove(OldestSeq, Entries)
            },
            evict_to_size(TargetSize, NewState)
    end.

-spec find({binary(), binary()}, state()) -> find_result().
find(Header, State) ->
    case find_static(Header) of
        {field, _} = Field -> Field;
        Static -> best(Static, find_dyn(Header, State))
    end.

-spec find_dyn({binary(), binary()}, state()) -> find_result().
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

-spec find_static({binary(), binary()}) -> find_result().
find_static({<<":authority">>, <<>>}) -> {field, 1};
find_static({<<":authority">>, _}) -> {name, 1};
find_static({<<":method">>, <<"GET">>}) -> {field, 2};
find_static({<<":method">>, <<"POST">>}) -> {field, 3};
find_static({<<":method">>, _}) -> {name, 2};
find_static({<<":path">>, <<"/">>}) -> {field, 4};
find_static({<<":path">>, <<"/index.html">>}) -> {field, 5};
find_static({<<":path">>, _}) -> {name, 4};
find_static({<<":scheme">>, <<"http">>}) -> {field, 6};
find_static({<<":scheme">>, <<"https">>}) -> {field, 7};
find_static({<<":scheme">>, _}) -> {name, 6};
find_static({<<":status">>, <<"200">>}) -> {field, 8};
find_static({<<":status">>, <<"204">>}) -> {field, 9};
find_static({<<":status">>, <<"206">>}) -> {field, 10};
find_static({<<":status">>, <<"304">>}) -> {field, 11};
find_static({<<":status">>, <<"400">>}) -> {field, 12};
find_static({<<":status">>, <<"404">>}) -> {field, 13};
find_static({<<":status">>, <<"500">>}) -> {field, 14};
find_static({<<":status">>, _}) -> {name, 8};
find_static({<<"accept-charset">>, <<>>}) -> {field, 15};
find_static({<<"accept-charset">>, _}) -> {name, 15};
find_static({<<"accept-encoding">>, <<"gzip, deflate">>}) -> {field, 16};
find_static({<<"accept-encoding">>, _}) -> {name, 16};
find_static({<<"accept-language">>, <<>>}) -> {field, 17};
find_static({<<"accept-language">>, _}) -> {name, 17};
find_static({<<"accept-ranges">>, <<>>}) -> {field, 18};
find_static({<<"accept-ranges">>, _}) -> {name, 18};
find_static({<<"accept">>, <<>>}) -> {field, 19};
find_static({<<"accept">>, _}) -> {name, 19};
find_static({<<"access-control-allow-origin">>, <<>>}) -> {field, 20};
find_static({<<"access-control-allow-origin">>, _}) -> {name, 20};
find_static({<<"age">>, <<>>}) -> {field, 21};
find_static({<<"age">>, _}) -> {name, 21};
find_static({<<"allow">>, <<>>}) -> {field, 22};
find_static({<<"allow">>, _}) -> {name, 22};
find_static({<<"authorization">>, <<>>}) -> {field, 23};
find_static({<<"authorization">>, _}) -> {name, 23};
find_static({<<"cache-control">>, <<>>}) -> {field, 24};
find_static({<<"cache-control">>, _}) -> {name, 24};
find_static({<<"content-disposition">>, <<>>}) -> {field, 25};
find_static({<<"content-disposition">>, _}) -> {name, 25};
find_static({<<"content-encoding">>, <<>>}) -> {field, 26};
find_static({<<"content-encoding">>, _}) -> {name, 26};
find_static({<<"content-language">>, <<>>}) -> {field, 27};
find_static({<<"content-language">>, _}) -> {name, 27};
find_static({<<"content-length">>, <<>>}) -> {field, 28};
find_static({<<"content-length">>, _}) -> {name, 28};
find_static({<<"content-location">>, <<>>}) -> {field, 29};
find_static({<<"content-location">>, _}) -> {name, 29};
find_static({<<"content-range">>, <<>>}) -> {field, 30};
find_static({<<"content-range">>, _}) -> {name, 30};
find_static({<<"content-type">>, <<>>}) -> {field, 31};
find_static({<<"content-type">>, _}) -> {name, 31};
find_static({<<"cookie">>, <<>>}) -> {field, 32};
find_static({<<"cookie">>, _}) -> {name, 32};
find_static({<<"date">>, <<>>}) -> {field, 33};
find_static({<<"date">>, _}) -> {name, 33};
find_static({<<"etag">>, <<>>}) -> {field, 34};
find_static({<<"etag">>, _}) -> {name, 34};
find_static({<<"expect">>, <<>>}) -> {field, 35};
find_static({<<"expect">>, _}) -> {name, 35};
find_static({<<"expires">>, <<>>}) -> {field, 36};
find_static({<<"expires">>, _}) -> {name, 36};
find_static({<<"from">>, <<>>}) -> {field, 37};
find_static({<<"from">>, _}) -> {name, 37};
find_static({<<"host">>, <<>>}) -> {field, 38};
find_static({<<"host">>, _}) -> {name, 38};
find_static({<<"if-match">>, <<>>}) -> {field, 39};
find_static({<<"if-match">>, _}) -> {name, 39};
find_static({<<"if-modified-since">>, <<>>}) -> {field, 40};
find_static({<<"if-modified-since">>, _}) -> {name, 40};
find_static({<<"if-none-match">>, <<>>}) -> {field, 41};
find_static({<<"if-none-match">>, _}) -> {name, 41};
find_static({<<"if-range">>, <<>>}) -> {field, 42};
find_static({<<"if-range">>, _}) -> {name, 42};
find_static({<<"if-unmodified-since">>, <<>>}) -> {field, 43};
find_static({<<"if-unmodified-since">>, _}) -> {name, 43};
find_static({<<"last-modified">>, <<>>}) -> {field, 44};
find_static({<<"last-modified">>, _}) -> {name, 44};
find_static({<<"link">>, <<>>}) -> {field, 45};
find_static({<<"link">>, _}) -> {name, 45};
find_static({<<"location">>, <<>>}) -> {field, 46};
find_static({<<"location">>, _}) -> {name, 46};
find_static({<<"max-forwards">>, <<>>}) -> {field, 47};
find_static({<<"max-forwards">>, _}) -> {name, 47};
find_static({<<"proxy-authenticate">>, <<>>}) -> {field, 48};
find_static({<<"proxy-authenticate">>, _}) -> {name, 48};
find_static({<<"proxy-authorization">>, <<>>}) -> {field, 49};
find_static({<<"proxy-authorization">>, _}) -> {name, 49};
find_static({<<"range">>, <<>>}) -> {field, 50};
find_static({<<"range">>, _}) -> {name, 50};
find_static({<<"referer">>, <<>>}) -> {field, 51};
find_static({<<"referer">>, _}) -> {name, 51};
find_static({<<"refresh">>, <<>>}) -> {field, 52};
find_static({<<"refresh">>, _}) -> {name, 52};
find_static({<<"retry-after">>, <<>>}) -> {field, 53};
find_static({<<"retry-after">>, _}) -> {name, 53};
find_static({<<"server">>, <<>>}) -> {field, 54};
find_static({<<"server">>, _}) -> {name, 54};
find_static({<<"set-cookie">>, <<>>}) -> {field, 55};
find_static({<<"set-cookie">>, _}) -> {name, 55};
find_static({<<"strict-transport-security">>, <<>>}) -> {field, 56};
find_static({<<"strict-transport-security">>, _}) -> {name, 56};
find_static({<<"transfer-encoding">>, <<>>}) -> {field, 57};
find_static({<<"transfer-encoding">>, _}) -> {name, 57};
find_static({<<"user-agent">>, <<>>}) -> {field, 58};
find_static({<<"user-agent">>, _}) -> {name, 58};
find_static({<<"vary">>, <<>>}) -> {field, 59};
find_static({<<"vary">>, _}) -> {name, 59};
find_static({<<"via">>, <<>>}) -> {field, 60};
find_static({<<"via">>, _}) -> {name, 60};
find_static({<<"www-authenticate">>, <<>>}) -> {field, 61};
find_static({<<"www-authenticate">>, _}) -> {name, 61};
find_static(_) -> not_found.

-spec first_invalid(verdict(), verdict()) -> verdict().
first_invalid(valid, Second) -> Second;
first_invalid(First, _) -> First.

-spec insert({binary(), binary()}, state()) -> state().
insert(Header, State) ->
    insert(Header, valid, State).

-spec insert({binary(), binary()}, verdict(), state()) -> state().
insert({Name, Value}, Verdict, State = #hpack{max_size = MaxSize, next_seq = NextSeq}) ->
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
                entries = maps:put(
                    NextSeq,
                    #entry{size = EntrySize, field = Header, verdict = Verdict},
                    Entries1
                ),
                full_index = maps:put(Header, NextSeq, FullIndex1),
                name_index = maps:put(Name, NextSeq, NameIndex1)
            }
    end.

-spec lookup(pos_integer(), state()) ->
    {ok, {binary(), binary()}, verdict()} | {error, decode_error()}.
lookup(1, _) ->
    {ok, {<<":authority">>, <<>>}, valid};
lookup(2, _) ->
    {ok, {<<":method">>, <<"GET">>}, valid};
lookup(3, _) ->
    {ok, {<<":method">>, <<"POST">>}, valid};
lookup(4, _) ->
    {ok, {<<":path">>, <<"/">>}, valid};
lookup(5, _) ->
    {ok, {<<":path">>, <<"/index.html">>}, valid};
lookup(6, _) ->
    {ok, {<<":scheme">>, <<"http">>}, valid};
lookup(7, _) ->
    {ok, {<<":scheme">>, <<"https">>}, valid};
lookup(8, _) ->
    {ok, {<<":status">>, <<"200">>}, valid};
lookup(9, _) ->
    {ok, {<<":status">>, <<"204">>}, valid};
lookup(10, _) ->
    {ok, {<<":status">>, <<"206">>}, valid};
lookup(11, _) ->
    {ok, {<<":status">>, <<"304">>}, valid};
lookup(12, _) ->
    {ok, {<<":status">>, <<"400">>}, valid};
lookup(13, _) ->
    {ok, {<<":status">>, <<"404">>}, valid};
lookup(14, _) ->
    {ok, {<<":status">>, <<"500">>}, valid};
lookup(15, _) ->
    {ok, {<<"accept-charset">>, <<>>}, valid};
lookup(16, _) ->
    {ok, {<<"accept-encoding">>, <<"gzip, deflate">>}, valid};
lookup(17, _) ->
    {ok, {<<"accept-language">>, <<>>}, valid};
lookup(18, _) ->
    {ok, {<<"accept-ranges">>, <<>>}, valid};
lookup(19, _) ->
    {ok, {<<"accept">>, <<>>}, valid};
lookup(20, _) ->
    {ok, {<<"access-control-allow-origin">>, <<>>}, valid};
lookup(21, _) ->
    {ok, {<<"age">>, <<>>}, valid};
lookup(22, _) ->
    {ok, {<<"allow">>, <<>>}, valid};
lookup(23, _) ->
    {ok, {<<"authorization">>, <<>>}, valid};
lookup(24, _) ->
    {ok, {<<"cache-control">>, <<>>}, valid};
lookup(25, _) ->
    {ok, {<<"content-disposition">>, <<>>}, valid};
lookup(26, _) ->
    {ok, {<<"content-encoding">>, <<>>}, valid};
lookup(27, _) ->
    {ok, {<<"content-language">>, <<>>}, valid};
lookup(28, _) ->
    {ok, {<<"content-length">>, <<>>}, valid};
lookup(29, _) ->
    {ok, {<<"content-location">>, <<>>}, valid};
lookup(30, _) ->
    {ok, {<<"content-range">>, <<>>}, valid};
lookup(31, _) ->
    {ok, {<<"content-type">>, <<>>}, valid};
lookup(32, _) ->
    {ok, {<<"cookie">>, <<>>}, valid};
lookup(33, _) ->
    {ok, {<<"date">>, <<>>}, valid};
lookup(34, _) ->
    {ok, {<<"etag">>, <<>>}, valid};
lookup(35, _) ->
    {ok, {<<"expect">>, <<>>}, valid};
lookup(36, _) ->
    {ok, {<<"expires">>, <<>>}, valid};
lookup(37, _) ->
    {ok, {<<"from">>, <<>>}, valid};
lookup(38, _) ->
    {ok, {<<"host">>, <<>>}, valid};
lookup(39, _) ->
    {ok, {<<"if-match">>, <<>>}, valid};
lookup(40, _) ->
    {ok, {<<"if-modified-since">>, <<>>}, valid};
lookup(41, _) ->
    {ok, {<<"if-none-match">>, <<>>}, valid};
lookup(42, _) ->
    {ok, {<<"if-range">>, <<>>}, valid};
lookup(43, _) ->
    {ok, {<<"if-unmodified-since">>, <<>>}, valid};
lookup(44, _) ->
    {ok, {<<"last-modified">>, <<>>}, valid};
lookup(45, _) ->
    {ok, {<<"link">>, <<>>}, valid};
lookup(46, _) ->
    {ok, {<<"location">>, <<>>}, valid};
lookup(47, _) ->
    {ok, {<<"max-forwards">>, <<>>}, valid};
lookup(48, _) ->
    {ok, {<<"proxy-authenticate">>, <<>>}, valid};
lookup(49, _) ->
    {ok, {<<"proxy-authorization">>, <<>>}, valid};
lookup(50, _) ->
    {ok, {<<"range">>, <<>>}, valid};
lookup(51, _) ->
    {ok, {<<"referer">>, <<>>}, valid};
lookup(52, _) ->
    {ok, {<<"refresh">>, <<>>}, valid};
lookup(53, _) ->
    {ok, {<<"retry-after">>, <<>>}, valid};
lookup(54, _) ->
    {ok, {<<"server">>, <<>>}, valid};
lookup(55, _) ->
    {ok, {<<"set-cookie">>, <<>>}, valid};
lookup(56, _) ->
    {ok, {<<"strict-transport-security">>, <<>>}, valid};
lookup(57, _) ->
    {ok, {<<"transfer-encoding">>, <<>>}, valid};
lookup(58, _) ->
    {ok, {<<"user-agent">>, <<>>}, valid};
lookup(59, _) ->
    {ok, {<<"vary">>, <<>>}, valid};
lookup(60, _) ->
    {ok, {<<"via">>, <<>>}, valid};
lookup(61, _) ->
    {ok, {<<"www-authenticate">>, <<>>}, valid};
lookup(Index, #hpack{next_seq = NextSeq, oldest_seq = OldestSeq, entries = Entries}) when
    Index > 61
->
    Seq = NextSeq - 1 - (Index - 62),
    case Seq >= OldestSeq andalso Seq < NextSeq of
        true ->
            case maps:get(Seq, Entries, undefined) of
                #entry{field = Field, verdict = Verdict} -> {ok, Field, Verdict};
                undefined -> {error, invalid_table_index}
            end;
        false ->
            {error, invalid_table_index}
    end;
lookup(0, _) ->
    {error, invalid_table_index}.

-spec lower_name({binary(), binary()}, binary(), binary()) -> {binary(), binary()}.
lower_name(Header, Name, Value) ->
    case nhttp_headers:lower_field_name(Name) of
        Name -> Header;
        Lower -> {Lower, Value}
    end.

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

-spec name_verdict(verdict()) -> verdict().
name_verdict({invalid_value, _}) -> valid;
name_verdict(Verdict) -> Verdict.

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
