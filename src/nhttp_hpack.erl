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
""".

%%%-----------------------------------------------------------------------------
%% INLINE DIRECTIVES
%%%-----------------------------------------------------------------------------
-compile({inline, [has_uppercase/1]}).

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
-export_type([decode_error/0, decode_opts/0, encode_opts/0, headers/0, state/0]).

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
    | uppercase_header_name.

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
    entries = #{} :: #{non_neg_integer() => {pos_integer(), {binary(), binary()}}},
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
-doc "Decode a header block.".
-spec decode(Data :: binary(), State :: state()) ->
    {ok, Headers :: headers(), NewState :: state()} | {error, decode_error()}.
decode(Data, State) ->
    decode(Data, State, #{}).

-doc """
Decode a header block, aborting with `{error, header_list_too_large}` once
the cumulative decoded list size exceeds `max_list_size`. The check matches
the RFC 9113 §10.5.1 octet count (name + value + 32 per entry).
""".
-spec decode(Data :: binary(), State :: state(), Opts :: decode_opts()) ->
    {ok, Headers :: headers(), NewState :: state()} | {error, decode_error()}.
decode(Data, State, Opts) ->
    Limit = maps:get(max_list_size, Opts, infinity),
    decode_block(Data, State, [], 0, Limit).

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
    pos_integer() | infinity
) ->
    {ok, headers(), state()} | {error, decode_error()}.
decode_block(
    <<2#001:3, Rest/bits>>, State = #hpack{configured_max_size = ConfigMax}, Acc, Total, Limit
) ->
    maybe
        {ok, MaxSize, Rest2} ?= map_int_error(nhttp_int:dec5(Rest)),
        case MaxSize =< ConfigMax of
            true ->
                State2 = update_table_size(MaxSize, State),
                decode_block(Rest2, State2, Acc, Total, Limit);
            false ->
                {error, dynamic_table_size_exceeded}
        end
    end;
decode_block(Data, State, Acc, Total, Limit) ->
    decode_headers(Data, State, Acc, Total, Limit).

-spec decode_headers(
    binary(),
    state(),
    headers(),
    non_neg_integer(),
    pos_integer() | infinity
) ->
    {ok, headers(), state()} | {error, decode_error()}.
decode_headers(<<>>, State, Acc, _Total, _Limit) ->
    {ok, lists:reverse(Acc), State};
decode_headers(<<2#1:1, Rest/bits>>, State, Acc, Total, Limit) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec7(Rest)),
        {ok, {Name, Value}} ?= lookup(Index, State),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest2, State, NewAcc, NewTotal, Limit)
    end;
decode_headers(<<2#01:2, 2#000000:6, Rest/bits>>, State, Acc, Total, Limit) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        ok ?= validate_name_no_uppercase(Name),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        State2 = insert({Name, Value}, State),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State2, NewAcc, NewTotal, Limit)
    end;
decode_headers(<<2#01:2, Rest/bits>>, State, Acc, Total, Limit) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec6(Rest)),
        {ok, {Name, _}} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        State2 = insert({Name, Value}, State),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State2, NewAcc, NewTotal, Limit)
    end;
decode_headers(<<2#0000:4, 2#0000:4, Rest/bits>>, State, Acc, Total, Limit) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        ok ?= validate_name_no_uppercase(Name),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit)
    end;
decode_headers(<<2#0000:4, Rest/bits>>, State, Acc, Total, Limit) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec4(Rest)),
        {ok, {Name, _}} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit)
    end;
decode_headers(<<2#0001:4, 2#0000:4, Rest/bits>>, State, Acc, Total, Limit) ->
    maybe
        {ok, Name, Rest2} ?= map_str_error(nhttp_str:decode(Rest)),
        ok ?= validate_name_no_uppercase(Name),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit)
    end;
decode_headers(<<2#0001:4, Rest/bits>>, State, Acc, Total, Limit) ->
    maybe
        {ok, Index, Rest2} ?= map_int_error(nhttp_int:dec4(Rest)),
        {ok, {Name, _}} ?= lookup(Index, State),
        {ok, Value, Rest3} ?= map_str_error(nhttp_str:decode(Rest2)),
        {ok, NewAcc, NewTotal} ?= push_header({Name, Value}, Acc, Total, Limit),
        decode_headers(Rest3, State, NewAcc, NewTotal, Limit)
    end;
decode_headers(_, _, _, _, _) ->
    {error, incomplete_header_block}.

encode_headers([], State, _, Acc) ->
    {lists:reverse(Acc), State};
encode_headers([{Name, Value} | Tail], State, UseHuffman, Acc) ->
    Header = {Name, Value},
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
        {EntrySize, _Header} ->
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

-spec has_uppercase(binary()) -> boolean().
has_uppercase(<<>>) -> false;
has_uppercase(<<C, _/binary>>) when C >= $A, C =< $Z -> true;
has_uppercase(<<_, Rest/binary>>) -> has_uppercase(Rest).

-spec insert({binary(), binary()}, state()) -> state().
insert({Name, Value}, State = #hpack{max_size = MaxSize, next_seq = NextSeq}) ->
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
                entries = maps:put(NextSeq, {EntrySize, Header}, Entries1),
                full_index = maps:put(Header, NextSeq, FullIndex1),
                name_index = maps:put(Name, NextSeq, NameIndex1)
            }
    end.

-spec lookup(pos_integer(), state()) -> {ok, {binary(), binary()}} | {error, decode_error()}.
lookup(1, _) ->
    {ok, {<<":authority">>, <<>>}};
lookup(2, _) ->
    {ok, {<<":method">>, <<"GET">>}};
lookup(3, _) ->
    {ok, {<<":method">>, <<"POST">>}};
lookup(4, _) ->
    {ok, {<<":path">>, <<"/">>}};
lookup(5, _) ->
    {ok, {<<":path">>, <<"/index.html">>}};
lookup(6, _) ->
    {ok, {<<":scheme">>, <<"http">>}};
lookup(7, _) ->
    {ok, {<<":scheme">>, <<"https">>}};
lookup(8, _) ->
    {ok, {<<":status">>, <<"200">>}};
lookup(9, _) ->
    {ok, {<<":status">>, <<"204">>}};
lookup(10, _) ->
    {ok, {<<":status">>, <<"206">>}};
lookup(11, _) ->
    {ok, {<<":status">>, <<"304">>}};
lookup(12, _) ->
    {ok, {<<":status">>, <<"400">>}};
lookup(13, _) ->
    {ok, {<<":status">>, <<"404">>}};
lookup(14, _) ->
    {ok, {<<":status">>, <<"500">>}};
lookup(15, _) ->
    {ok, {<<"accept-charset">>, <<>>}};
lookup(16, _) ->
    {ok, {<<"accept-encoding">>, <<"gzip, deflate">>}};
lookup(17, _) ->
    {ok, {<<"accept-language">>, <<>>}};
lookup(18, _) ->
    {ok, {<<"accept-ranges">>, <<>>}};
lookup(19, _) ->
    {ok, {<<"accept">>, <<>>}};
lookup(20, _) ->
    {ok, {<<"access-control-allow-origin">>, <<>>}};
lookup(21, _) ->
    {ok, {<<"age">>, <<>>}};
lookup(22, _) ->
    {ok, {<<"allow">>, <<>>}};
lookup(23, _) ->
    {ok, {<<"authorization">>, <<>>}};
lookup(24, _) ->
    {ok, {<<"cache-control">>, <<>>}};
lookup(25, _) ->
    {ok, {<<"content-disposition">>, <<>>}};
lookup(26, _) ->
    {ok, {<<"content-encoding">>, <<>>}};
lookup(27, _) ->
    {ok, {<<"content-language">>, <<>>}};
lookup(28, _) ->
    {ok, {<<"content-length">>, <<>>}};
lookup(29, _) ->
    {ok, {<<"content-location">>, <<>>}};
lookup(30, _) ->
    {ok, {<<"content-range">>, <<>>}};
lookup(31, _) ->
    {ok, {<<"content-type">>, <<>>}};
lookup(32, _) ->
    {ok, {<<"cookie">>, <<>>}};
lookup(33, _) ->
    {ok, {<<"date">>, <<>>}};
lookup(34, _) ->
    {ok, {<<"etag">>, <<>>}};
lookup(35, _) ->
    {ok, {<<"expect">>, <<>>}};
lookup(36, _) ->
    {ok, {<<"expires">>, <<>>}};
lookup(37, _) ->
    {ok, {<<"from">>, <<>>}};
lookup(38, _) ->
    {ok, {<<"host">>, <<>>}};
lookup(39, _) ->
    {ok, {<<"if-match">>, <<>>}};
lookup(40, _) ->
    {ok, {<<"if-modified-since">>, <<>>}};
lookup(41, _) ->
    {ok, {<<"if-none-match">>, <<>>}};
lookup(42, _) ->
    {ok, {<<"if-range">>, <<>>}};
lookup(43, _) ->
    {ok, {<<"if-unmodified-since">>, <<>>}};
lookup(44, _) ->
    {ok, {<<"last-modified">>, <<>>}};
lookup(45, _) ->
    {ok, {<<"link">>, <<>>}};
lookup(46, _) ->
    {ok, {<<"location">>, <<>>}};
lookup(47, _) ->
    {ok, {<<"max-forwards">>, <<>>}};
lookup(48, _) ->
    {ok, {<<"proxy-authenticate">>, <<>>}};
lookup(49, _) ->
    {ok, {<<"proxy-authorization">>, <<>>}};
lookup(50, _) ->
    {ok, {<<"range">>, <<>>}};
lookup(51, _) ->
    {ok, {<<"referer">>, <<>>}};
lookup(52, _) ->
    {ok, {<<"refresh">>, <<>>}};
lookup(53, _) ->
    {ok, {<<"retry-after">>, <<>>}};
lookup(54, _) ->
    {ok, {<<"server">>, <<>>}};
lookup(55, _) ->
    {ok, {<<"set-cookie">>, <<>>}};
lookup(56, _) ->
    {ok, {<<"strict-transport-security">>, <<>>}};
lookup(57, _) ->
    {ok, {<<"transfer-encoding">>, <<>>}};
lookup(58, _) ->
    {ok, {<<"user-agent">>, <<>>}};
lookup(59, _) ->
    {ok, {<<"vary">>, <<>>}};
lookup(60, _) ->
    {ok, {<<"via">>, <<>>}};
lookup(61, _) ->
    {ok, {<<"www-authenticate">>, <<>>}};
lookup(Index, #hpack{next_seq = NextSeq, oldest_seq = OldestSeq, entries = Entries}) when
    Index > 61
->
    Seq = NextSeq - 1 - (Index - 62),
    case Seq >= OldestSeq andalso Seq < NextSeq of
        true ->
            case maps:get(Seq, Entries, undefined) of
                {_, Header} -> {ok, Header};
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

-spec validate_name_no_uppercase(binary()) -> ok | {error, decode_error()}.
validate_name_no_uppercase(Name) ->
    case has_uppercase(Name) of
        true -> {error, uppercase_header_name};
        false -> ok
    end.
