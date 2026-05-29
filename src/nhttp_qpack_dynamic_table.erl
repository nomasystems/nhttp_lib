%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2025
%%% @end
%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_dynamic_table).

-moduledoc """
QPACK dynamic table implementation based on RFC 9204 Section 3.2.

Uses map-based O(1) lookups for both forward (absolute index to entry) and
reverse (name/value to absolute index) directions.
""".

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    capacity/1,
    current_size/1,
    drop_count/1,
    evict/1,
    find/3,
    insert/3,

    insert_count/1,
    lookup/2,
    new/1,

    set_capacity/2
]).

-export_type([entry/0, t/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type entry() :: {binary(), binary()}.

%%%-----------------------------------------------------------------------------
%% CONSTANTS
%%%-----------------------------------------------------------------------------
-define(ENTRY_OVERHEAD, 32).

%%%-----------------------------------------------------------------------------
%% RECORDS
%%%-----------------------------------------------------------------------------
-record(table, {
    entries :: #{non_neg_integer() => {pos_integer(), entry()}},
    full_index :: #{entry() => non_neg_integer()},
    name_index :: #{binary() => non_neg_integer()},
    insert_count :: non_neg_integer(),
    drop_count :: non_neg_integer(),
    capacity :: non_neg_integer(),
    max_capacity :: non_neg_integer(),
    current_size :: non_neg_integer()
}).

-opaque t() :: #table{}.

%%%-----------------------------------------------------------------------------
%% API FUNCTIONS
%%%-----------------------------------------------------------------------------
-doc "Evict the oldest entry from the table.".
-spec evict(t()) -> {ok, t()} | {error, empty}.
evict(#table{insert_count = IC, drop_count = DC}) when
    IC =:= DC
->
    {error, empty};
evict(
    #table{
        entries = Entries,
        full_index = FullIdx,
        name_index = NameIdx,
        drop_count = DC,
        current_size = CS
    } = Table
) ->
    #{DC := {Size, {Name, Value}}} = Entries,
    FullIdx1 =
        case FullIdx of
            #{{Name, Value} := DC} ->
                maps:remove({Name, Value}, FullIdx);
            _ ->
                FullIdx
        end,
    NameIdx1 =
        case NameIdx of
            #{Name := DC} ->
                maps:remove(Name, NameIdx);
            _ ->
                NameIdx
        end,
    {ok, Table#table{
        entries = maps:remove(DC, Entries),
        full_index = FullIdx1,
        name_index = NameIdx1,
        drop_count = DC + 1,
        current_size = CS - Size
    }}.

-doc """
Reverse lookup by name and value.
Returns `{ok, Index}` for an exact match, `{name, Index}` for a name-only
match, or `error` if nothing is found.
""".
-spec find(binary(), binary(), t()) ->
    {ok, non_neg_integer()} | {name, non_neg_integer()} | error.
find(Name, Value, #table{
    full_index = FullIdx,
    name_index = NameIdx,
    drop_count = DC
}) ->
    case FullIdx of
        #{{Name, Value} := Idx} when Idx >= DC ->
            {ok, Idx};
        _ ->
            case NameIdx of
                #{Name := Idx} when Idx >= DC ->
                    {name, Idx};
                _ ->
                    error
            end
    end.

-doc "Insert a header field entry, evicting as needed.".
-spec insert(binary(), binary(), t()) ->
    {ok, t()} | {error, no_space}.
insert(Name, Value, Table) ->
    Size = entry_size(Name, Value),
    maybe
        {ok, T0} ?= make_room(Size, Table),
        #table{
            entries = Entries,
            full_index = FullIdx,
            name_index = NameIdx,
            insert_count = IC,
            current_size = CS
        } = T0,
        {ok, T0#table{
            entries = Entries#{IC => {Size, {Name, Value}}},
            full_index = FullIdx#{{Name, Value} => IC},
            name_index = NameIdx#{Name => IC},
            insert_count = IC + 1,
            current_size = CS + Size
        }}
    end.

-doc "Look up an entry by absolute index.".
-spec lookup(non_neg_integer(), t()) ->
    {ok, entry()} | {error, bad_index}.
lookup(AbsoluteIndex, #table{entries = Entries}) ->
    case Entries of
        #{AbsoluteIndex := {_Size, Entry}} -> {ok, Entry};
        _ -> {error, bad_index}
    end.

-doc "Create a new dynamic table with the given maximum capacity.".
-spec new(non_neg_integer()) -> {ok, t()}.
new(MaxCapacity) ->
    {ok, #table{
        entries = #{},
        full_index = #{},
        name_index = #{},
        insert_count = 0,
        drop_count = 0,
        capacity = 0,
        max_capacity = MaxCapacity,
        current_size = 0
    }}.

-doc "Set the dynamic table capacity, evicting entries if needed.".
-spec set_capacity(non_neg_integer(), t()) ->
    {ok, t()} | {error, exceeds_max}.
set_capacity(Capacity, #table{max_capacity = Max}) when
    Capacity > Max
->
    {error, exceeds_max};
set_capacity(Capacity, Table) ->
    {ok, evict_to_fit(Table#table{capacity = Capacity})}.

%%%-----------------------------------------------------------------------------
%% ACCESSORS
%%%-----------------------------------------------------------------------------
-doc "Return the current capacity.".
-spec capacity(t()) -> non_neg_integer().
capacity(#table{capacity = C}) -> C.

-doc "Return the current size in bytes.".
-spec current_size(t()) -> non_neg_integer().
current_size(#table{current_size = CS}) -> CS.

-doc "Return the drop count.".
-spec drop_count(t()) -> non_neg_integer().
drop_count(#table{drop_count = DC}) -> DC.

-doc "Return the insert count.".
-spec insert_count(t()) -> non_neg_integer().
insert_count(#table{insert_count = IC}) -> IC.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-doc false.
-spec entry_size(binary(), binary()) -> pos_integer().
entry_size(Name, Value) ->
    byte_size(Name) + byte_size(Value) + ?ENTRY_OVERHEAD.

-doc false.
-spec evict_to_fit(t()) -> t().
evict_to_fit(#table{capacity = Cap, current_size = CS} = Table) when
    CS =< Cap
->
    Table;
evict_to_fit(Table) ->
    {ok, T} = evict(Table),
    evict_to_fit(T).

-doc false.
-spec make_room(pos_integer(), t()) ->
    {ok, t()} | {error, no_space}.
make_room(Needed, #table{capacity = Cap}) when
    Needed > Cap
->
    {error, no_space};
make_room(Needed, #table{capacity = Cap, current_size = CS} = Table) when
    CS + Needed =< Cap
->
    {ok, Table};
make_room(Needed, Table) ->
    case evict(Table) of
        {ok, T} -> make_room(Needed, T);
        {error, empty} -> {error, no_space}
    end.
