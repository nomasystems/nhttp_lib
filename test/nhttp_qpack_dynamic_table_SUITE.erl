%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_dynamic_table_SUITE).

-moduledoc "QPACK dynamic table test suite (RFC 9204).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, basic},
        {group, eviction},
        {group, capacity},
        {group, reverse_lookup},
        {group, absolute_indexing}
    ].

groups() ->
    [
        {basic, [parallel], [
            new_table,
            basic_insert_and_lookup,
            multiple_inserts
        ]},
        {eviction, [parallel], [
            eviction_on_insert,
            eviction_order,
            insert_too_large,
            evict_empty
        ]},
        {capacity, [parallel], [
            set_capacity,
            capacity_enforcement,
            set_capacity_zero
        ]},
        {reverse_lookup, [parallel], [
            find_exact_match,
            find_name_only,
            find_no_match,
            find_after_eviction,
            find_updated_after_insert
        ]},
        {absolute_indexing, [parallel], [
            drop_count_increases,
            absolute_index_after_evictions
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% BASIC TESTS
%%%-----------------------------------------------------------------------------

new_table(_Config) ->
    {ok, T} = nhttp_qpack_dynamic_table:new(4096),
    ?assertEqual(0, nhttp_qpack_dynamic_table:current_size(T)),
    ?assertEqual(0, nhttp_qpack_dynamic_table:insert_count(T)),
    ?assertEqual(0, nhttp_qpack_dynamic_table:capacity(T)).

basic_insert_and_lookup(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<":method">>, <<"GET">>, T1
    ),
    ?assertEqual(1, nhttp_qpack_dynamic_table:insert_count(T2)),
    ?assertEqual(
        {ok, {<<":method">>, <<"GET">>}},
        nhttp_qpack_dynamic_table:lookup(0, T2)
    ).

multiple_inserts(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<":method">>, <<"GET">>, T1
    ),
    {ok, T3} = nhttp_qpack_dynamic_table:insert(
        <<":path">>, <<"/">>, T2
    ),
    {ok, T4} = nhttp_qpack_dynamic_table:insert(
        <<":scheme">>, <<"https">>, T3
    ),
    ?assertEqual(3, nhttp_qpack_dynamic_table:insert_count(T4)),
    ?assertEqual(
        {ok, {<<":method">>, <<"GET">>}},
        nhttp_qpack_dynamic_table:lookup(0, T4)
    ),
    ?assertEqual(
        {ok, {<<":path">>, <<"/">>}},
        nhttp_qpack_dynamic_table:lookup(1, T4)
    ),
    ?assertEqual(
        {ok, {<<":scheme">>, <<"https">>}},
        nhttp_qpack_dynamic_table:lookup(2, T4)
    ).

%%%-----------------------------------------------------------------------------
%%% EVICTION TESTS
%%%-----------------------------------------------------------------------------

eviction_on_insert(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(100),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(100, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<":method">>, <<"GET">>, T1
    ),
    {ok, T3} = nhttp_qpack_dynamic_table:insert(
        <<":path">>, <<"/">>, T2
    ),
    {ok, T4} = nhttp_qpack_dynamic_table:insert(
        <<":scheme">>, <<"https">>, T3
    ),
    ?assertEqual(
        {error, bad_index},
        nhttp_qpack_dynamic_table:lookup(0, T4)
    ).

eviction_order(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(128),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(68, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"a">>, <<"1">>, T1
    ),
    {ok, T3} = nhttp_qpack_dynamic_table:insert(
        <<"b">>, <<"2">>, T2
    ),
    ?assertEqual(
        {ok, {<<"a">>, <<"1">>}},
        nhttp_qpack_dynamic_table:lookup(0, T3)
    ),
    ?assertEqual(
        {ok, {<<"b">>, <<"2">>}},
        nhttp_qpack_dynamic_table:lookup(1, T3)
    ),
    {ok, T4} = nhttp_qpack_dynamic_table:evict(T3),
    ?assertEqual(
        {error, bad_index},
        nhttp_qpack_dynamic_table:lookup(0, T4)
    ),
    ?assertEqual(
        {ok, {<<"b">>, <<"2">>}},
        nhttp_qpack_dynamic_table:lookup(1, T4)
    ).

insert_too_large(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(40),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(40, T0),
    ?assertEqual(
        {error, no_space},
        nhttp_qpack_dynamic_table:insert(
            <<"toolarge">>, <<"x">>, T1
        )
    ).

evict_empty(_Config) ->
    {ok, T} = nhttp_qpack_dynamic_table:new(4096),
    ?assertEqual(
        {error, empty},
        nhttp_qpack_dynamic_table:evict(T)
    ).

%%%-----------------------------------------------------------------------------
%%% CAPACITY TESTS
%%%-----------------------------------------------------------------------------

set_capacity(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(1024, T0),
    ?assertEqual(
        1024,
        nhttp_qpack_dynamic_table:capacity(T1)
    ),
    ?assertEqual(
        {error, exceeds_max},
        nhttp_qpack_dynamic_table:set_capacity(8192, T0)
    ).

capacity_enforcement(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"x-header">>, <<"value">>, T1
    ),
    ?assert(nhttp_qpack_dynamic_table:current_size(T2) > 0),
    {ok, T3} = nhttp_qpack_dynamic_table:set_capacity(1, T2),
    ?assertEqual(
        0,
        nhttp_qpack_dynamic_table:current_size(T3)
    ).

set_capacity_zero(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"a">>, <<"1">>, T1
    ),
    {ok, T3} = nhttp_qpack_dynamic_table:insert(
        <<"b">>, <<"2">>, T2
    ),
    ?assert(nhttp_qpack_dynamic_table:current_size(T3) > 0),
    {ok, T4} = nhttp_qpack_dynamic_table:set_capacity(0, T3),
    ?assertEqual(
        0,
        nhttp_qpack_dynamic_table:current_size(T4)
    ),
    ?assertEqual(
        0,
        nhttp_qpack_dynamic_table:capacity(T4)
    ).

%%%-----------------------------------------------------------------------------
%%% REVERSE LOOKUP TESTS
%%%-----------------------------------------------------------------------------

find_exact_match(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"x">>, <<"1">>, T1
    ),
    ?assertEqual(
        {ok, 0},
        nhttp_qpack_dynamic_table:find(<<"x">>, <<"1">>, T2)
    ).

find_name_only(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"x">>, <<"1">>, T1
    ),
    ?assertEqual(
        {name, 0},
        nhttp_qpack_dynamic_table:find(<<"x">>, <<"2">>, T2)
    ).

find_no_match(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    ?assertEqual(
        error,
        nhttp_qpack_dynamic_table:find(<<"x">>, <<"1">>, T1)
    ).

find_after_eviction(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"x">>, <<"1">>, T1
    ),
    {ok, T3} = nhttp_qpack_dynamic_table:evict(T2),
    ?assertEqual(
        error,
        nhttp_qpack_dynamic_table:find(<<"x">>, <<"1">>, T3)
    ).

find_updated_after_insert(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"x">>, <<"1">>, T1
    ),
    {ok, T3} = nhttp_qpack_dynamic_table:insert(
        <<"x">>, <<"2">>, T2
    ),
    ?assertEqual(
        {ok, 0},
        nhttp_qpack_dynamic_table:find(<<"x">>, <<"1">>, T3)
    ),
    ?assertEqual(
        {ok, 1},
        nhttp_qpack_dynamic_table:find(<<"x">>, <<"2">>, T3)
    ),
    ?assertEqual(
        {name, 1},
        nhttp_qpack_dynamic_table:find(<<"x">>, <<"3">>, T3)
    ).

%%%-----------------------------------------------------------------------------
%%% ABSOLUTE INDEXING TESTS
%%%-----------------------------------------------------------------------------

drop_count_increases(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"a">>, <<"1">>, T1
    ),
    ?assertEqual(
        0,
        nhttp_qpack_dynamic_table:drop_count(T2)
    ),
    {ok, T3} = nhttp_qpack_dynamic_table:evict(T2),
    ?assertEqual(
        1,
        nhttp_qpack_dynamic_table:drop_count(T3)
    ).

absolute_index_after_evictions(_Config) ->
    {ok, T0} = nhttp_qpack_dynamic_table:new(4096),
    {ok, T1} = nhttp_qpack_dynamic_table:set_capacity(4096, T0),
    {ok, T2} = nhttp_qpack_dynamic_table:insert(
        <<"a">>, <<"1">>, T1
    ),
    {ok, T3} = nhttp_qpack_dynamic_table:insert(
        <<"b">>, <<"2">>, T2
    ),
    {ok, T4} = nhttp_qpack_dynamic_table:insert(
        <<"c">>, <<"3">>, T3
    ),
    {ok, T5} = nhttp_qpack_dynamic_table:evict(T4),
    {ok, T6} = nhttp_qpack_dynamic_table:evict(T5),
    ?assertEqual(
        2,
        nhttp_qpack_dynamic_table:drop_count(T6)
    ),
    ?assertEqual(
        {ok, {<<"c">>, <<"3">>}},
        nhttp_qpack_dynamic_table:lookup(2, T6)
    ),
    ?assertEqual(
        {error, bad_index},
        nhttp_qpack_dynamic_table:lookup(0, T6)
    ),
    ?assertEqual(
        {error, bad_index},
        nhttp_qpack_dynamic_table:lookup(1, T6)
    ).
