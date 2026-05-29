%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_static_table_SUITE).

-moduledoc "QPACK static table test suite (RFC 9204).".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, lookup},
        {group, reverse_lookup},
        {group, persistent_term_caching}
    ].

groups() ->
    [
        {lookup, [parallel], [
            table_size,
            known_entries,
            all_entries_valid,
            boundary_indices,
            invalid_index
        ]},
        {reverse_lookup, [parallel], [
            find_name_exact,
            find_name_status,
            find_name_missing,
            find_name_value_exact,
            find_name_value_name_only,
            find_name_value_missing,
            find_name_value_content_type
        ]},
        {persistent_term_caching, [sequential], [
            cache_is_populated,
            cache_populated_before_first_call,
            cache_populated_after_purge_and_reload
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
%%% LOOKUP TESTS
%%%-----------------------------------------------------------------------------

table_size(_Config) ->
    ?assertEqual(99, nhttp_qpack_static_table:size()).

known_entries(_Config) ->
    ?assertEqual(
        {ok, {<<":authority">>, <<>>}},
        nhttp_qpack_static_table:lookup(0)
    ),
    ?assertEqual(
        {ok, {<<":path">>, <<"/">>}},
        nhttp_qpack_static_table:lookup(1)
    ),
    ?assertEqual(
        {ok, {<<":method">>, <<"GET">>}},
        nhttp_qpack_static_table:lookup(17)
    ),
    ?assertEqual(
        {ok, {<<":method">>, <<"POST">>}},
        nhttp_qpack_static_table:lookup(20)
    ),
    ?assertEqual(
        {ok, {<<":scheme">>, <<"https">>}},
        nhttp_qpack_static_table:lookup(23)
    ),
    ?assertEqual(
        {ok, {<<":status">>, <<"200">>}},
        nhttp_qpack_static_table:lookup(25)
    ),
    ?assertEqual(
        {ok, {<<"content-type">>, <<"application/json">>}},
        nhttp_qpack_static_table:lookup(46)
    ),
    ?assertEqual(
        {ok, {<<"x-frame-options">>, <<"sameorigin">>}},
        nhttp_qpack_static_table:lookup(98)
    ).

all_entries_valid(_Config) ->
    lists:foreach(
        fun(Index) ->
            Result = nhttp_qpack_static_table:lookup(Index),
            ?assertMatch({ok, {_, _}}, Result)
        end,
        lists:seq(0, 98)
    ).

boundary_indices(_Config) ->
    ?assertMatch(
        {ok, {_, _}},
        nhttp_qpack_static_table:lookup(0)
    ),
    ?assertMatch(
        {ok, {_, _}},
        nhttp_qpack_static_table:lookup(98)
    ).

invalid_index(_Config) ->
    ?assertEqual(
        {error, bad_index},
        nhttp_qpack_static_table:lookup(99)
    ),
    ?assertEqual(
        {error, bad_index},
        nhttp_qpack_static_table:lookup(1000)
    ).

%%%-----------------------------------------------------------------------------
%%% REVERSE LOOKUP TESTS
%%%-----------------------------------------------------------------------------

find_name_exact(_Config) ->
    ?assertEqual(
        {ok, 15},
        nhttp_qpack_static_table:find_name(<<":method">>)
    ).

find_name_status(_Config) ->
    ?assertEqual(
        {ok, 24},
        nhttp_qpack_static_table:find_name(<<":status">>)
    ).

find_name_missing(_Config) ->
    ?assertEqual(
        error,
        nhttp_qpack_static_table:find_name(<<"x-custom-header">>)
    ).

find_name_value_exact(_Config) ->
    ?assertEqual(
        {ok, 17},
        nhttp_qpack_static_table:find_name_value(
            <<":method">>, <<"GET">>
        )
    ).

find_name_value_name_only(_Config) ->
    ?assertEqual(
        {name, 15},
        nhttp_qpack_static_table:find_name_value(
            <<":method">>, <<"PATCH">>
        )
    ).

find_name_value_missing(_Config) ->
    ?assertEqual(
        error,
        nhttp_qpack_static_table:find_name_value(
            <<"x-custom">>, <<"val">>
        )
    ).

find_name_value_content_type(_Config) ->
    ?assertEqual(
        {ok, 46},
        nhttp_qpack_static_table:find_name_value(
            <<"content-type">>, <<"application/json">>
        )
    ).

%%%-----------------------------------------------------------------------------
%%% PERSISTENT TERM CACHING TESTS
%%%-----------------------------------------------------------------------------

cache_is_populated(_Config) ->
    _ = nhttp_qpack_static_table:find_name(<<":method">>),
    NameIndex = persistent_term:get(
        {nhttp_qpack_static_table, name_index}
    ),
    ?assert(is_map(NameIndex)).

cache_populated_before_first_call(_Config) ->
    NameIndex = persistent_term:get({nhttp_qpack_static_table, name_index}),
    FullIndex = persistent_term:get({nhttp_qpack_static_table, full_index}),
    ?assert(is_map(NameIndex)),
    ?assert(is_map(FullIndex)),
    ?assertMatch(#{<<":method">> := _}, NameIndex).

cache_populated_after_purge_and_reload(_Config) ->
    persistent_term:erase({nhttp_qpack_static_table, name_index}),
    persistent_term:erase({nhttp_qpack_static_table, full_index}),
    code:purge(nhttp_qpack_static_table),
    {module, nhttp_qpack_static_table} = code:load_file(nhttp_qpack_static_table),
    ?assert(is_map(persistent_term:get({nhttp_qpack_static_table, name_index}))),
    ?assert(is_map(persistent_term:get({nhttp_qpack_static_table, full_index}))).
