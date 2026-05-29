%%%-----------------------------------------------------------------------------
-module(nhttp_lib_pseudo_headers_SUITE).

-moduledoc "Tests for nhttp_lib:request_to_pseudo_headers/1.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        basic_get,
        host_header_filtered,
        method_atom_uppercased_on_wire,
        binary_method_passthrough,
        scheme_atom_to_wire,
        wss_scheme,
        extended_connect_protocol_preserved,
        regular_headers_order_preserved,
        empty_headers_passthrough,
        host_filter_only_removes_host
    ].

%%%-----------------------------------------------------------------------------
%%% TESTS
%%%-----------------------------------------------------------------------------

basic_get(_Config) ->
    Req = #{
        method => get,
        path => <<"/">>,
        scheme => https,
        authority => <<"example.com">>,
        headers => []
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":authority">>, <<"example.com">>},
            {<<":path">>, <<"/">>}
        ],
        Out
    ).

host_header_filtered(_Config) ->
    Req = #{
        method => get,
        path => <<"/">>,
        scheme => https,
        authority => <<"example.com">>,
        headers => [
            {<<"host">>, <<"other.example">>},
            {<<"accept">>, <<"*/*">>}
        ]
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":authority">>, <<"example.com">>},
            {<<":path">>, <<"/">>},
            {<<"accept">>, <<"*/*">>}
        ],
        Out
    ).

method_atom_uppercased_on_wire(_Config) ->
    Req = #{
        method => post,
        path => <<"/api">>,
        scheme => https,
        authority => <<"example.com">>,
        headers => []
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(<<"POST">>, proplists:get_value(<<":method">>, Out)).

binary_method_passthrough(_Config) ->
    Req = #{
        method => <<"PROPFIND">>,
        path => <<"/dav">>,
        scheme => https,
        authority => <<"example.com">>,
        headers => []
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(<<"PROPFIND">>, proplists:get_value(<<":method">>, Out)).

scheme_atom_to_wire(_Config) ->
    Req = #{
        method => get,
        path => <<"/">>,
        scheme => http,
        authority => <<"example.com">>,
        headers => []
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(<<"http">>, proplists:get_value(<<":scheme">>, Out)).

wss_scheme(_Config) ->
    Req = #{
        method => connect,
        path => <<"/chat">>,
        scheme => wss,
        authority => <<"example.com">>,
        headers => []
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(<<"wss">>, proplists:get_value(<<":scheme">>, Out)).

extended_connect_protocol_preserved(_Config) ->
    Req = #{
        method => connect,
        path => <<"/chat">>,
        scheme => https,
        authority => <<"example.com">>,
        headers => [{<<":protocol">>, <<"websocket">>}]
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(<<"websocket">>, proplists:get_value(<<":protocol">>, Out)),
    [_, _, _, _ | Tail] = Out,
    ?assertEqual([{<<":protocol">>, <<"websocket">>}], Tail).

regular_headers_order_preserved(_Config) ->
    Req = #{
        method => get,
        path => <<"/">>,
        scheme => https,
        authority => <<"example.com">>,
        headers => [
            {<<"x-a">>, <<"1">>},
            {<<"x-b">>, <<"2">>},
            {<<"x-c">>, <<"3">>}
        ]
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    [_, _, _, _ | Tail] = Out,
    ?assertEqual(
        [
            {<<"x-a">>, <<"1">>},
            {<<"x-b">>, <<"2">>},
            {<<"x-c">>, <<"3">>}
        ],
        Tail
    ).

empty_headers_passthrough(_Config) ->
    Req = #{
        method => get,
        path => <<"/">>,
        scheme => https,
        authority => <<"example.com">>,
        headers => []
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(4, length(Out)).

host_filter_only_removes_host(_Config) ->
    Req = #{
        method => get,
        path => <<"/">>,
        scheme => https,
        authority => <<"example.com">>,
        headers => [
            {<<"x-host-name">>, <<"keep">>},
            {<<"host">>, <<"drop">>},
            {<<"hostess">>, <<"keep">>}
        ]
    },
    Out = nhttp_lib:request_to_pseudo_headers(Req),
    ?assertEqual(undefined, proplists:get_value(<<"host">>, Out)),
    ?assertEqual(<<"keep">>, proplists:get_value(<<"x-host-name">>, Out)),
    ?assertEqual(<<"keep">>, proplists:get_value(<<"hostess">>, Out)).
