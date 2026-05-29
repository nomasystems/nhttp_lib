%%%-----------------------------------------------------------------------------
-module(nhttp_headers_SUITE).

-moduledoc "Tests for the protocol-agnostic header utility module.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, get},
        {group, has},
        {group, mutation},
        {group, filter},
        {group, to_lower}
    ].

groups() ->
    [
        {get, [parallel], [
            get_first_match,
            get_default_when_absent,
            get_undefined_when_absent,
            get_case_insensitive_lookup,
            get_returns_first_when_duplicate,
            get_handles_empty_headers
        ]},
        {has, [parallel], [
            has_present,
            has_absent,
            has_case_insensitive,
            has_empty_headers
        ]},
        {mutation, [parallel], [
            set_replaces_all_occurrences,
            set_appends_when_missing,
            set_normalises_name,
            append_preserves_existing,
            append_normalises_name,
            delete_removes_every_occurrence,
            delete_case_insensitive,
            delete_no_op_when_absent
        ]},
        {filter, [parallel], [
            filter_keeps_matching,
            filter_keep_all,
            filter_keep_none,
            filter_preserves_order
        ]},
        {to_lower, [parallel], [
            to_lower_common_request_headers,
            to_lower_common_response_headers,
            to_lower_cors_headers,
            to_lower_connection_values,
            to_lower_already_lowercase,
            to_lower_uncommon_header,
            to_lower_empty,
            to_lower_idempotent,
            to_lower_preserves_non_ascii_upper_bytes
        ]}
    ].

%%%-----------------------------------------------------------------------------
%%% GET
%%%-----------------------------------------------------------------------------

get_first_match(_Config) ->
    Headers = [
        {<<"content-type">>, <<"text/html">>},
        {<<"host">>, <<"localhost">>}
    ],
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"content-type">>, Headers)),
    ?assertEqual(<<"localhost">>, nhttp_headers:get(<<"host">>, Headers)).

get_default_when_absent(_Config) ->
    ?assertEqual(<<"fallback">>, nhttp_headers:get(<<"missing">>, [], <<"fallback">>)),
    ?assertEqual(custom, nhttp_headers:get(<<"missing">>, [{<<"x">>, <<"1">>}], custom)).

get_undefined_when_absent(_Config) ->
    ?assertEqual(undefined, nhttp_headers:get(<<"missing">>, [])),
    ?assertEqual(undefined, nhttp_headers:get(<<"missing">>, [{<<"x">>, <<"1">>}])).

get_case_insensitive_lookup(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}],
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"Content-Type">>, Headers)),
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"CONTENT-TYPE">>, Headers)),
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"content-type">>, Headers)).

get_returns_first_when_duplicate(_Config) ->
    Headers = [
        {<<"set-cookie">>, <<"a=1">>},
        {<<"set-cookie">>, <<"b=2">>}
    ],
    ?assertEqual(<<"a=1">>, nhttp_headers:get(<<"set-cookie">>, Headers)).

get_handles_empty_headers(_Config) ->
    ?assertEqual(undefined, nhttp_headers:get(<<"x">>, [])),
    ?assertEqual(default, nhttp_headers:get(<<"x">>, [], default)).

%%%-----------------------------------------------------------------------------
%%% HAS
%%%-----------------------------------------------------------------------------

has_present(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}, {<<"host">>, <<"x">>}],
    ?assert(nhttp_headers:has(<<"content-type">>, Headers)),
    ?assert(nhttp_headers:has(<<"host">>, Headers)).

has_absent(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}],
    ?assertNot(nhttp_headers:has(<<"missing">>, Headers)).

has_case_insensitive(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}],
    ?assert(nhttp_headers:has(<<"Content-Type">>, Headers)),
    ?assert(nhttp_headers:has(<<"CONTENT-TYPE">>, Headers)).

has_empty_headers(_Config) ->
    ?assertNot(nhttp_headers:has(<<"any">>, [])).

%%%-----------------------------------------------------------------------------
%%% MUTATION
%%%-----------------------------------------------------------------------------

set_replaces_all_occurrences(_Config) ->
    Headers = [
        {<<"x-trace">>, <<"a">>},
        {<<"host">>, <<"localhost">>},
        {<<"x-trace">>, <<"b">>}
    ],
    Updated = nhttp_headers:set(<<"x-trace">>, <<"only">>, Headers),
    ?assertEqual([{<<"host">>, <<"localhost">>}, {<<"x-trace">>, <<"only">>}], Updated).

set_appends_when_missing(_Config) ->
    Headers = [{<<"host">>, <<"localhost">>}],
    Updated = nhttp_headers:set(<<"x-id">>, <<"1">>, Headers),
    ?assertEqual([{<<"host">>, <<"localhost">>}, {<<"x-id">>, <<"1">>}], Updated).

set_normalises_name(_Config) ->
    Updated = nhttp_headers:set(<<"X-Custom">>, <<"v">>, []),
    ?assertEqual([{<<"x-custom">>, <<"v">>}], Updated).

append_preserves_existing(_Config) ->
    Headers = [{<<"set-cookie">>, <<"a=1">>}],
    Updated = nhttp_headers:append(<<"set-cookie">>, <<"b=2">>, Headers),
    ?assertEqual(
        [{<<"set-cookie">>, <<"a=1">>}, {<<"set-cookie">>, <<"b=2">>}],
        Updated
    ).

append_normalises_name(_Config) ->
    Updated = nhttp_headers:append(<<"Set-Cookie">>, <<"c=3">>, []),
    ?assertEqual([{<<"set-cookie">>, <<"c=3">>}], Updated).

delete_removes_every_occurrence(_Config) ->
    Headers = [
        {<<"x-trace">>, <<"a">>},
        {<<"host">>, <<"localhost">>},
        {<<"x-trace">>, <<"b">>}
    ],
    ?assertEqual(
        [{<<"host">>, <<"localhost">>}],
        nhttp_headers:delete(<<"x-trace">>, Headers)
    ).

delete_case_insensitive(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}, {<<"host">>, <<"x">>}],
    ?assertEqual(
        [{<<"host">>, <<"x">>}],
        nhttp_headers:delete(<<"Content-Type">>, Headers)
    ).

delete_no_op_when_absent(_Config) ->
    Headers = [{<<"host">>, <<"x">>}],
    ?assertEqual(Headers, nhttp_headers:delete(<<"missing">>, Headers)),
    ?assertEqual([], nhttp_headers:delete(<<"any">>, [])).

%%%-----------------------------------------------------------------------------
%%% FILTER
%%%-----------------------------------------------------------------------------

filter_keeps_matching(_Config) ->
    Headers = [
        {<<"content-type">>, <<"text/html">>},
        {<<"x-custom">>, <<"value">>},
        {<<"host">>, <<"localhost">>}
    ],
    Pred = fun
        (<<"x-", _/binary>>, _) -> true;
        (_, _) -> false
    end,
    ?assertEqual([{<<"x-custom">>, <<"value">>}], nhttp_headers:filter(Pred, Headers)).

filter_keep_all(_Config) ->
    Headers = [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}],
    ?assertEqual(Headers, nhttp_headers:filter(fun(_, _) -> true end, Headers)).

filter_keep_none(_Config) ->
    Headers = [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}],
    ?assertEqual([], nhttp_headers:filter(fun(_, _) -> false end, Headers)).

filter_preserves_order(_Config) ->
    Headers = [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}, {<<"c">>, <<"3">>}],
    Pred = fun(N, _) -> N =/= <<"b">> end,
    ?assertEqual(
        [{<<"a">>, <<"1">>}, {<<"c">>, <<"3">>}],
        nhttp_headers:filter(Pred, Headers)
    ).

%%%-----------------------------------------------------------------------------
%%% TO_LOWER
%%%-----------------------------------------------------------------------------

to_lower_common_request_headers(_Config) ->
    ?assertEqual(<<"host">>, nhttp_headers:to_lower(<<"Host">>)),
    ?assertEqual(<<"connection">>, nhttp_headers:to_lower(<<"Connection">>)),
    ?assertEqual(<<"content-type">>, nhttp_headers:to_lower(<<"Content-Type">>)),
    ?assertEqual(<<"content-length">>, nhttp_headers:to_lower(<<"Content-Length">>)),
    ?assertEqual(<<"transfer-encoding">>, nhttp_headers:to_lower(<<"Transfer-Encoding">>)),
    ?assertEqual(<<"accept">>, nhttp_headers:to_lower(<<"Accept">>)),
    ?assertEqual(<<"accept-encoding">>, nhttp_headers:to_lower(<<"Accept-Encoding">>)),
    ?assertEqual(<<"accept-language">>, nhttp_headers:to_lower(<<"Accept-Language">>)),
    ?assertEqual(<<"user-agent">>, nhttp_headers:to_lower(<<"User-Agent">>)),
    ?assertEqual(<<"cookie">>, nhttp_headers:to_lower(<<"Cookie">>)),
    ?assertEqual(<<"authorization">>, nhttp_headers:to_lower(<<"Authorization">>)),
    ?assertEqual(<<"cache-control">>, nhttp_headers:to_lower(<<"Cache-Control">>)),
    ?assertEqual(<<"if-none-match">>, nhttp_headers:to_lower(<<"If-None-Match">>)),
    ?assertEqual(<<"if-modified-since">>, nhttp_headers:to_lower(<<"If-Modified-Since">>)),
    ?assertEqual(<<"origin">>, nhttp_headers:to_lower(<<"Origin">>)),
    ?assertEqual(<<"referer">>, nhttp_headers:to_lower(<<"Referer">>)).

to_lower_common_response_headers(_Config) ->
    ?assertEqual(<<"content-encoding">>, nhttp_headers:to_lower(<<"Content-Encoding">>)),
    ?assertEqual(<<"set-cookie">>, nhttp_headers:to_lower(<<"Set-Cookie">>)),
    ?assertEqual(<<"keep-alive">>, nhttp_headers:to_lower(<<"Keep-Alive">>)),
    ?assertEqual(<<"location">>, nhttp_headers:to_lower(<<"Location">>)),
    ?assertEqual(<<"etag">>, nhttp_headers:to_lower(<<"ETag">>)),
    ?assertEqual(<<"last-modified">>, nhttp_headers:to_lower(<<"Last-Modified">>)),
    ?assertEqual(<<"expires">>, nhttp_headers:to_lower(<<"Expires">>)),
    ?assertEqual(<<"date">>, nhttp_headers:to_lower(<<"Date">>)),
    ?assertEqual(<<"server">>, nhttp_headers:to_lower(<<"Server">>)),
    ?assertEqual(<<"vary">>, nhttp_headers:to_lower(<<"Vary">>)).

to_lower_cors_headers(_Config) ->
    ?assertEqual(
        <<"access-control-allow-origin">>,
        nhttp_headers:to_lower(<<"Access-Control-Allow-Origin">>)
    ),
    ?assertEqual(
        <<"access-control-allow-methods">>,
        nhttp_headers:to_lower(<<"Access-Control-Allow-Methods">>)
    ),
    ?assertEqual(
        <<"access-control-allow-headers">>,
        nhttp_headers:to_lower(<<"Access-Control-Allow-Headers">>)
    ).

to_lower_connection_values(_Config) ->
    ?assertEqual(<<"close">>, nhttp_headers:to_lower(<<"Close">>)),
    ?assertEqual(<<"upgrade">>, nhttp_headers:to_lower(<<"Upgrade">>)).

to_lower_already_lowercase(_Config) ->
    ?assertEqual(<<"already-lowercase">>, nhttp_headers:to_lower(<<"already-lowercase">>)),
    ?assertEqual(<<"content-type">>, nhttp_headers:to_lower(<<"content-type">>)).

to_lower_uncommon_header(_Config) ->
    ?assertEqual(<<"x-custom-header">>, nhttp_headers:to_lower(<<"X-Custom-Header">>)),
    ?assertEqual(<<"x-foo-bar">>, nhttp_headers:to_lower(<<"X-FOO-BAR">>)).

to_lower_empty(_Config) ->
    ?assertEqual(<<>>, nhttp_headers:to_lower(<<>>)).

to_lower_idempotent(_Config) ->
    Inputs = [
        <<"Host">>,
        <<"Connection">>,
        <<"Content-Type">>,
        <<"Content-Length">>,
        <<"Transfer-Encoding">>,
        <<"Accept">>,
        <<"Accept-Encoding">>,
        <<"Accept-Language">>,
        <<"User-Agent">>,
        <<"Cookie">>,
        <<"Authorization">>,
        <<"Cache-Control">>,
        <<"If-None-Match">>,
        <<"If-Modified-Since">>,
        <<"Origin">>,
        <<"Referer">>,
        <<"Content-Encoding">>,
        <<"Set-Cookie">>,
        <<"Keep-Alive">>,
        <<"Location">>,
        <<"ETag">>,
        <<"Last-Modified">>,
        <<"Expires">>,
        <<"Date">>,
        <<"Server">>,
        <<"Vary">>,
        <<"Access-Control-Allow-Origin">>,
        <<"Access-Control-Allow-Methods">>,
        <<"Access-Control-Allow-Headers">>,
        <<"Close">>,
        <<"Upgrade">>,
        <<"X-Custom-Header">>,
        <<"already-lowercase">>
    ],
    lists:foreach(
        fun(In) ->
            Lower = nhttp_headers:to_lower(In),
            ?assertEqual(Lower, nhttp_headers:to_lower(Lower))
        end,
        Inputs
    ).

to_lower_preserves_non_ascii_upper_bytes(_Config) ->
    Bin = <<"X-Foo-", 16#80, "-Bar">>,
    Expected = <<"x-foo-", 16#80, "-bar">>,
    ?assertEqual(Expected, nhttp_headers:to_lower(Bin)).
