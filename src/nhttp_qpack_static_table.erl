-module(nhttp_qpack_static_table).

-moduledoc """
QPACK static table for HTTP/3 (RFC 9204 Appendix A).

This module provides the 99-entry static table used by QPACK header
compression. Forward lookup by index uses compile-time pattern matching
for O(1) access. Reverse lookups by name or name+value use maps cached
in `persistent_term/0`, built once at module load via the `-on_load`
callback below. Concurrent first-use callers therefore never race to
build the maps and never trigger more than the single global GC pair
caused by the two `persistent_term:put/2` calls.
""".

%%%-----------------------------------------------------------------------------
%% INLINE DIRECTIVES
%%%-----------------------------------------------------------------------------
-compile({inline, [lookup/1]}).

%%%-----------------------------------------------------------------------------
%% MODULE LOAD HOOK
%%%-----------------------------------------------------------------------------
-on_load(init/0).

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-export([
    find_name/1,
    find_name_value/2,
    lookup/1,
    size/0
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    index/0,
    static_entry/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type index() :: 0..98.
-type static_entry() :: {Name :: binary(), Value :: binary()}.

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc """
Find the smallest index matching the given header name.

Returns `{ok, Index}` if the name exists in the static table,
or `error` if it does not. When multiple entries share the same
name, the smallest index is returned.
""".
-spec find_name(binary()) -> {ok, index()} | error.
find_name(Name) ->
    Map = persistent_term:get({?MODULE, name_index}),
    case Map of
        #{Name := Index} -> {ok, Index};
        _ -> error
    end.

-doc """
Find an index matching the given header name and value.
Returns `{ok, Index}` for an exact name+value match,
`{name, Index}` if only the name matches (smallest index),
or `error` if the name is not found at all.
""".
-spec find_name_value(binary(), binary()) ->
    {ok, index()} | {name, index()} | error.
find_name_value(Name, Value) ->
    FullMap = persistent_term:get({?MODULE, full_index}),
    case FullMap of
        #{{Name, Value} := Index} ->
            {ok, Index};
        _ ->
            NameMap = persistent_term:get(
                {?MODULE, name_index}
            ),
            case NameMap of
                #{Name := Index} -> {name, Index};
                _ -> error
            end
    end.

-doc """
Look up a static table entry by index.
Returns `{ok, {Name, Value}}` for valid indices 0-98,
or `{error, bad_index}` for anything else.
""".
-spec lookup(non_neg_integer()) ->
    {ok, static_entry()} | {error, bad_index}.
lookup(0) ->
    {ok, {<<":authority">>, <<>>}};
lookup(1) ->
    {ok, {<<":path">>, <<"/">>}};
lookup(2) ->
    {ok, {<<"age">>, <<"0">>}};
lookup(3) ->
    {ok, {<<"content-disposition">>, <<>>}};
lookup(4) ->
    {ok, {<<"content-length">>, <<"0">>}};
lookup(5) ->
    {ok, {<<"cookie">>, <<>>}};
lookup(6) ->
    {ok, {<<"date">>, <<>>}};
lookup(7) ->
    {ok, {<<"etag">>, <<>>}};
lookup(8) ->
    {ok, {<<"if-modified-since">>, <<>>}};
lookup(9) ->
    {ok, {<<"if-none-match">>, <<>>}};
lookup(10) ->
    {ok, {<<"last-modified">>, <<>>}};
lookup(11) ->
    {ok, {<<"link">>, <<>>}};
lookup(12) ->
    {ok, {<<"location">>, <<>>}};
lookup(13) ->
    {ok, {<<"referer">>, <<>>}};
lookup(14) ->
    {ok, {<<"set-cookie">>, <<>>}};
lookup(15) ->
    {ok, {<<":method">>, <<"CONNECT">>}};
lookup(16) ->
    {ok, {<<":method">>, <<"DELETE">>}};
lookup(17) ->
    {ok, {<<":method">>, <<"GET">>}};
lookup(18) ->
    {ok, {<<":method">>, <<"HEAD">>}};
lookup(19) ->
    {ok, {<<":method">>, <<"OPTIONS">>}};
lookup(20) ->
    {ok, {<<":method">>, <<"POST">>}};
lookup(21) ->
    {ok, {<<":method">>, <<"PUT">>}};
lookup(22) ->
    {ok, {<<":scheme">>, <<"http">>}};
lookup(23) ->
    {ok, {<<":scheme">>, <<"https">>}};
lookup(24) ->
    {ok, {<<":status">>, <<"103">>}};
lookup(25) ->
    {ok, {<<":status">>, <<"200">>}};
lookup(26) ->
    {ok, {<<":status">>, <<"304">>}};
lookup(27) ->
    {ok, {<<":status">>, <<"404">>}};
lookup(28) ->
    {ok, {<<":status">>, <<"503">>}};
lookup(29) ->
    {ok, {<<"accept">>, <<"*/*">>}};
lookup(30) ->
    {ok, {<<"accept">>, <<"application/dns-message">>}};
lookup(31) ->
    {ok, {<<"accept-encoding">>, <<"gzip, deflate, br">>}};
lookup(32) ->
    {ok, {<<"accept-ranges">>, <<"bytes">>}};
lookup(33) ->
    {ok, {<<"access-control-allow-headers">>, <<"cache-control">>}};
lookup(34) ->
    {ok, {<<"access-control-allow-headers">>, <<"content-type">>}};
lookup(35) ->
    {ok, {<<"access-control-allow-origin">>, <<"*">>}};
lookup(36) ->
    {ok, {<<"cache-control">>, <<"max-age=0">>}};
lookup(37) ->
    {ok, {<<"cache-control">>, <<"max-age=2592000">>}};
lookup(38) ->
    {ok, {<<"cache-control">>, <<"max-age=604800">>}};
lookup(39) ->
    {ok, {<<"cache-control">>, <<"no-cache">>}};
lookup(40) ->
    {ok, {<<"cache-control">>, <<"no-store">>}};
lookup(41) ->
    {ok, {<<"cache-control">>, <<"public, max-age=31536000">>}};
lookup(42) ->
    {ok, {<<"content-encoding">>, <<"br">>}};
lookup(43) ->
    {ok, {<<"content-encoding">>, <<"gzip">>}};
lookup(44) ->
    {ok, {<<"content-type">>, <<"application/dns-message">>}};
lookup(45) ->
    {ok, {<<"content-type">>, <<"application/javascript">>}};
lookup(46) ->
    {ok, {<<"content-type">>, <<"application/json">>}};
lookup(47) ->
    {ok, {<<"content-type">>, <<"application/x-www-form-urlencoded">>}};
lookup(48) ->
    {ok, {<<"content-type">>, <<"image/gif">>}};
lookup(49) ->
    {ok, {<<"content-type">>, <<"image/jpeg">>}};
lookup(50) ->
    {ok, {<<"content-type">>, <<"image/png">>}};
lookup(51) ->
    {ok, {<<"content-type">>, <<"text/css">>}};
lookup(52) ->
    {ok, {<<"content-type">>, <<"text/html; charset=utf-8">>}};
lookup(53) ->
    {ok, {<<"content-type">>, <<"text/plain">>}};
lookup(54) ->
    {ok, {<<"content-type">>, <<"text/plain;charset=utf-8">>}};
lookup(55) ->
    {ok, {<<"range">>, <<"bytes=0-">>}};
lookup(56) ->
    {ok, {<<"strict-transport-security">>, <<"max-age=31536000">>}};
lookup(57) ->
    {ok, {<<"strict-transport-security">>, <<"max-age=31536000; includesubdomains">>}};
lookup(58) ->
    {ok, {<<"strict-transport-security">>, <<"max-age=31536000; includesubdomains; preload">>}};
lookup(59) ->
    {ok, {<<"vary">>, <<"accept-encoding">>}};
lookup(60) ->
    {ok, {<<"vary">>, <<"origin">>}};
lookup(61) ->
    {ok, {<<"x-content-type-options">>, <<"nosniff">>}};
lookup(62) ->
    {ok, {<<"x-xss-protection">>, <<"1; mode=block">>}};
lookup(63) ->
    {ok, {<<":status">>, <<"100">>}};
lookup(64) ->
    {ok, {<<":status">>, <<"204">>}};
lookup(65) ->
    {ok, {<<":status">>, <<"206">>}};
lookup(66) ->
    {ok, {<<":status">>, <<"302">>}};
lookup(67) ->
    {ok, {<<":status">>, <<"400">>}};
lookup(68) ->
    {ok, {<<":status">>, <<"403">>}};
lookup(69) ->
    {ok, {<<":status">>, <<"421">>}};
lookup(70) ->
    {ok, {<<":status">>, <<"425">>}};
lookup(71) ->
    {ok, {<<":status">>, <<"500">>}};
lookup(72) ->
    {ok, {<<"accept-language">>, <<>>}};
lookup(73) ->
    {ok, {<<"access-control-allow-credentials">>, <<"FALSE">>}};
lookup(74) ->
    {ok, {<<"access-control-allow-credentials">>, <<"TRUE">>}};
lookup(75) ->
    {ok, {<<"access-control-allow-headers">>, <<"*">>}};
lookup(76) ->
    {ok, {<<"access-control-allow-methods">>, <<"get">>}};
lookup(77) ->
    {ok, {<<"access-control-allow-methods">>, <<"get, post, options">>}};
lookup(78) ->
    {ok, {<<"access-control-allow-methods">>, <<"options">>}};
lookup(79) ->
    {ok, {<<"access-control-expose-headers">>, <<"content-length">>}};
lookup(80) ->
    {ok, {<<"access-control-request-headers">>, <<"content-type">>}};
lookup(81) ->
    {ok, {<<"access-control-request-method">>, <<"get">>}};
lookup(82) ->
    {ok, {<<"access-control-request-method">>, <<"post">>}};
lookup(83) ->
    {ok, {<<"alt-svc">>, <<"clear">>}};
lookup(84) ->
    {ok, {<<"authorization">>, <<>>}};
lookup(85) ->
    {ok,
        {<<"content-security-policy">>, <<
            "script-src 'none'; object-src 'none';"
            " base-uri 'none'"
        >>}};
lookup(86) ->
    {ok, {<<"early-data">>, <<"1">>}};
lookup(87) ->
    {ok, {<<"expect-ct">>, <<>>}};
lookup(88) ->
    {ok, {<<"forwarded">>, <<>>}};
lookup(89) ->
    {ok, {<<"if-range">>, <<>>}};
lookup(90) ->
    {ok, {<<"origin">>, <<>>}};
lookup(91) ->
    {ok, {<<"purpose">>, <<"prefetch">>}};
lookup(92) ->
    {ok, {<<"server">>, <<>>}};
lookup(93) ->
    {ok, {<<"timing-allow-origin">>, <<"*">>}};
lookup(94) ->
    {ok, {<<"upgrade-insecure-requests">>, <<"1">>}};
lookup(95) ->
    {ok, {<<"user-agent">>, <<>>}};
lookup(96) ->
    {ok, {<<"x-forwarded-for">>, <<>>}};
lookup(97) ->
    {ok, {<<"x-frame-options">>, <<"deny">>}};
lookup(98) ->
    {ok, {<<"x-frame-options">>, <<"sameorigin">>}};
lookup(_) ->
    {error, bad_index}.

-doc "Return the number of entries in the static table.".
-spec size() -> 99.
size() -> 99.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec build_indexes() -> ok.
build_indexes() ->
    {NameMap, FullMap} = build_maps(0, #{}, #{}),
    persistent_term:put({?MODULE, full_index}, FullMap),
    persistent_term:put({?MODULE, name_index}, NameMap),
    ok.

-spec build_maps(non_neg_integer(), NameMap, FullMap) ->
    {NameMap, FullMap}
when
    NameMap :: #{binary() => index()},
    FullMap :: #{{binary(), binary()} => index()}.
build_maps(Index, NameAcc, FullAcc) ->
    case lookup(Index) of
        {ok, {Name, Value}} ->
            NewNameAcc =
                case NameAcc of
                    #{Name := _} -> NameAcc;
                    _ -> NameAcc#{Name => Index}
                end,
            NewFullAcc = FullAcc#{{Name, Value} => Index},
            build_maps(Index + 1, NewNameAcc, NewFullAcc);
        {error, bad_index} ->
            {NameAcc, FullAcc}
    end.

-spec init() -> ok.
init() ->
    build_indexes().
