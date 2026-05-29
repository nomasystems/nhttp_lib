%%%-----------------------------------------------------------------------------
-module(nhttp_props_helpers).

-moduledoc """
Shared helpers and generators for the property test modules.

Pseudo-header matching and the request method/scheme mappings are
identical across the HTTP/2 and HTTP/3 property suites; the binary
status generator is shared by the HTTP/2 and HPACK suites.
""".

-include_lib("triq/include/triq.hrl").

-export([
    request_matches/2,
    split_request_pseudos/1,
    method_atom/1,
    scheme_atom/1,
    status_gen/0
]).

-spec request_matches([{binary(), binary()}], nhttp_lib:request()) -> boolean().
request_matches(Headers, Request) ->
    {Method, Path, Scheme, Authority, Filtered} = split_request_pseudos(Headers),
    maps:get(method, Request) =:= method_atom(Method) andalso
        maps:get(path, Request) =:= Path andalso
        maps:get(scheme, Request) =:= scheme_atom(Scheme) andalso
        maps:get(authority, Request) =:= Authority andalso
        maps:get(headers, Request) =:= Filtered.

-spec split_request_pseudos([{binary(), binary()}]) ->
    {binary(), binary(), binary(), binary(), [{binary(), binary()}]}.
split_request_pseudos(Headers) ->
    split_request_pseudos(Headers, undefined, <<>>, <<"http">>, <<>>, []).

split_request_pseudos([], M, P, S, A, Acc) ->
    {M, P, S, A, lists:reverse(Acc)};
split_request_pseudos([{<<":method">>, V} | T], _, P, S, A, Acc) ->
    split_request_pseudos(T, V, P, S, A, Acc);
split_request_pseudos([{<<":path">>, V} | T], M, _, S, A, Acc) ->
    split_request_pseudos(T, M, V, S, A, Acc);
split_request_pseudos([{<<":scheme">>, V} | T], M, P, _, A, Acc) ->
    split_request_pseudos(T, M, P, V, A, Acc);
split_request_pseudos([{<<":authority">>, V} | T], M, P, S, _, Acc) ->
    split_request_pseudos(T, M, P, S, V, Acc);
split_request_pseudos([H | T], M, P, S, A, Acc) ->
    split_request_pseudos(T, M, P, S, A, [H | Acc]).

-spec method_atom(binary()) -> atom() | binary().
method_atom(<<"GET">>) -> get;
method_atom(<<"HEAD">>) -> head;
method_atom(<<"POST">>) -> post;
method_atom(<<"PUT">>) -> put;
method_atom(<<"DELETE">>) -> delete;
method_atom(<<"CONNECT">>) -> connect;
method_atom(<<"OPTIONS">>) -> options;
method_atom(<<"TRACE">>) -> trace;
method_atom(<<"PATCH">>) -> patch;
method_atom(B) -> B.

-spec scheme_atom(binary()) -> atom() | binary().
scheme_atom(<<"http">>) -> http;
scheme_atom(<<"https">>) -> https;
scheme_atom(B) -> B.

-spec status_gen() -> triq_dom:domain().
status_gen() ->
    oneof([
        <<"200">>,
        <<"201">>,
        <<"204">>,
        <<"301">>,
        <<"302">>,
        <<"304">>,
        <<"400">>,
        <<"401">>,
        <<"403">>,
        <<"404">>,
        <<"500">>,
        <<"502">>,
        <<"503">>
    ]).
