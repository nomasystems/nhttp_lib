%%%-----------------------------------------------------------------------------
-module(nhttp_lib_props).

-moduledoc """
Property tests for the method properties of nhttp_lib.

Exercised via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

%%%-----------------------------------------------------------------------------
%%% PROPERTIES
%%%-----------------------------------------------------------------------------

%% RFC 9110 Section 9.2.2: every safe method is idempotent.
-spec prop_safe_implies_idempotent() -> triq:property().
prop_safe_implies_idempotent() ->
    ?FORALL(
        Method,
        method_gen(),
        not nhttp_lib:is_safe(Method) orelse nhttp_lib:is_idempotent(Method)
    ).

%%%-----------------------------------------------------------------------------
%%% GENERATORS
%%%-----------------------------------------------------------------------------

-spec method_gen() -> triq_dom:domain().
method_gen() ->
    oneof([
        elements([get, head, post, put, delete, connect, options, trace, patch, query]),
        ?LET(Token, non_empty(list(token_char_gen())), nhttp_lib:decode_method(list_to_binary(Token)))
    ]).

-spec token_char_gen() -> triq_dom:domain().
token_char_gen() ->
    elements("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ").
