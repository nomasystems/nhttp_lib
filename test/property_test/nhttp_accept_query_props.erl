%%%-----------------------------------------------------------------------------
-module(nhttp_accept_query_props).

-moduledoc """
Property tests for nhttp_accept_query.

Exercised via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

%%%-----------------------------------------------------------------------------
%%% PROPERTIES
%%%-----------------------------------------------------------------------------

%% RFC 9651 Sections 4.1 and 4.2: a valid list of media ranges survives the
%% encoder and the parser unchanged.
-spec prop_encode_parse_roundtrip() -> triq:property().
prop_encode_parse_roundtrip() ->
    ?FORALL(
        Ranges,
        non_empty(list(range_gen())),
        begin
            {ok, Wire} = nhttp_accept_query:encode(Ranges),
            nhttp_accept_query:parse_value(Wire) =:= {ok, Ranges}
        end
    ).

%%%-----------------------------------------------------------------------------
%%% GENERATORS
%%%-----------------------------------------------------------------------------

-spec range_gen() -> triq_dom:domain().
range_gen() ->
    ?LET(
        {{Type, Subtype}, Params},
        {type_subtype_gen(), list({key_gen(), value_gen()})},
        #{type => Type, subtype => Subtype, params => unique_keys(Params)}
    ).

-spec type_subtype_gen() -> triq_dom:domain().
type_subtype_gen() ->
    oneof([
        {<<"*">>, <<"*">>},
        {token_gen(), <<"*">>},
        ?SUCHTHAT({Type, _Subtype}, {token_gen(), token_gen()}, Type =/= <<"*">>)
    ]).

%% RFC 9110 tokens in lowercase, the normal form that the parser returns. A
%% token with a leading digit goes out as an SF String.
-spec token_gen() -> triq_dom:domain().
token_gen() ->
    ?LET(Chars, non_empty(list(token_char_gen())), list_to_binary(Chars)).

-spec token_char_gen() -> triq_dom:domain().
token_char_gen() ->
    elements("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz").

%% RFC 9651 Section 3.1.2: `key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_"
%% / "-" / "." / "*" )`.
-spec key_gen() -> triq_dom:domain().
key_gen() ->
    ?LET(
        {First, Rest},
        {elements("*abcdefghijklmnopqrstuvwxyz"), list(elements("abcdefghijklmnopqrstuvwxyz0123456789_-.*"))},
        list_to_binary([First | Rest])
    ).

%% RFC 9651 Section 3.3.3: a String holds octets 0x20 to 0x7E.
-spec value_gen() -> triq_dom:domain().
value_gen() ->
    oneof([
        token_gen(),
        ?LET(Chars, list(oneof([int(16#20, 16#7E), elements([$", $\\, $\s])])), list_to_binary(Chars))
    ]).

-spec unique_keys([{binary(), binary()}]) -> [{binary(), binary()}].
unique_keys(Params) ->
    lists:ukeysort(1, Params).
