%%%-----------------------------------------------------------------------------
-module(nhttp_media_type_props).

-moduledoc """
Property tests for nhttp_media_type.

Exercised via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

%%%-----------------------------------------------------------------------------
%%% PROPERTIES
%%%-----------------------------------------------------------------------------

%% RFC 9110 Sections 5.6.6 and 8.3.1: a media type serialized with any case
%% on its names, any OWS around `;`, empty parameters, and a token or a
%% quoted-string with any quoted-pairs for each value parses to the normal
%% form: lowercase names and the unescaped values.
-spec prop_serialized_parses_to_normal_form() -> triq:property().
prop_serialized_parses_to_normal_form() ->
    ?FORALL(
        {Normal, Wire},
        ?LET(Parts, parts_gen(), {normal(Parts), serialize(Parts)}),
        nhttp_media_type:parse(Wire) =:= {ok, Normal}
    ).

%%%-----------------------------------------------------------------------------
%%% GENERATORS
%%%-----------------------------------------------------------------------------

-spec parts_gen() -> triq_dom:domain().
parts_gen() ->
    {cased_token_gen(), cased_token_gen(), list(param_gen()), trailer_gen()}.

-spec param_gen() -> triq_dom:domain().
param_gen() ->
    {ows_gen(), list(ows_gen()), ows_gen(), cased_token_gen(), value_gen()}.

-spec value_gen() -> triq_dom:domain().
value_gen() ->
    oneof([
        {token, token_gen()},
        {quoted, list({bool(), qdtext_gen()})}
    ]).

-spec trailer_gen() -> triq_dom:domain().
trailer_gen() ->
    oneof([none, {ows_gen(), ows_gen()}]).

-spec token_gen() -> triq_dom:domain().
token_gen() ->
    ?LET(Chars, non_empty(list(token_char_gen())), list_to_binary(Chars)).

%% A token with every letter in a random case, paired with its lowercase form.
-spec cased_token_gen() -> triq_dom:domain().
cased_token_gen() ->
    ?LET(
        Chars,
        non_empty(list({token_char_gen(), bool()})),
        {
            list_to_binary([lower(C) || {C, _} <- Chars]),
            list_to_binary([recase(C, Upper) || {C, Upper} <- Chars])
        }
    ).

-spec token_char_gen() -> triq_dom:domain().
token_char_gen() ->
    elements("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ").

%% `qdtext` and the octets that only a quoted-pair carries: DQUOTE and the
%% backslash.
-spec qdtext_gen() -> triq_dom:domain().
qdtext_gen() ->
    oneof([
        elements([$\t, $\s, $", $\\, $;, $,, $=, 16#21, 16#7E, 16#80, 16#FF]),
        int(16#20, 16#7E),
        int(16#80, 16#FF)
    ]).

-spec ows_gen() -> triq_dom:domain().
ows_gen() ->
    elements([<<>>, <<>>, <<" ">>, <<"\t">>, <<" \t ">>]).

%%%-----------------------------------------------------------------------------
%%% MODEL
%%%-----------------------------------------------------------------------------

-type cased() :: {binary(), binary()}.
-type value() :: {token, binary()} | {quoted, [{boolean(), byte()}]}.
-type param() :: {binary(), [binary()], binary(), cased(), value()}.
-type parts() :: {cased(), cased(), [param()], none | {binary(), binary()}}.

-spec normal(parts()) -> nhttp_media_type:media_type().
normal({{Type, _}, {Subtype, _}, Params, _Trailer}) ->
    #{
        type => Type,
        subtype => Subtype,
        params => [{Name, value(Value)} || {_, _, _, {Name, _}, Value} <- Params]
    }.

-spec value(value()) -> binary().
value({token, Token}) ->
    Token;
value({quoted, Chars}) ->
    list_to_binary([C || {_, C} <- Chars]).

-spec serialize(parts()) -> binary().
serialize({{_, Type}, {_, Subtype}, Params, Trailer}) ->
    iolist_to_binary([
        Type,
        $/,
        Subtype,
        [serialize_param(P) || P <- Params],
        serialize_trailer(Trailer)
    ]).

-spec serialize_param(param()) -> iodata().
serialize_param({Before, Empty, After, {_, Name}, Value}) ->
    [[[Ows, $;] || Ows <- [Before | Empty]], After, Name, $=, serialize_value(Value)].

-spec serialize_value(value()) -> iodata().
serialize_value({token, Token}) ->
    Token;
serialize_value({quoted, Chars}) ->
    [$", [quote(Escape, C) || {Escape, C} <- Chars], $"].

-spec quote(boolean(), byte()) -> iodata().
quote(_Escape, C) when C =:= $"; C =:= $\\ -> [$\\, C];
quote(true, C) -> [$\\, C];
quote(false, C) -> C.

-spec serialize_trailer(none | {binary(), binary()}) -> iodata().
serialize_trailer(none) -> [];
serialize_trailer({Before, After}) -> [Before, $;, After].

-spec lower(byte()) -> byte().
lower(C) when C >= $A, C =< $Z -> C + 32;
lower(C) -> C.

-spec recase(byte(), boolean()) -> byte().
recase(C, true) when C >= $a, C =< $z -> C - 32;
recase(C, true) -> C;
recase(C, false) -> lower(C).
