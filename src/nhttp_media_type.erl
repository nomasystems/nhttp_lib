-module(nhttp_media_type).

-moduledoc """
Media type parser (RFC 9110 Section 8.3.1) and the `Content-Type` lookup.

`parse/1` reads `media-type = type "/" subtype parameters`, with the
parameters of RFC 9110 Section 5.6.6. A parameter value is a token or a
quoted-string (RFC 9110 Section 5.6.4), and the parser removes the
backslash of each quoted-pair. An empty parameter, as in
`text/plain;;charset=x`, is valid grammar and adds nothing to the result.

The type, the subtype and the parameter names are case-insensitive (RFC
9110 Section 8.3.1), so the result holds them in lowercase. Parameter
values keep their case. A repeated parameter name keeps every value, in
the order of the field.

The parser follows the grammar exactly. It accepts no whitespace around
`/` or `=`, and no whitespace at the start or the end of the value other
than the OWS around a `;`.
""".

-export([
    content_type/1,
    parse/1
]).

-export_type([
    content_type_error/0,
    media_type/0
]).

-type media_type() :: #{
    type := binary(),
    subtype := binary(),
    params := [{binary(), binary()}]
}.

-type content_type_error() :: missing_content_type | invalid_content_type.

-doc """
Parse the `content-type` field of `Headers`.

The lookup is exact on the lowercase name, the form that every codec of
this library gives. Content-Type is a singleton field (RFC 9110 Section
8.3), so two or more field lines are `invalid_content_type`, whatever
their values. RFC 10008 Section 2 makes a server fail a QUERY request
for which this function returns an error.
""".
-spec content_type(nhttp_lib:headers()) -> {ok, media_type()} | {error, content_type_error()}.
content_type(Headers) ->
    case [Value || {<<"content-type">>, Value} <- Headers] of
        [] -> {error, missing_content_type};
        [Value] -> content_type_value(parse(Value));
        [_, _ | _] -> {error, invalid_content_type}
    end.

-doc "Parse a media type into its normal form.".
-spec parse(binary()) -> {ok, media_type()} | {error, invalid_media_type}.
parse(Bin) ->
    maybe
        {ok, Type, <<$/, Rest0/binary>>} ?= token(Bin),
        {ok, Subtype, Rest1} ?= token(Rest0),
        {ok, Params} ?= params(Rest1, []),
        {ok, #{
            type => nhttp_headers:lower_field_name(Type),
            subtype => nhttp_headers:lower_field_name(Subtype),
            params => Params
        }}
    else
        {ok, _Type, _Rest} -> {error, invalid_media_type};
        error -> {error, invalid_media_type}
    end.

-spec content_type_value({ok, media_type()} | {error, invalid_media_type}) ->
    {ok, media_type()} | {error, invalid_content_type}.
content_type_value({ok, MediaType}) -> {ok, MediaType};
content_type_value({error, invalid_media_type}) -> {error, invalid_content_type}.

-spec params(binary(), [{binary(), binary()}]) -> {ok, [{binary(), binary()}]} | error.
params(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
params(Bin, Acc) ->
    case skip_ows(Bin) of
        <<$;, Rest/binary>> -> param(skip_ows(Rest), Acc);
        _ -> error
    end.

-spec param(binary(), [{binary(), binary()}]) -> {ok, [{binary(), binary()}]} | error.
param(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
param(<<$;, _/binary>> = Bin, Acc) ->
    params(Bin, Acc);
param(Bin, Acc) ->
    maybe
        {ok, Name, <<$=, Rest0/binary>>} ?= token(Bin),
        {ok, Value, Rest1} ?= param_value(Rest0),
        params(Rest1, [{nhttp_headers:lower_field_name(Name), Value} | Acc])
    else
        {ok, _Name, _Rest} -> error;
        error -> error
    end.

-spec param_value(binary()) -> {ok, binary(), binary()} | error.
param_value(<<$", Rest/binary>>) ->
    quoted(Rest, <<>>);
param_value(Bin) ->
    token(Bin).

-spec quoted(binary(), binary()) -> {ok, binary(), binary()} | error.
quoted(<<$", Rest/binary>>, Acc) ->
    {ok, Acc, Rest};
quoted(<<$\\, C, Rest/binary>>, Acc) when C =:= $\t; C >= 16#20, C =/= 16#7F ->
    quoted(Rest, <<Acc/binary, C>>);
quoted(<<$\\, _/binary>>, _Acc) ->
    error;
quoted(<<C, Rest/binary>>, Acc) when C =:= $\t; C >= 16#20, C =/= 16#7F ->
    quoted(Rest, <<Acc/binary, C>>);
quoted(_Bin, _Acc) ->
    error.

-spec token(binary()) -> {ok, binary(), binary()} | error.
token(Bin) ->
    token(Bin, binary:match(Bin, nhttp_headers:non_tchar_pattern())).

-spec token(binary(), nomatch | {non_neg_integer(), 1}) -> {ok, binary(), binary()} | error.
token(<<>>, nomatch) ->
    error;
token(Bin, nomatch) ->
    {ok, Bin, <<>>};
token(_Bin, {0, 1}) ->
    error;
token(Bin, {Len, 1}) ->
    <<Token:Len/binary, Rest/binary>> = Bin,
    {ok, Token, Rest}.

-spec skip_ows(binary()) -> binary().
skip_ows(<<$\s, Rest/binary>>) -> skip_ows(Rest);
skip_ows(<<$\t, Rest/binary>>) -> skip_ows(Rest);
skip_ows(Bin) -> Bin.
