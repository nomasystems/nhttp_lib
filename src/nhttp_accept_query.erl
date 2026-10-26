-module(nhttp_accept_query).

-moduledoc """
The `Accept-Query` field (RFC 10008 Section 3).

The field is a List Structured Field (RFC 9651 Section 3.1). Each member is a
Token or a String that holds a media range without parameters, and each
parameter value is a Token or a String. A Token and a String with the same
characters give the same term, because RFC 10008 Section 3 forbids a
difference in processing.

`parse_value/1` reads the List grammar of RFC 9651 Section 4.2.1 in full. It
accepts only the item types that RFC 10008 Section 3 allows, then checks that
each member is `type "/" subtype`, each side an RFC 9110 token. The wildcards
are `*/*` and `type/*` only. Every failure ignores the whole field (RFC 9651
Section 2.2), and the error names the first rule that the value breaks. An
offset in an error counts octets from the start of the joined field value.

The result holds the type, the subtype and the parameter names in lowercase,
the form of `t:nhttp_media_type:media_type/0`. Every binary in the result
and in a `not_media_range` error is a fresh copy, so a caller can keep a
value for as long as it stays fresh without the receive buffer.

`allows/2` matches a media type against the ranges. RFC 10008 does not define
a rule for parameters, so `allows/2` follows the media ranges of `Accept`
(RFC 9110 Section 12.5.1): each parameter of a range must be present in the
media type with an equal value. A `charset` value compares without case (RFC
9110 Section 8.3.2), every other value with case.
""".

-export([
    allows/2,
    encode/1,
    parse/1,
    parse_value/1
]).

-export_type([
    encode_error/0,
    media_range/0,
    parse_error/0
]).

-type media_range() :: nhttp_media_type:media_type().

-type parse_error() ::
    not_ascii
    | {sf_syntax, non_neg_integer()}
    | {unsupported_item, non_neg_integer()}
    | {unsupported_parameter, non_neg_integer()}
    | {not_media_range, binary()}.

-type encode_error() ::
    {not_media_range, binary()}
    | {invalid_parameter_name, binary()}
    | {invalid_parameter_value, binary()}.

-type sf_member() :: {binary(), [{binary(), binary()}]}.

-define(SF_JOIN, <<", ">>).

-doc """
True iff a range of `Ranges` matches `MediaType`. `*/*` matches any type,
`type/*` any subtype of `type`, and any other range its own type and
subtype. Names compare without case.
""".
-spec allows(nhttp_media_type:media_type(), [media_range()]) -> boolean().
allows(_MediaType, []) ->
    false;
allows(MediaType, [Range | Ranges]) ->
    matches(MediaType, Range) orelse allows(MediaType, Ranges).

-doc """
Serialize a non-empty list of media ranges (RFC 9651 Section 4.1.1).

A member or a parameter value goes out as a Token when it is a valid Token,
and as a String otherwise. A media type with a leading digit thus goes out
as a String, as RFC 10008 Section 3 requires. A parameter name goes out in
lowercase. An empty List is the absence of the field (RFC 9651 Section 4.1),
so the caller omits the field instead of calling this function.
""".
-spec encode([media_range(), ...]) -> {ok, binary()} | {error, encode_error()}.
encode([_ | _] = Ranges) ->
    encode(Ranges, []).

-doc """
Parse every `accept-query` field line of `Headers`.

The field lines join with `", "` before the parse (RFC 9651 Section 4.2). The
lookup is exact on the lowercase name, the form that every codec of this
library gives. An absent field gives `{ok, []}`.
""".
-spec parse(nhttp_lib:headers()) -> {ok, [media_range()]} | {error, parse_error()}.
parse(Headers) ->
    parse_value(iolist_to_binary(lists:join(?SF_JOIN, [V || {<<"accept-query">>, V} <- Headers]))).

-doc "Parse one `Accept-Query` field value. An empty value gives `{ok, []}`.".
-spec parse_value(binary()) -> {ok, [media_range()]} | {error, parse_error()}.
parse_value(Bin) ->
    maybe
        ok ?= ascii(Bin),
        {ok, Members} ?= sf_list(skip_sp(Bin), byte_size(Bin)),
        media_ranges(Members, [])
    end.

-spec ascii(binary()) -> ok | {error, not_ascii}.
ascii(<<C, _/binary>>) when C > 16#7F -> {error, not_ascii};
ascii(<<_, Rest/binary>>) -> ascii(Rest);
ascii(<<>>) -> ok.

-spec sf_list(binary(), non_neg_integer()) -> {ok, [sf_member()]} | {error, parse_error()}.
sf_list(<<>>, _Size) ->
    {ok, []};
sf_list(Bin, Size) ->
    sf_members(Bin, Size, []).

-spec sf_members(binary(), non_neg_integer(), [sf_member()]) ->
    {ok, [sf_member()]} | {error, parse_error()}.
sf_members(Bin, Size, Acc) ->
    maybe
        {ok, Member, Rest} ?= sf_member(Bin, Size),
        sf_after_member(skip_ows(Rest), Size, [Member | Acc])
    end.

-spec sf_after_member(binary(), non_neg_integer(), [sf_member()]) ->
    {ok, [sf_member()]} | {error, parse_error()}.
sf_after_member(<<>>, _Size, Acc) ->
    {ok, lists:reverse(Acc)};
sf_after_member(<<$,, Rest/binary>>, Size, Acc) ->
    case skip_ows(Rest) of
        <<>> -> {error, {sf_syntax, Size}};
        Next -> sf_members(Next, Size, Acc)
    end;
sf_after_member(Bin, Size, _Acc) ->
    {error, {sf_syntax, offset(Bin, Size)}}.

-spec sf_member(binary(), non_neg_integer()) ->
    {ok, sf_member(), binary()} | {error, parse_error()}.
sf_member(<<$(, _/binary>> = Bin, Size) ->
    {error, {unsupported_item, offset(Bin, Size)}};
sf_member(Bin, Size) ->
    maybe
        {ok, Value, Rest0} ?= sf_bare_item(Bin, Size, unsupported_item),
        {ok, Params, Rest1} ?= sf_params(Rest0, Size, []),
        {ok, {Value, Params}, Rest1}
    end.

-spec sf_bare_item(binary(), non_neg_integer(), unsupported_item | unsupported_parameter) ->
    {ok, binary(), binary()} | {error, parse_error()}.
sf_bare_item(<<$", Rest/binary>>, Size, _Unsupported) ->
    sf_string(Rest, Size, <<>>);
sf_bare_item(<<C, _/binary>> = Bin, _Size, _Unsupported) when
    C >= $a, C =< $z; C >= $A, C =< $Z; C =:= $*
->
    split(Bin, token_length(Bin, 0));
sf_bare_item(<<C, _/binary>> = Bin, Size, Unsupported) when
    C >= $0, C =< $9; C =:= $-; C =:= $:; C =:= $?; C =:= $@; C =:= $%
->
    {error, {Unsupported, offset(Bin, Size)}};
sf_bare_item(Bin, Size, _Unsupported) ->
    {error, {sf_syntax, offset(Bin, Size)}}.

-spec sf_string(binary(), non_neg_integer(), binary()) ->
    {ok, binary(), binary()} | {error, parse_error()}.
sf_string(<<$", Rest/binary>>, _Size, Acc) ->
    {ok, Acc, Rest};
sf_string(<<$\\, C, Rest/binary>>, Size, Acc) when C =:= $"; C =:= $\\ ->
    sf_string(Rest, Size, <<Acc/binary, C>>);
sf_string(<<$\\, Rest/binary>>, Size, _Acc) ->
    {error, {sf_syntax, offset(Rest, Size)}};
sf_string(<<C, Rest/binary>>, Size, Acc) when C >= 16#20, C =< 16#7E ->
    sf_string(Rest, Size, <<Acc/binary, C>>);
sf_string(Bin, Size, _Acc) ->
    {error, {sf_syntax, offset(Bin, Size)}}.

-spec token_length(binary(), non_neg_integer()) -> non_neg_integer().
token_length(<<C, Rest/binary>>, Len) ->
    case is_sf_token_char(C) of
        true -> token_length(Rest, Len + 1);
        false -> Len
    end;
token_length(<<>>, Len) ->
    Len.

-spec sf_params(binary(), non_neg_integer(), [{binary(), binary()}]) ->
    {ok, [{binary(), binary()}], binary()} | {error, parse_error()}.
sf_params(<<$;, Rest0/binary>>, Size, Acc) ->
    Rest1 = skip_sp(Rest0),
    maybe
        {ok, Key, Rest2} ?= sf_key(Rest1, Size),
        {ok, Value, Rest3} ?= sf_param_value(Rest2, Size, offset(Rest1, Size)),
        sf_params(Rest3, Size, lists:keystore(Key, 1, Acc, {Key, Value}))
    end;
sf_params(Bin, _Size, Acc) ->
    {ok, Acc, Bin}.

-spec sf_param_value(binary(), non_neg_integer(), non_neg_integer()) ->
    {ok, binary(), binary()} | {error, parse_error()}.
sf_param_value(<<$=, Rest/binary>>, Size, KeyOffset) ->
    case sf_bare_item(Rest, Size, unsupported_parameter) of
        {error, {unsupported_parameter, _}} -> {error, {unsupported_parameter, KeyOffset}};
        Result -> Result
    end;
sf_param_value(_Bin, _Size, KeyOffset) ->
    {error, {unsupported_parameter, KeyOffset}}.

-spec sf_key(binary(), non_neg_integer()) -> {ok, binary(), binary()} | {error, parse_error()}.
sf_key(<<C, _/binary>> = Bin, _Size) when C >= $a, C =< $z; C =:= $* ->
    split(Bin, key_length(Bin, 0));
sf_key(Bin, Size) ->
    {error, {sf_syntax, offset(Bin, Size)}}.

-spec key_length(binary(), non_neg_integer()) -> non_neg_integer().
key_length(<<C, Rest/binary>>, Len) ->
    case is_sf_key_char(C) of
        true -> key_length(Rest, Len + 1);
        false -> Len
    end;
key_length(<<>>, Len) ->
    Len.

-spec media_ranges([sf_member()], [media_range()]) ->
    {ok, [media_range()]} | {error, parse_error()}.
media_ranges([], Acc) ->
    {ok, lists:reverse(Acc)};
media_ranges([{Value, Params} | Members], Acc) ->
    case binary:split(Value, <<"/">>) of
        [Type, Subtype] ->
            media_range(is_media_range(Type, Subtype), Type, Subtype, Params, Value, Members, Acc);
        [Value] ->
            {error, {not_media_range, binary:copy(Value)}}
    end.

-spec media_range(
    boolean(), binary(), binary(), [{binary(), binary()}], binary(), [sf_member()], [media_range()]
) -> {ok, [media_range()]} | {error, parse_error()}.
media_range(true, Type, Subtype, Params, _Value, Members, Acc) ->
    Range = #{
        type => binary:copy(nhttp_headers:lower_field_name(Type)),
        subtype => binary:copy(nhttp_headers:lower_field_name(Subtype)),
        params => [{binary:copy(K), binary:copy(V)} || {K, V} <- Params]
    },
    media_ranges(Members, [Range | Acc]);
media_range(false, _Type, _Subtype, _Params, Value, _Members, _Acc) ->
    {error, {not_media_range, binary:copy(Value)}}.

-spec is_media_range(binary(), binary()) -> boolean().
is_media_range(<<"*">>, Subtype) ->
    Subtype =:= <<"*">>;
is_media_range(Type, Subtype) ->
    nhttp_headers:is_token(Type) andalso nhttp_headers:is_token(Subtype).

-spec encode([media_range()], [iodata()]) -> {ok, binary()} | {error, encode_error()}.
encode([], Acc) ->
    {ok, iolist_to_binary(lists:join(?SF_JOIN, lists:reverse(Acc)))};
encode([#{type := Type, subtype := Subtype, params := Params} | Ranges], Acc) ->
    Value = <<Type/binary, "/", Subtype/binary>>,
    maybe
        true ?= is_media_range(Type, Subtype) orelse {error, {not_media_range, Value}},
        {ok, Encoded} ?= encode_params(Params, []),
        encode(Ranges, [[encode_bare(Value), Encoded] | Acc])
    end.

-spec encode_params([{binary(), binary()}], [iodata()]) ->
    {ok, iodata()} | {error, encode_error()}.
encode_params([], Acc) ->
    {ok, lists:reverse(Acc)};
encode_params([{Name, Value} | Params], Acc) ->
    Key = nhttp_headers:lower_field_name(Name),
    maybe
        true ?= is_sf_key(Key) orelse {error, {invalid_parameter_name, Name}},
        true ?= is_sf_string(Value) orelse {error, {invalid_parameter_value, Value}},
        encode_params(Params, [[$;, Key, $=, encode_bare(Value)] | Acc])
    end.

-spec encode_bare(binary()) -> iodata().
encode_bare(Value) ->
    case is_sf_token(Value) of
        true -> Value;
        false -> [$", [escape(C) || <<C>> <= Value], $"]
    end.

-spec escape(byte()) -> byte() | [byte(), ...].
escape($") -> [$\\, $"];
escape($\\) -> [$\\, $\\];
escape(C) -> C.

-spec matches(nhttp_media_type:media_type(), media_range()) -> boolean().
matches(#{type := Type, subtype := Subtype, params := Have}, #{
    type := RangeType, subtype := RangeSubtype, params := Want
}) ->
    type_matches(Type, Subtype, RangeType, RangeSubtype) andalso params_match(Want, Have).

-spec type_matches(binary(), binary(), binary(), binary()) -> boolean().
type_matches(_Type, _Subtype, <<"*">>, <<"*">>) ->
    true;
type_matches(Type, _Subtype, RangeType, <<"*">>) ->
    nhttp_headers:name_eq(Type, RangeType);
type_matches(Type, Subtype, RangeType, RangeSubtype) ->
    nhttp_headers:name_eq(Type, RangeType) andalso nhttp_headers:name_eq(Subtype, RangeSubtype).

-spec params_match([{binary(), binary()}], [{binary(), binary()}]) -> boolean().
params_match([], _Have) ->
    true;
params_match([Param | Want], Have) ->
    has_param(Param, Have) andalso params_match(Want, Have).

-spec has_param({binary(), binary()}, [{binary(), binary()}]) -> boolean().
has_param(_Param, []) ->
    false;
has_param({Name, Value} = Param, [{HaveName, HaveValue} | Have]) ->
    (nhttp_headers:name_eq(Name, HaveName) andalso value_eq(Name, Value, HaveValue)) orelse
        has_param(Param, Have).

-spec value_eq(binary(), binary(), binary()) -> boolean().
value_eq(Name, Value, HaveValue) ->
    case nhttp_headers:name_eq(Name, <<"charset">>) of
        true -> nhttp_headers:name_eq(Value, HaveValue);
        false -> Value =:= HaveValue
    end.

-spec is_sf_token(binary()) -> boolean().
is_sf_token(<<C, _/binary>> = Bin) when C >= $a, C =< $z; C >= $A, C =< $Z; C =:= $* ->
    token_length(Bin, 0) =:= byte_size(Bin);
is_sf_token(_Bin) ->
    false.

-spec is_sf_token_char(byte()) -> boolean().
is_sf_token_char($:) -> true;
is_sf_token_char($/) -> true;
is_sf_token_char(C) -> nhttp_headers:is_tchar(C).

-spec is_sf_key(binary()) -> boolean().
is_sf_key(<<C, _/binary>> = Bin) when C >= $a, C =< $z; C =:= $* ->
    key_length(Bin, 0) =:= byte_size(Bin);
is_sf_key(_Bin) ->
    false.

-spec is_sf_key_char(byte()) -> boolean().
is_sf_key_char(C) when C >= $a, C =< $z; C >= $0, C =< $9 -> true;
is_sf_key_char($_) -> true;
is_sf_key_char($-) -> true;
is_sf_key_char($.) -> true;
is_sf_key_char($*) -> true;
is_sf_key_char(_C) -> false.

-spec is_sf_string(binary()) -> boolean().
is_sf_string(<<C, Rest/binary>>) when C >= 16#20, C =< 16#7E ->
    is_sf_string(Rest);
is_sf_string(<<_, _/binary>>) ->
    false;
is_sf_string(<<>>) ->
    true.

-spec split(binary(), non_neg_integer()) -> {ok, binary(), binary()}.
split(Bin, Len) ->
    <<Head:Len/binary, Rest/binary>> = Bin,
    {ok, Head, Rest}.

-spec offset(binary(), non_neg_integer()) -> non_neg_integer().
offset(Rest, Size) ->
    Size - byte_size(Rest).

-spec skip_sp(binary()) -> binary().
skip_sp(<<$\s, Rest/binary>>) -> skip_sp(Rest);
skip_sp(Bin) -> Bin.

-spec skip_ows(binary()) -> binary().
skip_ows(<<$\s, Rest/binary>>) -> skip_ows(Rest);
skip_ows(<<$\t, Rest/binary>>) -> skip_ows(Rest);
skip_ows(Bin) -> Bin.
