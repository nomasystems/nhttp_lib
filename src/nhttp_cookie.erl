-module(nhttp_cookie).

-moduledoc """
Cookie parsing and encoding utilities (RFC 6265).

This module provides symmetrical encode/decode functions for both Cookie
and Set-Cookie headers.

## Cookie Header (client → server)

The Cookie header contains simple name=value pairs separated by semicolons.

```erlang
%% Decode incoming Cookie header
{ok, Cookies} = nhttp_cookie:decode_cookie(<<"session=abc123; user=john">>),
%% Cookies = [#{name => <<"session">>, value => <<"abc123">>},
%%            #{name => <<"user">>, value => <<"john">>}]

{ok, CookieHeader} = nhttp_cookie:encode_cookie([
    #{name => <<"session">>, value => <<"abc123">>},
    #{name => <<"user">>, value => <<"john">>}
]),
%% <<"session=abc123; user=john">>
```

## Set-Cookie Header (server → client)

The Set-Cookie header contains a single cookie with optional attributes.

```erlang
%% Decode incoming Set-Cookie header
{ok, SetCookie} = nhttp_cookie:decode_set_cookie(
    <<"session=abc123; Path=/; HttpOnly; Secure">>
),
%% SetCookie = #{name => <<"session">>, value => <<"abc123">>,
%%               path => <<"/">>, http_only => true, secure => true, ...}

%% Encode Set-Cookie header for responses
{ok, SetCookieHeader} = nhttp_cookie:encode_set_cookie(#{
    name => <<"session">>,
    value => <<"abc123">>,
    path => <<"/">>,
    max_age => 3600,
    http_only => true,
    secure => true,
    same_site => strict
}),
%% <<"session=abc123; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict">>
```

## Roundtrip Support

The decode output can be fed back to encode when it conforms to the
RFC 6265 Section 4.1.1 grammar:

```erlang
{ok, SetCookie} = nhttp_cookie:decode_set_cookie(Header),
%% Modify and re-encode
{ok, NewHeader} = nhttp_cookie:encode_set_cookie(SetCookie#{max_age => 7200}).
```

The roundtrip is not total, and it must not be. The Section 5.2 parsing
algorithm is more permissive than the Section 4.1.1 grammar on purpose,
so `decode_set_cookie/1` accepts a value that carries internal
whitespace, a comma, or a CR and LF pair. The encoders enforce the
grammar and refuse such a value with `{error, Reason}`. Re-emitting it
is the header injection that the validation exists to stop.

A forwarder must therefore pass the original field value through rather
than decode it and encode it again. The decoded map is lossy in the same
direction: `decode_set_cookie/1` drops every attribute it does not name,
so a re-encode also discards the rest.
""".

%%%-----------------------------------------------------------------------------
%% API - COOKIE HEADER (CLIENT → SERVER)
%%%-----------------------------------------------------------------------------
-export([
    decode_cookie/1,
    encode_cookie/1
]).

%%%-----------------------------------------------------------------------------
%% API - SET-COOKIE HEADER (SERVER → CLIENT)
%%%-----------------------------------------------------------------------------
-export([
    decode_set_cookie/1,
    encode_set_cookie/1
]).

%%%-----------------------------------------------------------------------------
%% TYPE EXPORTS
%%%-----------------------------------------------------------------------------
-export_type([
    t/0,
    cookie_error/0,
    domain_violation/0,
    name_violation/0,
    path_violation/0,
    set_cookie/0,
    set_cookie_error/0,
    value_violation/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type t() :: #{
    name := binary(),
    value := binary()
}.

-type set_cookie() :: #{
    name := binary(),
    value := binary(),
    path => binary(),
    domain => binary(),
    expires => calendar:datetime(),
    max_age => integer(),
    secure => boolean(),
    http_only => boolean(),
    same_site => strict | lax | none
}.

-type name_violation() :: empty | non_token_octet.
-type value_violation() :: control_char | separator | non_ascii | unbalanced_quote.
-type path_violation() :: empty | no_leading_slash | control_char | semicolon | non_ascii.
-type domain_violation() :: empty | empty_label | invalid_label.

-type cookie_error() ::
    empty_name
    | invalid_format
    | {invalid_cookie_name, name_violation()}
    | {invalid_cookie_value, value_violation()}.

-type set_cookie_error() ::
    empty_name
    | invalid_format
    | {invalid_cookie_name, name_violation()}
    | {invalid_cookie_value, value_violation()}
    | {invalid_path, path_violation()}
    | {invalid_domain, domain_violation()}.

%%%-----------------------------------------------------------------------------
%% MACROS
%%%-----------------------------------------------------------------------------
-define(RFC850_YEAR_2000_THRESHOLD, 70).
-define(RFC850_YEAR_CENTURY_THRESHOLD, 100).

%%%-----------------------------------------------------------------------------
%% COOKIE HEADER ENCODING/DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a Cookie header value into a list of cookies.

Parses a semicolon-separated Cookie header and returns a list of cookie maps.
Empty names are rejected with an error.

```erlang
{ok, Cookies} = nhttp_cookie:decode_cookie(<<"session=abc; user=john">>).
%% Cookies = [#{name => <<"session">>, value => <<"abc">>},
%%            #{name => <<"user">>, value => <<"john">>}]
```
""".
-spec decode_cookie(binary()) -> {ok, [t()]} | {error, cookie_error()}.
decode_cookie(<<>>) ->
    {ok, []};
decode_cookie(CookieHeader) ->
    Pairs = binary:split(CookieHeader, <<";">>, [global, trim_all]),
    decode_cookie_pairs(Pairs, []).

-doc """
Encode a list of cookies into a Cookie header value.

Takes a list of cookie maps and produces a semicolon-separated string
suitable for the Cookie header.

```erlang
{ok, Header} = nhttp_cookie:encode_cookie([
    #{name => <<"session">>, value => <<"abc">>},
    #{name => <<"user">>, value => <<"john">>}
]).
%% Header = <<"session=abc; user=john">>
```

Every pair is validated against RFC 6265 Section 4.1.1, the grammar that
Section 4.2.1 reuses for `cookie-string`. A name must be a `token`. A
value must be `*cookie-octet`, or `*cookie-octet` inside a matched pair
of double quotes, which admits `%x21`, `%x23-2B`, `%x2D-3A`, `%x3C-5B`,
and `%x5D-7E`. That excludes CTLs, space, double quote, comma,
semicolon, backslash, and every octet above `%x7E`.

A value that leaves the set is refused with
`{error, {invalid_cookie_value, t:value_violation/0}}`. No value is
stripped, quoted, escaped, or truncated, and the error carries a class
rather than the offending bytes, which are often a session token.
Encode arbitrary data with Base64 before you put it in a cookie.
""".
-spec encode_cookie([t()]) -> {ok, binary()} | {error, cookie_error()}.
encode_cookie([]) ->
    {ok, <<>>};
encode_cookie([#{name := Name, value := Value} | Rest] = Cookies) ->
    maybe
        ok ?= validate_cookies(Cookies),
        Pairs = [encode_cookie_pair(C) || C <- Rest],
        {ok, iolist_to_binary([Name, $=, Value | Pairs])}
    end.

%%%-----------------------------------------------------------------------------
%% SET-COOKIE HEADER ENCODING/DECODING
%%%-----------------------------------------------------------------------------
-doc """
Decode a Set-Cookie header value into a set-cookie map.
Parses a Set-Cookie header with attributes and returns a map containing
the cookie name, value, and any parsed attributes.
```erlang
{ok, SetCookie} = nhttp_cookie:decode_set_cookie(
    <<"session=abc; Path=/; Secure; HttpOnly">>
).
%% SetCookie = #{name => <<"session">>, value => <<"abc">>,
%%               path => <<"/">>, secure => true, http_only => true, ...}
```
Invalid attributes are silently ignored (per RFC 6265 recommendations).
""".
-spec decode_set_cookie(binary()) -> {ok, set_cookie()} | {error, set_cookie_error()}.
decode_set_cookie(SetCookieHeader) when is_binary(SetCookieHeader) ->
    case binary:split(SetCookieHeader, <<";">>, [global]) of
        [NameValue | AttributeParts] ->
            case decode_name_value(NameValue) of
                {ok, Name, Value} ->
                    Attributes = decode_attributes(AttributeParts),
                    SetCookie = build_set_cookie(Name, Value, Attributes),
                    {ok, SetCookie};
                {error, _} = Error ->
                    Error
            end;
        _ ->
            {error, invalid_format}
    end.

-doc """
Encode a set-cookie map into a Set-Cookie header value.
Takes a map with `name` and `value` (required) plus optional attributes,
and produces a Set-Cookie header string.
```erlang
{ok, Header} = nhttp_cookie:encode_set_cookie(#{
    name => <<"session">>,
    value => <<"abc123">>,
    path => <<"/">>,
    max_age => 3600,
    secure => true
}).
%% Header = <<"session=abc123; Path=/; Max-Age=3600; Secure">>
```
Supported attributes: `path`, `domain`, `expires`, `max_age`, `secure`,
`http_only`, `same_site`.

The cookie pair is validated against the RFC 6265 Section 4.1.1 grammar.
A name must be a `token`. A value must be `*cookie-octet`, or
`*cookie-octet` inside a matched pair of double quotes, which admits
`%x21`, `%x23-2B`, `%x2D-3A`, `%x3C-5B`, and `%x5D-7E`. That excludes
CTLs, space, double quote, comma, semicolon, backslash, and every octet
above `%x7E`. Encode arbitrary data with Base64 before you put it in a
cookie.

The two attributes that carry caller data are validated too. `path` must
be `<any CHAR except CTLs or ";">` and must start with `/`, because
Section 5.2.4 makes a user agent discard any other value. `domain` must
be a `<subdomain>` per RFC 1034 Section 3.5 and RFC 1123 Section 2.1:
dot-separated labels of letters, digits, and hyphens, with an optional
leading dot that Section 5.2.3 strips.

A field that leaves its grammar is refused with
`{error, t:set_cookie_error/0}`. Nothing is stripped, quoted, escaped,
or truncated, and an error carries a class rather than the offending
bytes, which are often a session token.
""".
-spec encode_set_cookie(set_cookie()) -> {ok, binary()} | {error, set_cookie_error()}.
encode_set_cookie(#{name := Name, value := Value} = SetCookie) ->
    maybe
        ok ?= validate_cookie_name(Name),
        ok ?= validate_cookie_value(Value),
        ok ?= validate_set_cookie_attrs(SetCookie),
        Base = <<Name/binary, "=", Value/binary>>,
        {ok, encode_set_cookie_attrs(Base, SetCookie)}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL - COOKIE ENCODING
%%%-----------------------------------------------------------------------------
-spec encode_cookie_pair(t()) -> iolist().
encode_cookie_pair(#{name := Name, value := Value}) ->
    [<<"; ">>, Name, $=, Value].

%%%-----------------------------------------------------------------------------
%% INTERNAL - ENCODE VALIDATION (RFC 6265 SECTION 4.1.1)
%%%-----------------------------------------------------------------------------
-spec validate_cookies([t()]) -> ok | {error, cookie_error()}.
validate_cookies([]) ->
    ok;
validate_cookies([#{name := Name, value := Value} | Rest]) ->
    maybe
        ok ?= validate_cookie_name(Name),
        ok ?= validate_cookie_value(Value),
        validate_cookies(Rest)
    end.

-spec validate_cookie_name(binary()) -> ok | {error, {invalid_cookie_name, name_violation()}}.
validate_cookie_name(<<>>) ->
    {error, {invalid_cookie_name, empty}};
validate_cookie_name(Name) ->
    case nhttp_headers:is_token(Name) of
        true -> ok;
        false -> {error, {invalid_cookie_name, non_token_octet}}
    end.

-spec validate_cookie_value(binary()) -> ok | {error, {invalid_cookie_value, value_violation()}}.
validate_cookie_value(<<$", Rest/binary>>) ->
    validate_quoted_cookie_value(Rest);
validate_cookie_value(Value) ->
    check_cookie_octets(Value).

-spec validate_quoted_cookie_value(binary()) ->
    ok | {error, {invalid_cookie_value, value_violation()}}.
validate_quoted_cookie_value(<<>>) ->
    {error, {invalid_cookie_value, unbalanced_quote}};
validate_quoted_cookie_value(Rest) ->
    Last = byte_size(Rest) - 1,
    case binary:at(Rest, Last) of
        $" -> check_cookie_octets(binary:part(Rest, 0, Last));
        _ -> {error, {invalid_cookie_value, unbalanced_quote}}
    end.

-spec check_cookie_octets(binary()) -> ok | {error, {invalid_cookie_value, value_violation()}}.
check_cookie_octets(<<>>) ->
    ok;
check_cookie_octets(<<C, _/binary>>) when C =< 16#1F; C =:= 16#7F ->
    {error, {invalid_cookie_value, control_char}};
check_cookie_octets(<<C, _/binary>>) when
    C =:= $\s; C =:= $"; C =:= $,; C =:= $;; C =:= $\\
->
    {error, {invalid_cookie_value, separator}};
check_cookie_octets(<<C, _/binary>>) when C >= 16#80 ->
    {error, {invalid_cookie_value, non_ascii}};
check_cookie_octets(<<_, Rest/binary>>) ->
    %% What survives the clauses above is exactly cookie-octet:
    %% %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E.
    check_cookie_octets(Rest).

-spec validate_set_cookie_attrs(set_cookie()) -> ok | {error, set_cookie_error()}.
validate_set_cookie_attrs(SetCookie) ->
    maybe
        ok ?= validate_optional_path(SetCookie),
        validate_optional_domain(SetCookie)
    end.

-spec validate_optional_path(set_cookie()) -> ok | {error, {invalid_path, path_violation()}}.
validate_optional_path(#{path := Path}) when is_binary(Path) ->
    validate_path(Path);
validate_optional_path(_) ->
    ok.

-spec validate_optional_domain(set_cookie()) -> ok | {error, {invalid_domain, domain_violation()}}.
validate_optional_domain(#{domain := Domain}) when is_binary(Domain) ->
    validate_domain(Domain);
validate_optional_domain(_) ->
    ok.

-spec validate_path(binary()) -> ok | {error, {invalid_path, path_violation()}}.
validate_path(<<>>) ->
    {error, {invalid_path, empty}};
validate_path(<<$/, Rest/binary>>) ->
    check_path_octets(Rest);
validate_path(_) ->
    %% RFC 6265 Section 5.2.4: a user agent replaces any other value with
    %% the default-path, so emitting one is a silent no-op.
    {error, {invalid_path, no_leading_slash}}.

-spec check_path_octets(binary()) -> ok | {error, {invalid_path, path_violation()}}.
check_path_octets(<<>>) ->
    ok;
check_path_octets(<<C, _/binary>>) when C =< 16#1F; C =:= 16#7F ->
    {error, {invalid_path, control_char}};
check_path_octets(<<$;, _/binary>>) ->
    {error, {invalid_path, semicolon}};
check_path_octets(<<C, _/binary>>) when C >= 16#80 ->
    {error, {invalid_path, non_ascii}};
check_path_octets(<<_, Rest/binary>>) ->
    check_path_octets(Rest).

-spec validate_domain(binary()) -> ok | {error, {invalid_domain, domain_violation()}}.
validate_domain(<<>>) ->
    {error, {invalid_domain, empty}};
validate_domain(<<$., Rest/binary>>) ->
    %% RFC 6265 Section 5.2.3: a user agent strips one leading dot.
    validate_domain_labels(Rest);
validate_domain(Domain) ->
    validate_domain_labels(Domain).

-spec validate_domain_labels(binary()) -> ok | {error, {invalid_domain, domain_violation()}}.
validate_domain_labels(<<>>) ->
    {error, {invalid_domain, empty}};
validate_domain_labels(Domain) ->
    check_domain_labels(binary:split(Domain, <<".">>, [global])).

-spec check_domain_labels([binary()]) -> ok | {error, {invalid_domain, domain_violation()}}.
check_domain_labels([]) ->
    ok;
check_domain_labels([<<>> | _]) ->
    {error, {invalid_domain, empty_label}};
check_domain_labels([Label | Rest]) ->
    case is_domain_label(Label) of
        true -> check_domain_labels(Rest);
        false -> {error, {invalid_domain, invalid_label}}
    end.

-spec is_domain_label(binary()) -> boolean().
is_domain_label(Label) ->
    Last = byte_size(Label) - 1,
    is_let_dig(binary:first(Label)) andalso
        is_let_dig(binary:at(Label, Last)) andalso
        is_ldh(Label).

-spec is_ldh(binary()) -> boolean().
is_ldh(<<>>) ->
    true;
is_ldh(<<C, Rest/binary>>) ->
    case is_ldh_char(C) of
        true -> is_ldh(Rest);
        false -> false
    end.

-spec is_ldh_char(byte()) -> boolean().
is_ldh_char($-) -> true;
is_ldh_char(C) -> is_let_dig(C).

-spec is_let_dig(byte()) -> boolean().
is_let_dig(C) when C >= $a, C =< $z -> true;
is_let_dig(C) when C >= $A, C =< $Z -> true;
is_let_dig(C) when C >= $0, C =< $9 -> true;
is_let_dig(_) -> false.

%%%-----------------------------------------------------------------------------
%% INTERNAL - COOKIE DECODING
%%%-----------------------------------------------------------------------------
-spec decode_cookie_pairs([binary()], [t()]) ->
    {ok, [t()]} | {error, cookie_error()}.
decode_cookie_pairs([], Acc) ->
    {ok, lists:reverse(Acc)};
decode_cookie_pairs([Pair | Rest], Acc) ->
    Trimmed = trim_ws(Pair),
    case binary:split(Trimmed, <<"=">>) of
        [<<>>, _] ->
            {error, empty_name};
        [Name, Value] ->
            Cookie = #{name => trim_ws(Name), value => trim_ws(Value)},
            decode_cookie_pairs(Rest, [Cookie | Acc]);
        [Name] ->
            Cookie = #{name => trim_ws(Name), value => <<>>},
            decode_cookie_pairs(Rest, [Cookie | Acc]);
        _ ->
            {error, invalid_format}
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL - SET-COOKIE ENCODING
%%%-----------------------------------------------------------------------------
-spec day_name(1..7) -> string().
day_name(1) -> "Mon";
day_name(2) -> "Tue";
day_name(3) -> "Wed";
day_name(4) -> "Thu";
day_name(5) -> "Fri";
day_name(6) -> "Sat";
day_name(7) -> "Sun".

-spec encode_set_cookie_attrs(binary(), set_cookie()) -> binary().
encode_set_cookie_attrs(Acc, SetCookie) ->
    Acc1 = maybe_encode_attr(Acc, path, SetCookie),
    Acc2 = maybe_encode_attr(Acc1, domain, SetCookie),
    Acc3 = maybe_encode_attr(Acc2, expires, SetCookie),
    Acc4 = maybe_encode_attr(Acc3, max_age, SetCookie),
    Acc5 = maybe_encode_attr(Acc4, secure, SetCookie),
    Acc6 = maybe_encode_attr(Acc5, http_only, SetCookie),
    maybe_encode_attr(Acc6, same_site, SetCookie).

-spec format_expires(calendar:datetime()) -> binary().
format_expires({{Year, Month, Day}, {Hour, Min, Sec}}) ->
    DayOfWeek = calendar:day_of_the_week({Year, Month, Day}),
    DayName = day_name(DayOfWeek),
    MonthName = month_name(Month),
    list_to_binary(
        io_lib:format(
            "~s, ~2..0B ~s ~4..0B ~2..0B:~2..0B:~2..0B GMT",
            [DayName, Day, MonthName, Year, Hour, Min, Sec]
        )
    ).

-spec maybe_encode_attr(binary(), atom(), set_cookie()) -> binary().
maybe_encode_attr(Acc, path, #{path := Path}) when is_binary(Path) ->
    <<Acc/binary, "; Path=", Path/binary>>;
maybe_encode_attr(Acc, domain, #{domain := Domain}) when is_binary(Domain) ->
    <<Acc/binary, "; Domain=", Domain/binary>>;
maybe_encode_attr(Acc, expires, #{expires := DateTime}) ->
    ExpiresBin = format_expires(DateTime),
    <<Acc/binary, "; Expires=", ExpiresBin/binary>>;
maybe_encode_attr(Acc, max_age, #{max_age := MaxAge}) when is_integer(MaxAge) ->
    MaxAgeBin = integer_to_binary(MaxAge),
    <<Acc/binary, "; Max-Age=", MaxAgeBin/binary>>;
maybe_encode_attr(Acc, secure, #{secure := true}) ->
    <<Acc/binary, "; Secure">>;
maybe_encode_attr(Acc, http_only, #{http_only := true}) ->
    <<Acc/binary, "; HttpOnly">>;
maybe_encode_attr(Acc, same_site, #{same_site := strict}) ->
    <<Acc/binary, "; SameSite=Strict">>;
maybe_encode_attr(Acc, same_site, #{same_site := lax}) ->
    <<Acc/binary, "; SameSite=Lax">>;
maybe_encode_attr(Acc, same_site, #{same_site := none}) ->
    <<Acc/binary, "; SameSite=None">>;
maybe_encode_attr(Acc, _, _) ->
    Acc.

-spec month_name(1..12) -> string().
month_name(1) -> "Jan";
month_name(2) -> "Feb";
month_name(3) -> "Mar";
month_name(4) -> "Apr";
month_name(5) -> "May";
month_name(6) -> "Jun";
month_name(7) -> "Jul";
month_name(8) -> "Aug";
month_name(9) -> "Sep";
month_name(10) -> "Oct";
month_name(11) -> "Nov";
month_name(12) -> "Dec".

%%%-----------------------------------------------------------------------------
%% INTERNAL - SET-COOKIE DECODING
%%%-----------------------------------------------------------------------------
-spec decode_attribute(binary(), map()) -> map().
decode_attribute(Part, Acc) ->
    Trimmed = trim_ws(Part),
    case binary:split(Trimmed, <<"=">>) of
        [AttrName, AttrValue] ->
            decode_named_attribute(nhttp_headers:to_lower(AttrName), trim_ws(AttrValue), Acc);
        [AttrName] ->
            decode_flag_attribute(nhttp_headers:to_lower(AttrName), Acc)
    end.

-spec decode_attributes([binary()]) -> map().
decode_attributes(Parts) ->
    lists:foldl(fun decode_attribute/2, #{}, Parts).

-spec decode_expires(binary()) -> {ok, calendar:datetime()} | {error, invalid_date}.
decode_expires(Value) ->
    case decode_rfc1123_date(Value) of
        {ok, _} = Ok ->
            Ok;
        error ->
            case decode_rfc850_date(Value) of
                {ok, _} = Ok -> Ok;
                error -> {error, invalid_date}
            end
    end.

-spec decode_flag_attribute(binary(), map()) -> map().
decode_flag_attribute(<<"secure">>, Acc) ->
    Acc#{secure => true};
decode_flag_attribute(<<"httponly">>, Acc) ->
    Acc#{http_only => true};
decode_flag_attribute(_, Acc) ->
    Acc.

-spec decode_max_age(binary()) -> {ok, integer()} | {error, invalid_max_age}.
decode_max_age(Value) ->
    case safe_binary_to_integer(Value) of
        {ok, Seconds} -> {ok, Seconds};
        error -> {error, invalid_max_age}
    end.

-spec decode_month(binary()) -> {ok, 1..12} | error.
decode_month(<<"Jan">>) -> {ok, 1};
decode_month(<<"Feb">>) -> {ok, 2};
decode_month(<<"Mar">>) -> {ok, 3};
decode_month(<<"Apr">>) -> {ok, 4};
decode_month(<<"May">>) -> {ok, 5};
decode_month(<<"Jun">>) -> {ok, 6};
decode_month(<<"Jul">>) -> {ok, 7};
decode_month(<<"Aug">>) -> {ok, 8};
decode_month(<<"Sep">>) -> {ok, 9};
decode_month(<<"Oct">>) -> {ok, 10};
decode_month(<<"Nov">>) -> {ok, 11};
decode_month(<<"Dec">>) -> {ok, 12};
decode_month(_) -> error.

-spec decode_name_value(binary()) -> {ok, binary(), binary()} | {error, set_cookie_error()}.
decode_name_value(NameValue) ->
    Trimmed = trim_ws(NameValue),
    case binary:split(Trimmed, <<"=">>) of
        [<<>>, _] ->
            {error, empty_name};
        [Name, Value] ->
            {ok, trim_ws(Name), trim_ws(Value)};
        [Name] ->
            {ok, trim_ws(Name), <<>>};
        _ ->
            {error, invalid_format}
    end.

-spec decode_named_attribute(binary(), binary(), map()) -> map().
decode_named_attribute(<<"domain">>, Value, Acc) ->
    Acc#{domain => Value};
decode_named_attribute(<<"path">>, Value, Acc) ->
    Acc#{path => Value};
decode_named_attribute(<<"expires">>, Value, Acc) ->
    case decode_expires(Value) of
        {ok, DateTime} -> Acc#{expires => DateTime};
        {error, _} -> Acc
    end;
decode_named_attribute(<<"max-age">>, Value, Acc) ->
    case decode_max_age(Value) of
        {ok, Seconds} -> Acc#{max_age => Seconds};
        {error, _} -> Acc
    end;
decode_named_attribute(<<"samesite">>, Value, Acc) ->
    case nhttp_headers:to_lower(Value) of
        <<"strict">> -> Acc#{same_site => strict};
        <<"lax">> -> Acc#{same_site => lax};
        <<"none">> -> Acc#{same_site => none};
        _ -> Acc
    end;
decode_named_attribute(_, _, Acc) ->
    Acc.

-spec decode_rfc1123_date(binary()) -> {ok, calendar:datetime()} | error.
decode_rfc1123_date(Value) ->
    maybe
        [_, Rest] ?= split_once(Value, <<", ">>),
        [DayBin, MonthBin, YearBin, TimeBin | _] ?= split_at_least(Rest, <<" ">>, 4),
        {ok, Day} ?= safe_binary_to_integer(DayBin),
        {ok, Month} ?= decode_month(MonthBin),
        {ok, Year} ?= safe_binary_to_integer(YearBin),
        {ok, Time} ?= decode_time(TimeBin),
        {ok, {{Year, Month, Day}, Time}}
    else
        _ -> error
    end.

-spec decode_rfc850_date(binary()) -> {ok, calendar:datetime()} | error.
decode_rfc850_date(Value) ->
    maybe
        [_, Rest] ?= split_once(Value, <<", ">>),
        [DatePart, TimeBin | _] ?= split_at_least(Rest, <<" ">>, 2),
        [DayBin, MonthBin, YearBin] ?= split_exactly(DatePart, <<"-">>, 3),
        {ok, Day} ?= safe_binary_to_integer(DayBin),
        {ok, Month} ?= decode_month(MonthBin),
        {ok, Year0} ?= safe_binary_to_integer(YearBin),
        Year = normalize_year(Year0),
        {ok, Time} ?= decode_time(TimeBin),
        {ok, {{Year, Month, Day}, Time}}
    else
        _ -> error
    end.

-spec decode_time(binary()) -> {ok, {0..23, 0..59, 0..59}} | error.
decode_time(TimeBin) ->
    maybe
        [HourBin, MinBin, SecBin] ?= split_exactly(TimeBin, <<":">>, 3),
        {ok, Hour} ?= safe_binary_to_integer(HourBin),
        {ok, Min} ?= safe_binary_to_integer(MinBin),
        {ok, Sec} ?= safe_binary_to_integer(SecBin),
        {ok, {Hour, Min, Sec}}
    else
        _ -> error
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL - SAFE PARSING HELPERS
%%%-----------------------------------------------------------------------------
-spec build_set_cookie(binary(), binary(), map()) -> set_cookie().
build_set_cookie(Name, Value, Attributes) ->
    Base = #{name => Name, value => Value},
    maps:merge(Base, Attributes).

-spec normalize_year(integer()) -> integer().
normalize_year(Year) when Year < ?RFC850_YEAR_2000_THRESHOLD ->
    2000 + Year;
normalize_year(Year) when Year < ?RFC850_YEAR_CENTURY_THRESHOLD ->
    1900 + Year;
normalize_year(Year) ->
    Year.

-spec safe_binary_to_integer(binary()) -> {ok, integer()} | error.
safe_binary_to_integer(Bin) ->
    case string:to_integer(Bin) of
        {Int, <<>>} -> {ok, Int};
        _ -> error
    end.

-spec split_at_least(binary(), binary(), pos_integer()) -> [binary()] | error.
split_at_least(Bin, Sep, MinCount) ->
    Parts = binary:split(Bin, Sep, [global, trim_all]),
    case length(Parts) >= MinCount of
        true -> Parts;
        false -> error
    end.

-spec split_exactly(binary(), binary(), pos_integer()) -> [binary()] | error.
split_exactly(Bin, Sep, Count) ->
    Parts = binary:split(Bin, Sep, [global]),
    case length(Parts) of
        Count -> Parts;
        _ -> error
    end.

-spec split_once(binary(), binary()) -> [binary()] | error.
split_once(Bin, Sep) ->
    case binary:split(Bin, Sep) of
        [_, _] = Parts -> Parts;
        _ -> error
    end.

-spec trim_ws(binary()) -> binary().
trim_ws(Bin) ->
    trim_ws_trailing(trim_ws_leading(Bin)).

-spec trim_ws_leading(binary()) -> binary().
trim_ws_leading(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t ->
    trim_ws_leading(Rest);
trim_ws_leading(Bin) ->
    Bin.

-spec trim_ws_trailing(binary()) -> binary().
trim_ws_trailing(<<>>) ->
    <<>>;
trim_ws_trailing(Bin) ->
    Last = byte_size(Bin) - 1,
    case binary:at(Bin, Last) of
        C when C =:= $\s; C =:= $\t ->
            trim_ws_trailing(binary:part(Bin, 0, Last));
        _ ->
            Bin
    end.
