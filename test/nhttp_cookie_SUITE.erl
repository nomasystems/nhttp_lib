%%%-----------------------------------------------------------------------------
-module(nhttp_cookie_SUITE).

-moduledoc """
Cookie utilities test suite.

Tests cookie encoding and decoding according to RFC 6265.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------
-export([
    all/0,
    groups/0
]).

%%%-----------------------------------------------------------------------------
%%% TEST CASES
%%%-----------------------------------------------------------------------------
-export([
    decode_cookie_empty/1,
    decode_cookie_simple/1,
    decode_cookie_multiple/1,
    decode_cookie_no_value/1,
    decode_cookie_with_spaces/1,
    decode_cookie_special_chars/1,
    decode_cookie_empty_name/1,
    decode_cookie_multi_equals/1,
    encode_cookie_empty/1,
    encode_cookie_single/1,
    encode_cookie_multiple/1,
    cookie_roundtrip/1,
    decode_set_cookie_simple/1,
    decode_set_cookie_with_path/1,
    decode_set_cookie_with_domain/1,
    decode_set_cookie_with_expires_rfc1123/1,
    decode_set_cookie_with_expires_rfc850/1,
    decode_set_cookie_with_expires_2digit_year/1,
    decode_set_cookie_with_max_age/1,
    decode_set_cookie_with_secure/1,
    decode_set_cookie_with_http_only/1,
    decode_set_cookie_with_same_site/1,
    decode_set_cookie_all_attributes/1,
    decode_set_cookie_empty_name/1,
    decode_set_cookie_no_value/1,
    decode_set_cookie_invalid_max_age/1,
    decode_set_cookie_invalid_expires/1,
    decode_set_cookie_all_months_rfc1123/1,
    decode_set_cookie_invalid_samesite/1,
    decode_set_cookie_unknown_attribute/1,
    decode_set_cookie_invalid_time/1,
    decode_set_cookie_invalid_month/1,
    decode_set_cookie_4digit_year/1,
    decode_set_cookie_flag_unknown/1,
    encode_set_cookie_simple/1,
    encode_set_cookie_with_path/1,
    encode_set_cookie_with_domain/1,
    encode_set_cookie_with_max_age/1,
    encode_set_cookie_with_expires/1,
    encode_set_cookie_with_expires_all_days/1,
    encode_set_cookie_with_expires_all_months/1,
    encode_set_cookie_with_secure/1,
    encode_set_cookie_with_http_only/1,
    encode_set_cookie_with_same_site/1,
    encode_set_cookie_all_attributes/1,
    encode_set_cookie_false_flags/1,
    set_cookie_roundtrip/1,
    set_cookie_roundtrip_all_attrs/1
]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, decode_cookie},
        {group, encode_cookie},
        {group, decode_set_cookie},
        {group, encode_set_cookie},
        {group, roundtrip}
    ].

groups() ->
    [
        {decode_cookie, [parallel], [
            decode_cookie_empty,
            decode_cookie_simple,
            decode_cookie_multiple,
            decode_cookie_no_value,
            decode_cookie_with_spaces,
            decode_cookie_special_chars,
            decode_cookie_empty_name,
            decode_cookie_multi_equals
        ]},
        {encode_cookie, [parallel], [
            encode_cookie_empty,
            encode_cookie_single,
            encode_cookie_multiple
        ]},
        {decode_set_cookie, [parallel], [
            decode_set_cookie_simple,
            decode_set_cookie_with_path,
            decode_set_cookie_with_domain,
            decode_set_cookie_with_expires_rfc1123,
            decode_set_cookie_with_expires_rfc850,
            decode_set_cookie_with_expires_2digit_year,
            decode_set_cookie_with_max_age,
            decode_set_cookie_with_secure,
            decode_set_cookie_with_http_only,
            decode_set_cookie_with_same_site,
            decode_set_cookie_all_attributes,
            decode_set_cookie_empty_name,
            decode_set_cookie_no_value,
            decode_set_cookie_invalid_max_age,
            decode_set_cookie_invalid_expires,
            decode_set_cookie_all_months_rfc1123,
            decode_set_cookie_invalid_samesite,
            decode_set_cookie_unknown_attribute,
            decode_set_cookie_invalid_time,
            decode_set_cookie_invalid_month,
            decode_set_cookie_4digit_year,
            decode_set_cookie_flag_unknown
        ]},
        {encode_set_cookie, [parallel], [
            encode_set_cookie_simple,
            encode_set_cookie_with_path,
            encode_set_cookie_with_domain,
            encode_set_cookie_with_max_age,
            encode_set_cookie_with_expires,
            encode_set_cookie_with_expires_all_days,
            encode_set_cookie_with_expires_all_months,
            encode_set_cookie_with_secure,
            encode_set_cookie_with_http_only,
            encode_set_cookie_with_same_site,
            encode_set_cookie_all_attributes,
            encode_set_cookie_false_flags
        ]},
        {roundtrip, [parallel], [
            cookie_roundtrip,
            set_cookie_roundtrip,
            set_cookie_roundtrip_all_attrs
        ]}
    ].

%%%-----------------------------------------------------------------------------
%%% COOKIE HEADER DECODING TESTS
%%%-----------------------------------------------------------------------------

decode_cookie_empty(_Config) ->
    ?assertEqual({ok, []}, nhttp_cookie:decode_cookie(<<>>)).

decode_cookie_simple(_Config) ->
    {ok, Cookies} = nhttp_cookie:decode_cookie(<<"session=abc123">>),
    ?assertEqual([#{name => <<"session">>, value => <<"abc123">>}], Cookies).

decode_cookie_multiple(_Config) ->
    {ok, Cookies} = nhttp_cookie:decode_cookie(<<"session=abc123; user=john; theme=dark">>),
    ?assertEqual(
        [
            #{name => <<"session">>, value => <<"abc123">>},
            #{name => <<"user">>, value => <<"john">>},
            #{name => <<"theme">>, value => <<"dark">>}
        ],
        Cookies
    ).

decode_cookie_no_value(_Config) ->
    {ok, Cookies} = nhttp_cookie:decode_cookie(<<"flag">>),
    ?assertEqual([#{name => <<"flag">>, value => <<>>}], Cookies).

decode_cookie_with_spaces(_Config) ->
    {ok, Cookies} = nhttp_cookie:decode_cookie(<<"  session = abc123  ;  user=john  ">>),
    ?assertEqual(
        [
            #{name => <<"session">>, value => <<"abc123">>},
            #{name => <<"user">>, value => <<"john">>}
        ],
        Cookies
    ).

decode_cookie_special_chars(_Config) ->
    {ok, Cookies} = nhttp_cookie:decode_cookie(<<"token=abc%20def; data=hello+world">>),
    ?assertEqual(
        [
            #{name => <<"token">>, value => <<"abc%20def">>},
            #{name => <<"data">>, value => <<"hello+world">>}
        ],
        Cookies
    ).

decode_cookie_empty_name(_Config) ->
    ?assertEqual({error, empty_name}, nhttp_cookie:decode_cookie(<<"=value; valid=ok">>)).

decode_cookie_multi_equals(_Config) ->
    {ok, Cookies} = nhttp_cookie:decode_cookie(<<"token=abc=def=ghi">>),
    ?assertEqual([#{name => <<"token">>, value => <<"abc=def=ghi">>}], Cookies).

%%%-----------------------------------------------------------------------------
%%% COOKIE HEADER ENCODING TESTS
%%%-----------------------------------------------------------------------------

encode_cookie_empty(_Config) ->
    ?assertEqual({ok, <<>>}, nhttp_cookie:encode_cookie([])).

encode_cookie_single(_Config) ->
    {ok, Result} = nhttp_cookie:encode_cookie([#{name => <<"session">>, value => <<"abc123">>}]),
    ?assertEqual(<<"session=abc123">>, Result).

encode_cookie_multiple(_Config) ->
    {ok, Result} = nhttp_cookie:encode_cookie([
        #{name => <<"session">>, value => <<"abc">>},
        #{name => <<"user">>, value => <<"john">>},
        #{name => <<"theme">>, value => <<"dark">>}
    ]),
    ?assertEqual(<<"session=abc; user=john; theme=dark">>, Result).

%%%-----------------------------------------------------------------------------
%%% SET-COOKIE DECODING TESTS
%%%-----------------------------------------------------------------------------

decode_set_cookie_simple(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc123">>),
    ?assertEqual(<<"session">>, maps:get(name, Cookie)),
    ?assertEqual(<<"abc123">>, maps:get(value, Cookie)).

decode_set_cookie_with_path(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc; Path=/api">>),
    ?assertEqual(<<"session">>, maps:get(name, Cookie)),
    ?assertEqual(<<"/api">>, maps:get(path, Cookie)).

decode_set_cookie_with_domain(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc; Domain=.example.com">>),
    ?assertEqual(<<".example.com">>, maps:get(domain, Cookie)).

decode_set_cookie_with_expires_rfc1123(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sun, 06 Nov 1994 08:49:37 GMT">>
    ),
    ?assertEqual({{1994, 11, 6}, {8, 49, 37}}, maps:get(expires, Cookie)).

decode_set_cookie_with_expires_rfc850(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sunday, 06-Nov-94 08:49:37 GMT">>
    ),
    ?assertEqual({{1994, 11, 6}, {8, 49, 37}}, maps:get(expires, Cookie)).

decode_set_cookie_with_expires_2digit_year(_Config) ->
    {ok, Cookie1} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Mon, 01-Jan-25 00:00:00 GMT">>
    ),
    ?assertEqual({{2025, 1, 1}, {0, 0, 0}}, maps:get(expires, Cookie1)),
    {ok, Cookie2} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Mon, 01-Jan-99 00:00:00 GMT">>
    ),
    ?assertEqual({{1999, 1, 1}, {0, 0, 0}}, maps:get(expires, Cookie2)).

decode_set_cookie_with_max_age(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc; Max-Age=3600">>),
    ?assertEqual(3600, maps:get(max_age, Cookie)).

decode_set_cookie_with_secure(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc; Secure">>),
    ?assertEqual(true, maps:get(secure, Cookie)).

decode_set_cookie_with_http_only(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc; HttpOnly">>),
    ?assertEqual(true, maps:get(http_only, Cookie)).

decode_set_cookie_with_same_site(_Config) ->
    {ok, Cookie1} = nhttp_cookie:decode_set_cookie(<<"session=abc; SameSite=Strict">>),
    ?assertEqual(strict, maps:get(same_site, Cookie1)),
    {ok, Cookie2} = nhttp_cookie:decode_set_cookie(<<"session=abc; SameSite=Lax">>),
    ?assertEqual(lax, maps:get(same_site, Cookie2)),
    {ok, Cookie3} = nhttp_cookie:decode_set_cookie(<<"session=abc; SameSite=None">>),
    ?assertEqual(none, maps:get(same_site, Cookie3)).

decode_set_cookie_all_attributes(_Config) ->
    Header =
        <<"session=abc; Path=/; Domain=.example.com; Max-Age=3600; Secure; HttpOnly; SameSite=Strict">>,
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(Header),
    ?assertEqual(<<"session">>, maps:get(name, Cookie)),
    ?assertEqual(<<"abc">>, maps:get(value, Cookie)),
    ?assertEqual(<<"/">>, maps:get(path, Cookie)),
    ?assertEqual(<<".example.com">>, maps:get(domain, Cookie)),
    ?assertEqual(3600, maps:get(max_age, Cookie)),
    ?assertEqual(true, maps:get(secure, Cookie)),
    ?assertEqual(true, maps:get(http_only, Cookie)),
    ?assertEqual(strict, maps:get(same_site, Cookie)).

decode_set_cookie_empty_name(_Config) ->
    {error, empty_name} = nhttp_cookie:decode_set_cookie(<<"=value">>).

decode_set_cookie_no_value(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session">>),
    ?assertEqual(<<"session">>, maps:get(name, Cookie)),
    ?assertEqual(<<>>, maps:get(value, Cookie)).

decode_set_cookie_invalid_max_age(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc; Max-Age=invalid">>),
    ?assertEqual(undefined, maps:get(max_age, Cookie, undefined)).

decode_set_cookie_invalid_expires(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc; Expires=not-a-date">>),
    ?assertEqual(undefined, maps:get(expires, Cookie, undefined)).

%%%-----------------------------------------------------------------------------
%%% SET-COOKIE ENCODING TESTS
%%%-----------------------------------------------------------------------------

encode_set_cookie_simple(_Config) ->
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{name => <<"session">>, value => <<"abc123">>}),
    ?assertEqual(<<"session=abc123">>, Result).

encode_set_cookie_with_path(_Config) ->
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{
        name => <<"session">>,
        value => <<"abc">>,
        path => <<"/">>
    }),
    ?assertEqual(<<"session=abc; Path=/">>, Result).

encode_set_cookie_with_domain(_Config) ->
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{
        name => <<"session">>,
        value => <<"abc">>,
        domain => <<".example.com">>
    }),
    ?assertEqual(<<"session=abc; Domain=.example.com">>, Result).

encode_set_cookie_with_max_age(_Config) ->
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{
        name => <<"session">>,
        value => <<"abc">>,
        max_age => 3600
    }),
    ?assertEqual(<<"session=abc; Max-Age=3600">>, Result).

encode_set_cookie_with_expires(_Config) ->
    DateTime = {{2024, 12, 25}, {12, 0, 0}},
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{
        name => <<"session">>,
        value => <<"abc">>,
        expires => DateTime
    }),
    ?assertEqual(<<"session=abc; Expires=Wed, 25 Dec 2024 12:00:00 GMT">>, Result).

encode_set_cookie_with_expires_all_days(_Config) ->
    Days = [
        {{{2024, 1, 1}, {0, 0, 0}}, <<"Mon">>},
        {{{2024, 1, 2}, {0, 0, 0}}, <<"Tue">>},
        {{{2024, 1, 3}, {0, 0, 0}}, <<"Wed">>},
        {{{2024, 1, 4}, {0, 0, 0}}, <<"Thu">>},
        {{{2024, 1, 5}, {0, 0, 0}}, <<"Fri">>},
        {{{2024, 1, 6}, {0, 0, 0}}, <<"Sat">>},
        {{{2024, 1, 7}, {0, 0, 0}}, <<"Sun">>}
    ],
    lists:foreach(
        fun({DateTime, ExpectedDay}) ->
            {ok, Result} = nhttp_cookie:encode_set_cookie(#{
                name => <<"s">>,
                value => <<"v">>,
                expires => DateTime
            }),
            ?assert(binary:match(Result, ExpectedDay) =/= nomatch)
        end,
        Days
    ).

encode_set_cookie_with_expires_all_months(_Config) ->
    Months = [
        {{{2024, 1, 15}, {0, 0, 0}}, <<"Jan">>},
        {{{2024, 2, 15}, {0, 0, 0}}, <<"Feb">>},
        {{{2024, 3, 15}, {0, 0, 0}}, <<"Mar">>},
        {{{2024, 4, 15}, {0, 0, 0}}, <<"Apr">>},
        {{{2024, 5, 15}, {0, 0, 0}}, <<"May">>},
        {{{2024, 6, 15}, {0, 0, 0}}, <<"Jun">>},
        {{{2024, 7, 15}, {0, 0, 0}}, <<"Jul">>},
        {{{2024, 8, 15}, {0, 0, 0}}, <<"Aug">>},
        {{{2024, 9, 15}, {0, 0, 0}}, <<"Sep">>},
        {{{2024, 10, 15}, {0, 0, 0}}, <<"Oct">>},
        {{{2024, 11, 15}, {0, 0, 0}}, <<"Nov">>},
        {{{2024, 12, 15}, {0, 0, 0}}, <<"Dec">>}
    ],
    lists:foreach(
        fun({DateTime, ExpectedMonth}) ->
            {ok, Result} = nhttp_cookie:encode_set_cookie(#{
                name => <<"s">>,
                value => <<"v">>,
                expires => DateTime
            }),
            ?assert(binary:match(Result, ExpectedMonth) =/= nomatch)
        end,
        Months
    ).

encode_set_cookie_with_secure(_Config) ->
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{
        name => <<"session">>,
        value => <<"abc">>,
        secure => true
    }),
    ?assertEqual(<<"session=abc; Secure">>, Result).

encode_set_cookie_with_http_only(_Config) ->
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{
        name => <<"session">>,
        value => <<"abc">>,
        http_only => true
    }),
    ?assertEqual(<<"session=abc; HttpOnly">>, Result).

encode_set_cookie_with_same_site(_Config) ->
    {ok, Result1} = nhttp_cookie:encode_set_cookie(#{
        name => <<"s">>,
        value => <<"v">>,
        same_site => strict
    }),
    ?assertEqual(<<"s=v; SameSite=Strict">>, Result1),
    {ok, Result2} = nhttp_cookie:encode_set_cookie(#{
        name => <<"s">>,
        value => <<"v">>,
        same_site => lax
    }),
    ?assertEqual(<<"s=v; SameSite=Lax">>, Result2),
    {ok, Result3} = nhttp_cookie:encode_set_cookie(#{
        name => <<"s">>,
        value => <<"v">>,
        same_site => none
    }),
    ?assertEqual(<<"s=v; SameSite=None">>, Result3).

encode_set_cookie_all_attributes(_Config) ->
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{
        name => <<"session">>,
        value => <<"abc">>,
        path => <<"/">>,
        domain => <<".example.com">>,
        max_age => 3600,
        secure => true,
        http_only => true,
        same_site => strict
    }),
    ?assert(binary:match(Result, <<"session=abc">>) =/= nomatch),
    ?assert(binary:match(Result, <<"; Path=/">>) =/= nomatch),
    ?assert(binary:match(Result, <<"; Domain=.example.com">>) =/= nomatch),
    ?assert(binary:match(Result, <<"; Max-Age=3600">>) =/= nomatch),
    ?assert(binary:match(Result, <<"; Secure">>) =/= nomatch),
    ?assert(binary:match(Result, <<"; HttpOnly">>) =/= nomatch),
    ?assert(binary:match(Result, <<"; SameSite=Strict">>) =/= nomatch).

encode_set_cookie_false_flags(_Config) ->
    {ok, Result} = nhttp_cookie:encode_set_cookie(#{
        name => <<"session">>,
        value => <<"abc">>,
        secure => false,
        http_only => false
    }),
    ?assertEqual(<<"session=abc">>, Result).

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP TESTS
%%%-----------------------------------------------------------------------------

cookie_roundtrip(_Config) ->
    Original = [
        #{name => <<"session">>, value => <<"abc123">>},
        #{name => <<"user">>, value => <<"john">>}
    ],
    {ok, Encoded} = nhttp_cookie:encode_cookie(Original),
    {ok, Decoded} = nhttp_cookie:decode_cookie(Encoded),
    ?assertEqual(Original, Decoded).

set_cookie_roundtrip(_Config) ->
    Original = #{name => <<"session">>, value => <<"abc123">>},
    {ok, Encoded} = nhttp_cookie:encode_set_cookie(Original),
    {ok, Decoded} = nhttp_cookie:decode_set_cookie(Encoded),
    ?assertEqual(maps:get(name, Original), maps:get(name, Decoded)),
    ?assertEqual(maps:get(value, Original), maps:get(value, Decoded)).

set_cookie_roundtrip_all_attrs(_Config) ->
    Original = #{
        name => <<"session">>,
        value => <<"abc123">>,
        path => <<"/">>,
        domain => <<".example.com">>,
        max_age => 3600,
        secure => true,
        http_only => true,
        same_site => strict
    },
    {ok, Encoded} = nhttp_cookie:encode_set_cookie(Original),
    {ok, Decoded} = nhttp_cookie:decode_set_cookie(Encoded),
    ?assertEqual(maps:get(name, Original), maps:get(name, Decoded)),
    ?assertEqual(maps:get(value, Original), maps:get(value, Decoded)),
    ?assertEqual(maps:get(path, Original), maps:get(path, Decoded)),
    ?assertEqual(maps:get(domain, Original), maps:get(domain, Decoded)),
    ?assertEqual(maps:get(max_age, Original), maps:get(max_age, Decoded)),
    ?assertEqual(maps:get(secure, Original), maps:get(secure, Decoded)),
    ?assertEqual(maps:get(http_only, Original), maps:get(http_only, Decoded)),
    ?assertEqual(maps:get(same_site, Original), maps:get(same_site, Decoded)).

%%%-----------------------------------------------------------------------------
%%% ADDITIONAL COVERAGE TESTS
%%%-----------------------------------------------------------------------------

decode_set_cookie_all_months_rfc1123(_Config) ->
    MonthTests = [
        {<<"Sun, 15 Jan 2024 12:00:00 GMT">>, 1},
        {<<"Thu, 15 Feb 2024 12:00:00 GMT">>, 2},
        {<<"Fri, 15 Mar 2024 12:00:00 GMT">>, 3},
        {<<"Mon, 15 Apr 2024 12:00:00 GMT">>, 4},
        {<<"Wed, 15 May 2024 12:00:00 GMT">>, 5},
        {<<"Sat, 15 Jun 2024 12:00:00 GMT">>, 6},
        {<<"Mon, 15 Jul 2024 12:00:00 GMT">>, 7},
        {<<"Thu, 15 Aug 2024 12:00:00 GMT">>, 8},
        {<<"Sun, 15 Sep 2024 12:00:00 GMT">>, 9},
        {<<"Tue, 15 Oct 2024 12:00:00 GMT">>, 10},
        {<<"Fri, 15 Nov 2024 12:00:00 GMT">>, 11},
        {<<"Sun, 15 Dec 2024 12:00:00 GMT">>, 12}
    ],
    lists:foreach(
        fun({ExpiresValue, ExpectedMonth}) ->
            Header = <<"session=abc; Expires=", ExpiresValue/binary>>,
            {ok, Cookie} = nhttp_cookie:decode_set_cookie(Header),
            {{_Year, Month, _Day}, _Time} = maps:get(expires, Cookie),
            ?assertEqual(ExpectedMonth, Month)
        end,
        MonthTests
    ).

decode_set_cookie_invalid_samesite(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(<<"session=abc; SameSite=Invalid">>),
    ?assertEqual(undefined, maps:get(same_site, Cookie, undefined)).

decode_set_cookie_unknown_attribute(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; UnknownAttr=value; Path=/">>
    ),
    ?assertEqual(<<"session">>, maps:get(name, Cookie)),
    ?assertEqual(<<"/">>, maps:get(path, Cookie)),
    ?assertEqual(undefined, maps:get(unknown_attr, Cookie, undefined)).

decode_set_cookie_invalid_time(_Config) ->
    {ok, Cookie1} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sun, 15 Jan 2024 invalid GMT">>
    ),
    ?assertEqual(undefined, maps:get(expires, Cookie1, undefined)),

    {ok, Cookie2} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sun, 15 Jan 2024 12-00-00 GMT">>
    ),
    ?assertEqual(undefined, maps:get(expires, Cookie2, undefined)),

    {ok, Cookie3} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sun, 15 Jan 2024 xx:yy:zz GMT">>
    ),
    ?assertEqual(undefined, maps:get(expires, Cookie3, undefined)).

decode_set_cookie_invalid_month(_Config) ->
    {ok, Cookie1} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sun, 15 Xyz 2024 12:00:00 GMT">>
    ),
    ?assertEqual(undefined, maps:get(expires, Cookie1, undefined)),

    {ok, Cookie2} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sun, 15 jan 2024 12:00:00 GMT">>
    ),
    ?assertEqual(undefined, maps:get(expires, Cookie2, undefined)).

decode_set_cookie_4digit_year(_Config) ->
    {ok, Cookie1} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sun, 15 Jan 2024 12:00:00 GMT">>
    ),
    {{Year1, _, _}, _} = maps:get(expires, Cookie1),
    ?assertEqual(2024, Year1),

    {ok, Cookie2} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Sunday, 06-Nov-2024 08:49:37 GMT">>
    ),
    {{Year2, _, _}, _} = maps:get(expires, Cookie2),
    ?assertEqual(2024, Year2),

    {ok, Cookie3} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; Expires=Monday, 01-Jan-100 00:00:00 GMT">>
    ),
    {{Year3, _, _}, _} = maps:get(expires, Cookie3),
    ?assertEqual(100, Year3).

decode_set_cookie_flag_unknown(_Config) ->
    {ok, Cookie} = nhttp_cookie:decode_set_cookie(
        <<"session=abc; UnknownFlag; Secure">>
    ),
    ?assertEqual(<<"session">>, maps:get(name, Cookie)),
    ?assertEqual(true, maps:get(secure, Cookie)),
    ?assertEqual(undefined, maps:get(unknown_flag, Cookie, undefined)).
