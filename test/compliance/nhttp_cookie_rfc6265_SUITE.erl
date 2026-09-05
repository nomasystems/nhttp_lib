%%%-----------------------------------------------------------------------------
-module(nhttp_cookie_rfc6265_SUITE).

-moduledoc """
RFC 6265 Compliance Test Suite.

This suite tests compliance with RFC 6265 (HTTP State Management
Mechanism) for the encoding direction. Each group is linked to the
section of the specification that governs it.

Run with: rebar3 ct --suite=test/compliance/nhttp_cookie_rfc6265_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_4_1_1_set_cookie_grammar},
        {group, section_4_1_1_attribute_grammar},
        {group, section_4_2_1_cookie_grammar},
        {group, section_5_2_roundtrip}
    ].

groups() ->
    [
        {section_4_1_1_set_cookie_grammar, [parallel], [
            reject_value_with_crlf,
            reject_value_with_control_octets,
            reject_value_outside_cookie_octet,
            accept_every_cookie_octet,
            accept_quoted_value,
            reject_unbalanced_quote,
            reject_name_that_is_not_a_token,
            reject_empty_name,
            accept_every_tchar_in_name,
            no_value_is_rewritten
        ]},
        {section_4_1_1_attribute_grammar, [parallel], [
            reject_path_with_semicolon,
            reject_path_with_crlf,
            reject_path_outside_char,
            reject_path_without_leading_slash,
            accept_conforming_path,
            reject_domain_with_semicolon,
            reject_domain_that_is_not_a_subdomain,
            accept_conforming_domain
        ]},
        {section_4_2_1_cookie_grammar, [parallel], [
            reject_cookie_value_with_crlf,
            reject_cookie_value_outside_cookie_octet,
            reject_cookie_name_that_is_not_a_token,
            reject_invalid_pair_anywhere_in_the_list
        ]},
        {section_5_2_roundtrip, [parallel], [
            conforming_set_cookie_roundtrips,
            lenient_decode_of_injected_value_refuses_to_re_encode
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% Section 4.1.1 - set-cookie-string grammar
%%%
%%% cookie-pair  = cookie-name "=" cookie-value
%%% cookie-name  = token
%%% cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
%%% cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
%%%                  ; US-ASCII characters excluding CTLs,
%%%                  ; whitespace DQUOTE, comma, semicolon,
%%%                  ; and backslash
%%%-----------------------------------------------------------------------------

reject_value_with_crlf(_Config) ->
    SetCookie = #{name => <<"s">>, value => <<"v\r\nX: 1">>},
    ?assertEqual(
        {error, {invalid_cookie_value, control_char}},
        nhttp_cookie:encode_set_cookie(SetCookie)
    ).

reject_value_with_control_octets(_Config) ->
    lists:foreach(
        fun(Octet) ->
            SetCookie = #{name => <<"s">>, value => <<"a", Octet:8, "b">>},
            ?assertEqual(
                {error, {invalid_cookie_value, control_char}},
                nhttp_cookie:encode_set_cookie(SetCookie),
                {octet, Octet}
            )
        end,
        control_octets()
    ).

reject_value_outside_cookie_octet(_Config) ->
    lists:foreach(
        fun({Octet, Class}) ->
            SetCookie = #{name => <<"s">>, value => <<"a", Octet:8, "b">>},
            ?assertEqual(
                {error, {invalid_cookie_value, Class}},
                nhttp_cookie:encode_set_cookie(SetCookie),
                {octet, Octet}
            )
        end,
        [
            {$\s, separator},
            {$", separator},
            {$,, separator},
            {$;, separator},
            {$\\, separator},
            {16#80, non_ascii},
            {16#C3, non_ascii},
            {16#FF, non_ascii}
        ]
    ).

accept_every_cookie_octet(_Config) ->
    Value = list_to_binary(cookie_octets()),
    ?assertEqual(
        {ok, <<"s=", Value/binary>>},
        nhttp_cookie:encode_set_cookie(#{name => <<"s">>, value => Value})
    ).

accept_quoted_value(_Config) ->
    ?assertEqual(
        {ok, <<"s=\"abc\"">>},
        nhttp_cookie:encode_set_cookie(#{name => <<"s">>, value => <<"\"abc\"">>})
    ),
    ?assertEqual(
        {ok, <<"s=\"\"">>},
        nhttp_cookie:encode_set_cookie(#{name => <<"s">>, value => <<"\"\"">>})
    ),
    ?assertEqual(
        {error, {invalid_cookie_value, separator}},
        nhttp_cookie:encode_set_cookie(#{name => <<"s">>, value => <<"\"a;b\"">>})
    ).

reject_unbalanced_quote(_Config) ->
    lists:foreach(
        fun(Value) ->
            ?assertEqual(
                {error, {invalid_cookie_value, unbalanced_quote}},
                nhttp_cookie:encode_set_cookie(#{name => <<"s">>, value => Value}),
                {value, Value}
            )
        end,
        [<<"\"">>, <<"\"abc">>]
    ).

reject_name_that_is_not_a_token(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assertEqual(
                {error, {invalid_cookie_name, non_token_octet}},
                nhttp_cookie:encode_set_cookie(#{name => Name, value => <<"v">>}),
                {name, Name}
            )
        end,
        [<<"a b">>, <<"a=b">>, <<"a;b">>, <<"a\r\nb">>, <<"a\tb">>, <<"a,b">>, <<"a", 16#FF, "b">>]
    ).

reject_empty_name(_Config) ->
    ?assertEqual(
        {error, {invalid_cookie_name, empty}},
        nhttp_cookie:encode_set_cookie(#{name => <<>>, value => <<"v">>})
    ).

accept_every_tchar_in_name(_Config) ->
    Name = list_to_binary(tchars()),
    ?assertEqual(
        {ok, <<Name/binary, "=v">>},
        nhttp_cookie:encode_set_cookie(#{name => Name, value => <<"v">>})
    ).

no_value_is_rewritten(_Config) ->
    Value = <<"YWJjMTIz+/=">>,
    {ok, Encoded} = nhttp_cookie:encode_set_cookie(#{name => <<"s">>, value => Value}),
    ?assertEqual(<<"s=YWJjMTIz+/=">>, Encoded).

%%%-----------------------------------------------------------------------------
%%% Section 4.1.1 - attribute grammar
%%%
%%% path-value   = <any CHAR except CTLs or ";">      ; CHAR = %x01-7F
%%% domain-value = <subdomain>                        ; RFC 1034 Section 3.5,
%%%                                                   ; RFC 1123 Section 2.1
%%%-----------------------------------------------------------------------------

reject_path_with_semicolon(_Config) ->
    SetCookie = #{name => <<"s">>, value => <<"v">>, path => <<"/a;Secure">>},
    ?assertEqual(
        {error, {invalid_path, semicolon}},
        nhttp_cookie:encode_set_cookie(SetCookie)
    ).

reject_path_with_crlf(_Config) ->
    SetCookie = #{name => <<"s">>, value => <<"v">>, path => <<"/a\r\nX: 1">>},
    ?assertEqual(
        {error, {invalid_path, control_char}},
        nhttp_cookie:encode_set_cookie(SetCookie)
    ).

reject_path_outside_char(_Config) ->
    SetCookie = #{name => <<"s">>, value => <<"v">>, path => <<"/caf", 16#C3, 16#A9>>},
    ?assertEqual(
        {error, {invalid_path, non_ascii}},
        nhttp_cookie:encode_set_cookie(SetCookie)
    ).

reject_path_without_leading_slash(_Config) ->
    %% RFC 6265 Section 5.2.4: a path that does not start with "/" is
    %% discarded and the default-path is used, so the attribute is a no-op.
    ?assertEqual(
        {error, {invalid_path, no_leading_slash}},
        nhttp_cookie:encode_set_cookie(#{name => <<"s">>, value => <<"v">>, path => <<"a">>})
    ),
    ?assertEqual(
        {error, {invalid_path, empty}},
        nhttp_cookie:encode_set_cookie(#{name => <<"s">>, value => <<"v">>, path => <<>>})
    ).

accept_conforming_path(_Config) ->
    lists:foreach(
        fun(Path) ->
            ?assertMatch(
                {ok, _},
                nhttp_cookie:encode_set_cookie(#{
                    name => <<"s">>, value => <<"v">>, path => Path
                }),
                {path, Path}
            )
        end,
        [<<"/">>, <<"/a/b">>, <<"/a b">>, <<"/a,b">>, <<"/a\"b">>, <<"/a%20b">>]
    ).

reject_domain_with_semicolon(_Config) ->
    SetCookie = #{name => <<"s">>, value => <<"v">>, domain => <<"a.com;Secure">>},
    ?assertEqual(
        {error, {invalid_domain, invalid_label}},
        nhttp_cookie:encode_set_cookie(SetCookie)
    ).

reject_domain_that_is_not_a_subdomain(_Config) ->
    lists:foreach(
        fun({Domain, Class}) ->
            ?assertEqual(
                {error, {invalid_domain, Class}},
                nhttp_cookie:encode_set_cookie(#{
                    name => <<"s">>, value => <<"v">>, domain => Domain
                }),
                {domain, Domain}
            )
        end,
        [
            {<<"https://example.com">>, invalid_label},
            {<<"example.com:8443">>, invalid_label},
            {<<"example.com/">>, invalid_label},
            {<<"exa mple.com">>, invalid_label},
            {<<"example.com.">>, empty_label},
            {<<"example..com">>, empty_label},
            {<<"-example.com">>, invalid_label},
            {<<"example-.com">>, invalid_label},
            {<<>>, empty},
            {<<".">>, empty}
        ]
    ).

accept_conforming_domain(_Config) ->
    lists:foreach(
        fun(Domain) ->
            ?assertMatch(
                {ok, _},
                nhttp_cookie:encode_set_cookie(#{
                    name => <<"s">>, value => <<"v">>, domain => Domain
                }),
                {domain, Domain}
            )
        end,
        [<<"example.com">>, <<".example.com">>, <<"a">>, <<"1a.example.com">>, <<"a-b.example.com">>]
    ).

%%%-----------------------------------------------------------------------------
%%% Section 4.2.1 - cookie-string grammar
%%%
%%% cookie-string = cookie-pair *( ";" SP cookie-pair )
%%%-----------------------------------------------------------------------------

reject_cookie_value_with_crlf(_Config) ->
    Cookies = [#{name => <<"s">>, value => <<"v\r\nX: 1">>}],
    ?assertEqual(
        {error, {invalid_cookie_value, control_char}},
        nhttp_cookie:encode_cookie(Cookies)
    ).

reject_cookie_value_outside_cookie_octet(_Config) ->
    lists:foreach(
        fun({Octet, Class}) ->
            Cookies = [#{name => <<"s">>, value => <<"a", Octet:8, "b">>}],
            ?assertEqual(
                {error, {invalid_cookie_value, Class}},
                nhttp_cookie:encode_cookie(Cookies),
                {octet, Octet}
            )
        end,
        [{$\s, separator}, {$;, separator}, {$,, separator}, {16#C3, non_ascii}]
    ).

reject_cookie_name_that_is_not_a_token(_Config) ->
    ?assertEqual(
        {error, {invalid_cookie_name, non_token_octet}},
        nhttp_cookie:encode_cookie([#{name => <<"a b">>, value => <<"v">>}])
    ).

reject_invalid_pair_anywhere_in_the_list(_Config) ->
    Cookies = [
        #{name => <<"a">>, value => <<"1">>},
        #{name => <<"b">>, value => <<"2">>},
        #{name => <<"c">>, value => <<"3\r\nX: 1">>}
    ],
    ?assertEqual(
        {error, {invalid_cookie_value, control_char}},
        nhttp_cookie:encode_cookie(Cookies)
    ).

%%%-----------------------------------------------------------------------------
%%% Section 5.2 - the parsing algorithm is more permissive than Section 4.1
%%%-----------------------------------------------------------------------------

conforming_set_cookie_roundtrips(_Config) ->
    Header = <<"session=abc123; Path=/app; Domain=example.com; Secure; HttpOnly">>,
    {ok, Decoded} = nhttp_cookie:decode_set_cookie(Header),
    {ok, Encoded} = nhttp_cookie:encode_set_cookie(Decoded),
    {ok, Redecoded} = nhttp_cookie:decode_set_cookie(Encoded),
    ?assertEqual(Decoded, Redecoded).

lenient_decode_of_injected_value_refuses_to_re_encode(_Config) ->
    %% RFC 6265 Section 5.2 keeps internal whitespace and control octets that
    %% Section 4.1.1 forbids, so a forwarder must not re-emit what it decoded.
    {ok, Decoded} = nhttp_cookie:decode_set_cookie(<<"s=v\r\nX: 1">>),
    ?assertEqual(<<"v\r\nX: 1">>, maps:get(value, Decoded)),
    ?assertEqual(
        {error, {invalid_cookie_value, control_char}},
        nhttp_cookie:encode_set_cookie(Decoded)
    ).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec control_octets() -> [byte()].
control_octets() ->
    lists:seq(16#00, 16#1F) ++ [16#7F].

-spec cookie_octets() -> [byte()].
cookie_octets() ->
    [16#21] ++
        lists:seq(16#23, 16#2B) ++
        lists:seq(16#2D, 16#3A) ++
        lists:seq(16#3C, 16#5B) ++
        lists:seq(16#5D, 16#7E).

-spec tchars() -> [byte()].
tchars() ->
    lists:seq($a, $z) ++
        lists:seq($A, $Z) ++
        lists:seq($0, $9) ++
        [$!, $#, $$, $%, $&, $', $*, $+, $-, $., $^, $_, $`, $|, $~].
