%%%-----------------------------------------------------------------------------
-module(nhttp_media_type_SUITE).

-moduledoc """
Tests for `nhttp_media_type`, the media type grammar of RFC 9110 Section
8.3.1 with the parameters of Section 5.6.6, and the `Content-Type` lookup.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, parse},
        {group, content_type}
    ].

groups() ->
    [
        {parse, [parallel], [
            plain_type,
            token_parameter,
            quoted_parameter,
            quoted_pair_escapes,
            quoted_obs_text,
            empty_parameter,
            ows_around_semicolon,
            names_fold_case_values_keep_it,
            repeated_parameter_keeps_both,
            missing_equals,
            empty_parameter_value,
            bad_token,
            missing_subtype,
            missing_slash,
            whitespace_around_slash,
            trailing_whitespace_without_semicolon,
            unterminated_quoted_string,
            control_octet_in_quoted_string,
            whitespace_around_equals
        ]},
        {content_type, [parallel], [
            content_type_present,
            content_type_absent,
            content_type_repeated,
            content_type_repeated_split_quoted_string,
            content_type_invalid,
            content_type_name_is_exact
        ]}
    ].

%%%-----------------------------------------------------------------------------
%%% PARSE
%%%-----------------------------------------------------------------------------

plain_type(_Config) ->
    ?assertEqual({ok, mt(<<"text">>, <<"html">>, [])}, nhttp_media_type:parse(<<"text/html">>)).

token_parameter(_Config) ->
    ?assertEqual(
        {ok, mt(<<"text">>, <<"html">>, [{<<"charset">>, <<"utf-8">>}])},
        nhttp_media_type:parse(<<"text/html;charset=utf-8">>)
    ).

quoted_parameter(_Config) ->
    ?assertEqual(
        {ok, mt(<<"text">>, <<"html">>, [{<<"charset">>, <<"utf-8">>}])},
        nhttp_media_type:parse(<<"text/html;charset=\"utf-8\"">>)
    ),
    ?assertEqual(
        {ok, mt(<<"multipart">>, <<"form-data">>, [{<<"boundary">>, <<"a b;c,d">>}])},
        nhttp_media_type:parse(<<"multipart/form-data; boundary=\"a b;c,d\"">>)
    ).

%% RFC 9110 Section 5.6.4: the recipient removes the backslash of a
%% quoted-pair.
quoted_pair_escapes(_Config) ->
    ?assertEqual(
        {ok, mt(<<"text">>, <<"plain">>, [{<<"title">>, <<"a\"b\\c d">>}])},
        nhttp_media_type:parse(<<"text/plain;title=\"a\\\"b\\\\c\\ d\"">>)
    ).

quoted_obs_text(_Config) ->
    ?assertEqual(
        {ok, mt(<<"text">>, <<"plain">>, [{<<"t">>, <<16#E9, $\t, 16#FF>>}])},
        nhttp_media_type:parse(<<"text/plain;t=\"", 16#E9, $\t, $\\, 16#FF, "\"">>)
    ).

%% RFC 9110 Section 5.6.6: `parameters = *( OWS ";" OWS [ parameter ] )`.
empty_parameter(_Config) ->
    ?assertEqual(
        {ok, mt(<<"text">>, <<"plain">>, [{<<"charset">>, <<"x">>}])},
        nhttp_media_type:parse(<<"text/plain;;charset=x">>)
    ),
    ?assertEqual(
        {ok, mt(<<"text">>, <<"plain">>, [])}, nhttp_media_type:parse(<<"text/plain;">>)
    ),
    ?assertEqual(
        {ok, mt(<<"text">>, <<"plain">>, [])}, nhttp_media_type:parse(<<"text/plain ; ">>)
    ).

ows_around_semicolon(_Config) ->
    ?assertEqual(
        {ok, mt(<<"text">>, <<"plain">>, [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}])},
        nhttp_media_type:parse(<<"text/plain \t; a=1\t;\t b=2">>)
    ).

%% RFC 9110 Section 8.3.1: type, subtype and parameter names are
%% case-insensitive. Values keep their case.
names_fold_case_values_keep_it(_Config) ->
    ?assertEqual(
        {ok, mt(<<"text">>, <<"html">>, [{<<"charset">>, <<"UTF-8">>}])},
        nhttp_media_type:parse(<<"Text/HTML; Charset=UTF-8">>)
    ).

repeated_parameter_keeps_both(_Config) ->
    ?assertEqual(
        {ok, mt(<<"text">>, <<"plain">>, [{<<"a">>, <<"1">>}, {<<"a">>, <<"2">>}])},
        nhttp_media_type:parse(<<"text/plain;a=1;a=2">>)
    ).

missing_equals(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;charset">>)).

empty_parameter_value(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;charset=">>)),
    ?assertEqual(
        {ok, mt(<<"text">>, <<"plain">>, [{<<"charset">>, <<>>}])},
        nhttp_media_type:parse(<<"text/plain;charset=\"\"">>)
    ).

bad_token(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"te(x)t/plain">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/pl@in">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;ch@rset=x">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a=b@c">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/pl", 16#E9, "in">>)).

missing_subtype(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/;a=1">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"/plain">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<>>)).

missing_slash(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text;a=1">>)).

whitespace_around_slash(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text /plain">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/ plain">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<" text/plain">>)).

trailing_whitespace_without_semicolon(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain ">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a=1 ">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain, text/html">>)).

unterminated_quoted_string(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a=\"x">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a=\"x\\">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a=\"x\"y">>)).

control_octet_in_quoted_string(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a=\"x\ny\"">>)),
    ?assertEqual(
        {error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a=\"x", 16#7F, "\"">>)
    ),
    ?assertEqual(
        {error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a=\"x\\", 0, "\"">>)
    ).

whitespace_around_equals(_Config) ->
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a =1">>)),
    ?assertEqual({error, invalid_media_type}, nhttp_media_type:parse(<<"text/plain;a= 1">>)).

%%%-----------------------------------------------------------------------------
%%% CONTENT-TYPE
%%%-----------------------------------------------------------------------------

content_type_present(_Config) ->
    Headers = [{<<"host">>, <<"a">>}, {<<"content-type">>, <<"application/sql">>}],
    ?assertEqual(
        {ok, mt(<<"application">>, <<"sql">>, [])}, nhttp_media_type:content_type(Headers)
    ).

content_type_absent(_Config) ->
    ?assertEqual({error, missing_content_type}, nhttp_media_type:content_type([])),
    ?assertEqual(
        {error, missing_content_type},
        nhttp_media_type:content_type([{<<"content-length">>, <<"1">>}])
    ).

%% RFC 9110 Section 8.3: Content-Type is a singleton field.
content_type_repeated(_Config) ->
    Headers = [
        {<<"content-type">>, <<"application/sql">>},
        {<<"content-type">>, <<"application/sql">>}
    ],
    ?assertEqual({error, invalid_content_type}, nhttp_media_type:content_type(Headers)).

%% Two lines that a comma join turns into one valid media type still name two
%% values of a singleton field.
content_type_repeated_split_quoted_string(_Config) ->
    Headers = [
        {<<"content-type">>, <<"text/plain;a=\"x">>},
        {<<"content-type">>, <<"y\"">>}
    ],
    ?assertEqual({error, invalid_content_type}, nhttp_media_type:content_type(Headers)).

content_type_invalid(_Config) ->
    ?assertEqual(
        {error, invalid_content_type},
        nhttp_media_type:content_type([{<<"content-type">>, <<"text">>}])
    ),
    ?assertEqual(
        {error, invalid_content_type},
        nhttp_media_type:content_type([{<<"content-type">>, <<>>}])
    ).

%% The codecs give lowercase names, so the lookup is exact.
content_type_name_is_exact(_Config) ->
    ?assertEqual(
        {error, missing_content_type},
        nhttp_media_type:content_type([{<<"Content-Type">>, <<"text/plain">>}])
    ).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

mt(Type, Subtype, Params) ->
    #{type => Type, subtype => Subtype, params => Params}.
