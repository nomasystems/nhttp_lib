%%%-----------------------------------------------------------------------------
-module(nhttp_headers_SUITE).

-moduledoc "Tests for the protocol-agnostic header utility module.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, get},
        {group, has},
        {group, mutation},
        {group, filter},
        {group, to_lower},
        {group, token},
        {group, field_name_validity},
        {group, field_value_validity},
        {group, lower_field_name}
    ].

groups() ->
    [
        {get, [parallel], [
            get_first_match,
            get_default_when_absent,
            get_undefined_when_absent,
            get_case_insensitive_lookup,
            get_matches_stored_mixed_case,
            get_returns_first_when_duplicate,
            get_handles_empty_headers
        ]},
        {has, [parallel], [
            has_present,
            has_absent,
            has_case_insensitive,
            has_matches_stored_mixed_case,
            has_empty_headers
        ]},
        {mutation, [parallel], [
            set_replaces_all_occurrences,
            set_appends_when_missing,
            set_normalises_name,
            set_replaces_stored_mixed_case,
            append_preserves_existing,
            append_normalises_name,
            delete_removes_every_occurrence,
            delete_case_insensitive,
            delete_removes_stored_mixed_case,
            delete_no_op_when_absent
        ]},
        {filter, [parallel], [
            filter_keeps_matching,
            filter_keep_all,
            filter_keep_none,
            filter_preserves_order
        ]},
        {to_lower, [parallel], [
            to_lower_common_request_headers,
            to_lower_common_response_headers,
            to_lower_cors_headers,
            to_lower_connection_values,
            to_lower_already_lowercase,
            to_lower_uncommon_header,
            to_lower_empty,
            to_lower_idempotent,
            to_lower_preserves_non_ascii_upper_bytes
        ]},
        {token, [parallel], [
            is_tchar_accepts_every_tchar,
            is_tchar_rejects_separators_and_controls,
            is_token_rejects_empty,
            is_token_accepts_field_names,
            is_token_rejects_non_tchar_octets
        ]},
        {field_name_validity, [parallel], [
            name_rejects_empty,
            name_rejects_bare_colon,
            name_rejects_interior_colon,
            name_rejects_uppercase,
            name_rejects_space_and_controls,
            name_rejects_high_octets,
            name_accepts_pseudo_header,
            name_accepts_visible_boundaries,
            name_every_octet_matches_the_rule,
            name_every_leading_octet_matches_the_rule
        ]},
        {field_value_validity, [parallel], [
            value_accepts_empty,
            value_rejects_nul_lf_cr,
            value_rejects_del_and_other_controls,
            value_rejects_leading_whitespace,
            value_rejects_trailing_whitespace,
            value_accepts_interior_whitespace,
            value_accepts_obs_text,
            value_every_octet_matches_the_rule,
            value_word_scan_agrees_with_the_pattern,
            forbidden_value_octet_matches_the_octet_set
        ]},
        {lower_field_name, [parallel], [
            lower_field_name_returns_the_input_binary,
            lower_field_name_copies_when_uppercase,
            lower_field_name_preserves_non_ascii_upper_bytes,
            lower_field_name_empty,
            lower_field_name_agrees_with_to_lower
        ]}
    ].

%%%-----------------------------------------------------------------------------
%%% GET
%%%-----------------------------------------------------------------------------

get_first_match(_Config) ->
    Headers = [
        {<<"content-type">>, <<"text/html">>},
        {<<"host">>, <<"localhost">>}
    ],
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"content-type">>, Headers)),
    ?assertEqual(<<"localhost">>, nhttp_headers:get(<<"host">>, Headers)).

get_default_when_absent(_Config) ->
    ?assertEqual(<<"fallback">>, nhttp_headers:get(<<"missing">>, [], <<"fallback">>)),
    ?assertEqual(custom, nhttp_headers:get(<<"missing">>, [{<<"x">>, <<"1">>}], custom)).

get_undefined_when_absent(_Config) ->
    ?assertEqual(undefined, nhttp_headers:get(<<"missing">>, [])),
    ?assertEqual(undefined, nhttp_headers:get(<<"missing">>, [{<<"x">>, <<"1">>}])).

get_case_insensitive_lookup(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}],
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"Content-Type">>, Headers)),
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"CONTENT-TYPE">>, Headers)),
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"content-type">>, Headers)).

%% RFC 9110 Section 5.1: a field name is case-insensitive, so a lookup with a
%% lowercase name finds a name that the caller stored in any case.
get_matches_stored_mixed_case(_Config) ->
    Headers = [{<<"Content-Length">>, <<"5">>}, {<<"CoNtEnT-TyPe">>, <<"text/html">>}],
    ?assertEqual(<<"5">>, nhttp_headers:get(<<"content-length">>, Headers)),
    ?assertEqual(<<"text/html">>, nhttp_headers:get(<<"content-type">>, Headers)),
    ?assertEqual(undefined, nhttp_headers:get(<<"content-lengti">>, Headers)),
    ?assertEqual(undefined, nhttp_headers:get(<<"content_length">>, Headers)).

get_returns_first_when_duplicate(_Config) ->
    Headers = [
        {<<"set-cookie">>, <<"a=1">>},
        {<<"set-cookie">>, <<"b=2">>}
    ],
    ?assertEqual(<<"a=1">>, nhttp_headers:get(<<"set-cookie">>, Headers)).

get_handles_empty_headers(_Config) ->
    ?assertEqual(undefined, nhttp_headers:get(<<"x">>, [])),
    ?assertEqual(default, nhttp_headers:get(<<"x">>, [], default)).

%%%-----------------------------------------------------------------------------
%%% HAS
%%%-----------------------------------------------------------------------------

has_present(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}, {<<"host">>, <<"x">>}],
    ?assert(nhttp_headers:has(<<"content-type">>, Headers)),
    ?assert(nhttp_headers:has(<<"host">>, Headers)).

has_absent(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}],
    ?assertNot(nhttp_headers:has(<<"missing">>, Headers)).

has_case_insensitive(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}],
    ?assert(nhttp_headers:has(<<"Content-Type">>, Headers)),
    ?assert(nhttp_headers:has(<<"CONTENT-TYPE">>, Headers)).

has_matches_stored_mixed_case(_Config) ->
    Headers = [{<<"Content-Length">>, <<"5">>}],
    ?assert(nhttp_headers:has(<<"content-length">>, Headers)),
    ?assert(nhttp_headers:has(<<"CONTENT-LENGTH">>, Headers)),
    ?assertNot(nhttp_headers:has(<<"content-lengti">>, Headers)),
    ?assertNot(nhttp_headers:has(<<"content-lengt">>, Headers)).

has_empty_headers(_Config) ->
    ?assertNot(nhttp_headers:has(<<"any">>, [])).

%%%-----------------------------------------------------------------------------
%%% MUTATION
%%%-----------------------------------------------------------------------------

set_replaces_all_occurrences(_Config) ->
    Headers = [
        {<<"x-trace">>, <<"a">>},
        {<<"host">>, <<"localhost">>},
        {<<"x-trace">>, <<"b">>}
    ],
    Updated = nhttp_headers:set(<<"x-trace">>, <<"only">>, Headers),
    ?assertEqual([{<<"host">>, <<"localhost">>}, {<<"x-trace">>, <<"only">>}], Updated).

set_appends_when_missing(_Config) ->
    Headers = [{<<"host">>, <<"localhost">>}],
    Updated = nhttp_headers:set(<<"x-id">>, <<"1">>, Headers),
    ?assertEqual([{<<"host">>, <<"localhost">>}, {<<"x-id">>, <<"1">>}], Updated).

set_normalises_name(_Config) ->
    Updated = nhttp_headers:set(<<"X-Custom">>, <<"v">>, []),
    ?assertEqual([{<<"x-custom">>, <<"v">>}], Updated).

%% A `set` over a stored mixed-case name replaces it. Without the
%% case-insensitive match the entry survives and `set` appends a second one.
set_replaces_stored_mixed_case(_Config) ->
    Headers = [{<<"Content-Length">>, <<"0">>}, {<<"Host">>, <<"localhost">>}],
    ?assertEqual(
        [{<<"Host">>, <<"localhost">>}, {<<"content-length">>, <<"5">>}],
        nhttp_headers:set(<<"content-length">>, <<"5">>, Headers)
    ).

append_preserves_existing(_Config) ->
    Headers = [{<<"set-cookie">>, <<"a=1">>}],
    Updated = nhttp_headers:append(<<"set-cookie">>, <<"b=2">>, Headers),
    ?assertEqual(
        [{<<"set-cookie">>, <<"a=1">>}, {<<"set-cookie">>, <<"b=2">>}],
        Updated
    ).

append_normalises_name(_Config) ->
    Updated = nhttp_headers:append(<<"Set-Cookie">>, <<"c=3">>, []),
    ?assertEqual([{<<"set-cookie">>, <<"c=3">>}], Updated).

delete_removes_every_occurrence(_Config) ->
    Headers = [
        {<<"x-trace">>, <<"a">>},
        {<<"host">>, <<"localhost">>},
        {<<"x-trace">>, <<"b">>}
    ],
    ?assertEqual(
        [{<<"host">>, <<"localhost">>}],
        nhttp_headers:delete(<<"x-trace">>, Headers)
    ).

delete_case_insensitive(_Config) ->
    Headers = [{<<"content-type">>, <<"text/html">>}, {<<"host">>, <<"x">>}],
    ?assertEqual(
        [{<<"host">>, <<"x">>}],
        nhttp_headers:delete(<<"Content-Type">>, Headers)
    ).

delete_removes_stored_mixed_case(_Config) ->
    Headers = [
        {<<"Content-Length">>, <<"0">>}, {<<"CONTENT-LENGTH">>, <<"1">>}, {<<"x">>, <<"y">>}
    ],
    ?assertEqual([{<<"x">>, <<"y">>}], nhttp_headers:delete(<<"content-length">>, Headers)).

delete_no_op_when_absent(_Config) ->
    Headers = [{<<"host">>, <<"x">>}],
    ?assertEqual(Headers, nhttp_headers:delete(<<"missing">>, Headers)),
    ?assertEqual([], nhttp_headers:delete(<<"any">>, [])).

%%%-----------------------------------------------------------------------------
%%% FILTER
%%%-----------------------------------------------------------------------------

filter_keeps_matching(_Config) ->
    Headers = [
        {<<"content-type">>, <<"text/html">>},
        {<<"x-custom">>, <<"value">>},
        {<<"host">>, <<"localhost">>}
    ],
    Pred = fun
        (<<"x-", _/binary>>, _) -> true;
        (_, _) -> false
    end,
    ?assertEqual([{<<"x-custom">>, <<"value">>}], nhttp_headers:filter(Pred, Headers)).

filter_keep_all(_Config) ->
    Headers = [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}],
    ?assertEqual(Headers, nhttp_headers:filter(fun(_, _) -> true end, Headers)).

filter_keep_none(_Config) ->
    Headers = [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}],
    ?assertEqual([], nhttp_headers:filter(fun(_, _) -> false end, Headers)).

filter_preserves_order(_Config) ->
    Headers = [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}, {<<"c">>, <<"3">>}],
    Pred = fun(N, _) -> N =/= <<"b">> end,
    ?assertEqual(
        [{<<"a">>, <<"1">>}, {<<"c">>, <<"3">>}],
        nhttp_headers:filter(Pred, Headers)
    ).

%%%-----------------------------------------------------------------------------
%%% TO_LOWER
%%%-----------------------------------------------------------------------------

to_lower_common_request_headers(_Config) ->
    ?assertEqual(<<"host">>, nhttp_headers:to_lower(<<"Host">>)),
    ?assertEqual(<<"connection">>, nhttp_headers:to_lower(<<"Connection">>)),
    ?assertEqual(<<"content-type">>, nhttp_headers:to_lower(<<"Content-Type">>)),
    ?assertEqual(<<"content-length">>, nhttp_headers:to_lower(<<"Content-Length">>)),
    ?assertEqual(<<"transfer-encoding">>, nhttp_headers:to_lower(<<"Transfer-Encoding">>)),
    ?assertEqual(<<"accept">>, nhttp_headers:to_lower(<<"Accept">>)),
    ?assertEqual(<<"accept-encoding">>, nhttp_headers:to_lower(<<"Accept-Encoding">>)),
    ?assertEqual(<<"accept-language">>, nhttp_headers:to_lower(<<"Accept-Language">>)),
    ?assertEqual(<<"user-agent">>, nhttp_headers:to_lower(<<"User-Agent">>)),
    ?assertEqual(<<"cookie">>, nhttp_headers:to_lower(<<"Cookie">>)),
    ?assertEqual(<<"authorization">>, nhttp_headers:to_lower(<<"Authorization">>)),
    ?assertEqual(<<"cache-control">>, nhttp_headers:to_lower(<<"Cache-Control">>)),
    ?assertEqual(<<"if-none-match">>, nhttp_headers:to_lower(<<"If-None-Match">>)),
    ?assertEqual(<<"if-modified-since">>, nhttp_headers:to_lower(<<"If-Modified-Since">>)),
    ?assertEqual(<<"origin">>, nhttp_headers:to_lower(<<"Origin">>)),
    ?assertEqual(<<"referer">>, nhttp_headers:to_lower(<<"Referer">>)).

to_lower_common_response_headers(_Config) ->
    ?assertEqual(<<"content-encoding">>, nhttp_headers:to_lower(<<"Content-Encoding">>)),
    ?assertEqual(<<"set-cookie">>, nhttp_headers:to_lower(<<"Set-Cookie">>)),
    ?assertEqual(<<"keep-alive">>, nhttp_headers:to_lower(<<"Keep-Alive">>)),
    ?assertEqual(<<"location">>, nhttp_headers:to_lower(<<"Location">>)),
    ?assertEqual(<<"etag">>, nhttp_headers:to_lower(<<"ETag">>)),
    ?assertEqual(<<"last-modified">>, nhttp_headers:to_lower(<<"Last-Modified">>)),
    ?assertEqual(<<"expires">>, nhttp_headers:to_lower(<<"Expires">>)),
    ?assertEqual(<<"date">>, nhttp_headers:to_lower(<<"Date">>)),
    ?assertEqual(<<"server">>, nhttp_headers:to_lower(<<"Server">>)),
    ?assertEqual(<<"vary">>, nhttp_headers:to_lower(<<"Vary">>)).

to_lower_cors_headers(_Config) ->
    ?assertEqual(
        <<"access-control-allow-origin">>,
        nhttp_headers:to_lower(<<"Access-Control-Allow-Origin">>)
    ),
    ?assertEqual(
        <<"access-control-allow-methods">>,
        nhttp_headers:to_lower(<<"Access-Control-Allow-Methods">>)
    ),
    ?assertEqual(
        <<"access-control-allow-headers">>,
        nhttp_headers:to_lower(<<"Access-Control-Allow-Headers">>)
    ).

to_lower_connection_values(_Config) ->
    ?assertEqual(<<"close">>, nhttp_headers:to_lower(<<"Close">>)),
    ?assertEqual(<<"upgrade">>, nhttp_headers:to_lower(<<"Upgrade">>)).

to_lower_already_lowercase(_Config) ->
    ?assertEqual(<<"already-lowercase">>, nhttp_headers:to_lower(<<"already-lowercase">>)),
    ?assertEqual(<<"content-type">>, nhttp_headers:to_lower(<<"content-type">>)).

to_lower_uncommon_header(_Config) ->
    ?assertEqual(<<"x-custom-header">>, nhttp_headers:to_lower(<<"X-Custom-Header">>)),
    ?assertEqual(<<"x-foo-bar">>, nhttp_headers:to_lower(<<"X-FOO-BAR">>)).

to_lower_empty(_Config) ->
    ?assertEqual(<<>>, nhttp_headers:to_lower(<<>>)).

to_lower_idempotent(_Config) ->
    Inputs = [
        <<"Host">>,
        <<"Connection">>,
        <<"Content-Type">>,
        <<"Content-Length">>,
        <<"Transfer-Encoding">>,
        <<"Accept">>,
        <<"Accept-Encoding">>,
        <<"Accept-Language">>,
        <<"User-Agent">>,
        <<"Cookie">>,
        <<"Authorization">>,
        <<"Cache-Control">>,
        <<"If-None-Match">>,
        <<"If-Modified-Since">>,
        <<"Origin">>,
        <<"Referer">>,
        <<"Content-Encoding">>,
        <<"Set-Cookie">>,
        <<"Keep-Alive">>,
        <<"Location">>,
        <<"ETag">>,
        <<"Last-Modified">>,
        <<"Expires">>,
        <<"Date">>,
        <<"Server">>,
        <<"Vary">>,
        <<"Access-Control-Allow-Origin">>,
        <<"Access-Control-Allow-Methods">>,
        <<"Access-Control-Allow-Headers">>,
        <<"Close">>,
        <<"Upgrade">>,
        <<"X-Custom-Header">>,
        <<"already-lowercase">>
    ],
    lists:foreach(
        fun(In) ->
            Lower = nhttp_headers:to_lower(In),
            ?assertEqual(Lower, nhttp_headers:to_lower(Lower))
        end,
        Inputs
    ).

to_lower_preserves_non_ascii_upper_bytes(_Config) ->
    Bin = <<"X-Foo-", 16#80, "-Bar">>,
    Expected = <<"x-foo-", 16#80, "-bar">>,
    ?assertEqual(Expected, nhttp_headers:to_lower(Bin)).

%%%-----------------------------------------------------------------------------
%%% TOKEN
%%%
%%% RFC 9110 Section 5.6.2: token = 1*tchar.
%%%-----------------------------------------------------------------------------

is_tchar_accepts_every_tchar(_Config) ->
    lists:foreach(
        fun(C) -> ?assert(nhttp_headers:is_tchar(C), {octet, C}) end,
        tchars()
    ).

is_tchar_rejects_separators_and_controls(_Config) ->
    Rejected = lists:seq(16#00, 16#20) ++ [16#7F] ++ separators() ++ lists:seq(16#80, 16#FF),
    lists:foreach(
        fun(C) -> ?assertNot(nhttp_headers:is_tchar(C), {octet, C}) end,
        Rejected
    ).

is_token_rejects_empty(_Config) ->
    ?assertNot(nhttp_headers:is_token(<<>>)).

is_token_accepts_field_names(_Config) ->
    lists:foreach(
        fun(Bin) -> ?assert(nhttp_headers:is_token(Bin), {token, Bin}) end,
        [<<"content-length">>, <<"X-Custom">>, <<"!#$%&'*+-.^_`|~">>, <<"a">>, <<"200">>]
    ).

is_token_rejects_non_tchar_octets(_Config) ->
    lists:foreach(
        fun(Bin) -> ?assertNot(nhttp_headers:is_token(Bin), {token, Bin}) end,
        [<<"a b">>, <<"a:b">>, <<"a\r\nb">>, <<"a\tb">>, <<"a", 0, "b">>, <<"a", 16#FF, "b">>]
    ).

-spec tchars() -> [byte()].
tchars() ->
    lists:seq($a, $z) ++
        lists:seq($A, $Z) ++
        lists:seq($0, $9) ++
        [$!, $#, $$, $%, $&, $', $*, $+, $-, $., $^, $_, $`, $|, $~].

-spec separators() -> [byte()].
separators() ->
    [$(, $), $<, $>, $@, $,, $;, $:, $\\, $", $/, $[, $], $?, $=, ${, $}].

%%%-----------------------------------------------------------------------------
%%% FIELD NAME VALIDITY
%%%
%%% RFC 9113 Section 8.2.1: a field name must not hold an octet in 0x00-0x20,
%%% 0x41-0x5A or 0x7F-0xFF, and must not hold a colon except the single
%%% leading colon of a pseudo-header field. RFC 9114 Section 4.1.2 lists the
%%% same conditions for HTTP/3 and names the uppercase case apart.
%%%-----------------------------------------------------------------------------

name_rejects_empty(_Config) ->
    ?assertEqual({error, empty_field_name}, nhttp_headers:validate_field_name(<<>>)).

%% A bare colon starts with a single colon but names no pseudo-header field.
name_rejects_bare_colon(_Config) ->
    ?assertEqual({error, empty_field_name}, nhttp_headers:validate_field_name(<<":">>)).

name_rejects_interior_colon(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assertEqual(
                {error, invalid_field_name_char},
                nhttp_headers:validate_field_name(Name),
                {name, Name}
            )
        end,
        [<<"a:b">>, <<"::method">>, <<":method:">>, <<"content-length:">>, <<"::">>]
    ).

name_rejects_uppercase(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assertEqual(
                {error, uppercase_field_name},
                nhttp_headers:validate_field_name(Name),
                {name, Name}
            )
        end,
        [<<"Content-Length">>, <<"ETag">>, <<"x-vendoR">>, <<"A">>, <<":Method">>]
    ).

name_rejects_space_and_controls(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assertEqual(
                {error, invalid_field_name_char},
                nhttp_headers:validate_field_name(Name),
                {name, Name}
            )
        end,
        [
            <<"a b">>,
            <<" a">>,
            <<"a ">>,
            <<"a", 0, "b">>,
            <<"a\tb">>,
            <<"a\rb">>,
            <<"a\nb">>,
            <<"a", 16#7F, "b">>
        ]
    ).

name_rejects_high_octets(_Config) ->
    lists:foreach(
        fun(C) ->
            Name = <<"a", C, "b">>,
            ?assertEqual(
                {error, invalid_field_name_char},
                nhttp_headers:validate_field_name(Name),
                {octet, C}
            )
        end,
        lists:seq(16#80, 16#FF)
    ).

name_accepts_pseudo_header(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assertEqual(ok, nhttp_headers:validate_field_name(Name), {name, Name})
        end,
        [<<":method">>, <<":path">>, <<":scheme">>, <<":authority">>, <<":status">>, <<":a">>]
    ).

name_accepts_visible_boundaries(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assertEqual(ok, nhttp_headers:validate_field_name(Name), {name, Name})
        end,
        [<<16#21>>, <<16#7E>>, <<16#21, 16#7E>>, <<"!#$%&'*+-.^_`|~">>, <<"a{b}c">>]
    ).

name_every_octet_matches_the_rule(_Config) ->
    Allowed = allowed_name_octets(),
    lists:foreach(
        fun(C) ->
            Name = <<$x, C>>,
            case nhttp_headers:validate_field_name(Name) of
                ok ->
                    ?assert(lists:member(C, Allowed), {accepted, C});
                {error, uppercase_field_name} ->
                    ?assert(C >= $A andalso C =< $Z, {uppercase, C});
                {error, invalid_field_name_char} ->
                    ?assertNot(lists:member(C, Allowed), {refused, C}),
                    ?assertNot(C >= $A andalso C =< $Z, {uppercase, C})
            end
        end,
        lists:seq(0, 255)
    ).

name_every_leading_octet_matches_the_rule(_Config) ->
    Allowed = allowed_name_octets(),
    lists:foreach(
        fun(C) ->
            Name = <<C, $x>>,
            Ok = lists:member(C, Allowed) orelse C =:= $:,
            case nhttp_headers:validate_field_name(Name) of
                ok ->
                    ?assert(Ok, {accepted, C});
                {error, uppercase_field_name} ->
                    ?assert(C >= $A andalso C =< $Z, {uppercase, C});
                {error, invalid_field_name_char} ->
                    ?assertNot(Ok, {refused, C})
            end
        end,
        lists:seq(0, 255)
    ).

%%%-----------------------------------------------------------------------------
%%% FIELD VALUE VALIDITY
%%%
%%% RFC 9110 Section 5.5 forbids 0x00-0x1F except 0x09, and 0x7F. RFC 9113
%%% Section 8.2.1 forbids a leading or trailing SP or HTAB.
%%%-----------------------------------------------------------------------------

value_accepts_empty(_Config) ->
    ?assertEqual(ok, nhttp_headers:validate_field_value(<<>>)).

value_rejects_nul_lf_cr(_Config) ->
    lists:foreach(
        fun(Value) ->
            ?assertEqual(
                {error, invalid_field_value_char},
                nhttp_headers:validate_field_value(Value),
                {value, Value}
            )
        end,
        [
            <<"a", 0, "b">>,
            <<"a\nb">>,
            <<"a\rb">>,
            <<"a\r\nb">>,
            <<0>>,
            <<"text/html\r\nx-injected: 1">>
        ]
    ).

value_rejects_del_and_other_controls(_Config) ->
    lists:foreach(
        fun(C) ->
            Value = <<"a", C, "b">>,
            ?assertEqual(
                {error, invalid_field_value_char},
                nhttp_headers:validate_field_value(Value),
                {octet, C}
            )
        end,
        [C || C <- lists:seq(16#00, 16#1F), C =/= 16#09] ++ [16#7F]
    ).

value_rejects_leading_whitespace(_Config) ->
    lists:foreach(
        fun(Value) ->
            ?assertEqual(
                {error, field_value_edge_whitespace},
                nhttp_headers:validate_field_value(Value),
                {value, Value}
            )
        end,
        [<<" a">>, <<"\ta">>, <<" ">>, <<"\t">>, <<"  a  ">>]
    ).

value_rejects_trailing_whitespace(_Config) ->
    Long = binary:copy(<<"long-">>, 40),
    lists:foreach(
        fun(Value) ->
            ?assertEqual(
                {error, field_value_edge_whitespace},
                nhttp_headers:validate_field_value(Value),
                {value, Value}
            )
        end,
        [<<"a ">>, <<"a\t">>, <<"a b ">>, <<Long/binary, " ">>, <<Long/binary, "\t">>]
    ).

value_accepts_interior_whitespace(_Config) ->
    lists:foreach(
        fun(Value) ->
            ?assertEqual(ok, nhttp_headers:validate_field_value(Value), {value, Value})
        end,
        [<<"a b">>, <<"a\tb">>, <<"a \t b">>, <<"text/html; charset=utf-8">>]
    ).

value_accepts_obs_text(_Config) ->
    lists:foreach(
        fun(C) ->
            Value = <<"a", C, "b">>,
            ?assertEqual(ok, nhttp_headers:validate_field_value(Value), {octet, C})
        end,
        lists:seq(16#80, 16#FF)
    ).

value_every_octet_matches_the_rule(_Config) ->
    Forbidden = forbidden_value_octets(),
    lists:foreach(
        fun(C) ->
            Value = <<$v, C, $v>>,
            Expected =
                case lists:member(C, Forbidden) of
                    false -> ok;
                    true -> {error, invalid_field_value_char}
                end,
            ?assertEqual(
                Expected, nhttp_headers:validate_field_value(Value), {octet, C}
            )
        end,
        lists:seq(0, 255)
    ).

%% The length switch inside the value scan picks `binary:match/2' below 112
%% octets and the word scan at that length and above. Both instruments must
%% report the same refusal at every offset.
value_word_scan_agrees_with_the_pattern(_Config) ->
    lists:foreach(
        fun(Len) ->
            Clean = binary:copy(<<$v>>, Len),
            ?assertEqual(ok, nhttp_headers:validate_field_value(Clean), {clean, Len}),
            lists:foreach(
                fun(Pos) ->
                    Bad = set_octet(Clean, Pos, 0),
                    ?assertEqual(
                        {error, invalid_field_value_char},
                        nhttp_headers:validate_field_value(Bad),
                        {Len, Pos}
                    )
                end,
                lists:seq(0, Len - 1)
            )
        end,
        [1, 8, 56, 111, 112, 113, 224, 449]
    ).

forbidden_value_octet_matches_the_octet_set(_Config) ->
    Forbidden = forbidden_value_octets(),
    lists:foreach(
        fun(Len) ->
            Clean = binary:copy(<<$v>>, Len),
            ?assertNot(nhttp_headers:has_forbidden_value_octet(Clean), {clean, Len}),
            lists:foreach(
                fun(C) ->
                    Bin = <<Clean/binary, C>>,
                    ?assertEqual(
                        lists:member(C, Forbidden),
                        nhttp_headers:has_forbidden_value_octet(Bin),
                        {Len, C}
                    )
                end,
                lists:seq(0, 255)
            )
        end,
        lists:seq(0, 60)
    ).

%%%-----------------------------------------------------------------------------
%%% LOWER FIELD NAME
%%%
%%% RFC 9114 Section 4.2: characters in field names are converted to lowercase
%%% before their encoding.
%%%-----------------------------------------------------------------------------

%% The conformant path must not allocate, so a name that holds no uppercase
%% octet comes back as the very binary that the caller passed in.
lower_field_name_returns_the_input_binary(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assert(
                erts_debug:same(Name, nhttp_headers:lower_field_name(Name)),
                {copied, Name}
            )
        end,
        [
            <<"content-length">>,
            <<":method">>,
            <<"x-vendor-trace-id">>,
            <<"a">>,
            <<>>,
            <<"x-", 16#80, "-y">>,
            binary:copy(<<"x-long-vendor-name-">>, 20)
        ]
    ).

lower_field_name_copies_when_uppercase(_Config) ->
    ?assertEqual(<<"content-length">>, nhttp_headers:lower_field_name(<<"Content-Length">>)),
    ?assertEqual(<<"etag">>, nhttp_headers:lower_field_name(<<"ETag">>)),
    ?assertEqual(<<"x-a">>, nhttp_headers:lower_field_name(<<"X-A">>)),
    ?assertEqual(<<"a">>, nhttp_headers:lower_field_name(<<"A">>)),
    Mixed = <<"X-Vendor-Trace-Id">>,
    ?assertNot(erts_debug:same(Mixed, nhttp_headers:lower_field_name(Mixed))).

lower_field_name_preserves_non_ascii_upper_bytes(_Config) ->
    ?assertEqual(
        <<"x-foo-", 16#80, "-bar">>,
        nhttp_headers:lower_field_name(<<"X-Foo-", 16#80, "-Bar">>)
    ).

lower_field_name_empty(_Config) ->
    ?assertEqual(<<>>, nhttp_headers:lower_field_name(<<>>)).

lower_field_name_agrees_with_to_lower(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assertEqual(
                nhttp_headers:to_lower(Name),
                nhttp_headers:lower_field_name(Name),
                {name, Name}
            )
        end,
        [
            <<"Content-Length">>,
            <<"content-length">>,
            <<"ETag">>,
            <<"X-Custom-Header">>,
            <<":Method">>,
            <<>>,
            <<"UPPER">>,
            <<"x-", 16#80, 16#C0, "-y">>,
            <<"a{B}c">>
        ]
    ).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

%% Written from the prose of RFC 9113 Section 8.2.1 rather than from the
%% ranges that the implementation matches on.
-spec allowed_name_octets() -> [byte()].
allowed_name_octets() ->
    Forbidden = forbidden_name_octets(),
    [C || C <- lists:seq(0, 255), not lists:member(C, Forbidden), C =/= $:].

-spec forbidden_name_octets() -> [byte()].
forbidden_name_octets() ->
    lists:seq(16#00, 16#20) ++ lists:seq(16#41, 16#5A) ++ lists:seq(16#7F, 16#FF).

-spec forbidden_value_octets() -> [byte()].
forbidden_value_octets() ->
    [C || C <- lists:seq(16#00, 16#1F), C =/= 16#09] ++ [16#7F].

-spec set_octet(binary(), non_neg_integer(), byte()) -> binary().
set_octet(Bin, Pos, Octet) ->
    Tail = byte_size(Bin) - Pos - 1,
    <<Head:Pos/binary, _, Rest:Tail/binary>> = Bin,
    <<Head/binary, Octet, Rest/binary>>.
