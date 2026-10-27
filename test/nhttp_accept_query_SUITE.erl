%%%-----------------------------------------------------------------------------
-module(nhttp_accept_query_SUITE).

-moduledoc """
Tests for `nhttp_accept_query`, the `Accept-Query` field of RFC 10008
Section 3 on the List grammar of RFC 9651.

The `differential` group replays four files of the httpwg
structured-field-tests corpus, copied with their license into
`test/fixtures/structured-field-tests/`.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

-define(SF_FILES, ["list.json", "param-list.json", "string.json", "token.json"]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, parse},
        {group, encode},
        {group, allows},
        {group, differential}
    ].

groups() ->
    [
        {parse, [parallel], [
            absent_and_empty_field,
            field_lines_join,
            string_split_across_field_lines_fails,
            non_ascii_fails_the_field,
            list_whitespace,
            trailing_comma,
            trailing_octets,
            unsupported_items,
            bare_item_syntax,
            parameter_key_grammar,
            parameter_whitespace,
            unsupported_parameters,
            repeated_key_overwrites_in_place,
            member_is_not_a_media_range,
            type_and_subtype_fold_case,
            one_failure_ignores_the_field,
            string_escapes,
            string_syntax,
            result_holds_fresh_binaries
        ]},
        {encode, [parallel], [
            encode_tokens,
            encode_strings,
            encode_lowercases_parameter_names,
            encode_rejects_parameter_names,
            encode_escapes_parameter_values,
            encode_rejects_parameter_values,
            encode_rejects_media_ranges
        ]},
        {allows, [parallel], [
            allows_exact_range,
            allows_type_wildcard,
            allows_any_wildcard,
            allows_never_matches_subtype_wildcard_alone,
            allows_parameter_subset,
            allows_charset_without_case,
            allows_ignores_order,
            allows_nothing_from_no_range
        ]},
        {differential, [parallel], [
            structured_field_tests
        ]}
    ].

%%%-----------------------------------------------------------------------------
%%% PARSE
%%%-----------------------------------------------------------------------------

absent_and_empty_field(_Config) ->
    ?assertEqual({ok, []}, nhttp_accept_query:parse([])),
    ?assertEqual({ok, []}, nhttp_accept_query:parse([{<<"content-type">>, <<"a/b">>}])),
    ?assertEqual({ok, []}, nhttp_accept_query:parse([{<<"accept-query">>, <<>>}])),
    ?assertEqual({ok, []}, nhttp_accept_query:parse_value(<<>>)),
    ?assertEqual({ok, []}, nhttp_accept_query:parse_value(<<"   ">>)).

field_lines_join(_Config) ->
    Headers = [
        {<<"accept-query">>, <<"application/sql">>},
        {<<"host">>, <<"a">>},
        {<<"accept-query">>, <<"\"text/plain\";charset=utf-8">>}
    ],
    ?assertEqual(
        {ok, [
            mt(<<"application">>, <<"sql">>, []),
            mt(<<"text">>, <<"plain">>, [{<<"charset">>, <<"utf-8">>}])
        ]},
        nhttp_accept_query:parse(Headers)
    ),
    ?assertMatch(
        {error, {sf_syntax, _}},
        nhttp_accept_query:parse([
            {<<"accept-query">>, <<"application/sql">>}, {<<"accept-query">>, <<>>}
        ])
    ).

string_split_across_field_lines_fails(_Config) ->
    Headers = [{<<"accept-query">>, <<"\"application/">>}, {<<"accept-query">>, <<"sql\"">>}],
    ?assertEqual(
        {error, {not_media_range, <<"application/, sql">>}}, nhttp_accept_query:parse(Headers)
    ).

non_ascii_fails_the_field(_Config) ->
    ?assertEqual({error, not_ascii}, nhttp_accept_query:parse_value(<<"a/b, \"", 16#E9, "\"">>)),
    ?assertEqual({error, not_ascii}, nhttp_accept_query:parse_value(<<"(, ", 16#80>>)),
    ?assertEqual({error, not_ascii}, nhttp_accept_query:parse_value(<<16#FF>>)).

list_whitespace(_Config) ->
    Expected = {ok, [mt(<<"a">>, <<"b">>, []), mt(<<"c">>, <<"d">>, [])]},
    ?assertEqual(Expected, nhttp_accept_query:parse_value(<<"  a/b,c/d">>)),
    ?assertEqual(Expected, nhttp_accept_query:parse_value(<<"a/b \t,\t c/d \t">>)),
    ?assertEqual({error, {sf_syntax, 0}}, nhttp_accept_query:parse_value(<<"\ta/b">>)).

trailing_comma(_Config) ->
    ?assertEqual({error, {sf_syntax, 5}}, nhttp_accept_query:parse_value(<<"a/b, ">>)),
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b,">>)),
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b,,c/d">>)),
    ?assertEqual({error, {sf_syntax, 0}}, nhttp_accept_query:parse_value(<<",a/b">>)).

trailing_octets(_Config) ->
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b c/d">>)),
    ?assertEqual({error, {sf_syntax, 5}}, nhttp_accept_query:parse_value(<<"\"a/b\"x">>)),
    ?assertEqual({error, {sf_syntax, 3}}, nhttp_accept_query:parse_value(<<"a/b)">>)).

unsupported_items(_Config) ->
    lists:foreach(
        fun({Value, Offset}) ->
            ?assertEqual(
                {Value, {error, {unsupported_item, Offset}}},
                {Value, nhttp_accept_query:parse_value(Value)}
            )
        end,
        [
            {<<"(a/b)">>, 0},
            {<<"()">>, 0},
            {<<"1">>, 0},
            {<<"-1">>, 0},
            {<<"1.5">>, 0},
            {<<"?1">>, 0},
            {<<":AAAA:">>, 0},
            {<<"@1659578233">>, 0},
            {<<"%\"x\"">>, 0},
            {<<"a/b, 42">>, 5}
        ]
    ).

bare_item_syntax(_Config) ->
    lists:foreach(
        fun({Value, Offset}) ->
            ?assertEqual(
                {Value, {error, {sf_syntax, Offset}}},
                {Value, nhttp_accept_query:parse_value(Value)}
            )
        end,
        [
            {<<")">>, 0},
            {<<"'a/b'">>, 0},
            {<<"#a">>, 0},
            {<<"a/b, =">>, 5},
            {<<"a/b;c=(d)">>, 6},
            {<<"a/b;c=">>, 6}
        ]
    ).

parameter_key_grammar(_Config) ->
    ?assertEqual(
        {ok, [mt(<<"a">>, <<"b">>, [{<<"*x_1-.*">>, <<"v">>}])]},
        nhttp_accept_query:parse_value(<<"a/b;*x_1-.*=v">>)
    ),
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b;Charset=v">>)),
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b;1x=v">>)),
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b;=v">>)),
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b;">>)),
    ?assertEqual(
        {error, {unsupported_parameter, 4}}, nhttp_accept_query:parse_value(<<"a/b;cH=v">>)
    ).

parameter_whitespace(_Config) ->
    ?assertEqual(
        {ok, [mt(<<"a">>, <<"b">>, [{<<"c">>, <<"d">>}])]},
        nhttp_accept_query:parse_value(<<"a/b;  c=d">>)
    ),
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b ;c=d">>)),
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"a/b;\tc=d">>)),
    ?assertEqual(
        {error, {unsupported_parameter, 4}}, nhttp_accept_query:parse_value(<<"a/b;c =d">>)
    ),
    ?assertEqual({error, {sf_syntax, 6}}, nhttp_accept_query:parse_value(<<"a/b;c= d">>)).

unsupported_parameters(_Config) ->
    lists:foreach(
        fun({Value, Offset}) ->
            ?assertEqual(
                {Value, {error, {unsupported_parameter, Offset}}},
                {Value, nhttp_accept_query:parse_value(Value)}
            )
        end,
        [
            {<<"a/b;c">>, 4},
            {<<"a/b;c;d=e">>, 4},
            {<<"a/b;d=e;c">>, 8},
            {<<"a/b;c=1">>, 4},
            {<<"a/b;c=?1">>, 4},
            {<<"a/b;c=:AA==:">>, 4},
            {<<"a/b; c=1">>, 5}
        ]
    ).

repeated_key_overwrites_in_place(_Config) ->
    ?assertEqual(
        {ok, [mt(<<"a">>, <<"b">>, [{<<"x">>, <<"c">>}, {<<"y">>, <<"b">>}])]},
        nhttp_accept_query:parse_value(<<"a/b;x=a;y=b;x=c">>)
    ).

member_is_not_a_media_range(_Config) ->
    lists:foreach(
        fun({Value, Member}) ->
            ?assertEqual(
                {Value, {error, {not_media_range, Member}}},
                {Value, nhttp_accept_query:parse_value(Value)}
            )
        end,
        [
            {<<"text">>, <<"text">>},
            {<<"a:b/c">>, <<"a:b/c">>},
            {<<"text/plain/x">>, <<"text/plain/x">>},
            {<<"text/">>, <<"text/">>},
            {<<"\"/plain\"">>, <<"/plain">>},
            {<<"\"text/plain;charset=utf-8\"">>, <<"text/plain;charset=utf-8">>},
            {<<"\"text plain\"">>, <<"text plain">>},
            {<<"\"\"">>, <<>>},
            {<<"a/b, */b">>, <<"*/b">>}
        ]
    ).

type_and_subtype_fold_case(_Config) ->
    ?assertEqual(
        {ok, [mt(<<"application">>, <<"sql">>, [{<<"v">>, <<"MiXed">>}])]},
        nhttp_accept_query:parse_value(<<"Application/SQL;v=MiXed">>)
    ),
    ?assertEqual(
        nhttp_accept_query:parse_value(<<"application/sql">>),
        nhttp_accept_query:parse_value(<<"\"APPLICATION/Sql\"">>)
    ).

one_failure_ignores_the_field(_Config) ->
    ?assertMatch({error, _}, nhttp_accept_query:parse_value(<<"application/sql, 1">>)),
    ?assertMatch({error, _}, nhttp_accept_query:parse_value(<<"application/sql, text">>)),
    ?assertMatch({error, _}, nhttp_accept_query:parse_value(<<"application/sql;a">>)).

string_escapes(_Config) ->
    ?assertEqual(
        {ok, [mt(<<"a">>, <<"b">>, [{<<"t">>, <<"x\"y\\z">>}])]},
        nhttp_accept_query:parse_value(<<"a/b;t=\"x\\\"y\\\\z\"">>)
    ),
    ?assertEqual({error, {sf_syntax, 9}}, nhttp_accept_query:parse_value(<<"a/b;t=\"x\\y\"">>)).

string_syntax(_Config) ->
    ?assertEqual({error, {sf_syntax, 4}}, nhttp_accept_query:parse_value(<<"\"a/b">>)),
    ?assertEqual({error, {sf_syntax, 5}}, nhttp_accept_query:parse_value(<<"\"a/b\\">>)),
    ?assertEqual({error, {sf_syntax, 2}}, nhttp_accept_query:parse_value(<<"\"a\tb/c\"">>)),
    ?assertEqual({error, {sf_syntax, 2}}, nhttp_accept_query:parse_value(<<"\"a", 16#7F, "\"">>)),
    ?assertEqual({error, {sf_syntax, 2}}, nhttp_accept_query:parse_value(<<"\"a\nb\"">>)).

result_holds_fresh_binaries(_Config) ->
    Pad = binary:copy(<<"p">>, 80),
    Buffer = <<
        (binary:copy(<<"x">>, 4096))/binary,
        "Text/Plain;charset=utf-8;q=\"a\";",
        Pad/binary,
        "=",
        Pad/binary
    >>,
    <<_:4096/binary, Value/binary>> = Buffer,
    ?assert(binary:referenced_byte_size(Value) > byte_size(Value)),
    {ok, [#{type := Type, subtype := Subtype, params := Params}]} =
        nhttp_accept_query:parse_value(Value),
    lists:foreach(
        fun(Bin) -> ?assert(binary:referenced_byte_size(Bin) < byte_size(Buffer), Bin) end,
        [Type, Subtype | lists:append([[K, V] || {K, V} <- Params])]
    ),
    Bad = <<(binary:copy(<<"x">>, 4096))/binary, "text", Pad/binary>>,
    <<_:4096/binary, BadValue/binary>> = Bad,
    ?assert(binary:referenced_byte_size(BadValue) > byte_size(BadValue)),
    {error, {not_media_range, Member}} = nhttp_accept_query:parse_value(BadValue),
    ?assert(binary:referenced_byte_size(Member) < byte_size(Bad), Member).

%%%-----------------------------------------------------------------------------
%%% ENCODE
%%%-----------------------------------------------------------------------------

encode_tokens(_Config) ->
    ?assertEqual(
        {ok, <<"application/sql, */*, text/*;charset=utf-8;a=b">>},
        nhttp_accept_query:encode([
            mt(<<"application">>, <<"sql">>, []),
            mt(<<"*">>, <<"*">>, []),
            mt(<<"text">>, <<"*">>, [{<<"charset">>, <<"utf-8">>}, {<<"a">>, <<"b">>}])
        ])
    ).

encode_strings(_Config) ->
    ?assertEqual(
        {ok, <<"\"3gpp/x\";v=\"1\";w=\"a b\";e=\"\"">>},
        nhttp_accept_query:encode([
            mt(<<"3gpp">>, <<"x">>, [{<<"v">>, <<"1">>}, {<<"w">>, <<"a b">>}, {<<"e">>, <<>>}])
        ])
    ).

encode_lowercases_parameter_names(_Config) ->
    ?assertEqual(
        {ok, <<"text/plain;charset=UTF-8">>},
        nhttp_accept_query:encode([mt(<<"text">>, <<"plain">>, [{<<"Charset">>, <<"UTF-8">>}])])
    ).

encode_rejects_parameter_names(_Config) ->
    lists:foreach(
        fun(Name) ->
            ?assertEqual(
                {error, {invalid_parameter_name, Name}},
                nhttp_accept_query:encode([mt(<<"a">>, <<"b">>, [{Name, <<"v">>}])])
            )
        end,
        [<<>>, <<"1x">>, <<"a b">>, <<"a=b">>, <<"_x">>, <<"x/y">>, <<"a", 16#E9>>]
    ).

encode_escapes_parameter_values(_Config) ->
    ?assertEqual(
        {ok, <<"a/b;t=\"x\\\"y\\\\z\"">>},
        nhttp_accept_query:encode([mt(<<"a">>, <<"b">>, [{<<"t">>, <<"x\"y\\z">>}])])
    ).

encode_rejects_parameter_values(_Config) ->
    lists:foreach(
        fun(Value) ->
            ?assertEqual(
                {error, {invalid_parameter_value, Value}},
                nhttp_accept_query:encode([mt(<<"a">>, <<"b">>, [{<<"t">>, Value}])])
            )
        end,
        [<<"a\tb">>, <<"a\nb">>, <<0>>, <<16#7F>>, <<16#E9>>]
    ).

encode_rejects_media_ranges(_Config) ->
    lists:foreach(
        fun({Type, Subtype}) ->
            ?assertEqual(
                {error, {not_media_range, <<Type/binary, "/", Subtype/binary>>}},
                nhttp_accept_query:encode([
                    mt(<<"a">>, <<"b">>, []), mt(Type, Subtype, [])
                ])
            )
        end,
        [
            {<<"*">>, <<"b">>},
            {<<>>, <<"b">>},
            {<<"a">>, <<>>},
            {<<"text plain">>, <<"b">>},
            {<<"a/b">>, <<"c">>},
            {<<"a">>, <<"b;c">>}
        ]
    ).

%%%-----------------------------------------------------------------------------
%%% ALLOWS
%%%-----------------------------------------------------------------------------

allows_exact_range(_Config) ->
    Ranges = [mt(<<"application">>, <<"sql">>, [])],
    ?assert(nhttp_accept_query:allows(mt(<<"application">>, <<"sql">>, []), Ranges)),
    ?assertNot(nhttp_accept_query:allows(mt(<<"application">>, <<"json">>, []), Ranges)),
    ?assertNot(nhttp_accept_query:allows(mt(<<"text">>, <<"sql">>, []), Ranges)).

allows_type_wildcard(_Config) ->
    Ranges = [mt(<<"text">>, <<"*">>, [])],
    ?assert(nhttp_accept_query:allows(mt(<<"text">>, <<"plain">>, []), Ranges)),
    ?assertNot(nhttp_accept_query:allows(mt(<<"application">>, <<"plain">>, []), Ranges)).

allows_any_wildcard(_Config) ->
    Ranges = [mt(<<"*">>, <<"*">>, [])],
    ?assert(nhttp_accept_query:allows(mt(<<"text">>, <<"plain">>, []), Ranges)),
    ?assert(
        nhttp_accept_query:allows(mt(<<"application">>, <<"sql">>, [{<<"a">>, <<"b">>}]), Ranges)
    ).

allows_never_matches_subtype_wildcard_alone(_Config) ->
    ?assertMatch({error, _}, nhttp_accept_query:parse_value(<<"*/sql">>)),
    ?assertNot(
        nhttp_accept_query:allows(mt(<<"application">>, <<"sql">>, []), [mt(<<"*">>, <<"sql">>, [])])
    ).

allows_parameter_subset(_Config) ->
    Ranges = [mt(<<"text">>, <<"plain">>, [{<<"charset">>, <<"utf-8">>}])],
    Both = mt(<<"text">>, <<"plain">>, [{<<"format">>, <<"flowed">>}, {<<"charset">>, <<"utf-8">>}]),
    ?assert(nhttp_accept_query:allows(Both, Ranges)),
    ?assertNot(nhttp_accept_query:allows(mt(<<"text">>, <<"plain">>, []), Ranges)),
    ?assert(nhttp_accept_query:allows(Both, [mt(<<"text">>, <<"plain">>, [])])),
    ?assert(
        nhttp_accept_query:allows(Both, [mt(<<"*">>, <<"*">>, [{<<"format">>, <<"flowed">>}])])
    ),
    ?assertNot(
        nhttp_accept_query:allows(Both, [mt(<<"text">>, <<"*">>, [{<<"format">>, <<"fixed">>}])])
    ).

allows_charset_without_case(_Config) ->
    Ranges = [mt(<<"text">>, <<"plain">>, [{<<"charset">>, <<"UTF-8">>}])],
    ?assert(
        nhttp_accept_query:allows(
            mt(<<"text">>, <<"plain">>, [{<<"charset">>, <<"utf-8">>}]), Ranges
        )
    ),
    ?assertNot(
        nhttp_accept_query:allows(
            mt(<<"text">>, <<"plain">>, [{<<"format">>, <<"Flowed">>}]),
            [mt(<<"text">>, <<"plain">>, [{<<"format">>, <<"flowed">>}])]
        )
    ).

allows_ignores_order(_Config) ->
    A = mt(<<"application">>, <<"sql">>, []),
    B = mt(<<"text">>, <<"*">>, []),
    lists:foreach(
        fun(Media) ->
            ?assertEqual(
                nhttp_accept_query:allows(Media, [A, B]), nhttp_accept_query:allows(Media, [B, A])
            )
        end,
        [
            mt(<<"application">>, <<"sql">>, []),
            mt(<<"text">>, <<"x">>, []),
            mt(<<"a">>, <<"b">>, [])
        ]
    ).

allows_nothing_from_no_range(_Config) ->
    ?assertNot(nhttp_accept_query:allows(mt(<<"text">>, <<"plain">>, []), [])).

%%%-----------------------------------------------------------------------------
%%% DIFFERENTIAL
%%%-----------------------------------------------------------------------------
structured_field_tests(_Config) ->
    Cases = lists:append([sf_cases(File) || File <- ?SF_FILES]),
    Tally = lists:foldl(fun sf_check/2, #{}, Cases),
    ct:pal("structured-field-tests ~p cases ~0p", [length(Cases), Tally]),
    lists:foreach(
        fun(Kind) -> ?assert(maps:get(Kind, Tally, 0) > 0, {Kind, Tally}) end,
        [must_fail, ranges, not_media_range, unsupported]
    ).

sf_check(#{<<"name">> := Name, <<"raw">> := Raw} = Case, Tally) ->
    Result = nhttp_accept_query:parse([{<<"accept-query">>, Line} || Line <- Raw]),
    Kind = sf_kind(Case),
    CanFail = maps:get(<<"can_fail">>, Case, false) =:= true,
    ?assert(sf_agrees(Kind, CanFail, Result), {Name, Kind, Result}),
    maps:update_with(element(1, Kind), fun(N) -> N + 1 end, 1, Tally).

sf_agrees({must_fail}, _CanFail, Result) ->
    is_error(Result);
sf_agrees(_Kind, true, {error, _}) ->
    true;
sf_agrees({ranges, Ranges}, _CanFail, Result) ->
    Result =:= {ok, Ranges};
sf_agrees({not_media_range, Member}, _CanFail, Result) ->
    Result =:= {error, {not_media_range, Member}};
sf_agrees({unsupported}, _CanFail, {error, {unsupported_item, _}}) ->
    true;
sf_agrees({unsupported}, _CanFail, {error, {unsupported_parameter, _}}) ->
    true;
sf_agrees({unsupported}, _CanFail, _Result) ->
    false.

is_error({error, _}) -> true;
is_error({ok, _}) -> false.

sf_kind(#{<<"must_fail">> := true}) ->
    {must_fail};
sf_kind(#{<<"header_type">> := <<"item">>, <<"expected">> := Item} = Case) ->
    sf_kind(Case#{<<"header_type">> := <<"list">>, <<"expected">> := [Item]});
sf_kind(#{<<"header_type">> := <<"list">>, <<"expected">> := Members}) ->
    case lists:all(fun sf_simple_member/1, Members) of
        true ->
            sf_simple_kind([{sf_text(V), [{K, sf_text(P)} || [K, P] <- Ps]} || [V, Ps] <- Members]);
        false ->
            {unsupported}
    end.

sf_simple_kind(Members) ->
    case [V || {V, _} <- Members, not sf_media_range(V)] of
        [] ->
            {ranges, [
                mt(lower(T), lower(S), Ps)
             || {V, Ps} <- Members, [T, S] <- [binary:split(V, <<"/">>)]
            ]};
        [First | _] ->
            {not_media_range, First}
    end.

sf_simple_member([Value, Params]) ->
    sf_is_text(Value) andalso lists:all(fun([_K, P]) -> sf_is_text(P) end, Params).

sf_is_text(#{<<"__type">> := <<"token">>}) -> true;
sf_is_text(Value) -> is_binary(Value).

sf_text(#{<<"__type">> := <<"token">>, <<"value">> := Value}) -> Value;
sf_text(Value) when is_binary(Value) -> Value.

sf_media_range(Value) ->
    case re:run(Value, "^[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+$") of
        nomatch -> false;
        {match, _} -> binary:match(Value, <<"*/">>) =/= {0, 2} orelse Value =:= <<"*/*">>
    end.

sf_cases(File) ->
    Path = filename:join([project_root(), "test", "fixtures", "structured-field-tests", File]),
    {ok, Json} = file:read_file(Path),
    json:decode(Json).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

mt(Type, Subtype, Params) ->
    #{type => Type, subtype => Subtype, params => Params}.

lower(Bin) ->
    string:lowercase(Bin).

project_root() ->
    find_project_root(filename:dirname(code:which(?MODULE))).

find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true ->
            Dir;
        false ->
            case filename:dirname(Dir) of
                Dir -> Dir;
                Parent -> find_project_root(Parent)
            end
    end.
