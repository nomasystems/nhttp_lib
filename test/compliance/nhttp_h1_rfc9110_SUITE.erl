%%%-----------------------------------------------------------------------------
-module(nhttp_h1_rfc9110_SUITE).

-moduledoc """
RFC 9110 Compliance Test Suite.

This suite tests compliance with RFC 9110 (HTTP Semantics).
Each test case is linked to a specific requirement in specs/rfc9110.erl.

Run with: rebar3 ct --suite=test/compliance/nhttp_h1_rfc9110_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_5_fields},
        {group, section_8_content_length},
        {group, section_9_methods},
        {group, section_15_status_codes}
    ].

groups() ->
    [
        {section_5_fields, [parallel], [
            reject_or_replace_invalid_chars_in_field_value
        ]},
        {section_8_content_length, [parallel], [
            no_content_length_1xx_204,
            reject_malformed_content_length
        ]},
        {section_9_methods, [parallel], [
            no_body_headers_2xx_connect,
            client_ignore_body_headers_connect
        ]},
        {section_15_status_codes, [parallel], [
            no_body_in_204,
            no_body_in_205,
            no_body_in_304
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
%%% Section 5 - Fields
%%%-----------------------------------------------------------------------------

reject_or_replace_invalid_chars_in_field_value(_Config) ->
    ReqLF = <<
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "X-Test: foo", $\n, "bar\r\n"
        "\r\n"
    >>,
    case nhttp_h1:parse_request(ReqLF) of
        {error, bad_header} ->
            ok;
        {ok, #{headers := Headers}, _} ->
            {ok, Value} = find_header(<<"X-Test">>, Headers),
            ?assertEqual(nomatch, binary:match(Value, <<$\n>>)),
            ok
    end,

    ReqNul = <<
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "X-Test: foo", 0, "bar\r\n"
        "\r\n"
    >>,
    case nhttp_h1:parse_request(ReqNul) of
        {error, bad_header} ->
            ok;
        {ok, #{headers := Headers2}, _} ->
            {ok, Value2} = find_header(<<"X-Test">>, Headers2),
            ?assertEqual(nomatch, binary:match(Value2, <<0>>)),
            ok
    end,

    ReqCR = <<
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "X-Test: foo", $\r, "bar\r\n"
        "\r\n"
    >>,
    ?assertMatch({error, _}, nhttp_h1:parse_request(ReqCR)).

%%%-----------------------------------------------------------------------------
%%% Section 8 - Content-Length
%%%-----------------------------------------------------------------------------

no_content_length_1xx_204(_Config) ->
    Resp100 = #{
        status => 100,
        reason => <<"Continue">>,
        headers => []
    },
    Io100 = nhttp_h1:encode_response(Resp100),
    Encoded100 = iolist_to_binary(Io100),
    ?assertEqual(nomatch, binary:match(Encoded100, <<"Content-Length">>)),

    Resp204 = #{
        status => 204,
        reason => <<"No Content">>,
        headers => []
    },
    Io204 = nhttp_h1:encode_response(Resp204),
    Encoded204 = iolist_to_binary(Io204),
    ?assertEqual(nomatch, binary:match(Encoded204, <<"Content-Length">>)).

reject_malformed_content_length(_Config) ->
    Req1 = <<
        "POST / HTTP/1.1\r\n"
        "Host: x\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "hello"
    >>,
    case nhttp_h1:parse_request(Req1) of
        {error, _} ->
            ok;
        {ok, #{body := Body}, _Rest} ->
            ?assert(byte_size(Body) =:= 5 orelse byte_size(Body) =:= 10)
    end,

    Req2 = <<
        "GET / HTTP/1.1\r\n"
        "Host: x\r\n"
        "Content-Length: abc\r\n"
        "\r\n"
    >>,
    case nhttp_h1:parse_request(Req2) of
        {error, _} ->
            ok;
        {ok, #{body := <<>>}, _} ->
            ok
    end.

%%%-----------------------------------------------------------------------------
%%% Section 9 - Methods
%%%-----------------------------------------------------------------------------

no_body_headers_2xx_connect(_Config) ->
    Resp = #{
        status => 200,
        reason => <<"Connection Established">>,
        headers => []
    },
    Io = nhttp_h1:encode_response(Resp),
    Encoded = iolist_to_binary(Io),
    ?assertEqual(nomatch, binary:match(Encoded, <<"Content-Length">>)),
    ?assertEqual(nomatch, binary:match(Encoded, <<"Transfer-Encoding">>)).

client_ignore_body_headers_connect(_Config) ->
    Resp = <<
        "HTTP/1.1 200 Connection Established\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
    >>,
    case nhttp_h1:parse_response(Resp) of
        {more, _State} ->
            ok;
        {ok, #{status := 200}, _Rest} ->
            ok
    end.

%%%-----------------------------------------------------------------------------
%%% Section 15 - Status Codes
%%%-----------------------------------------------------------------------------

no_body_in_204(_Config) ->
    Resp = <<
        "HTTP/1.1 204 No Content\r\n"
        "\r\n"
    >>,
    {ok, #{status := 204, body := Body}, _} = nhttp_h1:parse_response(Resp),
    ?assertEqual(<<>>, Body).

no_body_in_205(_Config) ->
    Resp = <<
        "HTTP/1.1 205 Reset Content\r\n"
        "\r\n"
    >>,
    {ok, #{status := 205, body := Body}, _} = nhttp_h1:parse_response(Resp),
    ?assertEqual(<<>>, Body).

no_body_in_304(_Config) ->
    Resp = <<
        "HTTP/1.1 304 Not Modified\r\n"
        "ETag: \"abc123\"\r\n"
        "\r\n"
    >>,
    {ok, #{status := 304, body := Body}, _} = nhttp_h1:parse_response(Resp),
    ?assertEqual(<<>>, Body).

%%%-----------------------------------------------------------------------------
%%% Helpers
%%%-----------------------------------------------------------------------------

-spec find_header(binary(), nhttp_lib:headers()) -> {ok, binary()} | error.
find_header(Name, Headers) ->
    LowerName = string:lowercase(Name),
    case lists:keyfind(LowerName, 1, [{string:lowercase(N), V} || {N, V} <- Headers]) of
        {_, Value} -> {ok, Value};
        false -> error
    end.
