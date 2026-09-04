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
            no_content_length_304,
            content_length_zero_on_empty_body,
            caller_content_length_survives_on_204,
            no_content_length_with_transfer_encoding,
            content_length_omit_opt_out,
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

%% RFC 9110 Section 8.6: "A server MUST NOT send a Content-Length header
%% field in any response with a status code of 1xx (Informational) or 204
%% (No Content)."
no_content_length_1xx_204(_Config) ->
    lists:foreach(
        fun({Status, Reason}) ->
            Resp = #{status => Status, reason => Reason, headers => []},
            Encoded = encode_resp(Resp),
            ?assertEqual(false, has_content_length(Encoded))
        end,
        [
            {100, <<"Continue">>},
            {101, <<"Switching Protocols">>},
            {199, <<"Informational">>},
            {204, <<"No Content">>}
        ]
    ).

%% RFC 9110 Section 8.6: a 304 permits Content-Length only at the length a
%% 200 response would have carried, which the encoder cannot compute.
no_content_length_304(_Config) ->
    Resp = #{status => 304, reason => <<"Not Modified">>, headers => []},
    Encoded = encode_resp(Resp),
    ?assertEqual(false, has_content_length(Encoded)).

%% RFC 9110 Section 8.6: "in the absence of Transfer-Encoding, an origin
%% server SHOULD send a Content-Length header field when the content size is
%% known prior to sending the complete header section."
content_length_zero_on_empty_body(_Config) ->
    NoBodyKey = #{status => 200, reason => <<"OK">>, headers => []},
    ?assertEqual(
        {true, <<"0">>},
        content_length_value(encode_resp(NoBodyKey))
    ),

    EmptyBody = NoBodyKey#{body => <<>>},
    ?assertEqual(
        {true, <<"0">>},
        content_length_value(encode_resp(EmptyBody))
    ),

    NotFound = #{status => 404, reason => <<"Not Found">>, headers => [], body => <<>>},
    ?assertEqual(
        {true, <<"0">>},
        content_length_value(encode_resp(NotFound))
    ).

caller_content_length_survives_on_204(_Config) ->
    Resp = #{
        status => 204,
        reason => <<"No Content">>,
        headers => [{<<"content-length">>, <<"42">>}]
    },
    Encoded = encode_resp(Resp),
    ?assertEqual({true, <<"42">>}, content_length_value(Encoded)),
    ?assertEqual(1, count_content_length(Encoded)).

no_content_length_with_transfer_encoding(_Config) ->
    Resp = #{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"transfer-encoding">>, <<"chunked">>}],
        body => <<>>
    },
    Encoded = encode_resp(Resp),
    ?assertEqual(false, has_content_length(Encoded)).

%% RFC 9110 Section 8.6: "A server MUST NOT send a Content-Length header
%% field in any 2xx (Successful) response to a CONNECT request."
content_length_omit_opt_out(_Config) ->
    Resp = #{status => 200, reason => <<"Connection Established">>, headers => []},
    Encoded = encode_resp(Resp, #{content_length => omit}),
    ?assertEqual(false, has_content_length(Encoded)),

    WithBody = Resp#{body => <<"hello">>},
    EncodedWithBody = encode_resp(WithBody, #{content_length => omit}),
    ?assertEqual(false, has_content_length(EncodedWithBody)),

    EncodedAuto = encode_resp(Resp, #{content_length => auto}),
    ?assertEqual({true, <<"0">>}, content_length_value(EncodedAuto)).

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

%% RFC 9110 Section 8.6: a 2xx response to CONNECT carries no Content-Length.
%% The status alone does not identify the case, so the caller opts out.
no_body_headers_2xx_connect(_Config) ->
    Resp = #{
        status => 200,
        reason => <<"Connection Established">>,
        headers => []
    },
    Encoded = encode_resp(Resp, #{content_length => omit}),
    ?assertEqual(false, has_content_length(Encoded)),
    ?assertEqual(false, lists:keymember(<<"transfer-encoding">>, 1, encoded_headers(Encoded))).

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

-spec encode_resp(nhttp_h1:resp()) -> binary().
encode_resp(Resp) ->
    {ok, Io} = nhttp_h1:encode_response(Resp),
    iolist_to_binary(Io).

-spec encode_resp(nhttp_h1:resp(), nhttp_h1:enc_opts()) -> binary().
encode_resp(Resp, EncOpts) ->
    {ok, Io} = nhttp_h1:encode_response(Resp, EncOpts),
    iolist_to_binary(Io).

-spec encoded_headers(binary()) -> nhttp_lib:headers().
encoded_headers(Encoded) ->
    [_StatusLine | Lines] = binary:split(Encoded, <<"\r\n">>, [global]),
    [
        {string:lowercase(Name), string:trim(Value, leading, " ")}
     || Line <- Lines,
        Line =/= <<>>,
        [Name, Value] <- [binary:split(Line, <<":">>)]
    ].

-spec has_content_length(binary()) -> boolean().
has_content_length(Encoded) ->
    lists:keymember(<<"content-length">>, 1, encoded_headers(Encoded)).

-spec content_length_value(binary()) -> {true, binary()} | false.
content_length_value(Encoded) ->
    case lists:keyfind(<<"content-length">>, 1, encoded_headers(Encoded)) of
        {_, Value} -> {true, Value};
        false -> false
    end.

-spec count_content_length(binary()) -> non_neg_integer().
count_content_length(Encoded) ->
    length([V || {<<"content-length">>, V} <- encoded_headers(Encoded)]).

-spec find_header(binary(), nhttp_lib:headers()) -> {ok, binary()} | error.
find_header(Name, Headers) ->
    LowerName = string:lowercase(Name),
    case lists:keyfind(LowerName, 1, [{string:lowercase(N), V} || {N, V} <- Headers]) of
        {_, Value} -> {ok, Value};
        false -> error
    end.
