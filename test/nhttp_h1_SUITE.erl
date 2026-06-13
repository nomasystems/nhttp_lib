%%%-----------------------------------------------------------------------------
-module(nhttp_h1_SUITE).

-moduledoc "HTTP/1.1 codec test suite.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, request_parsing},
        {group, response_parsing},
        {group, encoding},
        {group, streaming},
        {group, streaming_request},
        {group, chunked},
        {group, utilities},
        {group, reason_phrases},
        {group, edge_cases},
        {group, limits}
    ].

groups() ->
    [
        {request_parsing, [parallel], [
            parse_simple_get,
            parse_get_with_headers,
            parse_post_with_body,
            parse_all_methods,
            parse_connect_method,
            parse_custom_method,
            parse_query_string,
            parse_empty_request,
            reject_invalid_request_line,
            reject_invalid_method,
            reject_invalid_version,
            reject_whitespace_before_colon,
            parse_populates_version,
            parse_populates_default_scheme,
            parse_populates_scheme_from_opts,
            parse_populates_authority_from_host,
            parse_populates_authority_from_absolute_uri,
            parse_populates_authority_https_absolute_uri,
            parse_populates_authority_absolute_uri_no_path,
            parse_populates_authority_absolute_uri_empty_path_falls_back_to_host,
            parse_populates_authority_empty_when_missing,
            parse_populates_peer_from_opts,
            parse_omits_peer_when_not_supplied
        ]},
        {response_parsing, [parallel], [
            parse_simple_response,
            parse_response_with_body,
            parse_response_no_body,
            parse_common_status_codes,
            parse_302_found,
            parse_http1_0_response,
            parse_empty_response,
            parse_generic_status,
            parse_invalid_content_length,
            parse_zero_content_length,
            reject_invalid_status_line,
            reject_status_line_missing_code,
            reject_status_line_invalid_digit
        ]},
        {encoding, [parallel], [
            encode_simple_request,
            encode_request_with_body,
            encode_request_custom_method,
            encode_request_all_methods,
            encode_request_http1_0,
            encode_request_rejects_h2_h3,
            encode_simple_response,
            encode_response_with_body,
            encode_response_no_body,
            encode_response_head,
            encode_response_existing_content_length,
            encode_response_transfer_encoding
        ]},
        {streaming, [sequence], [
            parse_partial_request_line,
            parse_partial_headers,
            parse_partial_body,
            parse_multi_chunk_data,
            parse_partial_method,
            parse_partial_path,
            parse_partial_response_reason,
            parse_partial_content_length_body,
            parse_partial_chunked_body
        ]},
        {streaming_request, [parallel], [
            headers_only_no_body,
            headers_then_content_length_body_full,
            headers_then_content_length_partial_then_complete,
            headers_then_chunked_simple,
            headers_then_chunked_multiple_chunks,
            headers_then_chunked_with_trailers,
            headers_then_chunked_partial_size,
            headers_then_chunked_partial_data,
            headers_then_chunked_invalid_size,
            headers_then_streaming_marker
        ]},
        {chunked, [parallel], [
            parse_chunked_request,
            parse_chunked_response,
            parse_multiple_chunks,
            parse_chunked_partial,
            parse_invalid_chunk_size,
            encode_chunk,
            encode_chunk_iolist,
            encode_last_chunk,
            parse_chunked_with_trailers,
            parse_chunked_partial_trailers,
            parse_chunked_with_extension
        ]},
        {utilities, [parallel], [
            split_at_test,
            encode_method_coverage
        ]},
        {reason_phrases, [parallel], [
            reason_phrase_informational,
            reason_phrase_success,
            reason_phrase_redirect,
            reason_phrase_client_error,
            reason_phrase_server_error,
            reason_phrase_unknown
        ]},
        {edge_cases, [parallel], [
            parse_response_headers_test,
            parse_response_headers_empty,
            parse_response_headers_partial,
            parse_response_headers_error,
            parse_request_cold_path,
            parse_request_version_edge_cases,
            parse_request_crlf_early,
            parse_request_short_buffer,
            parse_request_http1_0,
            parse_header_edge_cases,
            parse_content_length_negative,
            parse_unknown_method_with_crlf_before_space,
            parse_unknown_method_long,
            parse_unknown_method_success,
            parse_path_without_http_version,
            parse_path_with_http_but_wrong_version,
            encode_response_head_all_status,
            parse_partial_version_digit,
            parse_chunked_multiple_trailer_fields,
            parse_header_empty_value,
            parse_response_http1_0_generic,
            fast_path_matches_generic_path,
            fast_path_rejects_invalid_value,
            fast_path_trims_value_ows
        ]},
        {limits, [parallel], [
            limit_header_size_exceeded_request,
            limit_header_size_exceeded_response,
            limit_header_count_exceeded_request,
            limit_header_count_exceeded_response,
            limit_body_size_exceeded_request,
            limit_body_size_exceeded_response,
            limit_body_size_chunked_request,
            limit_body_size_chunked_response,
            limit_within_bounds_request,
            limit_within_bounds_response,
            limit_infinity_allows_all,
            duplicate_content_length_different_values_request,
            duplicate_content_length_different_values_response,
            duplicate_content_length_same_values_request,
            duplicate_content_length_same_values_response,
            te_and_content_length_request_rejected,
            te_and_content_length_response_rejected,
            limit_incomplete_head_capped_parse_request,
            limit_incomplete_head_capped_parse_request_headers,
            limit_incomplete_request_line_capped,
            limit_incomplete_head_below_cap_returns_more,
            limit_incomplete_head_unbounded_without_limit,
            limit_incomplete_trailers_capped,
            limit_chunk_size_line_capped
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

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% REQUEST PARSING TESTS
%%%-----------------------------------------------------------------------------

parse_simple_get(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(get, maps:get(method, Req)),
    ?assertEqual(<<"/">>, maps:get(path, Req)),
    ?assertEqual(http1_1, maps:get(version, Req)),
    ?assertEqual([{<<"host">>, <<"localhost">>}], maps:get(headers, Req)).

parse_get_with_headers(_Config) ->
    Data =
        <<"GET /path HTTP/1.1\r\n", "Host: example.com\r\n", "Accept: text/html\r\n",
            "User-Agent: test\r\n", "\r\n">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(get, maps:get(method, Req)),
    ?assertEqual(<<"/path">>, maps:get(path, Req)),
    ?assertEqual(3, length(maps:get(headers, Req))).

parse_post_with_body(_Config) ->
    Body = <<"hello world">>,
    Data =
        <<"POST /submit HTTP/1.1\r\n", "Host: localhost\r\n", "Content-Length: 11\r\n", "\r\n",
            Body/binary>>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(post, maps:get(method, Req)),
    ?assertEqual(<<"/submit">>, maps:get(path, Req)),
    ?assertEqual(Body, maps:get(body, Req)).

parse_all_methods(_Config) ->
    Methods = [get, head, post, put, delete, options, trace, patch],
    lists:foreach(
        fun(Method) ->
            MethodBin = nhttp_lib:encode_method(Method),
            Data = <<MethodBin/binary, " / HTTP/1.1\r\nHost: x\r\n\r\n">>,
            {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
            ?assertEqual(byte_size(Data), Consumed),
            ?assertEqual(Method, maps:get(method, Req))
        end,
        Methods
    ).

parse_connect_method(_Config) ->
    Data = <<"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(connect, maps:get(method, Req)).

parse_custom_method(_Config) ->
    Data = <<"CUSTOM /path HTTP/1.1\r\nHost: x\r\n\r\n">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(<<"CUSTOM">>, maps:get(method, Req)).

parse_query_string(_Config) ->
    Data = <<"GET /search?q=test&page=1 HTTP/1.1\r\nHost: x\r\n\r\n">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(<<"/search?q=test&page=1">>, maps:get(path, Req)).

parse_empty_request(_Config) ->
    {more, 1} = nhttp_h1:parse_request(<<>>).

reject_invalid_request_line(_Config) ->
    {error, bad_request_line} = nhttp_h1:parse_request(<<"GET\r\n">>),
    {error, bad_request_line} = nhttp_h1:parse_request(<<"GET /\r\n">>),
    {error, bad_request_line} = nhttp_h1:parse_request(<<"\r\n">>).

reject_invalid_method(_Config) ->
    {error, invalid_method} = nhttp_h1:parse_request(<<"get / HTTP/1.1\r\n\r\n">>).

reject_invalid_version(_Config) ->
    {error, invalid_version} = nhttp_h1:parse_request(<<"GET / HTTP/2.0\r\n\r\n">>).

parse_populates_version(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(http1_1, maps:get(version, Req)).

parse_populates_default_scheme(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(http, maps:get(scheme, Req)).

parse_populates_scheme_from_opts(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data, #{scheme => https}),
    ?assertEqual(https, maps:get(scheme, Req)).

parse_populates_authority_from_host(_Config) ->
    Data = <<"GET /path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(<<"example.com:8080">>, maps:get(authority, Req)).

parse_populates_authority_from_absolute_uri(_Config) ->
    Data = <<"GET http://origin.example.com/foo HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(<<"origin.example.com">>, maps:get(authority, Req)).

parse_populates_authority_https_absolute_uri(_Config) ->
    Data = <<"GET https://example.com:8443/x?q=1 HTTP/1.1\r\nHost: ignored\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(<<"example.com:8443">>, maps:get(authority, Req)).

parse_populates_authority_absolute_uri_no_path(_Config) ->
    Data = <<"GET http://example.com HTTP/1.1\r\nHost: ignored\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(<<"example.com">>, maps:get(authority, Req)).

parse_populates_authority_absolute_uri_empty_path_falls_back_to_host(_Config) ->
    Data = <<"GET http:/// HTTP/1.1\r\nHost: fallback.example\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(<<"fallback.example">>, maps:get(authority, Req)).

parse_populates_authority_empty_when_missing(_Config) ->
    Data = <<"GET / HTTP/1.0\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(<<>>, maps:get(authority, Req)).

parse_populates_peer_from_opts(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n">>,
    Peer = {{127, 0, 0, 1}, 54321},
    {ok, Req, _} = nhttp_h1:parse_request(Data, #{peer => Peer}),
    ?assertEqual(Peer, maps:get(peer, Req)).

parse_omits_peer_when_not_supplied(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertNot(maps:is_key(peer, Req)).

reject_whitespace_before_colon(_Config) ->
    {error, bad_header} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r\nHost : x\r\n\r\n">>).

%%%-----------------------------------------------------------------------------
%%% RESPONSE PARSING TESTS
%%%-----------------------------------------------------------------------------

parse_simple_response(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(200, maps:get(status, Resp)),
    ?assertEqual(<<"OK">>, maps:get(reason, Resp)),
    ?assertEqual(<<"hello">>, maps:get(body, Resp)).

parse_response_with_body(_Config) ->
    Body = <<"response body content">>,
    Len = integer_to_binary(byte_size(Body)),
    Data =
        <<"HTTP/1.1 201 Created\r\n", "Content-Length: ", Len/binary, "\r\n", "\r\n", Body/binary>>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(201, maps:get(status, Resp)),
    ?assertEqual(Body, maps:get(body, Resp)).

parse_response_no_body(_Config) ->
    Data = <<"HTTP/1.1 204 No Content\r\n\r\n">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(204, maps:get(status, Resp)),
    ?assertEqual(<<>>, maps:get(body, Resp)).

parse_common_status_codes(_Config) ->
    Codes = [
        {200, <<"OK">>},
        {301, <<"Moved Permanently">>},
        {400, <<"Bad Request">>},
        {404, <<"Not Found">>},
        {500, <<"Internal Server Error">>}
    ],
    lists:foreach(
        fun({Code, Reason}) ->
            CodeBin = integer_to_binary(Code),
            Data = <<"HTTP/1.1 ", CodeBin/binary, " ", Reason/binary, "\r\n\r\n">>,
            {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
            ?assertEqual(byte_size(Data), Consumed),
            ?assertEqual(Code, maps:get(status, Resp))
        end,
        Codes
    ).

parse_302_found(_Config) ->
    Data = <<"HTTP/1.1 302 Found\r\n\r\n">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(302, maps:get(status, Resp)),
    ?assertEqual(<<"Found">>, maps:get(reason, Resp)).

parse_http1_0_response(_Config) ->
    Data = <<"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(http1_0, maps:get(version, Resp)),
    ?assertEqual(200, maps:get(status, Resp)),
    ?assertEqual(<<"ok">>, maps:get(body, Resp)).

parse_empty_response(_Config) ->
    {more, 1} = nhttp_h1:parse_response(<<>>).

parse_generic_status(_Config) ->
    Data = <<"HTTP/1.1 418 I'm a teapot\r\n\r\n">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(418, maps:get(status, Resp)),
    ?assertEqual(<<"I'm a teapot">>, maps:get(reason, Resp)).

reject_invalid_status_line(_Config) ->
    {error, bad_status_line} = nhttp_h1:parse_response(<<"HTTP/1.1\r\n">>),
    {error, bad_status_line} = nhttp_h1:parse_response(<<"HTTP/1.1 abc OK\r\n">>).

reject_status_line_missing_code(_Config) ->
    {error, bad_status_line} = nhttp_h1:parse_response(<<"HTTP/1.0\r\n">>).

reject_status_line_invalid_digit(_Config) ->
    {error, bad_status_line} = nhttp_h1:parse_response(<<"HTTP/1.1 XYZ\r\n">>),
    {error, bad_status_line} = nhttp_h1:parse_response(<<"HTTP/1.0 ABC\r\n">>).

parse_invalid_content_length(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n">>,
    ?assertEqual({error, invalid_content_length}, nhttp_h1:parse_response(Data)).

parse_zero_content_length(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n">>,
    {ok, Resp, _Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(<<>>, maps:get(body, Resp)).

%%%-----------------------------------------------------------------------------
%%% ENCODING TESTS
%%%-----------------------------------------------------------------------------

encode_simple_request(_Config) ->
    Req = #{
        method => get,
        path => <<"/">>,
        headers => [{<<"Host">>, <<"localhost">>}]
    },
    IOList = nhttp_h1:encode_request(Req),
    Bin = iolist_to_binary(IOList),
    ?assertMatch(<<"GET / HTTP/1.1\r\n", _/binary>>, Bin),
    ?assertMatch({match, _}, re:run(Bin, <<"Host: localhost">>)).

encode_request_with_body(_Config) ->
    Req = #{
        method => post,
        path => <<"/submit">>,
        headers => [{<<"Host">>, <<"localhost">>}],
        body => <<"test body">>
    },
    IOList = nhttp_h1:encode_request(Req),
    Bin = iolist_to_binary(IOList),
    ?assertMatch(<<"POST /submit HTTP/1.1\r\n", _/binary>>, Bin),
    ?assertMatch({match, _}, re:run(Bin, <<"Content-Length: 9">>, [caseless])),
    ?assertMatch({match, _}, re:run(Bin, <<"test body">>)).

encode_request_custom_method(_Config) ->
    Req = #{
        method => <<"PROPFIND">>,
        path => <<"/">>,
        headers => []
    },
    IOList = nhttp_h1:encode_request(Req),
    Bin = iolist_to_binary(IOList),
    ?assertMatch(<<"PROPFIND / HTTP/1.1\r\n", _/binary>>, Bin).

encode_request_all_methods(_Config) ->
    Methods = [get, head, post, put, delete, connect, options, trace, patch],
    lists:foreach(
        fun(Method) ->
            Req = #{method => Method, path => <<"/">>, headers => []},
            IOList = nhttp_h1:encode_request(Req),
            Bin = iolist_to_binary(IOList),
            MethodBin = nhttp_lib:encode_method(Method),
            ?assertMatch({match, _}, re:run(Bin, MethodBin))
        end,
        Methods
    ).

encode_request_http1_0(_Config) ->
    Req = #{
        method => get,
        path => <<"/">>,
        version => http1_0,
        headers => []
    },
    IOList = nhttp_h1:encode_request(Req),
    Bin = iolist_to_binary(IOList),
    ?assertMatch(<<"GET / HTTP/1.0\r\n", _/binary>>, Bin).

encode_request_rejects_h2_h3(_Config) ->
    Req = #{method => get, path => <<"/">>, version => http1_1, headers => []},
    ?assertError(function_clause, nhttp_h1:encode_request(Req#{version => http2})),
    ?assertError(function_clause, nhttp_h1:encode_request(Req#{version => http3})).

encode_simple_response(_Config) ->
    Resp = #{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"Content-Type">>, <<"text/plain">>}],
        body => <<"hello">>
    },
    IOList = nhttp_h1:encode_response(Resp),
    Bin = iolist_to_binary(IOList),
    ?assertMatch(<<"HTTP/1.1 200 OK\r\n", _/binary>>, Bin),
    ?assertMatch({match, _}, re:run(Bin, <<"Content-Length: 5">>, [caseless])),
    ?assertMatch({match, _}, re:run(Bin, <<"hello">>)).

encode_response_with_body(_Config) ->
    Body = <<"longer response body">>,
    Resp = #{
        status => 201,
        reason => <<"Created">>,
        headers => [],
        body => Body
    },
    IOList = nhttp_h1:encode_response(Resp),
    Bin = iolist_to_binary(IOList),
    ?assertMatch({match, _}, re:run(Bin, Body)).

encode_response_no_body(_Config) ->
    Resp = #{
        status => 204,
        reason => <<"No Content">>,
        headers => []
    },
    IOList = nhttp_h1:encode_response(Resp),
    Bin = iolist_to_binary(IOList),
    ?assertMatch(<<"HTTP/1.1 204 No Content\r\n", _/binary>>, Bin).

encode_response_head(_Config) ->
    IOList = nhttp_h1:encode_response_head(
        http1_1, 200, [{<<"Transfer-Encoding">>, <<"chunked">>}]
    ),
    Bin = iolist_to_binary(IOList),
    ?assertMatch(<<"HTTP/1.1 200 OK\r\n", _/binary>>, Bin),
    ?assertMatch({match, _}, re:run(Bin, <<"Transfer-Encoding: chunked">>)),
    IOList10 = nhttp_h1:encode_response_head(http1_0, 200, []),
    ?assertMatch(<<"HTTP/1.0 200 OK\r\n", _/binary>>, iolist_to_binary(IOList10)).

encode_response_existing_content_length(_Config) ->
    Resp = #{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"content-length">>, <<"5">>}],
        body => <<"hello">>
    },
    IOList = nhttp_h1:encode_response(Resp),
    Bin = iolist_to_binary(IOList),
    {match, Matches} = re:run(Bin, <<"content-length">>, [global]),
    ?assertEqual(1, length(Matches)).

encode_response_transfer_encoding(_Config) ->
    Resp = #{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"transfer-encoding">>, <<"chunked">>}],
        body => <<"hello">>
    },
    IOList = nhttp_h1:encode_response(Resp),
    Bin = iolist_to_binary(IOList),
    ?assertEqual(nomatch, re:run(Bin, <<"content-length">>)).

%%%-----------------------------------------------------------------------------
%%% STREAMING TESTS (stateless - test {more, N} returns)
%%%-----------------------------------------------------------------------------

parse_partial_request_line(_Config) ->
    {more, _} = nhttp_h1:parse_request(<<"GET / HT">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r\nHost: x">>),
    Data = <<"GET / HTTP/1.1\r\nHost: x\r\n\r\n">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(get, maps:get(method, Req)).

parse_partial_headers(_Config) ->
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r\nHost: lo">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: ">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r\nHost: localhost\r">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r\nHos">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r\nHost: val\r">>),
    Data = <<"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(2, length(maps:get(headers, Req))).

parse_partial_body(_Config) ->
    {more, N} = nhttp_h1:parse_request(<<"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhel">>),
    ?assertEqual(7, N),
    Data = <<"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nhelloworld">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(<<"helloworld">>, maps:get(body, Req)).

parse_multi_chunk_data(_Config) ->
    Parts = [<<"G">>, <<"ET ">>, <<"/ ">>, <<"HTTP/1.1\r">>, <<"\nHost: x\r\n\r\n">>],
    Data = iolist_to_binary(Parts),
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(get, maps:get(method, Req)).

parse_partial_method(_Config) ->
    {more, _} = nhttp_h1:parse_request(<<"PROPFIN">>),
    {more, _} = nhttp_h1:parse_request(<<"MKCOL">>).

parse_partial_path(_Config) ->
    {more, _} = nhttp_h1:parse_request(<<"GET /some/long/path">>).

parse_partial_response_reason(_Config) ->
    {more, _} = nhttp_h1:parse_response(<<"HTTP/1.1 418 I'm a teapo">>),
    {more, _} = nhttp_h1:parse_response(<<"HTTP/1.1 20">>).

parse_partial_content_length_body(_Config) ->
    {more, _} = nhttp_h1:parse_response(<<"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel">>).

parse_partial_chunked_body(_Config) ->
    {more, _} = nhttp_h1:parse_response(
        <<"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel">>
    ),
    {more, _} = nhttp_h1:parse_response(
        <<"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n">>
    ).

%%%-----------------------------------------------------------------------------
%%% CHUNKED TRANSFER TESTS
%%%-----------------------------------------------------------------------------

parse_chunked_request(_Config) ->
    Data =
        <<"POST / HTTP/1.1\r\n", "Host: x\r\n", "Transfer-Encoding: chunked\r\n", "\r\n",
            "5\r\nhello\r\n", "0\r\n\r\n">>,
    {ok, Req, Consumed} = nhttp_h1:parse_request(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(<<"hello">>, maps:get(body, Req)).

parse_chunked_response(_Config) ->
    Data =
        <<"HTTP/1.1 200 OK\r\n", "Transfer-Encoding: chunked\r\n", "\r\n", "5\r\nhello\r\n",
            "0\r\n\r\n">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(<<"hello">>, maps:get(body, Resp)).

parse_multiple_chunks(_Config) ->
    Data =
        <<"HTTP/1.1 200 OK\r\n", "Transfer-Encoding: chunked\r\n", "\r\n", "5\r\nhello\r\n",
            "1\r\n \r\n", "5\r\nworld\r\n", "0\r\n\r\n">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(<<"hello world">>, maps:get(body, Resp)).

parse_chunked_partial(_Config) ->
    Data = <<"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel">>,
    {more, _} = nhttp_h1:parse_request(Data),
    Data2 = <<"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    {more, _} = nhttp_h1:parse_request(Data2).

parse_invalid_chunk_size(_Config) ->
    Data = <<"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nXYZ\r\nhello\r\n0\r\n\r\n">>,
    {error, invalid_chunk_size} = nhttp_h1:parse_request(Data).

encode_chunk(_Config) ->
    Chunk = nhttp_h1:encode_chunk(<<"hello">>),
    Bin = iolist_to_binary(Chunk),
    ?assertEqual(<<"5\r\nhello\r\n">>, Bin).

encode_chunk_iolist(_Config) ->
    Chunk = nhttp_h1:encode_chunk(["hel", "lo"]),
    Bin = iolist_to_binary(Chunk),
    ?assertEqual(<<"5\r\nhello\r\n">>, Bin).

encode_last_chunk(_Config) ->
    Last = nhttp_h1:encode_last_chunk(),
    ?assertEqual(<<"0\r\n\r\n">>, Last).

%%%-----------------------------------------------------------------------------
%%% ADDITIONAL COVERAGE TESTS
%%%-----------------------------------------------------------------------------

split_at_test(_Config) ->
    ?assertEqual(<<"world">>, nhttp_h1:split_at(<<"hello world">>, 6)),
    ?assertEqual(<<"">>, nhttp_h1:split_at(<<"hello">>, 5)),
    ?assertEqual(<<"hello">>, nhttp_h1:split_at(<<"hello">>, 0)).

parse_response_headers_test(_Config) ->
    Data =
        <<"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom: value\r\n\r\nbody content here">>,
    {ok, Status, Headers, Rest} = nhttp_h1:parse_response_headers(Data),
    ?assertEqual(200, Status),
    ?assertEqual(2, length(Headers)),
    ?assertEqual(<<"body content here">>, Rest).

parse_response_headers_empty(_Config) ->
    {more, 1} = nhttp_h1:parse_response_headers(<<>>).

parse_response_headers_partial(_Config) ->
    {more, _} = nhttp_h1:parse_response_headers(<<"HTTP/1.1 20">>),
    {more, _} = nhttp_h1:parse_response_headers(<<"HTTP/1.1 200 OK\r\nContent-Type: tex">>).

parse_response_headers_error(_Config) ->
    {error, bad_status_line} = nhttp_h1:parse_response_headers(
        <<"INVALID STATUS LINE HERE\r\n\r\n">>
    ).

reason_phrase_informational(_Config) ->
    Data = <<"HTTP/1.1 100 Continue\r\n\r\n">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    ?assertEqual(100, maps:get(status, Resp)),

    Data2 = <<"HTTP/1.1 101 Switching Protocols\r\n\r\n">>,
    {ok, Resp2, _} = nhttp_h1:parse_response(Data2),
    ?assertEqual(101, maps:get(status, Resp2)).

reason_phrase_success(_Config) ->
    Data = <<"HTTP/1.1 202 Accepted\r\n\r\n">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    ?assertEqual(202, maps:get(status, Resp)),

    Data2 = <<"HTTP/1.1 206 Partial Content\r\nContent-Length: 0\r\n\r\n">>,
    {ok, Resp2, _} = nhttp_h1:parse_response(Data2),
    ?assertEqual(206, maps:get(status, Resp2)).

reason_phrase_redirect(_Config) ->
    Data = <<"HTTP/1.1 303 See Other\r\n\r\n">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    ?assertEqual(303, maps:get(status, Resp)),

    Data2 = <<"HTTP/1.1 307 Temporary Redirect\r\n\r\n">>,
    {ok, Resp2, _} = nhttp_h1:parse_response(Data2),
    ?assertEqual(307, maps:get(status, Resp2)),

    Data3 = <<"HTTP/1.1 308 Permanent Redirect\r\n\r\n">>,
    {ok, Resp3, _} = nhttp_h1:parse_response(Data3),
    ?assertEqual(308, maps:get(status, Resp3)).

reason_phrase_client_error(_Config) ->
    Tests = [
        {405, <<"Method Not Allowed">>},
        {408, <<"Request Timeout">>},
        {409, <<"Conflict">>},
        {410, <<"Gone">>},
        {411, <<"Length Required">>},
        {413, <<"Content Too Large">>},
        {414, <<"URI Too Long">>},
        {415, <<"Unsupported Media Type">>},
        {416, <<"Range Not Satisfiable">>},
        {417, <<"Expectation Failed">>},
        {422, <<"Unprocessable Content">>},
        {426, <<"Upgrade Required">>},
        {429, <<"Too Many Requests">>}
    ],
    lists:foreach(
        fun({Code, Reason}) ->
            CodeBin = integer_to_binary(Code),
            Data = <<"HTTP/1.1 ", CodeBin/binary, " ", Reason/binary, "\r\n\r\n">>,
            {ok, Resp, _} = nhttp_h1:parse_response(Data),
            ?assertEqual(Code, maps:get(status, Resp))
        end,
        Tests
    ).

reason_phrase_server_error(_Config) ->
    Data = <<"HTTP/1.1 501 Not Implemented\r\n\r\n">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    ?assertEqual(501, maps:get(status, Resp)),

    Data2 = <<"HTTP/1.1 504 Gateway Timeout\r\n\r\n">>,
    {ok, Resp2, _} = nhttp_h1:parse_response(Data2),
    ?assertEqual(504, maps:get(status, Resp2)),

    Data3 = <<"HTTP/1.1 505 HTTP Version Not Supported\r\n\r\n">>,
    {ok, Resp3, _} = nhttp_h1:parse_response(Data3),
    ?assertEqual(505, maps:get(status, Resp3)).

reason_phrase_unknown(_Config) ->
    IOList = nhttp_h1:encode_response_head(http1_1, 999, []),
    Bin = iolist_to_binary(IOList),
    ?assertMatch(<<"HTTP/1.1 999 \r\n", _/binary>>, Bin).

parse_request_cold_path(_Config) ->
    {more, _} = nhttp_h1:parse_request(<<"SUPERLONGMETH">>).

parse_request_version_edge_cases(_Config) ->
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.1">>),
    {error, invalid_version} = nhttp_h1:parse_request(<<"GET / HTTP/1.2\r\n">>).

parse_request_crlf_early(_Config) ->
    {error, bad_request_line} = nhttp_h1:parse_request(<<"\r\nGET / HTTP/1.1\r\n">>).

parse_request_short_buffer(_Config) ->
    {more, _} = nhttp_h1:parse_request(<<"G">>),
    {more, _} = nhttp_h1:parse_request(<<"GE">>),
    {more, _} = nhttp_h1:parse_request(<<"GET">>).

parse_request_http1_0(_Config) ->
    Data = <<"GET / HTTP/1.0\r\nHost: x\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(http1_0, maps:get(version, Req)).

parse_header_edge_cases(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost:\t  localhost  \r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual([{<<"host">>, <<"localhost">>}], maps:get(headers, Req)),
    {error, bad_header} = nhttp_h1:parse_request(<<"GET / HTTP/1.1\r\nInvalid\r\n\r\n">>),
    {error, bad_header} = nhttp_h1:parse_request(
        <<"GET / HTTP/1.1\r\nHost: bad\x00value\r\n\r\n">>
    ),
    {error, bad_header} = nhttp_h1:parse_request(
        <<"GET / HTTP/1.1\r\nHost \t: localhost\r\n\r\n">>
    ).

parse_content_length_negative(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n">>,
    ?assertEqual({error, invalid_content_length}, nhttp_h1:parse_response(Data)).

parse_chunked_with_trailers(_Config) ->
    Data =
        <<"HTTP/1.1 200 OK\r\n", "Transfer-Encoding: chunked\r\n", "\r\n", "5\r\nhello\r\n",
            "0\r\n", "X-Checksum: abc123\r\n", "X-Signature: xyz789\r\n", "\r\n">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(<<"hello">>, maps:get(body, Resp)).

parse_chunked_partial_trailers(_Config) ->
    Data =
        <<"HTTP/1.1 200 OK\r\n", "Transfer-Encoding: chunked\r\n", "\r\n", "5\r\nhello\r\n",
            "0\r\n", "X-Check">>,
    {more, _} = nhttp_h1:parse_response(Data).

parse_chunked_with_extension(_Config) ->
    Data =
        <<"HTTP/1.1 200 OK\r\n", "Transfer-Encoding: chunked\r\n", "\r\n",
            "5;name=value\r\nhello\r\n", "0\r\n\r\n">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    ?assertEqual(<<"hello">>, maps:get(body, Resp)).

encode_method_coverage(_Config) ->
    ?assertEqual(<<"GET">>, nhttp_lib:encode_method(get)),
    ?assertEqual(<<"HEAD">>, nhttp_lib:encode_method(head)),
    ?assertEqual(<<"POST">>, nhttp_lib:encode_method(post)),
    ?assertEqual(<<"PUT">>, nhttp_lib:encode_method(put)),
    ?assertEqual(<<"DELETE">>, nhttp_lib:encode_method(delete)),
    ?assertEqual(<<"CONNECT">>, nhttp_lib:encode_method(connect)),
    ?assertEqual(<<"OPTIONS">>, nhttp_lib:encode_method(options)),
    ?assertEqual(<<"TRACE">>, nhttp_lib:encode_method(trace)),
    ?assertEqual(<<"PATCH">>, nhttp_lib:encode_method(patch)),
    ?assertEqual(<<"CUSTOM">>, nhttp_lib:encode_method(<<"CUSTOM">>)).

parse_unknown_method_with_crlf_before_space(_Config) ->
    {error, bad_request_line} = nhttp_h1:parse_request(<<"UNKNOWNMETHOD\r\n/ HTTP/1.1\r\n\r\n">>).

parse_unknown_method_long(_Config) ->
    {error, bad_request_line} = nhttp_h1:parse_request(<<"VERYLONGMETHODNAME / HTTP/1.1\r\n\r\n">>).

parse_unknown_method_success(_Config) ->
    Data = <<"PROPFIND / HTTP/1.1\r\nHost: x\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(<<"PROPFIND">>, maps:get(method, Req)).

parse_path_without_http_version(_Config) ->
    {error, bad_request_line} = nhttp_h1:parse_request(<<"GET /path\r\n\r\n">>).

parse_path_with_http_but_wrong_version(_Config) ->
    {error, invalid_version} = nhttp_h1:parse_request(<<"GET / HTTP/3.0\r\n\r\n">>).

encode_response_head_all_status(_Config) ->
    lists:foreach(
        fun(Code) ->
            IOList = nhttp_h1:encode_response_head(http1_1, Code, []),
            Bin = iolist_to_binary(IOList),
            ?assertMatch(<<"HTTP/1.1 ", _/binary>>, Bin)
        end,
        [
            100,
            101,
            200,
            201,
            202,
            204,
            206,
            301,
            302,
            303,
            304,
            307,
            308,
            400,
            401,
            403,
            404,
            405,
            408,
            409,
            410,
            411,
            413,
            414,
            415,
            416,
            417,
            422,
            426,
            429,
            500,
            501,
            502,
            503,
            504,
            505
        ]
    ).

parse_partial_version_digit(_Config) ->
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.0">>),
    {more, _} = nhttp_h1:parse_request(<<"GET / HTTP/1.0\r">>).

parse_chunked_multiple_trailer_fields(_Config) ->
    Data =
        <<"HTTP/1.1 200 OK\r\n", "Transfer-Encoding: chunked\r\n", "\r\n", "3\r\nabc\r\n", "0\r\n",
            "X-A: 1\r\n", "X-Longer-Header: longer-value-here\r\n", "X-B: 2\r\n", "\r\n">>,
    {ok, Resp, Consumed} = nhttp_h1:parse_response(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(<<"abc">>, maps:get(body, Resp)).

parse_header_empty_value(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost:\r\n\r\n">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual([{<<"host">>, <<>>}], maps:get(headers, Req)).

fast_path_matches_generic_path(_Config) ->
    FastNames = [
        <<"Content-Type">>,
        <<"Cache-Control">>,
        <<"ETag">>,
        <<"Last-Modified">>,
        <<"Accept-Ranges">>,
        <<"Set-Cookie">>,
        <<"Vary">>
    ],
    GenericName = <<"X-Not-A-Fast-Path-Header">>,
    Values = [<<"plain">>, <<"a, b, c">>, <<"value  ">>, <<"  value">>, <<>>],
    lists:foreach(
        fun(Value) ->
            Fast = parse_one_header(hd(FastNames), Value),
            Generic = parse_one_header(GenericName, Value),
            ExpectedFast = {<<"content-type">>, trim_expect(Value)},
            ExpectedGeneric = {<<"x-not-a-fast-path-header">>, trim_expect(Value)},
            ?assertEqual(ExpectedFast, Fast),
            ?assertEqual(ExpectedGeneric, Generic)
        end,
        Values
    ),
    lists:foreach(
        fun(Name) ->
            {LowerName, _} = parse_one_header(Name, <<"x">>),
            ?assertEqual(string:lowercase(Name), LowerName)
        end,
        FastNames
    ).

fast_path_rejects_invalid_value(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Type: a\x00b\r\n\r\n">>,
    ?assertEqual({error, bad_header}, nhttp_h1:parse_response(Data)).

fast_path_trims_value_ows(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Type: text/plain  \r\n\r\n">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    ?assertEqual([{<<"content-type">>, <<"text/plain">>}], maps:get(headers, Resp)).

parse_one_header(Name, Value) ->
    Data = <<"HTTP/1.1 200 OK\r\n", Name/binary, ": ", Value/binary, "\r\n\r\n">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    [Header] = maps:get(headers, Resp),
    Header.

trim_expect(Value) ->
    string:trim(Value, both, " \t").

parse_response_http1_0_generic(_Config) ->
    Data = <<"HTTP/1.0 418 I'm a teapot\r\n\r\n">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    ?assertEqual(http1_0, maps:get(version, Resp)),
    ?assertEqual(418, maps:get(status, Resp)).

%%%-----------------------------------------------------------------------------
%%% LIMITS TESTS
%%%-----------------------------------------------------------------------------

limit_header_size_exceeded_request(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: example.com\r\nX-Long: value123456789\r\n\r\n">>,
    Opts = #{max_header_size => 30},
    ?assertEqual({error, header_too_large}, nhttp_h1:parse_request(Data, Opts)).

limit_header_size_exceeded_response(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Long: value123456789\r\n\r\n">>,
    Opts = #{max_header_size => 30},
    ?assertEqual({error, header_too_large}, nhttp_h1:parse_response(Data, Opts)).

limit_header_count_exceeded_request(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nH1: v1\r\nH2: v2\r\nH3: v3\r\nH4: v4\r\n\r\n">>,
    Opts = #{max_headers_count => 2},
    ?assertEqual({error, too_many_headers}, nhttp_h1:parse_request(Data, Opts)).

limit_header_count_exceeded_response(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nH1: v1\r\nH2: v2\r\nH3: v3\r\nH4: v4\r\n\r\n">>,
    Opts = #{max_headers_count => 2},
    ?assertEqual({error, too_many_headers}, nhttp_h1:parse_response(Data, Opts)).

limit_body_size_exceeded_request(_Config) ->
    Body = <<"This is a test body that is too large">>,
    Data = <<"GET / HTTP/1.1\r\nContent-Length: 38\r\n\r\n", Body/binary>>,
    Opts = #{max_body_size => 10},
    ?assertMatch(
        {error, {body_too_large, 38, 10}}, nhttp_h1:parse_request(Data, Opts)
    ).

limit_body_size_exceeded_response(_Config) ->
    Body = <<"This is a response body that is too large">>,
    BodyLen = integer_to_binary(byte_size(Body)),
    BodySize = byte_size(Body),
    Data = <<"HTTP/1.1 200 OK\r\nContent-Length: ", BodyLen/binary, "\r\n\r\n", Body/binary>>,
    Opts = #{max_body_size => 10},
    ?assertMatch(
        {error, {body_too_large, BodySize, 10}}, nhttp_h1:parse_response(Data, Opts)
    ).

limit_body_size_chunked_request(_Config) ->
    Data =
        <<"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", "a\r\n1234567890\r\n",
            "a\r\n1234567890\r\n", "0\r\n\r\n">>,
    Opts = #{max_body_size => 15},
    ?assertMatch(
        {error, {body_too_large, _, 15}}, nhttp_h1:parse_request(Data, Opts)
    ).

limit_body_size_chunked_response(_Config) ->
    Data =
        <<"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "a\r\n1234567890\r\n",
            "a\r\n1234567890\r\n", "0\r\n\r\n">>,
    Opts = #{max_body_size => 15},
    ?assertMatch(
        {error, {body_too_large, _, 15}}, nhttp_h1:parse_response(Data, Opts)
    ).

limit_within_bounds_request(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello">>,
    Opts = #{max_header_size => 100, max_headers_count => 10, max_body_size => 100},
    {ok, Req, _} = nhttp_h1:parse_request(Data, Opts),
    ?assertEqual(get, maps:get(method, Req)),
    ?assertEqual(<<"hello">>, maps:get(body, Req)).

limit_within_bounds_response(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello">>,
    Opts = #{max_header_size => 100, max_headers_count => 10, max_body_size => 100},
    {ok, Resp, _} = nhttp_h1:parse_response(Data, Opts),
    ?assertEqual(200, maps:get(status, Resp)),
    ?assertEqual(<<"hello">>, maps:get(body, Resp)).

limit_infinity_allows_all(_Config) ->
    LargeBody = binary:copy(<<"x">>, 10000),
    BodyLen = integer_to_binary(byte_size(LargeBody)),
    Data = <<"GET / HTTP/1.1\r\nContent-Length: ", BodyLen/binary, "\r\n\r\n", LargeBody/binary>>,
    {ok, Req, _} = nhttp_h1:parse_request(Data, #{}),
    ?assertEqual(LargeBody, maps:get(body, Req)).

duplicate_content_length_different_values_request(_Config) ->
    Data =
        <<"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello">>,
    ?assertEqual({error, duplicate_content_length}, nhttp_h1:parse_request(Data)).

duplicate_content_length_different_values_response(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello">>,
    ?assertEqual({error, duplicate_content_length}, nhttp_h1:parse_response(Data)).

duplicate_content_length_same_values_request(_Config) ->
    Data =
        <<"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello">>,
    {ok, Req, _} = nhttp_h1:parse_request(Data),
    ?assertEqual(<<"hello">>, maps:get(body, Req)).

duplicate_content_length_same_values_response(_Config) ->
    Data = <<"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello">>,
    {ok, Resp, _} = nhttp_h1:parse_response(Data),
    ?assertEqual(<<"hello">>, maps:get(body, Resp)).

te_and_content_length_request_rejected(_Config) ->
    Data = <<
        "POST / HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "0\r\n\r\n"
    >>,
    ?assertEqual({error, conflicting_framing}, nhttp_h1:parse_request(Data)).

te_and_content_length_response_rejected(_Config) ->
    Data = <<
        "HTTP/1.1 200 OK\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "0\r\n\r\n"
    >>,
    ?assertEqual({error, conflicting_framing}, nhttp_h1:parse_response(Data)).

limit_incomplete_head_capped_parse_request(_Config) ->
    Tail = binary:copy(<<"x">>, 16384),
    Data = <<"GET / HTTP/1.1\r\nX-Endless: ", Tail/binary>>,
    Opts = #{max_header_size => 1024},
    ?assertEqual({error, header_too_large}, nhttp_h1:parse_request(Data, Opts)).

limit_incomplete_head_capped_parse_request_headers(_Config) ->
    Tail = binary:copy(<<"x">>, 16384),
    Data = <<"GET / HTTP/1.1\r\nX-Endless: ", Tail/binary>>,
    Opts = #{max_header_size => 1024},
    ?assertEqual({error, header_too_large}, nhttp_h1:parse_request_headers(Data, Opts)).

limit_incomplete_request_line_capped(_Config) ->
    Data = <<"GET /", (binary:copy(<<"a">>, 16384))/binary>>,
    Opts = #{max_header_size => 1024},
    ?assertEqual({error, header_too_large}, nhttp_h1:parse_request_headers(Data, Opts)).

limit_incomplete_head_below_cap_returns_more(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nX-Pending: ", (binary:copy(<<"x">>, 100))/binary>>,
    Opts = #{max_header_size => 1024},
    ?assertMatch({more, _}, nhttp_h1:parse_request_headers(Data, Opts)).

limit_incomplete_head_unbounded_without_limit(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nX-Endless: ", (binary:copy(<<"x">>, 16384))/binary>>,
    ?assertMatch({more, _}, nhttp_h1:parse_request_headers(Data, #{})).

limit_incomplete_trailers_capped(_Config) ->
    Head = <<"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    Opts = #{max_header_size => 256},
    {ok, _Req, {chunked, St}, _Consumed} = nhttp_h1:parse_request_headers(Head, Opts),
    Body = <<"5\r\nhello\r\n0\r\nX-Endless: ", (binary:copy(<<"x">>, 1024))/binary>>,
    ?assertEqual({error, header_too_large}, nhttp_h1:parse_request_body(Body, {chunked, St})).

limit_chunk_size_line_capped(_Config) ->
    Head = <<"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    {ok, _Req, {chunked, St}, _Consumed} = nhttp_h1:parse_request_headers(Head, #{}),
    Body = <<"5;ext=", (binary:copy(<<"a">>, 4096))/binary>>,
    ?assertEqual({error, invalid_chunk_size}, nhttp_h1:parse_request_body(Body, {chunked, St})).

%%%-----------------------------------------------------------------------------
%%% STREAMING REQUEST TESTS
%%%-----------------------------------------------------------------------------

headers_only_no_body(_Config) ->
    Data = <<"GET / HTTP/1.1\r\nHost: x\r\n\r\n">>,
    {ok, Req, Stream, Consumed} = nhttp_h1:parse_request_headers(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertEqual(streaming, maps:get(body, Req)),
    ?assertEqual(none, Stream),
    ?assertEqual({ok, [{fin, []}], none, 0}, nhttp_h1:parse_request_body(<<>>, none)).

headers_then_content_length_body_full(_Config) ->
    Headers = <<"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n">>,
    Body = <<"hello">>,
    Data = <<Headers/binary, Body/binary>>,
    {ok, Req, Stream, Consumed} = nhttp_h1:parse_request_headers(Data),
    ?assertEqual(byte_size(Headers), Consumed),
    ?assertEqual(streaming, maps:get(body, Req)),
    ?assertEqual({length, 5}, Stream),
    Rest = nhttp_h1:split_at(Data, Consumed),
    {ok, Chunks, FinalStream, BodyConsumed} = nhttp_h1:parse_request_body(Rest, Stream),
    ?assertEqual(none, FinalStream),
    ?assertEqual(5, BodyConsumed),
    ?assertEqual([{data, <<"hello">>}, {fin, []}], Chunks).

headers_then_content_length_partial_then_complete(_Config) ->
    Headers = <<"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n">>,
    {ok, _Req, Stream0, _} = nhttp_h1:parse_request_headers(Headers),
    ?assertEqual({length, 10}, Stream0),
    {ok, [{data, <<"hello">>}], Stream1, 5} =
        nhttp_h1:parse_request_body(<<"hello">>, Stream0),
    ?assertEqual({length, 5}, Stream1),
    {ok, Chunks, FinalStream, 5} =
        nhttp_h1:parse_request_body(<<"world">>, Stream1),
    ?assertEqual(none, FinalStream),
    ?assertEqual([{data, <<"world">>}, {fin, []}], Chunks).

headers_then_chunked_simple(_Config) ->
    Headers = <<"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    Body = <<"5\r\nhello\r\n0\r\n\r\n">>,
    {ok, Req, Stream, _} = nhttp_h1:parse_request_headers(Headers),
    ?assertEqual(streaming, maps:get(body, Req)),
    ?assertMatch({chunked, _}, Stream),
    {ok, Chunks, FinalStream, Consumed} = nhttp_h1:parse_request_body(Body, Stream),
    ?assertEqual(none, FinalStream),
    ?assertEqual(byte_size(Body), Consumed),
    Data = [D || {data, D} <- Chunks],
    ?assertEqual(<<"hello">>, iolist_to_binary(Data)),
    ?assertEqual([{fin, []}], [C || {fin, _} = C <- Chunks]).

headers_then_chunked_multiple_chunks(_Config) ->
    Headers = <<"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    Body = <<"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n">>,
    {ok, _Req, Stream, _} = nhttp_h1:parse_request_headers(Headers),
    {ok, Chunks, FinalStream, Consumed} = nhttp_h1:parse_request_body(Body, Stream),
    ?assertEqual(none, FinalStream),
    ?assertEqual(byte_size(Body), Consumed),
    Data = [D || {data, D} <- Chunks],
    ?assertEqual(<<"hello world">>, iolist_to_binary(Data)),
    ?assertEqual([{fin, []}], [C || {fin, _} = C <- Chunks]).

headers_then_chunked_with_trailers(_Config) ->
    Headers = <<"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    Body = <<"5\r\nhello\r\n0\r\nX-Custom: foo\r\n\r\n">>,
    {ok, _Req, Stream, _} = nhttp_h1:parse_request_headers(Headers),
    {ok, Chunks, FinalStream, Consumed} = nhttp_h1:parse_request_body(Body, Stream),
    ?assertEqual(none, FinalStream),
    ?assertEqual(byte_size(Body), Consumed),
    Data = [D || {data, D} <- Chunks],
    ?assertEqual(<<"hello">>, iolist_to_binary(Data)),
    Fins = [T || {fin, T} <- Chunks],
    ?assertEqual([[{<<"x-custom">>, <<"foo">>}]], Fins).

headers_then_chunked_partial_size(_Config) ->
    Headers = <<"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    {ok, _Req, Stream, _} = nhttp_h1:parse_request_headers(Headers),
    Result = nhttp_h1:parse_request_body(<<"5\r">>, Stream),
    ?assertMatch({more, _, {chunked, _}}, Result).

headers_then_chunked_partial_data(_Config) ->
    Headers = <<"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    {ok, _Req, Stream, _} = nhttp_h1:parse_request_headers(Headers),
    Result = nhttp_h1:parse_request_body(<<"5\r\nhel">>, Stream),
    ?assertMatch({ok, [{data, <<"hel">>}], {chunked, _}, _}, Result),
    {ok, _, Stream1, Consumed1} = Result,
    ?assertEqual(6, Consumed1),
    Result2 = nhttp_h1:parse_request_body(<<"lo\r\n0\r\n\r\n">>, Stream1),
    {ok, Chunks2, FinalStream, _} = Result2,
    ?assertEqual(none, FinalStream),
    Data = [D || {data, D} <- Chunks2],
    ?assertEqual(<<"lo">>, iolist_to_binary(Data)),
    ?assertEqual([{fin, []}], [C || {fin, _} = C <- Chunks2]).

headers_then_chunked_invalid_size(_Config) ->
    Headers = <<"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n">>,
    {ok, _Req, Stream, _} = nhttp_h1:parse_request_headers(Headers),
    ?assertEqual(
        {error, invalid_chunk_size},
        nhttp_h1:parse_request_body(<<"XYZ\r\nhello\r\n0\r\n\r\n">>, Stream)
    ).

headers_then_streaming_marker(_Config) ->
    Data = <<"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc">>,
    {ok, Req, _Stream, _Consumed} = nhttp_h1:parse_request_headers(Data),
    ?assertEqual(streaming, maps:get(body, Req)),
    ?assertEqual(post, maps:get(method, Req)),
    ?assertEqual(<<"/">>, maps:get(path, Req)),
    ?assertEqual(<<"x">>, maps:get(authority, Req)),
    ?assertEqual(http, maps:get(scheme, Req)),
    ?assertEqual(http1_1, maps:get(version, Req)).
