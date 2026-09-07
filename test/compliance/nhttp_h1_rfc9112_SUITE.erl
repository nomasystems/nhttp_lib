%%%-----------------------------------------------------------------------------
-module(nhttp_h1_rfc9112_SUITE).

-moduledoc """
RFC 9112 Compliance Test Suite.

This suite tests compliance with RFC 9112 (HTTP/1.1 Message Syntax).
Each test case is linked to a specific requirement in specs/rfc9112.erl.

Run with: rebar3 ct --suite=test/compliance/nhttp_h1_rfc9112_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_2_message},
        {group, section_3_request_line},
        {group, section_4_status_line},
        {group, section_5_field_syntax},
        {group, section_6_message_body},
        {group, section_6_1_transfer_encoding},
        {group, section_6_3_single_framing_field},
        {group, section_7_transfer_codings},
        {group, section_11_response_splitting}
    ].

groups() ->
    [
        {section_2_message, [parallel], [
            parse_as_ascii_superset,
            reject_or_replace_bare_cr,
            reject_whitespace_before_headers
        ]},
        {section_3_request_line, [parallel], [
            reject_method_with_crlf,
            reject_method_with_non_token_octets,
            reject_method_with_whitespace,
            reject_lowercase_method,
            reject_overlong_method,
            accept_token_method_outside_alpha,
            known_methods_return_atom,
            truncated_request_line_returns_more
        ]},
        {section_4_status_line, [parallel], [
            status_line_space_before_reason
        ]},
        {section_5_field_syntax, [parallel], [
            reject_whitespace_before_colon,
            no_obs_fold_generation,
            handle_obs_fold
        ]},
        {section_6_message_body, [parallel], [
            parse_chunked_transfer,
            reject_invalid_content_length,
            transfer_encoding_overrides_content_length
        ]},
        {section_6_1_transfer_encoding, [parallel], [
            join_transfer_encoding_field_lines,
            reject_chunked_before_other_coding,
            accept_other_coding_before_chunked,
            reject_repeated_chunked,
            transfer_coding_case_and_ows,
            reject_empty_transfer_encoding,
            reject_content_length_with_transfer_encoding,
            response_transfer_encoding_field_lines
        ]},
        {section_7_transfer_codings, [parallel], [
            parse_chunked,
            handle_large_chunk_size,
            ignore_chunk_extensions,
            handle_trailer_fields,
            reject_chunk_data_without_crlf_request,
            reject_chunk_data_without_crlf_response,
            short_chunk_data_returns_more
        ]},
        {section_6_3_single_framing_field, [parallel], [
            encode_response_mixed_case_content_length,
            encode_response_mixed_case_transfer_encoding,
            encode_request_mixed_case_content_length,
            encode_request_mixed_case_transfer_encoding
        ]},
        {section_11_response_splitting, [parallel], [
            reject_field_value_injection,
            reject_field_name_injection,
            reject_reason_phrase_injection,
            reject_request_target_injection,
            valid_message_still_encodes,
            single_header_terminator
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
%%% Section 2 - Message
%%%-----------------------------------------------------------------------------

parse_as_ascii_superset(_Config) ->
    Req = <<"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n">>,
    {ok, #{path := <<"/path">>}, _} = nhttp_h1:parse_request(Req),

    ReqUtf8 = <<"GET /caf", 195, 169, " HTTP/1.1\r\nHost: x\r\n\r\n">>,
    {ok, #{path := <<"/caf", 195, 169>>}, _} = nhttp_h1:parse_request(ReqUtf8).

reject_or_replace_bare_cr(_Config) ->
    Req = <<"GET / HTTP/1.1\r\nHost: exam", $\r, "ple\r\n\r\n">>,
    case nhttp_h1:parse_request(Req) of
        {error, _} ->
            ok;
        {ok, #{headers := Headers}, _} ->
            {ok, Host} = find_header(<<"Host">>, Headers),
            ?assertNot(binary:match(Host, <<$\r>>) =/= nomatch)
    end.

reject_whitespace_before_headers(_Config) ->
    Req = <<"GET / HTTP/1.1\r\n Host: x\r\n\r\n">>,
    ?assertMatch({error, _}, nhttp_h1:parse_request(Req)).

%%%-----------------------------------------------------------------------------
%%% Section 3 - Request Line
%%%
%%% RFC 9112 Section 3.1: method = token.
%%% RFC 9110 Section 5.6.2: token = 1*tchar.
%%%-----------------------------------------------------------------------------

reject_method_with_crlf(_Config) ->
    Req = <<"XX\r\nY /p HTTP/1.1\r\nHost: a\r\n\r\n">>,
    ?assertEqual({error, invalid_method}, nhttp_h1:parse_request(Req)),
    ?assertEqual({error, invalid_method}, nhttp_h1:parse_request_headers(Req, #{})).

reject_method_with_non_token_octets(_Config) ->
    lists:foreach(
        fun(Octet) ->
            Req = request_with_method(<<"GE", Octet:8, "T">>),
            ?assertEqual(
                {error, invalid_method},
                nhttp_h1:parse_request(Req),
                {octet, Octet}
            )
        end,
        non_tchar_octets()
    ).

reject_method_with_whitespace(_Config) ->
    ?assertMatch(
        {error, _}, nhttp_h1:parse_request(<<"GE T /p HTTP/1.1\r\nHost: a\r\n\r\n">>)
    ),
    ?assertEqual(
        {error, invalid_method}, nhttp_h1:parse_request(request_with_method(<<"GE\tT">>))
    ).

reject_lowercase_method(_Config) ->
    ?assertEqual(
        {error, invalid_method}, nhttp_h1:parse_request(request_with_method(<<"get">>))
    ),
    ?assertEqual(
        {error, invalid_method}, nhttp_h1:parse_request(request_with_method(<<"gEt">>))
    ).

reject_overlong_method(_Config) ->
    ?assertMatch(
        {ok, #{method := <<"ABCDEFGHIJKLMNOP">>}, _},
        nhttp_h1:parse_request(request_with_method(<<"ABCDEFGHIJKLMNOP">>))
    ),
    ?assertMatch(
        {error, _}, nhttp_h1:parse_request(request_with_method(<<"ABCDEFGHIJKLMNOPQ">>))
    ).

accept_token_method_outside_alpha(_Config) ->
    lists:foreach(
        fun(Method) ->
            ?assertMatch(
                {ok, #{method := Method}, _},
                nhttp_h1:parse_request(request_with_method(Method)),
                {method, Method}
            )
        end,
        [
            <<"PROPFIND">>,
            <<"M-SEARCH">>,
            <<"!#$%&*">>,
            <<"7ZIP">>,
            <<"X'A">>,
            <<"A+B.C">>,
            <<"^_`|~">>
        ]
    ).

known_methods_return_atom(_Config) ->
    Known = [
        {<<"GET">>, get},
        {<<"POST">>, post},
        {<<"PUT">>, put},
        {<<"HEAD">>, head},
        {<<"DELETE">>, delete},
        {<<"PATCH">>, patch},
        {<<"OPTIONS">>, options},
        {<<"CONNECT">>, connect},
        {<<"TRACE">>, trace}
    ],
    lists:foreach(
        fun({Bin, Atom}) ->
            ?assertMatch(
                {ok, #{method := Atom}, _},
                nhttp_h1:parse_request(request_with_method(Bin)),
                {method, Bin}
            )
        end,
        Known
    ).

truncated_request_line_returns_more(_Config) ->
    Fulls = [
        request_with_method(<<"GET">>),
        request_with_method(<<"PROPFIND">>),
        request_with_method(<<"M-SEARCH">>),
        request_with_method(<<"!#$%&*">>),
        request_with_method(<<"7ZIP">>)
    ],
    lists:foreach(
        fun(Full) ->
            lists:foreach(
                fun(N) ->
                    Prefix = binary:part(Full, 0, N),
                    ?assertMatch(
                        {more, More} when More >= 1,
                        nhttp_h1:parse_request(Prefix),
                        {prefix, Prefix}
                    )
                end,
                lists:seq(0, byte_size(Full) - 1)
            )
        end,
        Fulls
    ).

%%%-----------------------------------------------------------------------------
%%% Section 4 - Status Line
%%%-----------------------------------------------------------------------------

status_line_space_before_reason(_Config) ->
    Resp = #{status => 200, reason => <<"OK">>, headers => []},
    {ok, Io} = nhttp_h1:encode_response(Resp),
    Encoded = iolist_to_binary(Io),
    ?assertMatch(<<"HTTP/1.1 200 OK\r\n", _/binary>>, Encoded),

    RespEmpty = #{status => 200, reason => <<>>, headers => []},
    {ok, IoEmpty} = nhttp_h1:encode_response(RespEmpty),
    EncodedEmpty = iolist_to_binary(IoEmpty),
    ?assertMatch(<<"HTTP/1.1 200 \r\n", _/binary>>, EncodedEmpty).

%%%-----------------------------------------------------------------------------
%%% Section 5 - Field Syntax
%%%-----------------------------------------------------------------------------

reject_whitespace_before_colon(_Config) ->
    Req = <<"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n">>,
    ?assertMatch({error, bad_header}, nhttp_h1:parse_request(Req)).

no_obs_fold_generation(_Config) ->
    LongValue = binary:copy(<<"x">>, 1000),
    Resp = #{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"X-Long">>, LongValue}]
    },
    {ok, Io} = nhttp_h1:encode_response(Resp),
    Encoded = iolist_to_binary(Io),

    ?assertEqual(nomatch, binary:match(Encoded, <<"\r\n ">>)),
    ?assertEqual(nomatch, binary:match(Encoded, <<"\r\n\t">>)).

handle_obs_fold(_Config) ->
    Req = <<"GET / HTTP/1.1\r\nHost: example\r\n .com\r\n\r\n">>,
    case nhttp_h1:parse_request(Req) of
        {error, _} ->
            ok;
        {ok, #{headers := Headers}, _} ->
            {ok, Host} = find_header(<<"Host">>, Headers),
            ?assertEqual(<<"example .com">>, Host)
    end.

%%%-----------------------------------------------------------------------------
%%% Section 6 - Message Body
%%%-----------------------------------------------------------------------------

parse_chunked_transfer(_Config) ->
    Req = <<"POST / HTTP/1.1\r\n",
            "Host: x\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "6\r\n world\r\n",
            "0\r\n\r\n">>,
    {ok, #{body := Body}, _} = nhttp_h1:parse_request(Req),
    ?assertEqual(<<"hello world">>, Body).

reject_invalid_content_length(_Config) ->
    Req1 = <<"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n">>,
    case nhttp_h1:parse_request(Req1) of
        {error, _} -> ok;
        {ok, #{body := <<>>}, _} -> ok
    end,

    Req2 = <<"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n">>,
    case nhttp_h1:parse_request(Req2) of
        {error, _} -> ok;
        {ok, #{body := <<>>}, _} -> ok
    end.

transfer_encoding_overrides_content_length(_Config) ->
    Req = <<"POST / HTTP/1.1\r\n",
            "Host: x\r\n",
            "Content-Length: 100\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "0\r\n\r\n">>,
    ?assertEqual({error, conflicting_framing}, nhttp_h1:parse_request(Req)).

%%%-----------------------------------------------------------------------------
%%% Section 6.1 - Transfer-Encoding
%%%-----------------------------------------------------------------------------

%% RFC 9110 Section 5.3: a recipient combines multiple field lines with the
%% same name into one comma-separated list, in order of receipt. Framing that
%% reads only the first field line desynchronizes against a recipient that
%% performs the join.
join_transfer_encoding_field_lines(_Config) ->
    ?assertEqual(te_framing([<<"gzip, chunked">>]), te_framing([<<"gzip">>, <<"chunked">>])),
    ?assertEqual(te_framing([<<"chunked, gzip">>]), te_framing([<<"chunked">>, <<"gzip">>])),
    ?assertEqual(
        te_framing([<<"deflate, gzip, chunked">>]),
        te_framing([<<"deflate">>, <<"gzip, chunked">>])
    ).

%% RFC 9112 Section 6.3 item 4: a request whose final transfer coding is not
%% chunked has no reliable body length, and the server answers 400.
reject_chunked_before_other_coding(_Config) ->
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<"chunked">>, <<"gzip">>])),
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<"chunked, gzip">>])),
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<"gzip">>])).

%% RFC 9112 Section 6.1: chunked is the final transfer coding of a request.
accept_other_coding_before_chunked(_Config) ->
    ?assertEqual(chunked, te_framing([<<"gzip, chunked">>])),
    ?assertEqual(chunked, te_framing([<<"gzip">>, <<"chunked">>])),
    ?assertEqual(chunked, te_framing([<<"deflate">>, <<"gzip">>, <<"chunked">>])).

%% RFC 9112 Section 6.1: "A sender MUST NOT apply the chunked transfer coding
%% more than once to a message body". Two recipients that disagree on the
%% number of chunked layers disagree on every byte after the first chunk.
reject_repeated_chunked(_Config) ->
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<"chunked, chunked">>])),
    ?assertEqual(
        {error, unsupported_transfer_encoding}, te_framing([<<"chunked">>, <<"chunked">>])
    ),
    ?assertEqual(
        {error, unsupported_transfer_encoding}, te_framing([<<"chunked">>, <<"gzip, chunked">>])
    ).

%% RFC 9110 Section 10.1.4: transfer-coding is a token, and tokens are
%% case-insensitive. RFC 9110 Section 5.6.1.2: a recipient ignores empty list
%% elements and the OWS around each element.
transfer_coding_case_and_ows(_Config) ->
    ?assertEqual(chunked, te_framing([<<"Chunked">>])),
    ?assertEqual(chunked, te_framing([<<"CHUNKED">>])),
    ?assertEqual(chunked, te_framing([<<"  chunked  ">>])),
    ?assertEqual(chunked, te_framing([<<"gzip ,\tchunked">>])),
    ?assertEqual(chunked, te_framing([<<"chunked,">>])),
    ?assertEqual(chunked, te_framing([<<"gzip, , chunked">>])),
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<"Chunked, chunked">>])).

%% RFC 9110 Section 5.6.1.2: an empty list has no elements, so the message
%% declares no transfer coding and cannot be framed by one.
reject_empty_transfer_encoding(_Config) ->
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<>>])),
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<",">>])),
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<" ,\t,">>])),
    ?assertEqual({error, unsupported_transfer_encoding}, te_framing([<<>>, <<>>])).

%% RFC 9112 Section 6.3 item 3: a message carrying both fields is handled as
%% an error. The field line count does not change that.
reject_content_length_with_transfer_encoding(_Config) ->
    ?assertEqual({error, conflicting_framing}, cl_te_framing([<<"chunked">>])),
    ?assertEqual({error, conflicting_framing}, cl_te_framing([<<"gzip">>, <<"chunked">>])),
    ?assertEqual({error, conflicting_framing}, cl_te_framing([<<"chunked">>, <<"chunked">>])),
    ?assertEqual({error, conflicting_framing}, cl_te_framing([<<"gzip">>])).

%% RFC 9112 Section 6.3 item 4: a response whose final transfer coding is not
%% chunked is delimited by the connection close, not by an error.
response_transfer_encoding_field_lines(_Config) ->
    ?assertEqual(chunked, response_framing([<<"gzip">>, <<"chunked">>])),
    ?assertEqual(chunked, response_framing([<<"gzip, chunked">>])),
    ?assertEqual(until_close, response_framing([<<"chunked">>, <<"gzip">>])),
    ?assertEqual(until_close, response_framing([<<"chunked">>, <<"chunked">>])),
    ?assertEqual(until_close, response_framing([<<>>])),
    ?assertEqual(
        {error, unsupported_transfer_encoding}, one_shot_response_framing([<<"chunked">>, <<"gzip">>])
    ),
    ?assertEqual(chunked, one_shot_response_framing([<<"gzip">>, <<"chunked">>])).

%%%-----------------------------------------------------------------------------
%%% Section 6.1 helpers
%%%-----------------------------------------------------------------------------

%% The one-shot parser and the streaming parser must reach the same framing
%% decision, so every case runs through both.
te_framing(Lines) ->
    Streaming = streaming_framing(te_request(Lines)),
    ?assertEqual(Streaming, one_shot_framing(te_request(Lines))),
    Streaming.

cl_te_framing(Lines) ->
    Head = <<"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n">>,
    Streaming = streaming_framing(te_message(Head, Lines)),
    ?assertEqual(Streaming, one_shot_framing(te_message(Head, Lines))),
    Streaming.

te_request(Lines) ->
    te_message(<<"POST / HTTP/1.1\r\nHost: x\r\n">>, Lines).

te_message(Head, Lines) ->
    Field = [[<<"Transfer-Encoding: ">>, Line, <<"\r\n">>] || Line <- Lines],
    iolist_to_binary([Head, Field, <<"\r\n5\r\nhello\r\n0\r\n\r\n">>]).

streaming_framing(Bin) ->
    case nhttp_h1:parse_request_headers(Bin, #{}) of
        {ok, _Req, {chunked, _St}, _Consumed} -> chunked;
        {ok, _Req, Stream, _Consumed} -> Stream;
        Other -> Other
    end.

one_shot_framing(Bin) ->
    case nhttp_h1:parse_request(Bin) of
        {ok, #{body := <<"hello">>}, _Consumed} -> chunked;
        {ok, #{body := Body}, _Consumed} -> {body, Body};
        Other -> Other
    end.

response_framing(Lines) ->
    Head = <<"HTTP/1.1 200 OK\r\n">>,
    {ok, 200, Headers, _Rest} = nhttp_h1:parse_response_headers(te_message(Head, Lines)),
    case nhttp_h1:body_stream_from_response(get, 200, Headers) of
        {chunked, _St} -> chunked;
        Stream -> Stream
    end.

one_shot_response_framing(Lines) ->
    Head = <<"HTTP/1.1 200 OK\r\n">>,
    case nhttp_h1:parse_response(te_message(Head, Lines)) of
        {ok, #{body := <<"hello">>}, _Consumed} -> chunked;
        {ok, #{body := Body}, _Consumed} -> {body, Body};
        Other -> Other
    end.

%%%-----------------------------------------------------------------------------
%%% Section 7 - Transfer Codings
%%%-----------------------------------------------------------------------------

parse_chunked(_Config) ->
    Resp = <<"HTTP/1.1 200 OK\r\n",
             "Transfer-Encoding: chunked\r\n",
             "\r\n",
             "a\r\n0123456789\r\n",
             "5\r\nabcde\r\n",
             "0\r\n\r\n">>,
    {ok, #{body := Body}, _} = nhttp_h1:parse_response(Resp),
    ?assertEqual(<<"0123456789abcde">>, Body).

handle_large_chunk_size(_Config) ->
    LargeSize = 16#FFFF,
    SizeHex = integer_to_binary(LargeSize, 16),
    Data = binary:copy(<<"x">>, LargeSize),
    Resp = <<"HTTP/1.1 200 OK\r\n",
             "Transfer-Encoding: chunked\r\n",
             "\r\n",
             SizeHex/binary, "\r\n",
             Data/binary, "\r\n",
             "0\r\n\r\n">>,
    {ok, #{body := Body}, _} = nhttp_h1:parse_response(Resp),
    ?assertEqual(LargeSize, byte_size(Body)).

ignore_chunk_extensions(_Config) ->
    Resp = <<"HTTP/1.1 200 OK\r\n",
             "Transfer-Encoding: chunked\r\n",
             "\r\n",
             "5;ext=value;other\r\nhello\r\n",
             "0\r\n\r\n">>,
    {ok, #{body := Body}, _} = nhttp_h1:parse_response(Resp),
    ?assertEqual(<<"hello">>, iolist_to_binary(Body)).

handle_trailer_fields(_Config) ->
    Resp = <<"HTTP/1.1 200 OK\r\n",
             "Transfer-Encoding: chunked\r\n",
             "Trailer: X-Checksum\r\n",
             "\r\n",
             "5\r\nhello\r\n",
             "0\r\n",
             "X-Checksum: abc123\r\n",
             "\r\n">>,
    {ok, #{body := Body}, _} = nhttp_h1:parse_response(Resp),
    ?assertEqual(<<"hello">>, iolist_to_binary(Body)).

%% RFC 9112 Section 7.1: chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF.
%% The CRLF behind chunk-data is mandatory. Data long enough to satisfy the
%% chunk-size, with any other pair of octets behind it, is a refusal and not a
%% crash.
reject_chunk_data_without_crlf_request(_Config) ->
    Req = <<"POST / HTTP/1.1\r\n",
            "Host: x\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "1\r\nABC">>,
    ?assertEqual({error, incomplete_chunk}, nhttp_h1:parse_request(Req)).

reject_chunk_data_without_crlf_response(_Config) ->
    Resp = <<"HTTP/1.1 200 OK\r\n",
             "Transfer-Encoding: chunked\r\n",
             "\r\n",
             "1\r\nABC">>,
    ?assertEqual({error, incomplete_chunk}, nhttp_h1:parse_response(Resp)).

%% RFC 9112 Section 7.1: the octet count and the terminator are two rules. A
%% body that holds fewer octets than the chunk-size names is incomplete, not
%% malformed, so the parser asks for more.
short_chunk_data_returns_more(_Config) ->
    Req = <<"POST / HTTP/1.1\r\n",
            "Host: x\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nAB">>,
    ?assertEqual({more, 5}, nhttp_h1:parse_request(Req)),
    Valid = <<"POST / HTTP/1.1\r\n",
              "Host: x\r\n",
              "Transfer-Encoding: chunked\r\n",
              "\r\n",
              "1\r\nA\r\n0\r\n\r\n">>,
    ?assertMatch({ok, #{body := <<"A">>}, 67}, nhttp_h1:parse_request(Valid)),
    ?assertEqual(byte_size(Valid), 67).

%%%-----------------------------------------------------------------------------
%%% Section 6.3 - One framing field, whatever the case of the name
%%%
%%% RFC 9110 Section 5.1: a field name is case-insensitive. RFC 9110
%%% Section 5.6.2 admits A-Z in a token, so a caller can supply
%%% `Content-Length' or `Transfer-Encoding' and the encoder writes the name
%%% unchanged. The encoder must still see the field it was given.
%%%-----------------------------------------------------------------------------

%% RFC 9110 Section 8.6: "a sender MUST NOT forward a message with a
%% Content-Length header field value that is known to be incorrect". A
%% generated second Content-Length puts two lengths on the wire for one body,
%% so one of the two is incorrect.
encode_response_mixed_case_content_length(_Config) ->
    {ok, Io} = nhttp_h1:encode_response(#{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"Content-Length">>, <<"5">>}],
        body => <<"hello">>
    }),
    Bin = iolist_to_binary(Io),
    ?assertEqual(1, count_field(<<"content-length">>, Bin)),
    ?assertMatch({ok, #{body := <<"hello">>}, _}, nhttp_h1:parse_response(Bin)),
    {ok, _, Consumed} = nhttp_h1:parse_response(Bin),
    ?assertEqual(byte_size(Bin), Consumed).

%% RFC 9112 Section 6.1: "A sender MUST NOT send a Content-Length header field
%% in any message that contains a Transfer-Encoding header field". RFC 9112
%% Section 6.3 item 3 names the risk in the message that breaks the rule: it
%% "might indicate an attempt to perform request smuggling (Section 11.2) or
%% response splitting (Section 11.1) and ought to be handled as an error".
encode_response_mixed_case_transfer_encoding(_Config) ->
    {ok, Io} = nhttp_h1:encode_response(#{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"Transfer-Encoding">>, <<"chunked">>}],
        body => <<"5\r\nhello\r\n0\r\n\r\n">>
    }),
    Bin = iolist_to_binary(Io),
    ?assertEqual(0, count_field(<<"content-length">>, Bin)),
    ?assertEqual(1, count_field(<<"transfer-encoding">>, Bin)),
    ?assertMatch({ok, #{body := <<"hello">>}, _}, nhttp_h1:parse_response(Bin)),
    {ok, _, Consumed} = nhttp_h1:parse_response(Bin),
    ?assertEqual(byte_size(Bin), Consumed).

%% RFC 9110 Section 8.6, as above, on the request side.
encode_request_mixed_case_content_length(_Config) ->
    {ok, Io} = nhttp_h1:encode_request(#{
        method => post,
        path => <<"/p">>,
        headers => [{<<"Host">>, <<"example.com">>}, {<<"Content-Length">>, <<"5">>}],
        body => <<"hello">>
    }),
    Bin = iolist_to_binary(Io),
    ?assertEqual(1, count_field(<<"content-length">>, Bin)),
    ?assertMatch({ok, #{body := <<"hello">>}, _}, nhttp_h1:parse_request(Bin)),
    {ok, _, Consumed} = nhttp_h1:parse_request(Bin),
    ?assertEqual(byte_size(Bin), Consumed).

%% RFC 9112 Section 6.1 and Section 6.3 item 3, as above, on the request side.
encode_request_mixed_case_transfer_encoding(_Config) ->
    {ok, Io} = nhttp_h1:encode_request(#{
        method => post,
        path => <<"/p">>,
        headers => [{<<"Host">>, <<"example.com">>}, {<<"Transfer-Encoding">>, <<"chunked">>}],
        body => <<"5\r\nhello\r\n0\r\n\r\n">>
    }),
    Bin = iolist_to_binary(Io),
    ?assertEqual(0, count_field(<<"content-length">>, Bin)),
    ?assertEqual(1, count_field(<<"transfer-encoding">>, Bin)),
    ?assertMatch({ok, #{body := <<"hello">>}, _}, nhttp_h1:parse_request(Bin)),
    {ok, _, Consumed} = nhttp_h1:parse_request(Bin),
    ?assertEqual(byte_size(Bin), Consumed).

%%%-----------------------------------------------------------------------------
%%% Section 11.1 - Response Splitting
%%%-----------------------------------------------------------------------------

%% RFC 9112 Section 11.1: "A more effective mitigation is to prevent anything
%% other than the server's core protocol libraries from sending a CR or LF
%% within the header section, which means restricting the output of header
%% fields to APIs that filter for bad octets."
%% RFC 9110 Section 5.5: "Field values containing CR, LF, or NUL characters
%% are invalid and dangerous."
reject_field_value_injection(_Config) ->
    Split = <<"a\r\nSet-Cookie: evil=1">>,
    ?assertEqual(
        {error, {invalid_field_value, Split}},
        nhttp_h1:encode_response(#{
            status => 200, headers => [{<<"x">>, Split}], body => <<>>
        })
    ),
    lists:foreach(
        fun(Value) ->
            Resp = #{status => 200, reason => <<"OK">>, headers => [{<<"x">>, Value}]},
            ?assertEqual(
                {error, {invalid_field_value, Value}},
                nhttp_h1:encode_response(Resp)
            ),
            ?assertEqual(
                {error, {invalid_field_value, Value}},
                nhttp_h1:encode_response(Resp, #{content_length => omit})
            ),
            ?assertEqual(
                {error, {invalid_field_value, Value}},
                nhttp_h1:encode_response_head(http1_1, 200, [{<<"x">>, Value}])
            ),
            Req = #{method => get, path => <<"/">>, headers => [{<<"x">>, Value}]},
            ?assertEqual(
                {error, {invalid_field_value, Value}},
                nhttp_h1:encode_request(Req)
            )
        end,
        injection_values()
    ).

%% RFC 9110 Section 5.1: "field-name = token". RFC 9110 Section 5.6.2 defines
%% token as 1*tchar, which excludes CR, LF, NUL, DEL, SP, and ":".
reject_field_name_injection(_Config) ->
    lists:foreach(
        fun(Name) ->
            Resp = #{status => 200, reason => <<"OK">>, headers => [{Name, <<"v">>}]},
            ?assertEqual(
                {error, {invalid_field_name, Name}},
                nhttp_h1:encode_response(Resp)
            ),
            ?assertEqual(
                {error, {invalid_field_name, Name}},
                nhttp_h1:encode_response_head(http1_1, 200, [{Name, <<"v">>}])
            ),
            Req = #{method => get, path => <<"/">>, headers => [{Name, <<"v">>}]},
            ?assertEqual(
                {error, {invalid_field_name, Name}},
                nhttp_h1:encode_request(Req)
            )
        end,
        injection_values() ++ [<<"x y">>, <<"x:y">>, <<>>]
    ).

%% RFC 9112 Section 4.1: "reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )".
%% The status-line grammar makes the element optional, so an empty phrase is
%% legal and still encodes.
reject_reason_phrase_injection(_Config) ->
    lists:foreach(
        fun(Reason) ->
            Resp = #{status => 200, reason => Reason, headers => []},
            ?assertEqual(
                {error, {invalid_reason_phrase, Reason}},
                nhttp_h1:encode_response(Resp)
            ),
            ?assertEqual(
                {error, {invalid_reason_phrase, Reason}},
                nhttp_h1:encode_response(Resp, #{content_length => omit})
            )
        end,
        injection_values()
    ),
    {ok, Io} = nhttp_h1:encode_response(#{status => 200, reason => <<>>, headers => []}),
    ?assertMatch(<<"HTTP/1.1 200 \r\n", _/binary>>, iolist_to_binary(Io)).

%% RFC 9112 Section 2.2: "A sender MUST NOT generate a bare CR (a CR character
%% not immediately followed by LF) within any protocol elements other than the
%% content." A request target carrying SP or CRLF injects a second request line.
reject_request_target_injection(_Config) ->
    Smuggle = <<"/a HTTP/1.1\r\nHost: evil\r\n\r\nGET /b">>,
    ?assertEqual(
        {error, {invalid_request_target, Smuggle}},
        nhttp_h1:encode_request(#{method => get, path => Smuggle, headers => []})
    ),
    lists:foreach(
        fun(Target) ->
            Req = #{method => get, path => Target, headers => []},
            ?assertEqual(
                {error, {invalid_request_target, Target}},
                nhttp_h1:encode_request(Req)
            )
        end,
        [<<"/a\rb">>, <<"/a\nb">>, <<"/a\r\nb">>, <<"/a", 0, "b">>, <<"/a", 16#7F, "b">>,
            <<"/a b">>, <<"/a\tb">>, <<>>]
    ).

%% RFC 9110 Section 5.5: SP, HTAB, VCHAR, and obs-text (%x80-FF) are all legal
%% inside a field value, so validation refuses nothing that the grammar permits.
valid_message_still_encodes(_Config) ->
    Headers = [
        {<<"X-Tab">>, <<"a\tb">>},
        {<<"X-Space">>, <<"a b">>},
        {<<"X-Obs-Text">>, <<"caf", 16#E9>>},
        {<<"X-Vchar">>, <<"!#$%&'*+-.^_`|~">>},
        {<<"X-Empty">>, <<>>}
    ],
    {ok, Io} = nhttp_h1:encode_response(#{
        status => 200, reason => <<"OK">>, headers => Headers, body => <<>>
    }),
    Encoded = iolist_to_binary(Io),
    lists:foreach(
        fun({Name, Value}) ->
            Line = <<Name/binary, ": ", Value/binary, "\r\n">>,
            ?assertNotEqual(nomatch, binary:match(Encoded, Line))
        end,
        Headers
    ),

    {ok, ReqIo} = nhttp_h1:encode_request(#{
        method => get, path => <<"/a%20b?q=1">>, headers => Headers
    }),
    ?assertMatch(<<"GET /a%20b?q=1 HTTP/1.1\r\n", _/binary>>, iolist_to_binary(ReqIo)),

    {ok, HeadIo} = nhttp_h1:encode_response_head(http1_1, 200, Headers),
    ?assertMatch(<<"HTTP/1.1 200 OK\r\n", _/binary>>, iolist_to_binary(HeadIo)).

%% RFC 9112 Section 2.1: the empty line that ends the header section appears
%% exactly once, which is the invariant response splitting breaks.
single_header_terminator(_Config) ->
    {ok, Io} = nhttp_h1:encode_response(#{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"x">>, <<"a">>}, {<<"y">>, <<"b">>}],
        body => <<"payload">>
    }),
    ?assertEqual(1, count_terminators(iolist_to_binary(Io))),

    {ok, ReqIo} = nhttp_h1:encode_request(#{
        method => post,
        path => <<"/">>,
        headers => [{<<"x">>, <<"a">>}],
        body => <<"payload">>
    }),
    ?assertEqual(1, count_terminators(iolist_to_binary(ReqIo))).

%%%-----------------------------------------------------------------------------
%%% Helpers
%%%-----------------------------------------------------------------------------

-spec request_with_method(binary()) -> binary().
request_with_method(Method) ->
    <<Method/binary, " /p HTTP/1.1\r\nHost: a\r\n\r\n">>.

-spec non_tchar_octets() -> [byte()].
non_tchar_octets() ->
    [0, 16#09, 16#0A, 16#0B, 16#0C, 16#0D, 16#7F, 16#80, 16#FF] ++
        [$", $(, $), $,, $/, $:, $;, $<, $=, $>, $?, $@, $[, $\\, $], ${, $}].

-spec injection_values() -> [binary()].
injection_values() ->
    [<<"a\rb">>, <<"a\nb">>, <<"a\r\nb">>, <<"a", 0, "b">>, <<"a", 16#7F, "b">>].

-spec count_terminators(binary()) -> non_neg_integer().
count_terminators(Bin) ->
    count_terminators(Bin, 0).

-spec count_terminators(binary(), non_neg_integer()) -> non_neg_integer().
count_terminators(<<>>, N) ->
    N;
count_terminators(<<"\r\n\r\n", _/binary>> = Bin, N) ->
    <<_, Rest/binary>> = Bin,
    count_terminators(Rest, N + 1);
count_terminators(<<_, Rest/binary>>, N) ->
    count_terminators(Rest, N).

-spec find_header(binary(), nhttp_lib:headers()) -> {ok, binary()} | error.
find_header(Name, Headers) ->
    LowerName = string:lowercase(Name),
    case lists:keyfind(LowerName, 1, [{string:lowercase(N), V} || {N, V} <- Headers]) of
        {_, Value} -> {ok, Value};
        false -> error
    end.

-spec count_field(binary(), binary()) -> non_neg_integer().
count_field(LowerName, Bin) ->
    Lines = binary:split(Bin, <<"\r\n">>, [global]),
    length([Line || Line <- Lines, is_field_line(LowerName, Line)]).

-spec is_field_line(binary(), binary()) -> boolean().
is_field_line(LowerName, Line) ->
    Size = byte_size(LowerName),
    case Line of
        <<Candidate:Size/binary, $:, _/binary>> -> string:lowercase(Candidate) =:= LowerName;
        _ -> false
    end.
