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
            encode_trailer_section,
            trailers_require_chunked_framing,
            reject_chunk_data_without_crlf_request,
            reject_chunk_data_without_crlf_response,
            short_chunk_data_returns_more
        ]},
        {section_6_3_single_framing_field, [parallel], [
            encode_response_mixed_case_content_length,
            encode_response_mixed_case_transfer_encoding,
            encode_request_mixed_case_content_length,
            encode_request_mixed_case_transfer_encoding,
            encode_response_framing_field_after_other_fields,
            encode_response_prepared_framing_field
        ]},
        {section_11_response_splitting, [parallel], [
            reject_field_value_injection,
            reject_caller_framing_field_injection,
            reject_field_name_injection,
            reject_reason_phrase_injection,
            reason_phrase_octet_set,
            reject_request_target_injection,
            valid_message_still_encodes,
            single_header_terminator,
            reject_field_injection_at_every_position,
            first_offending_field_names_the_error,
            reject_trailer_field_injection,
            reject_framing_trailer_field,
            field_value_octet_set_at_every_length
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

%% RFC 9112 Section 7.1: chunked-body = *chunk last-chunk trailer-section CRLF.
%% One call writes the last chunk, the field lines and the single CRLF that
%% closes the body. RFC 9110 Section 6.6.2 names the Trailer header field that
%% announces the section.
encode_trailer_section(_Config) ->
    {ok, Empty} = nhttp_h1:encode_trailers([]),
    ?assertEqual(nhttp_h1:encode_last_chunk(), iolist_to_binary(Empty)),

    {ok, Io} = nhttp_h1:encode_trailers([{<<"x-checksum">>, <<"abc123">>}]),
    ?assertEqual(<<"0\r\nx-checksum: abc123\r\n\r\n">>, iolist_to_binary(Io)),

    Head = <<"HTTP/1.1 200 OK\r\n",
             "Transfer-Encoding: chunked\r\n",
             "Trailer: X-Checksum\r\n",
             "\r\n">>,
    Wire = iolist_to_binary([Head, nhttp_h1:encode_chunk(<<"hello">>), Io]),
    {ok, 200, Headers, Rest} = nhttp_h1:parse_response_headers(Wire),
    Stream = nhttp_h1:body_stream_from_response(get, 200, Headers),
    {ok, Chunks, _Stream, Consumed} = nhttp_h1:parse_response_body(Rest, Stream),
    ?assertEqual(byte_size(Rest), Consumed),
    ?assertEqual(<<"hello">>, iolist_to_binary([D || {data, D} <- Chunks])),
    ?assertEqual(
        [{<<"x-checksum">>, <<"abc123">>}],
        lists:append([T || {fin, T} <- Chunks])
    ).

%% RFC 9110 Section 6.5.1: "A trailer section is only possible when supported by
%% the version of HTTP in use and enabled by an explicit framing mechanism."
%% RFC 9112 Section 7.1.2 names the chunked transfer coding as that mechanism.
%% Content-Length framing holds no position for the field lines, so the encoder
%% refuses the message instead of dropping the trailers.
trailers_require_chunked_framing(_Config) ->
    Trailers = [{<<"x-checksum">>, <<"abc123">>}],
    Base = #{
        status => 200,
        reason => <<"OK">>,
        headers => [],
        body => <<"hello">>,
        trailers => Trailers
    },
    lists:foreach(
        fun(Headers) ->
            ?assertEqual(
                {error, {trailers_require_chunked, Trailers}},
                nhttp_h1:encode_response(Base#{headers => Headers})
            )
        end,
        [
            [],
            [{<<"content-length">>, <<"5">>}],
            [{<<"Transfer-Encoding">>, <<"gzip">>}],
            [{<<"Transfer-Encoding">>, <<"chunked, gzip">>}],
            [{<<"x-seventeen-bytes">>, <<"1">>}]
        ]
    ),

    {ok, Io} = nhttp_h1:encode_response(
        Base#{headers => [{<<"Transfer-Encoding">>, <<"chunked">>}]}
    ),
    ?assertEqual(
        <<"HTTP/1.1 200 OK\r\n",
          "Transfer-Encoding: chunked\r\n",
          "\r\n",
          "5\r\nhello\r\n",
          "0\r\nx-checksum: abc123\r\n\r\n">>,
        iolist_to_binary(Io)
    ),

    {ok, GzipIo} = nhttp_h1:encode_response(
        Base#{headers => [{<<"Transfer-Encoding">>, <<"gzip, chunked">>}]}
    ),
    ?assertMatch(
        <<"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\n", _/binary>>,
        iolist_to_binary(GzipIo)
    ),

    {ok, EmptyIo} = nhttp_h1:encode_response(
        Base#{headers => [{<<"Transfer-Encoding">>, <<"chunked">>}], body => <<>>}
    ),
    ?assertEqual(
        <<"HTTP/1.1 200 OK\r\n",
          "Transfer-Encoding: chunked\r\n",
          "\r\n",
          "0\r\nx-checksum: abc123\r\n\r\n">>,
        iolist_to_binary(EmptyIo)
    ),

    {ok, NoneIo} = nhttp_h1:encode_response(Base#{trailers => []}),
    ?assertEqual(
        <<"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello">>,
        iolist_to_binary(NoneIo)
    ).

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

%% RFC 9110 Section 8.6 and RFC 9112 Section 6.1, at a field position that is
%% not the first. The encoder reads the framing question in the same walk that
%% builds the field lines, so a framing field that other field lines precede
%% must reach the same answer as one that stands alone.
encode_response_framing_field_after_other_fields(_Config) ->
    lists:foreach(
        fun({Name, Value, Body, ClCount}) ->
            {ok, Io} = nhttp_h1:encode_response(#{
                status => 200,
                reason => <<"OK">>,
                headers => [
                    {<<"Server">>, <<"nhttp">>},
                    {<<"Cache-Control">>, <<"no-store">>},
                    {Name, Value}
                ],
                body => Body
            }),
            Bin = iolist_to_binary(Io),
            ?assertEqual(ClCount, count_field(<<"content-length">>, Bin)),
            ?assertEqual(1, count_field(string:lowercase(Name), Bin)),
            ?assertMatch({ok, #{body := <<"hello">>}, _}, nhttp_h1:parse_response(Bin)),
            {ok, _, Consumed} = nhttp_h1:parse_response(Bin),
            ?assertEqual(byte_size(Bin), Consumed)
        end,
        [
            {<<"Content-Length">>, <<"5">>, <<"hello">>, 1},
            {<<"content-length">>, <<"5">>, <<"hello">>, 1},
            {<<"Transfer-Encoding">>, <<"chunked">>, <<"5\r\nhello\r\n0\r\n\r\n">>, 0}
        ]
    ).

%% RFC 9112 Section 6.3: a message carries one framing field, never two. A
%% prepared block is part of the header section, so a framing field inside it
%% suppresses the derived Content-Length exactly as a message field does.
encode_response_prepared_framing_field(_Config) ->
    lists:foreach(
        fun({Name, Value, Body, ClCount}) ->
            {ok, Prepared} = nhttp_h1:prepare_headers([
                {<<"Server">>, <<"nhttp">>},
                {Name, Value}
            ]),
            {ok, Io} = nhttp_h1:encode_response(
                #{
                    status => 200,
                    reason => <<"OK">>,
                    headers => [{<<"Cache-Control">>, <<"no-store">>}],
                    body => Body
                },
                #{prepared => Prepared}
            ),
            Bin = iolist_to_binary(Io),
            ?assertEqual(ClCount, count_field(<<"content-length">>, Bin)),
            ?assertEqual(1, count_field(string:lowercase(Name), Bin)),
            {ok, #{body := <<"hello">>}, Consumed} = nhttp_h1:parse_response(Bin),
            ?assertEqual(byte_size(Bin), Consumed)
        end,
        [
            {<<"Content-Length">>, <<"5">>, <<"hello">>, 1},
            {<<"content-length">>, <<"5">>, <<"hello">>, 1},
            {<<"Transfer-Encoding">>, <<"chunked">>, <<"5\r\nhello\r\n0\r\n\r\n">>, 0}
        ]
    ),
    {ok, Plain} = nhttp_h1:prepare_headers([{<<"Server">>, <<"nhttp">>}]),
    {ok, Derived} = nhttp_h1:encode_response(
        #{status => 200, reason => <<"OK">>, headers => [], body => <<"hello">>},
        #{prepared => Plain}
    ),
    ?assertEqual(1, count_field(<<"content-length">>, iolist_to_binary(Derived))).

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

%% RFC 9110 Section 5.5 and RFC 9112 Section 11.1, as above, on the two fields
%% that frame the message. The encoder derives its own `Content-Length` from
%% `integer_to_binary/1` and does not scan those octets. A `content-length` or
%% a `transfer-encoding` that a caller supplies suppresses that derivation and
%% carries caller octets, so it is scanned like any other field.
reject_caller_framing_field_injection(_Config) ->
    lists:foreach(
        fun({Name, Value}) ->
            Resp = #{
                status => 200,
                reason => <<"OK">>,
                headers => [{Name, Value}],
                body => <<"hello">>
            },
            ?assertEqual(
                {error, {invalid_field_value, Value}},
                nhttp_h1:encode_response(Resp)
            ),
            ?assertEqual(
                {error, {invalid_field_value, Value}},
                nhttp_h1:encode_response_head(http1_1, 200, [{Name, Value}])
            ),
            Req = #{
                method => post,
                path => <<"/">>,
                headers => [{Name, Value}],
                body => <<"hello">>
            },
            ?assertEqual(
                {error, {invalid_field_value, Value}},
                nhttp_h1:encode_request(Req)
            )
        end,
        [
            {N, V}
         || N <- [<<"content-length">>, <<"Content-Length">>, <<"Transfer-Encoding">>],
            V <- injection_values()
        ]
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

%% RFC 9112 Section 4.1: "reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )".
%% The refused set is every control octet other than HTAB, plus DEL. The
%% encoder holds one compiled pattern for a field value and for a reason
%% phrase, so this case pins the octet set that both readings share.
reason_phrase_octet_set(_Config) ->
    {_NameBad, ValueBad} = persistent_term:get({nhttp_h1, encode_patterns}),
    ?assertEqual(persistent_term:get({nhttp_h1, field_value_bad_pattern}), ValueBad),
    lists:foreach(
        fun(C) ->
            Reason = <<"a", C, "b">>,
            Resp = #{status => 200, reason => Reason, headers => []},
            case (C < 16#20 andalso C =/= $\t) orelse C =:= 16#7F of
                true ->
                    ?assertEqual(
                        {error, {invalid_reason_phrase, Reason}},
                        nhttp_h1:encode_response(Resp)
                    );
                false ->
                    ?assertMatch({ok, _}, nhttp_h1:encode_response(Resp))
            end
        end,
        lists:seq(16#00, 16#FF)
    ).

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


%% RFC 9112 Section 11.1 and RFC 9110 Section 5.5 hold whatever the field count and
%% whatever the position of the offending field. The refusal must not depend on where
%% the offending field sits in the list.
reject_field_injection_at_every_position(_Config) ->
    Clean = [
        {<<"a">>, <<"1">>},
        {<<"b">>, <<"2">>},
        {<<"c">>, <<"3">>},
        {<<"d">>, <<"4">>},
        {<<"e">>, <<"5">>},
        {<<"f">>, <<"6">>}
    ],
    Positions = lists:seq(1, length(Clean) + 1),
    lists:foreach(
        fun(Bad) ->
            lists:foreach(
                fun(Pos) ->
                    Value = insert_field(Clean, Pos, {<<"x">>, Bad}),
                    ?assertEqual(
                        {error, {invalid_field_value, Bad}}, encode_both(Value)
                    ),
                    Name = insert_field(Clean, Pos, {Bad, <<"v">>}),
                    ?assertEqual(
                        {error, {invalid_field_name, Bad}}, encode_both(Name)
                    ),
                    Empty = insert_field(Clean, Pos, {<<>>, <<"v">>}),
                    ?assertEqual(
                        {error, {invalid_field_name, <<>>}}, encode_both(Empty)
                    )
                end,
                Positions
            )
        end,
        injection_values()
    ).

%% The encoder reports the first field line that breaks the grammar, reading each
%% field line left to right and the name before the value. RFC 9110 Section 5.5 and
%% Section 5.6.2 make both refusals mandatory, so only the order is at stake here.
first_offending_field_names_the_error(_Config) ->
    BadValue = <<"a\r\nSet-Cookie: evil=1">>,
    BadName = <<"bad name">>,
    Filler = [{<<"p">>, <<"1">>}, {<<"q">>, <<"2">>}, {<<"r">>, <<"3">>}, {<<"s">>, <<"4">>}],
    ?assertEqual(
        {error, {invalid_field_value, BadValue}},
        encode_both([{<<"x">>, BadValue}, {BadName, <<"v">>} | Filler])
    ),
    ?assertEqual(
        {error, {invalid_field_name, BadName}},
        encode_both([{BadName, <<"v">>}, {<<"x">>, BadValue} | Filler])
    ),
    ?assertEqual(
        {error, {invalid_field_value, BadValue}},
        encode_both([{<<"x">>, BadValue}, {<<>>, <<"v">>} | Filler])
    ),
    ?assertEqual(
        {error, {invalid_field_name, <<>>}},
        encode_both([{<<>>, <<"v">>}, {<<"x">>, BadValue} | Filler])
    ).

%% RFC 9110 Section 5.5 and RFC 9112 Section 11.1 hold over the trailer section
%% as they hold over the header section. A chunked message ends with the field
%% lines the trailer encoder writes, so an unscanned CR there splits the message
%% exactly as one in the header section does.
reject_trailer_field_injection(_Config) ->
    Clean = {<<"p">>, <<"1">>},
    lists:foreach(
        fun(Value) ->
            Trailers = [{<<"x">>, Value}],
            Behind = [Clean, {<<"x">>, Value}],
            ?assertEqual(
                {error, {invalid_field_value, Value}}, nhttp_h1:encode_trailers(Trailers)
            ),
            ?assertEqual(
                {error, {invalid_field_value, Value}}, nhttp_h1:encode_trailers(Behind)
            ),
            ?assertEqual(
                {error, {invalid_field_value, Value}}, encode_chunked_response(Trailers)
            )
        end,
        injection_values()
    ),
    lists:foreach(
        fun(Name) ->
            Trailers = [{Name, <<"v">>}],
            Behind = [Clean, {Name, <<"v">>}],
            ?assertEqual(
                {error, {invalid_field_name, Name}}, nhttp_h1:encode_trailers(Trailers)
            ),
            ?assertEqual(
                {error, {invalid_field_name, Name}}, nhttp_h1:encode_trailers(Behind)
            ),
            ?assertEqual(
                {error, {invalid_field_name, Name}}, encode_chunked_response(Trailers)
            )
        end,
        injection_values() ++ [<<"x y">>, <<"x:y">>, <<>>]
    ).

%% RFC 9112 Section 11.1. RFC 9112 Section 7.1.3 has a recipient compute the
%% content length and rewrite Transfer-Encoding at the point where the trailer
%% section arrives. A recipient that merges one of these four names into the
%% header section, against RFC 9110 Section 6.5.1, then holds two framing
%% statements for one message. The four names are a defence against that
%% recipient. They are not an RFC enumeration: RFC 9110 blesses ETag
%% (Section 8.8.3), Accept-Ranges (Section 14.3) and Authentication-Info
%% (Section 11.6.3) in a trailer section by name, and those still encode.
reject_framing_trailer_field(_Config) ->
    lists:foreach(
        fun(Name) ->
            Trailers = [{Name, <<"1">>}],
            ?assertEqual(
                {error, {forbidden_trailer_field, Name}}, nhttp_h1:encode_trailers(Trailers)
            ),
            ?assertEqual(
                {error, {forbidden_trailer_field, Name}}, encode_chunked_response(Trailers)
            )
        end,
        [
            <<"transfer-encoding">>,
            <<"Transfer-Encoding">>,
            <<"content-length">>,
            <<"Content-Length">>,
            <<"host">>,
            <<"Host">>,
            <<"trailer">>,
            <<"Trailer">>
        ]
    ),
    {ok, Io} = nhttp_h1:encode_trailers([
        {<<"etag">>, <<"\"xyzzy\"">>},
        {<<"accept-ranges">>, <<"bytes">>},
        {<<"authentication-info">>, <<"nextnonce=\"1\"">>}
    ]),
    ?assertEqual(1, count_terminators(iolist_to_binary(Io))).
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


-spec insert_field(nhttp_lib:headers(), pos_integer(), {binary(), binary()}) ->
    nhttp_lib:headers().
insert_field(Headers, Pos, Field) ->
    lists:sublist(Headers, Pos - 1) ++ [Field | lists:nthtail(Pos - 1, Headers)].

-spec encode_both(nhttp_lib:headers()) -> {error, term()}.
encode_both(Headers) ->
    Resp = #{status => 200, reason => <<"OK">>, headers => Headers},
    Req = #{method => get, path => <<"/">>, headers => Headers},
    Results = [
        nhttp_h1:encode_response(Resp),
        nhttp_h1:encode_response_head(http1_1, 200, Headers),
        nhttp_h1:encode_request(Req)
    ],
    [Single] = lists:usort(Results),
    Single.

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

-spec encode_chunked_response(nhttp_lib:headers()) -> {ok, iolist()} | {error, term()}.
encode_chunked_response(Trailers) ->
    nhttp_h1:encode_response(#{
        status => 200,
        reason => <<"OK">>,
        headers => [{<<"Transfer-Encoding">>, <<"chunked">>}],
        body => <<"hello">>,
        trailers => Trailers
    }).

%% RFC 9110 Section 5.5 names the field value octet set, and RFC 9112 Section
%% 11.1 names the filter that reads it. The encoder reads a value below 112
%% octets with `binary:match/2` and a value at that length or above with a word
%% scan, and the sweep holds the two instruments to the same answer. It walks
%% every position of a short value and the word and stride boundaries of a long
%% one, over five fillers, and refuses or accepts each of the 256 octets.
field_value_octet_set_at_every_length(_Config) ->
    lists:foreach(
        fun(Filler) ->
            [
                sweep_value_octet(Filler, Len, Pos)
             || Len <- lists:seq(0, 130) ++ [255, 448, 4096],
                Pos <- sweep_positions(Len)
            ]
        end,
        [$v, $\t, $\s, 16#80, 16#FF]
    ).

-spec sweep_positions(non_neg_integer()) -> [non_neg_integer()].
sweep_positions(Len) when Len =< 20 ->
    lists:seq(0, Len - 1);
sweep_positions(Len) ->
    Edges = [0, 1, 54, 55, 56, 57, 110, 111, 112, 113, 447, 448, Len div 2, Len - 2, Len - 1],
    lists:usort([P || P <- Edges, P >= 0, P < Len]).

-spec sweep_value_octet(byte(), non_neg_integer(), non_neg_integer()) -> ok.
sweep_value_octet(Filler, Len, Pos) ->
    Base = binary:copy(<<Filler>>, Len),
    <<Head:Pos/binary, _, Tail/binary>> = Base,
    lists:foreach(
        fun(C) ->
            Value = <<Head/binary, C, Tail/binary>>,
            Resp = #{status => 200, reason => <<"OK">>, headers => [{<<"x">>, Value}]},
            case (C < 16#20 andalso C =/= $\t) orelse C =:= 16#7F of
                true ->
                    ?assertEqual(
                        {error, {invalid_field_value, Value}},
                        nhttp_h1:encode_response(Resp)
                    );
                false ->
                    ?assertMatch({ok, _}, nhttp_h1:encode_response(Resp))
            end
        end,
        lists:seq(16#00, 16#FF)
    ).
