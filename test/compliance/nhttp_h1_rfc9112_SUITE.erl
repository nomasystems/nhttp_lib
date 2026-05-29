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
        {group, section_4_status_line},
        {group, section_5_field_syntax},
        {group, section_6_message_body},
        {group, section_7_transfer_codings}
    ].

groups() ->
    [
        {section_2_message, [parallel], [
            parse_as_ascii_superset,
            reject_or_replace_bare_cr,
            reject_whitespace_before_headers
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
        {section_7_transfer_codings, [parallel], [
            parse_chunked,
            handle_large_chunk_size,
            ignore_chunk_extensions,
            handle_trailer_fields
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
%%% Section 4 - Status Line
%%%-----------------------------------------------------------------------------

status_line_space_before_reason(_Config) ->
    Resp = #{status => 200, reason => <<"OK">>, headers => []},
    Io = nhttp_h1:encode_response(Resp),
    Encoded = iolist_to_binary(Io),
    ?assertMatch(<<"HTTP/1.1 200 OK\r\n", _/binary>>, Encoded),

    RespEmpty = #{status => 200, reason => <<>>, headers => []},
    IoEmpty = nhttp_h1:encode_response(RespEmpty),
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
    Io = nhttp_h1:encode_response(Resp),
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
