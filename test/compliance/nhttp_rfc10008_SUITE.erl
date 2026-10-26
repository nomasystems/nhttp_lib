%%%-----------------------------------------------------------------------------
-module(nhttp_rfc10008_SUITE).

-moduledoc """
RFC 10008 Compliance Test Suite.

Tests the QUERY method (RFC 10008) on HTTP/1.1, HTTP/2 and HTTP/3.

Each test case cites the RFC requirement it exercises as
`RFC10008-N.N-K: <paraphrased rule>`.

Run with: rebar3 ct --suite=test/compliance/nhttp_rfc10008_SUITE
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, section_2_method},
        {group, section_2_h1},
        {group, section_2_h2},
        {group, section_2_h3},
        {group, section_2_properties},
        {group, section_2_content_type},
        {group, section_3_accept_query}
    ].

groups() ->
    [
        {section_2_method, [parallel], [
            decode_query_method,
            encode_query_method,
            lowercase_query_is_not_query,
            pseudo_headers_carry_query
        ]},
        {section_2_h1, [parallel], [
            h1_query_with_content_length,
            h1_query_streaming_chunked,
            h1_query_without_framing_has_no_body,
            h1_query_encode_round_trip,
            h1_lowercase_query_is_invalid_method,
            h1_query_response_has_body
        ]},
        {section_2_h2, [parallel], [
            h2_query_with_data,
            h2_query_with_protocol_is_stream_error
        ]},
        {section_2_h3, [parallel], [
            h3_query_with_data,
            h3_query_with_protocol_is_stream_error
        ]},
        {section_2_properties, [parallel], [
            query_is_safe_and_idempotent,
            method_property_table
        ]},
        {section_2_content_type, [parallel], [
            query_without_content_type_fails,
            query_with_invalid_content_type_fails,
            query_with_content_type_names_the_media_type
        ]},
        {section_3_accept_query, [parallel], [
            accept_query_section_3_example,
            accept_query_appendix_a3_example,
            accept_query_appendix_a5_example,
            accept_query_appendix_a6_example,
            accept_query_token_and_string_are_one_term,
            accept_query_leading_digit_goes_out_as_string,
            accept_query_wildcards,
            accept_query_rejects_subtype_wildcard_alone,
            accept_query_rejects_parameter_of_other_type,
            accept_query_selects_unsupported_media_type
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
%%% Section 2 - The method token
%%%-----------------------------------------------------------------------------

%% RFC10008-2-1: QUERY is a registered method, decoded as a known method.
decode_query_method(_Config) ->
    ?assertEqual(query, nhttp_lib:decode_method(<<"QUERY">>)).

%% RFC10008-2-2: QUERY is encoded as the registered method token.
encode_query_method(_Config) ->
    ?assertEqual(<<"QUERY">>, nhttp_lib:encode_method(query)).

%% RFC9110-9.1-1: the method token is case-sensitive.
lowercase_query_is_not_query(_Config) ->
    ?assertEqual(<<"query">>, nhttp_lib:decode_method(<<"query">>)),
    ?assertEqual(<<"Query">>, nhttp_lib:decode_method(<<"Query">>)).

%% RFC10008-2-3: an HTTP/2 or HTTP/3 request carries QUERY in `:method`.
pseudo_headers_carry_query(_Config) ->
    [Method | _] = nhttp_lib:request_to_pseudo_headers(query_request()),
    ?assertEqual({<<":method">>, <<"QUERY">>}, Method).

%%%-----------------------------------------------------------------------------
%%% Section 2 - HTTP/1.1
%%%-----------------------------------------------------------------------------

%% RFC10008-2-4: the request content carries the query.
h1_query_with_content_length(_Config) ->
    Wire = <<
        "QUERY /contacts HTTP/1.1\r\n"
        "Host: example.org\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 30\r\n"
        "\r\n",
        (query_content())/binary
    >>,
    ?assertMatch(
        {ok, #{method := query, path := <<"/contacts">>}, _},
        nhttp_h1:parse_request(Wire)
    ),
    {ok, #{body := Body}, Consumed} = nhttp_h1:parse_request(Wire),
    ?assertEqual(query_content(), iolist_to_binary(Body)),
    ?assertEqual(byte_size(Wire), Consumed).

%% RFC10008-2-5: the content of a QUERY request can arrive chunked.
h1_query_streaming_chunked(_Config) ->
    Head = <<
        "QUERY /contacts HTTP/1.1\r\n"
        "Host: example.org\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
    >>,
    Chunked = <<"1e\r\n", (query_content())/binary, "\r\n0\r\n\r\n">>,
    {ok, Req, BodyStream, HeadConsumed} =
        nhttp_h1:parse_request_headers(<<Head/binary, Chunked/binary>>),
    ?assertMatch(#{method := query}, Req),
    ?assertEqual(byte_size(Head), HeadConsumed),
    {ok, Chunks, _, BodyConsumed} = nhttp_h1:parse_request_body(Chunked, BodyStream),
    ?assertEqual([{data, query_content()}, {fin, []}], Chunks),
    ?assertEqual(byte_size(Chunked), BodyConsumed).

%% RFC9112-6.3-7: a request without Content-Length or Transfer-Encoding has
%% no content, whatever the method.
h1_query_without_framing_has_no_body(_Config) ->
    Wire = <<"QUERY /contacts HTTP/1.1\r\nHost: example.org\r\n\r\n">>,
    ?assertMatch(
        {ok, #{method := query}, none, _},
        nhttp_h1:parse_request_headers(Wire)
    ).

%% RFC10008-2-6: an encoded QUERY request frames its content and parses back.
h1_query_encode_round_trip(_Config) ->
    {ok, Io} = nhttp_h1:encode_request(query_request()),
    Wire = iolist_to_binary(Io),
    ?assertMatch(<<"QUERY /contacts HTTP/1.1\r\n", _/binary>>, Wire),
    {ok, Parsed, Consumed} = nhttp_h1:parse_request(Wire),
    ?assertEqual(byte_size(Wire), Consumed),
    ?assertMatch(#{method := query, path := <<"/contacts">>}, Parsed),
    ?assertEqual(query_content(), iolist_to_binary(maps:get(body, Parsed))),
    ?assertEqual(
        <<"30">>, nhttp_headers:get_exact(<<"content-length">>, maps:get(headers, Parsed))
    ).

%% RFC9110-9.1-1: a lowercase method token is not QUERY.
h1_lowercase_query_is_invalid_method(_Config) ->
    ?assertEqual(
        {error, invalid_method},
        nhttp_h1:parse_request(<<"query / HTTP/1.1\r\nHost: a\r\n\r\n">>)
    ).

%% RFC10008-2-7: a 200 response to QUERY encloses the result as content.
h1_query_response_has_body(_Config) ->
    Headers = [{<<"content-length">>, <<"2">>}],
    ?assertEqual({length, 2}, nhttp_h1:body_stream_from_response(query, 200, Headers)),
    ?assertEqual(none, nhttp_h1:body_stream_from_response(query, 204, Headers)),
    ?assertEqual(none, nhttp_h1:body_stream_from_response(query, 304, Headers)).

%%%-----------------------------------------------------------------------------
%%% Section 2 - HTTP/2
%%%-----------------------------------------------------------------------------

%% RFC10008-2-4: on HTTP/2 the content of a QUERY request arrives as DATA.
h2_query_with_data(_Config) ->
    Conn0 = h2_server(nhttp_h2:new(server)),
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, nofin, fin, h2_block(query_fields())),
    {ok, Events1, Conn1} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch([{request, 1, #{method := query, path := <<"/contacts">>}, nofin}], Events1),
    {ok, DataFrame} = nhttp_h2_frame:data(1, fin, query_content()),
    Events2 = h2_events(nhttp_h2:recv(Conn1, iolist_to_binary(DataFrame))),
    ?assertEqual([{data, 1, query_content(), fin}], Events2).

%% RFC8441-4-1: `:protocol` requires CONNECT, so QUERY with it is malformed.
h2_query_with_protocol_is_stream_error(_Config) ->
    Conn0 = h2_server(nhttp_h2:new(server, #{enable_connect_protocol => true})),
    Fields = query_fields() ++ [{<<":protocol">>, <<"websocket">>}],
    {ok, HeadersFrame} = nhttp_h2_frame:headers(1, fin, fin, h2_block(Fields)),
    {ok, [], _Conn1, RstFrame} = nhttp_h2:recv(Conn0, iolist_to_binary(HeadersFrame)),
    ?assertMatch(
        {ok, {rst_stream, 1, protocol_error}, _},
        nhttp_h2_frame:decode(iolist_to_binary(RstFrame))
    ).

%%%-----------------------------------------------------------------------------
%%% Section 2 - HTTP/3
%%%-----------------------------------------------------------------------------

%% RFC10008-2-4: on HTTP/3 the content of a QUERY request arrives as DATA.
h3_query_with_data(_Config) ->
    Server0 = h3_server(#{}),
    {ok, Events1, Server1, _} = nhttp_h3:recv(Server0, 0, h3_headers(query_fields()), nofin),
    ?assertMatch([{request, 0, #{method := query, path := <<"/contacts">>}, nofin}], Events1),
    {ok, DataFrame} = nhttp_h3_frame:data(query_content()),
    {ok, Events2, _Server2, _} =
        nhttp_h3:recv(Server1, 0, iolist_to_binary(DataFrame), fin),
    ?assertEqual([{data, 0, query_content(), fin}], Events2).

%% RFC9220-3-1: `:protocol` requires CONNECT, so QUERY with it is malformed.
h3_query_with_protocol_is_stream_error(_Config) ->
    Server = h3_server(#{enable_connect_protocol => true}),
    Fields = query_fields() ++ [{<<":protocol">>, <<"websocket">>}],
    ?assertMatch(
        {error, {stream_error, 0, h3_message_error, _}},
        nhttp_h3:recv(Server, 0, h3_headers(Fields), fin)
    ).

%%%-----------------------------------------------------------------------------
%%% Section 2 - Method properties
%%%-----------------------------------------------------------------------------

%% RFC10008-2-8: QUERY is safe and idempotent.
query_is_safe_and_idempotent(_Config) ->
    ?assert(nhttp_lib:is_safe(query)),
    ?assert(nhttp_lib:is_idempotent(query)).

%% RFC9110-9.2.1-1, RFC9110-9.2.2-1: the safe and the idempotent methods. A
%% method that the library does not know is neither, because RFC 9110
%% Section 9.2.2 forbids an automatic retry without knowledge of idempotency.
method_property_table(_Config) ->
    Table = [
        {get, true, true},
        {head, true, true},
        {options, true, true},
        {trace, true, true},
        {query, true, true},
        {put, false, true},
        {delete, false, true},
        {post, false, false},
        {patch, false, false},
        {connect, false, false},
        {<<"FROB">>, false, false},
        {<<"X-PURGE">>, false, false},
        {<<"A">>, false, false},
        {<<"query">>, false, false}
    ],
    lists:foreach(
        fun({Method, Safe, Idempotent}) ->
            ?assertEqual({Method, Safe}, {Method, nhttp_lib:is_safe(Method)}),
            ?assertEqual({Method, Idempotent}, {Method, nhttp_lib:is_idempotent(Method)})
        end,
        Table
    ).

%%%-----------------------------------------------------------------------------
%%% Section 2 - Content-Type
%%%-----------------------------------------------------------------------------

%% RFC10008-2-9: a server MUST fail a request without a Content-Type.
query_without_content_type_fails(_Config) ->
    Wire = <<"QUERY /contacts HTTP/1.1\r\nHost: example.org\r\nContent-Length: 1\r\n\r\nq">>,
    {ok, #{method := query, headers := Headers}, _} = nhttp_h1:parse_request(Wire),
    ?assertEqual({error, missing_content_type}, nhttp_media_type:content_type(Headers)).

%% RFC10008-2.1-1: a Content-Type that is not a media type is no media type
%% information.
query_with_invalid_content_type_fails(_Config) ->
    Wire = <<
        "QUERY /contacts HTTP/1.1\r\nHost: example.org\r\n"
        "Content-Type: application\r\nContent-Length: 1\r\n\r\nq"
    >>,
    {ok, #{headers := Headers}, _} = nhttp_h1:parse_request(Wire),
    ?assertEqual({error, invalid_content_type}, nhttp_media_type:content_type(Headers)).

%% RFC10008-2-10: the content of the request and its media type define the
%% query.
query_with_content_type_names_the_media_type(_Config) ->
    {ok, #{headers := Headers}, _} = nhttp_h1:parse_request(
        iolist_to_binary(element(2, nhttp_h1:encode_request(query_request())))
    ),
    ?assertEqual(
        {ok, #{type => <<"application">>, subtype => <<"x-www-form-urlencoded">>, params => []}},
        nhttp_media_type:content_type(Headers)
    ).

%%%-----------------------------------------------------------------------------
%%% Section 3 - Accept-Query
%%%-----------------------------------------------------------------------------

%% RFC10008-3-1: the example of Section 3.
accept_query_section_3_example(_Config) ->
    ?assertEqual(
        {ok, [
            media_type(<<"application">>, <<"jsonpath">>, []),
            media_type(<<"application">>, <<"sql">>, [{<<"charset">>, <<"UTF-8">>}])
        ]},
        nhttp_accept_query:parse([
            {<<"accept-query">>, <<"\"application/jsonpath\", application/sql;charset=\"UTF-8\"">>}
        ])
    ).

%% RFC10008-A.3-1: the example of Appendix A.3.
accept_query_appendix_a3_example(_Config) ->
    ?assertEqual(
        {ok, [
            media_type(<<"application">>, <<"x-www-form-urlencoded">>, []),
            media_type(<<"application">>, <<"sql">>, [])
        ]},
        nhttp_accept_query:parse_value(<<"application/x-www-form-urlencoded, application/sql">>)
    ).

%% RFC10008-A.5-1: the example of Appendix A.5.
accept_query_appendix_a5_example(_Config) ->
    ?assertEqual(
        {ok, [
            media_type(<<"application">>, <<"sql">>, []),
            media_type(<<"application">>, <<"xslt+xml">>, [])
        ]},
        nhttp_accept_query:parse_value(<<"\"application/sql\", \"application/xslt+xml\"">>)
    ).

%% RFC10008-A.6-1: the example of Appendix A.6.
accept_query_appendix_a6_example(_Config) ->
    {ok, Ranges} =
        nhttp_accept_query:parse_value(<<"\"application/jsonpath\", \"application/xslt+xml\"">>),
    ?assertEqual(
        [
            media_type(<<"application">>, <<"jsonpath">>, []),
            media_type(<<"application">>, <<"xslt+xml">>, [])
        ],
        Ranges
    ),
    ?assert(nhttp_accept_query:allows(media_type(<<"application">>, <<"jsonpath">>, []), Ranges)),
    ?assertNot(nhttp_accept_query:allows(media_type(<<"application">>, <<"sql">>, []), Ranges)).

%% RFC10008-3-2: a recipient MUST NOT process a Token apart from a String.
accept_query_token_and_string_are_one_term(_Config) ->
    ?assertEqual(
        nhttp_accept_query:parse_value(<<"application/sql;charset=utf-8">>),
        nhttp_accept_query:parse_value(<<"\"application/sql\";charset=\"utf-8\"">>)
    ).

%% RFC10008-3-3: a media type with a leading digit needs the String form.
accept_query_leading_digit_goes_out_as_string(_Config) ->
    Ranges = [media_type(<<"3gpp">>, <<"query">>, [])],
    ?assertEqual({ok, <<"\"3gpp/query\"">>}, nhttp_accept_query:encode(Ranges)),
    ?assertEqual({ok, Ranges}, nhttp_accept_query:parse_value(<<"\"3gpp/query\"">>)),
    ?assertMatch({error, {unsupported_item, 0}}, nhttp_accept_query:parse_value(<<"3gpp/query">>)).

%% RFC10008-3-4: `*/*` matches any type and `type/*` any subtype of `type`.
accept_query_wildcards(_Config) ->
    {ok, Any} = nhttp_accept_query:parse_value(<<"*/*">>),
    {ok, AnyApp} = nhttp_accept_query:parse_value(<<"application/*">>),
    ?assertEqual([media_type(<<"*">>, <<"*">>, [])], Any),
    ?assertEqual([media_type(<<"application">>, <<"*">>, [])], AnyApp),
    ?assert(nhttp_accept_query:allows(media_type(<<"text">>, <<"plain">>, []), Any)),
    ?assert(nhttp_accept_query:allows(media_type(<<"application">>, <<"sql">>, []), AnyApp)),
    ?assertNot(nhttp_accept_query:allows(media_type(<<"text">>, <<"sql">>, []), AnyApp)).

%% RFC10008-3-5: `*/*` and `type/*` are the only wildcards.
accept_query_rejects_subtype_wildcard_alone(_Config) ->
    ?assertEqual(
        {error, {not_media_range, <<"*/sql">>}}, nhttp_accept_query:parse_value(<<"*/sql">>)
    ),
    ?assertEqual(
        {error, {not_media_range, <<"*/sql">>}},
        nhttp_accept_query:encode([media_type(<<"*">>, <<"sql">>, [])])
    ).

%% RFC10008-3-6: a parameter is a String or a Token.
accept_query_rejects_parameter_of_other_type(_Config) ->
    ?assertEqual(
        {error, {unsupported_parameter, 16}},
        nhttp_accept_query:parse_value(<<"application/sql;q=1">>)
    ),
    ?assertEqual(
        {error, {unsupported_parameter, 16}},
        nhttp_accept_query:parse_value(<<"application/sql;strict">>)
    ).

%% RFC10008-2.1-2: a server answers 415 with Accept-Query when it does not
%% support the media type of the request.
accept_query_selects_unsupported_media_type(_Config) ->
    {ok, Supported} = nhttp_accept_query:parse_value(<<"application/sql;charset=utf-8">>),
    {ok, Utf8} = nhttp_media_type:parse(<<"application/sql; charset=UTF-8">>),
    {ok, Latin1} = nhttp_media_type:parse(<<"application/sql; charset=latin1">>),
    ?assert(nhttp_accept_query:allows(Utf8, Supported)),
    ?assertNot(nhttp_accept_query:allows(Latin1, Supported)),
    ?assertEqual(
        {ok, <<"application/sql;charset=utf-8">>}, nhttp_accept_query:encode(Supported)
    ).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

media_type(Type, Subtype, Params) ->
    #{type => Type, subtype => Subtype, params => Params}.

query_content() ->
    <<"q=foo&limit=10&sort=-published">>.

query_request() ->
    #{
        method => query,
        path => <<"/contacts">>,
        scheme => https,
        authority => <<"example.org">>,
        headers => [
            {<<"host">>, <<"example.org">>},
            {<<"content-type">>, <<"application/x-www-form-urlencoded">>}
        ],
        body => query_content()
    }.

query_fields() ->
    [
        {<<":method">>, <<"QUERY">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.org">>},
        {<<":path">>, <<"/contacts">>},
        {<<"content-type">>, <<"application/x-www-form-urlencoded">>}
    ].

h2_server(Conn0) ->
    {ok, Preface} = nhttp_h2_frame:preface(),
    {ok, Settings} = nhttp_h2_frame:settings(#{}),
    {ok, [{settings, #{}}], Conn1, _Ack} =
        nhttp_h2:recv(Conn0, iolist_to_binary([Preface, Settings])),
    Conn1.

h2_block(Fields) ->
    {ok, Enc} = nhttp_hpack:new(),
    {ok, Block, _} = nhttp_hpack:encode(Fields, Enc),
    iolist_to_binary(Block).

h2_events({ok, Events, _Conn}) -> Events;
h2_events({ok, Events, _Conn, _Out}) -> Events.

h3_server(Opts) ->
    Server0 = nhttp_h3:new(server, Opts),
    {ok, Server1, _} = nhttp_h3:init_local_streams(Server0, #{
        control => 3, encoder => 7, decoder => 11
    }),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    ControlData = iolist_to_binary([<<0>>, SettingsFrame]),
    {ok, _, Server2, _} = nhttp_h3:recv(Server1, 2, ControlData, nofin),
    {ok, [], Server3, _} = nhttp_h3:recv(Server2, 6, <<2>>, nofin),
    {ok, [], Server4, _} = nhttp_h3:recv(Server3, 10, <<3>>, nofin),
    Server4.

h3_headers(Fields) ->
    {ok, Enc0} = nhttp_qpack:new_encoder(#{max_table_capacity => 0, max_blocked_streams => 0}),
    {ok, _Enc1, _EncStream, FieldSection} = nhttp_qpack:encode_field_section(Enc0, 0, Fields),
    {ok, Frame} = nhttp_h3_frame:headers(FieldSection),
    iolist_to_binary(Frame).
