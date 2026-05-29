%%%-----------------------------------------------------------------------------
-module(nhttp_msg_SUITE).

-moduledoc "Tests for nhttp_msg shared HTTP/2 + HTTP/3 message helpers.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, is_digits},
        {group, parse_content_length},
        {group, extract_content_length},
        {group, validate_content_length},
        {group, host_header_or_empty},
        {group, validate_trailers},
        {group, extract_request_pseudo},
        {group, extract_response_pseudo},
        {group, validate_wire_scheme},
        {group, check_authority_host_match},
        {group, build_request},
        {group, build_response},
        {group, check_extended_connect},
        {group, validate_request_pseudo_shape}
    ].

groups() ->
    [
        {is_digits, [parallel], [
            is_digits_empty_is_true,
            is_digits_all_digits,
            is_digits_rejects_letters,
            is_digits_rejects_minus,
            is_digits_rejects_space
        ]},
        {parse_content_length, [parallel], [
            parse_cl_empty_is_undefined,
            parse_cl_decimal,
            parse_cl_zero,
            parse_cl_non_digits_undefined,
            parse_cl_negative_undefined,
            parse_cl_with_space_undefined
        ]},
        {extract_content_length, [parallel], [
            extract_cl_absent,
            extract_cl_present_binary,
            extract_cl_skips_non_binary_value,
            extract_cl_first_match_wins,
            extract_cl_non_digit_value_undefined
        ]},
        {validate_content_length, [parallel], [
            vcl_undefined_always_ok,
            vcl_fin_match_ok,
            vcl_fin_mismatch_short,
            vcl_fin_mismatch_long,
            vcl_nofin_under_ok,
            vcl_nofin_equal_ok,
            vcl_nofin_over_mismatch
        ]},
        {host_header_or_empty, [parallel], [
            host_present,
            host_missing,
            host_first_match_wins
        ]},
        {validate_trailers, [parallel], [
            trailers_empty_ok,
            trailers_regular_only_ok,
            trailers_pseudo_first,
            trailers_pseudo_middle,
            trailers_status_pseudo_rejected
        ]},
        {extract_request_pseudo, [parallel], [
            erp_empty_defaults,
            erp_full_pseudo_set,
            erp_unknown_pseudo_dropped,
            erp_regular_order_preserved,
            erp_pseudo_after_regular,
            erp_method_decoded_to_atom
        ]},
        {extract_response_pseudo, [parallel], [
            rsp_empty_default_zero,
            rsp_status_parsed,
            rsp_unknown_pseudo_dropped,
            rsp_regular_order_preserved
        ]},
        {validate_wire_scheme, [parallel], [
            vws_http_ok,
            vws_https_ok,
            vws_other_rejected,
            vws_undefined_rejected,
            vws_uppercase_rejected
        ]},
        {check_authority_host_match, [parallel], [
            cahm_both_undefined_ok,
            cahm_authority_undefined_ok,
            cahm_host_undefined_ok,
            cahm_equal_ok,
            cahm_mismatch_rejected
        ]},
        {build_request, [parallel], [
            br_h2_minimal,
            br_h3_minimal,
            br_authority_fallback_to_host,
            br_authority_preferred_over_host,
            br_peer_added_when_defined,
            br_peer_omitted_when_undefined,
            br_connect_protocol_added,
            br_unknown_pseudo_dropped
        ]},
        {build_response, [parallel], [
            brsp_h2,
            brsp_h3,
            brsp_status_and_filtered_headers
        ]},
        {check_extended_connect, [parallel], [
            cec_no_protocol_ok,
            cec_connect_missing_authority,
            cec_connect_not_enabled,
            cec_connect_enabled_ok,
            cec_non_connect_with_protocol
        ]},
        {validate_request_pseudo_shape, [parallel], [
            vrps_minimal_get,
            vrps_te_passes_through,
            vrps_host_extracted_and_kept,
            vrps_authority_and_host,
            vrps_extended_connect_pseudo,
            vrps_duplicate_pseudo,
            vrps_unknown_pseudo,
            vrps_pseudo_after_regular,
            vrps_forbidden_connection_header_set,
            vrps_multiple_hosts,
            vrps_missing_method,
            vrps_missing_scheme,
            vrps_missing_path,
            vrps_empty_path,
            vrps_bad_wire_scheme,
            vrps_authority_host_mismatch,
            vrps_regular_header_order_preserved
        ]}
    ].

%%%-----------------------------------------------------------------------------
%%% is_digits
%%%-----------------------------------------------------------------------------

is_digits_empty_is_true(_Config) ->
    ?assert(nhttp_msg:is_digits(<<>>)).

is_digits_all_digits(_Config) ->
    ?assert(nhttp_msg:is_digits(<<"0">>)),
    ?assert(nhttp_msg:is_digits(<<"1234567890">>)).

is_digits_rejects_letters(_Config) ->
    ?assertNot(nhttp_msg:is_digits(<<"12a">>)),
    ?assertNot(nhttp_msg:is_digits(<<"abc">>)).

is_digits_rejects_minus(_Config) ->
    ?assertNot(nhttp_msg:is_digits(<<"-1">>)).

is_digits_rejects_space(_Config) ->
    ?assertNot(nhttp_msg:is_digits(<<"1 2">>)),
    ?assertNot(nhttp_msg:is_digits(<<" 1">>)).

%%%-----------------------------------------------------------------------------
%%% parse_content_length
%%%-----------------------------------------------------------------------------

parse_cl_empty_is_undefined(_Config) ->
    ?assertEqual(undefined, nhttp_msg:parse_content_length(<<>>)).

parse_cl_decimal(_Config) ->
    ?assertEqual(0, nhttp_msg:parse_content_length(<<"0">>)),
    ?assertEqual(1, nhttp_msg:parse_content_length(<<"1">>)),
    ?assertEqual(1234567890, nhttp_msg:parse_content_length(<<"1234567890">>)).

parse_cl_zero(_Config) ->
    ?assertEqual(0, nhttp_msg:parse_content_length(<<"00">>)).

parse_cl_non_digits_undefined(_Config) ->
    ?assertEqual(undefined, nhttp_msg:parse_content_length(<<"abc">>)),
    ?assertEqual(undefined, nhttp_msg:parse_content_length(<<"1.5">>)),
    ?assertEqual(undefined, nhttp_msg:parse_content_length(<<"+1">>)).

parse_cl_negative_undefined(_Config) ->
    ?assertEqual(undefined, nhttp_msg:parse_content_length(<<"-1">>)).

parse_cl_with_space_undefined(_Config) ->
    ?assertEqual(undefined, nhttp_msg:parse_content_length(<<" 1">>)),
    ?assertEqual(undefined, nhttp_msg:parse_content_length(<<"1 ">>)).

%%%-----------------------------------------------------------------------------
%%% extract_content_length
%%%-----------------------------------------------------------------------------

extract_cl_absent(_Config) ->
    ?assertEqual(undefined, nhttp_msg:extract_content_length([])),
    ?assertEqual(
        undefined,
        nhttp_msg:extract_content_length([{<<"x-foo">>, <<"bar">>}])
    ).

extract_cl_present_binary(_Config) ->
    ?assertEqual(
        42,
        nhttp_msg:extract_content_length([{<<"content-length">>, <<"42">>}])
    ).

extract_cl_skips_non_binary_value(_Config) ->
    Headers = [{<<"content-length">>, not_a_binary}, {<<"x-foo">>, <<"bar">>}],
    ?assertEqual(undefined, nhttp_msg:extract_content_length(Headers)).

extract_cl_first_match_wins(_Config) ->
    Headers = [
        {<<"x-foo">>, <<"bar">>},
        {<<"content-length">>, <<"1">>},
        {<<"content-length">>, <<"2">>}
    ],
    ?assertEqual(1, nhttp_msg:extract_content_length(Headers)).

extract_cl_non_digit_value_undefined(_Config) ->
    Headers = [{<<"content-length">>, <<"abc">>}],
    ?assertEqual(undefined, nhttp_msg:extract_content_length(Headers)).

%%%-----------------------------------------------------------------------------
%%% validate_content_length
%%%-----------------------------------------------------------------------------

vcl_undefined_always_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:validate_content_length(undefined, 0, fin)),
    ?assertEqual(ok, nhttp_msg:validate_content_length(undefined, 99, nofin)).

vcl_fin_match_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:validate_content_length(0, 0, fin)),
    ?assertEqual(ok, nhttp_msg:validate_content_length(42, 42, fin)).

vcl_fin_mismatch_short(_Config) ->
    ?assertEqual(
        {error, content_length_mismatch},
        nhttp_msg:validate_content_length(42, 41, fin)
    ).

vcl_fin_mismatch_long(_Config) ->
    ?assertEqual(
        {error, content_length_mismatch},
        nhttp_msg:validate_content_length(42, 43, fin)
    ).

vcl_nofin_under_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:validate_content_length(42, 0, nofin)),
    ?assertEqual(ok, nhttp_msg:validate_content_length(42, 41, nofin)).

vcl_nofin_equal_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:validate_content_length(42, 42, nofin)).

vcl_nofin_over_mismatch(_Config) ->
    ?assertEqual(
        {error, content_length_mismatch},
        nhttp_msg:validate_content_length(42, 43, nofin)
    ).

%%%-----------------------------------------------------------------------------
%%% host_header_or_empty
%%%-----------------------------------------------------------------------------

host_present(_Config) ->
    ?assertEqual(
        <<"example.com">>,
        nhttp_msg:host_header_or_empty([{<<"host">>, <<"example.com">>}])
    ).

host_missing(_Config) ->
    ?assertEqual(<<>>, nhttp_msg:host_header_or_empty([])),
    ?assertEqual(<<>>, nhttp_msg:host_header_or_empty([{<<"x-foo">>, <<"bar">>}])).

host_first_match_wins(_Config) ->
    Headers = [
        {<<"host">>, <<"first.example">>},
        {<<"host">>, <<"second.example">>}
    ],
    ?assertEqual(<<"first.example">>, nhttp_msg:host_header_or_empty(Headers)).

%%%-----------------------------------------------------------------------------
%%% validate_trailers
%%%-----------------------------------------------------------------------------

trailers_empty_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:validate_trailers([])).

trailers_regular_only_ok(_Config) ->
    ?assertEqual(
        ok,
        nhttp_msg:validate_trailers([
            {<<"x-foo">>, <<"bar">>},
            {<<"x-baz">>, <<"qux">>}
        ])
    ).

trailers_pseudo_first(_Config) ->
    ?assertEqual(
        {error, pseudo_in_trailers},
        nhttp_msg:validate_trailers([{<<":method">>, <<"GET">>}])
    ).

trailers_pseudo_middle(_Config) ->
    ?assertEqual(
        {error, pseudo_in_trailers},
        nhttp_msg:validate_trailers([
            {<<"x-foo">>, <<"bar">>},
            {<<":authority">>, <<"example.com">>},
            {<<"x-baz">>, <<"qux">>}
        ])
    ).

trailers_status_pseudo_rejected(_Config) ->
    ?assertEqual(
        {error, pseudo_in_trailers},
        nhttp_msg:validate_trailers([{<<":status">>, <<"200">>}])
    ).

%%%-----------------------------------------------------------------------------
%%% extract_request_pseudo
%%%-----------------------------------------------------------------------------

erp_empty_defaults(_Config) ->
    ?assertEqual(
        {undefined, <<>>, http, <<>>, undefined, []},
        nhttp_msg:extract_request_pseudo([])
    ).

erp_full_pseudo_set(_Config) ->
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/api">>},
        {<<":protocol">>, <<"websocket">>}
    ],
    ?assertEqual(
        {post, <<"/api">>, https, <<"example.com">>, <<"websocket">>, []},
        nhttp_msg:extract_request_pseudo(Headers)
    ).

erp_unknown_pseudo_dropped(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":bogus">>, <<"x">>},
        {<<"x-foo">>, <<"bar">>}
    ],
    {Method, _Path, _Scheme, _Auth, _CProt, Filtered} =
        nhttp_msg:extract_request_pseudo(Headers),
    ?assertEqual(get, Method),
    ?assertEqual([{<<"x-foo">>, <<"bar">>}], Filtered).

erp_regular_order_preserved(_Config) ->
    Headers = [
        {<<"x-a">>, <<"1">>},
        {<<":method">>, <<"GET">>},
        {<<"x-b">>, <<"2">>},
        {<<":path">>, <<"/">>},
        {<<"x-c">>, <<"3">>}
    ],
    {_M, _P, _S, _A, _CP, Filtered} = nhttp_msg:extract_request_pseudo(Headers),
    ?assertEqual(
        [
            {<<"x-a">>, <<"1">>},
            {<<"x-b">>, <<"2">>},
            {<<"x-c">>, <<"3">>}
        ],
        Filtered
    ).

erp_pseudo_after_regular(_Config) ->
    Headers = [
        {<<"x-a">>, <<"1">>},
        {<<":method">>, <<"GET">>}
    ],
    {Method, _, _, _, _, _} = nhttp_msg:extract_request_pseudo(Headers),
    ?assertEqual(get, Method).

erp_method_decoded_to_atom(_Config) ->
    Headers = [{<<":method">>, <<"DELETE">>}],
    {delete, _, _, _, _, _} = nhttp_msg:extract_request_pseudo(Headers).

%%%-----------------------------------------------------------------------------
%%% extract_response_pseudo
%%%-----------------------------------------------------------------------------

rsp_empty_default_zero(_Config) ->
    ?assertEqual({0, []}, nhttp_msg:extract_response_pseudo([])).

rsp_status_parsed(_Config) ->
    ?assertEqual(
        {200, []},
        nhttp_msg:extract_response_pseudo([{<<":status">>, <<"200">>}])
    ).

rsp_unknown_pseudo_dropped(_Config) ->
    Headers = [
        {<<":status">>, <<"404">>},
        {<<":bogus">>, <<"x">>},
        {<<"x-foo">>, <<"bar">>}
    ],
    ?assertEqual(
        {404, [{<<"x-foo">>, <<"bar">>}]},
        nhttp_msg:extract_response_pseudo(Headers)
    ).

rsp_regular_order_preserved(_Config) ->
    Headers = [
        {<<"x-a">>, <<"1">>},
        {<<":status">>, <<"200">>},
        {<<"x-b">>, <<"2">>}
    ],
    ?assertEqual(
        {200, [{<<"x-a">>, <<"1">>}, {<<"x-b">>, <<"2">>}]},
        nhttp_msg:extract_response_pseudo(Headers)
    ).

%%%-----------------------------------------------------------------------------
%%% validate_wire_scheme
%%%-----------------------------------------------------------------------------

vws_http_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:validate_wire_scheme(<<"http">>)).

vws_https_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:validate_wire_scheme(<<"https">>)).

vws_other_rejected(_Config) ->
    ?assertEqual({error, protocol_error}, nhttp_msg:validate_wire_scheme(<<"ws">>)),
    ?assertEqual({error, protocol_error}, nhttp_msg:validate_wire_scheme(<<"ftp">>)),
    ?assertEqual({error, protocol_error}, nhttp_msg:validate_wire_scheme(<<>>)).

vws_undefined_rejected(_Config) ->
    ?assertEqual({error, protocol_error}, nhttp_msg:validate_wire_scheme(undefined)).

vws_uppercase_rejected(_Config) ->
    ?assertEqual({error, protocol_error}, nhttp_msg:validate_wire_scheme(<<"HTTP">>)),
    ?assertEqual({error, protocol_error}, nhttp_msg:validate_wire_scheme(<<"HTTPS">>)).

%%%-----------------------------------------------------------------------------
%%% check_authority_host_match
%%%-----------------------------------------------------------------------------

cahm_both_undefined_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:check_authority_host_match(undefined, undefined)).

cahm_authority_undefined_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:check_authority_host_match(undefined, <<"a">>)).

cahm_host_undefined_ok(_Config) ->
    ?assertEqual(ok, nhttp_msg:check_authority_host_match(<<"a">>, undefined)).

cahm_equal_ok(_Config) ->
    ?assertEqual(
        ok,
        nhttp_msg:check_authority_host_match(<<"example.com">>, <<"example.com">>)
    ).

cahm_mismatch_rejected(_Config) ->
    ?assertEqual(
        {error, protocol_error},
        nhttp_msg:check_authority_host_match(<<"a.example">>, <<"b.example">>)
    ).

%%%-----------------------------------------------------------------------------
%%% build_request
%%%-----------------------------------------------------------------------------

br_h2_minimal(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ],
    Req = nhttp_msg:build_request(http2, undefined, Headers),
    ?assertEqual(get, maps:get(method, Req)),
    ?assertEqual(<<"/">>, maps:get(path, Req)),
    ?assertEqual(https, maps:get(scheme, Req)),
    ?assertEqual(<<"example.com">>, maps:get(authority, Req)),
    ?assertEqual(http2, maps:get(version, Req)),
    ?assertEqual([], maps:get(headers, Req)),
    ?assertNot(maps:is_key(peer, Req)),
    ?assertNot(maps:is_key(connect_protocol, Req)).

br_h3_minimal(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ],
    Req = nhttp_msg:build_request(http3, undefined, Headers),
    ?assertEqual(http3, maps:get(version, Req)).

br_authority_fallback_to_host(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"example.com">>}
    ],
    Req = nhttp_msg:build_request(http2, undefined, Headers),
    ?assertEqual(<<"example.com">>, maps:get(authority, Req)),
    ?assertEqual([{<<"host">>, <<"example.com">>}], maps:get(headers, Req)).

br_authority_preferred_over_host(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"primary.example">>},
        {<<":path">>, <<"/">>},
        {<<"host">>, <<"secondary.example">>}
    ],
    Req = nhttp_msg:build_request(http3, undefined, Headers),
    ?assertEqual(<<"primary.example">>, maps:get(authority, Req)).

br_peer_added_when_defined(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ],
    Peer = {{127, 0, 0, 1}, 12345},
    Req = nhttp_msg:build_request(http2, Peer, Headers),
    ?assertEqual(Peer, maps:get(peer, Req)).

br_peer_omitted_when_undefined(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ],
    Req = nhttp_msg:build_request(http2, undefined, Headers),
    ?assertNot(maps:is_key(peer, Req)).

br_connect_protocol_added(_Config) ->
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<":protocol">>, <<"websocket">>}
    ],
    Req = nhttp_msg:build_request(http2, undefined, Headers),
    ?assertEqual(<<"websocket">>, maps:get(connect_protocol, Req)).

br_unknown_pseudo_dropped(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<":bogus">>, <<"x">>},
        {<<"x-foo">>, <<"bar">>}
    ],
    Req = nhttp_msg:build_request(http2, undefined, Headers),
    ?assertEqual([{<<"x-foo">>, <<"bar">>}], maps:get(headers, Req)).

%%%-----------------------------------------------------------------------------
%%% build_response
%%%-----------------------------------------------------------------------------

brsp_h2(_Config) ->
    Resp = nhttp_msg:build_response(http2, [{<<":status">>, <<"200">>}]),
    ?assertEqual(200, maps:get(status, Resp)),
    ?assertEqual(http2, maps:get(version, Resp)),
    ?assertEqual(<<>>, maps:get(reason, Resp)),
    ?assertEqual([], maps:get(headers, Resp)).

brsp_h3(_Config) ->
    Resp = nhttp_msg:build_response(http3, [{<<":status">>, <<"204">>}]),
    ?assertEqual(204, maps:get(status, Resp)),
    ?assertEqual(http3, maps:get(version, Resp)).

brsp_status_and_filtered_headers(_Config) ->
    Resp = nhttp_msg:build_response(http2, [
        {<<":status">>, <<"301">>},
        {<<"location">>, <<"/elsewhere">>}
    ]),
    ?assertEqual(301, maps:get(status, Resp)),
    ?assertEqual([{<<"location">>, <<"/elsewhere">>}], maps:get(headers, Resp)).

%%%-----------------------------------------------------------------------------
%%% check_extended_connect
%%%-----------------------------------------------------------------------------

cec_no_protocol_ok(_Config) ->
    ?assertEqual(
        ok,
        nhttp_msg:check_extended_connect(<<"GET">>, undefined, <<"a">>, #{})
    ),
    ?assertEqual(
        ok,
        nhttp_msg:check_extended_connect(<<"CONNECT">>, undefined, undefined, #{})
    ).

cec_connect_missing_authority(_Config) ->
    ?assertEqual(
        {error, missing_authority},
        nhttp_msg:check_extended_connect(
            <<"CONNECT">>, <<"websocket">>, undefined, #{enable_connect_protocol => true}
        )
    ).

cec_connect_not_enabled(_Config) ->
    ?assertEqual(
        {error, not_enabled},
        nhttp_msg:check_extended_connect(<<"CONNECT">>, <<"websocket">>, <<"a">>, #{})
    ),
    ?assertEqual(
        {error, not_enabled},
        nhttp_msg:check_extended_connect(
            <<"CONNECT">>, <<"websocket">>, <<"a">>, #{enable_connect_protocol => false}
        )
    ).

cec_connect_enabled_ok(_Config) ->
    ?assertEqual(
        ok,
        nhttp_msg:check_extended_connect(
            <<"CONNECT">>, <<"websocket">>, <<"a">>, #{enable_connect_protocol => true}
        )
    ).

cec_non_connect_with_protocol(_Config) ->
    ?assertEqual(
        {error, bad_method},
        nhttp_msg:check_extended_connect(
            <<"GET">>, <<"websocket">>, <<"a">>, #{enable_connect_protocol => true}
        )
    ),
    ?assertEqual(
        {error, bad_method},
        nhttp_msg:check_extended_connect(undefined, <<"websocket">>, <<"a">>, #{})
    ).

%%%-----------------------------------------------------------------------------
%%% validate_request_pseudo_shape
%%%-----------------------------------------------------------------------------

minimal_request_headers() ->
    [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ].

vrps_minimal_get(_Config) ->
    {ok, Shape} = nhttp_msg:validate_request_pseudo_shape(minimal_request_headers()),
    ?assertEqual(<<"GET">>, maps:get(method, Shape)),
    ?assertEqual(<<"https">>, maps:get(scheme, Shape)),
    ?assertEqual(<<"/">>, maps:get(path, Shape)),
    ?assertEqual(<<"example.com">>, maps:get(authority, Shape)),
    ?assertEqual(undefined, maps:get(host, Shape)),
    ?assertEqual(undefined, maps:get(protocol, Shape)),
    ?assertEqual([], maps:get(headers, Shape)).

vrps_te_passes_through(_Config) ->
    Headers = minimal_request_headers() ++ [{<<"te">>, <<"gzip">>}],
    {ok, Shape} = nhttp_msg:validate_request_pseudo_shape(Headers),
    ?assertEqual(
        [{<<"te">>, <<"gzip">>}],
        maps:get(headers, Shape)
    ).

vrps_host_extracted_and_kept(_Config) ->
    Pseudos = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>}
    ],
    Headers = Pseudos ++ [{<<"host">>, <<"example.com">>}],
    {ok, Shape} = nhttp_msg:validate_request_pseudo_shape(Headers),
    ?assertEqual(<<"example.com">>, maps:get(host, Shape)),
    ?assertEqual(undefined, maps:get(authority, Shape)),
    ?assertEqual([{<<"host">>, <<"example.com">>}], maps:get(headers, Shape)).

vrps_authority_and_host(_Config) ->
    Headers = minimal_request_headers() ++ [{<<"host">>, <<"example.com">>}],
    {ok, Shape} = nhttp_msg:validate_request_pseudo_shape(Headers),
    ?assertEqual(<<"example.com">>, maps:get(authority, Shape)),
    ?assertEqual(<<"example.com">>, maps:get(host, Shape)).

vrps_extended_connect_pseudo(_Config) ->
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>},
        {<<":protocol">>, <<"websocket">>}
    ],
    {ok, Shape} = nhttp_msg:validate_request_pseudo_shape(Headers),
    ?assertEqual(<<"websocket">>, maps:get(protocol, Shape)).

vrps_duplicate_pseudo(_Config) ->
    Headers = minimal_request_headers() ++ [{<<":method">>, <<"POST">>}],
    ?assertEqual(
        {error, duplicate_pseudo},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_unknown_pseudo(_Config) ->
    Headers = minimal_request_headers() ++ [{<<":bogus">>, <<"x">>}],
    ?assertEqual(
        {error, unknown_pseudo},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_pseudo_after_regular(_Config) ->
    Headers =
        minimal_request_headers() ++
            [{<<"x-foo">>, <<"bar">>}, {<<":authority">>, <<"late.example">>}],
    ?assertEqual(
        {error, pseudo_after_regular},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_forbidden_connection_header_set(_Config) ->
    Cases = [
        <<"connection">>,
        <<"keep-alive">>,
        <<"proxy-connection">>,
        <<"transfer-encoding">>,
        <<"upgrade">>
    ],
    lists:foreach(
        fun(Name) ->
            Headers = minimal_request_headers() ++ [{Name, <<"x">>}],
            ?assertEqual(
                {error, forbidden_connection_header},
                nhttp_msg:validate_request_pseudo_shape(Headers)
            )
        end,
        Cases
    ).

vrps_multiple_hosts(_Config) ->
    Headers =
        minimal_request_headers() ++
            [{<<"host">>, <<"a.example">>}, {<<"host">>, <<"b.example">>}],
    ?assertEqual(
        {error, multiple_host_headers},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_missing_method(_Config) ->
    Headers = [
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ],
    ?assertEqual(
        {error, missing_required_pseudo},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_missing_scheme(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ],
    ?assertEqual(
        {error, missing_required_pseudo},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_missing_path(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>}
    ],
    ?assertEqual(
        {error, missing_required_pseudo},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_empty_path(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<>>}
    ],
    ?assertEqual(
        {error, missing_required_pseudo},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_bad_wire_scheme(_Config) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"ftp">>},
        {<<":authority">>, <<"example.com">>},
        {<<":path">>, <<"/">>}
    ],
    ?assertEqual(
        {error, bad_wire_scheme},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_authority_host_mismatch(_Config) ->
    Headers = minimal_request_headers() ++ [{<<"host">>, <<"other.example">>}],
    ?assertEqual(
        {error, authority_host_mismatch},
        nhttp_msg:validate_request_pseudo_shape(Headers)
    ).

vrps_regular_header_order_preserved(_Config) ->
    Headers =
        minimal_request_headers() ++
            [
                {<<"x-a">>, <<"1">>},
                {<<"x-b">>, <<"2">>},
                {<<"x-c">>, <<"3">>}
            ],
    {ok, Shape} = nhttp_msg:validate_request_pseudo_shape(Headers),
    ?assertEqual(
        [
            {<<"x-a">>, <<"1">>},
            {<<"x-b">>, <<"2">>},
            {<<"x-c">>, <<"3">>}
        ],
        maps:get(headers, Shape)
    ).
