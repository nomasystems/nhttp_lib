%%%-----------------------------------------------------------------------------
-module(nhttp_error_SUITE).

-moduledoc "Test suite for nhttp_error module. Tests constructors, normalization, classification, and formatting.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1
]).

%%%-----------------------------------------------------------------------------
%%% TEST CASES
%%%-----------------------------------------------------------------------------

-export([
    connection_constructors_test/1,
    request_constructors_test/1,
    http2_constructors_test/1,
    pool_constructors_test/1,
    file_upload_constructors_test/1,
    stream_constructors_test/1,
    server_constructors_test/1,

    normalize_posix_errors_test/1,
    normalize_tls_errors_test/1,
    normalize_http2_errors_test/1,
    normalize_pool_errors_test/1,
    normalize_legacy_3tuple_test/1,
    normalize_idempotent_test/1,
    normalize_unknown_passthrough_test/1,
    normalize_request_errors_test/1,
    normalize_server_errors_test/1,
    normalize_additional_server_errors_test/1,

    is_retryable_connection_test/1,
    is_retryable_request_test/1,
    is_retryable_http2_test/1,
    is_retryable_pool_test/1,
    is_retryable_raw_errors_test/1,
    is_transient_test/1,
    is_retryable_server_test/1,
    is_retryable_normalize_branch_test/1,
    is_transient_normalize_branch_test/1,

    category_extraction_test/1,
    format_connection_test/1,
    format_request_test/1,
    format_http2_test/1,
    format_pool_test/1,
    format_fallback_test/1,
    format_server_test/1,
    format_additional_server_test/1,
    format_additional_request_test/1,
    format_unknown_category_test/1
]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS IMPLEMENTATION
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, constructors},
        {group, normalization},
        {group, classification},
        {group, utilities}
    ].

groups() ->
    [
        {constructors, [parallel], [
            connection_constructors_test,
            request_constructors_test,
            http2_constructors_test,
            pool_constructors_test,
            file_upload_constructors_test,
            stream_constructors_test,
            server_constructors_test
        ]},
        {normalization, [parallel], [
            normalize_posix_errors_test,
            normalize_tls_errors_test,
            normalize_http2_errors_test,
            normalize_pool_errors_test,
            normalize_legacy_3tuple_test,
            normalize_idempotent_test,
            normalize_unknown_passthrough_test,
            normalize_request_errors_test,
            normalize_server_errors_test,
            normalize_additional_server_errors_test
        ]},
        {classification, [parallel], [
            is_retryable_connection_test,
            is_retryable_request_test,
            is_retryable_http2_test,
            is_retryable_pool_test,
            is_retryable_raw_errors_test,
            is_transient_test,
            is_retryable_server_test,
            is_retryable_normalize_branch_test,
            is_transient_normalize_branch_test
        ]},
        {utilities, [parallel], [
            category_extraction_test,
            format_connection_test,
            format_request_test,
            format_http2_test,
            format_pool_test,
            format_fallback_test,
            format_server_test,
            format_additional_server_test,
            format_additional_request_test,
            format_unknown_category_test
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% CONSTRUCTOR TESTS
%%%-----------------------------------------------------------------------------

connection_constructors_test(_Config) ->
    ?assertEqual(
        {error, {connection, #{type => connect_timeout}}},
        nhttp_error:connect_timeout()
    ),

    {error, {connection, Map1}} = nhttp_error:connect_timeout(5000),
    ?assertEqual(connect_timeout, maps:get(type, Map1)),
    ?assertEqual(5000, maps:get(value, Map1)),

    {error, {connection, Map2}} = nhttp_error:connect_refused(econnrefused),
    ?assertEqual(connect_refused, maps:get(type, Map2)),
    ?assertEqual(econnrefused, maps:get(posix, Map2)),

    {error, {connection, Map3}} = nhttp_error:connect_failed(enetunreach),
    ?assertEqual(connect_failed, maps:get(type, Map3)),
    ?assertEqual(enetunreach, maps:get(posix, Map3)),

    {error, {connection, Map4}} = nhttp_error:tls_error(certificate_expired),
    ?assertEqual(tls_error, maps:get(type, Map4)),
    ?assertEqual(certificate_expired, maps:get(reason, Map4)),

    {error, {connection, Map5}} = nhttp_error:alpn_error(no_protocol),
    ?assertEqual(alpn_error, maps:get(type, Map5)),
    ?assertEqual(no_protocol, maps:get(reason, Map5)),

    ?assertEqual(
        {error, {connection, #{type => not_ready}}},
        nhttp_error:connect_not_ready()
    ),

    ok.

request_constructors_test(_Config) ->
    ?assertEqual(
        {error, {request, #{type => request_timeout}}},
        nhttp_error:request_timeout()
    ),

    {error, {request, Map1}} = nhttp_error:request_timeout(30000),
    ?assertEqual(request_timeout, maps:get(type, Map1)),
    ?assertEqual(30000, maps:get(value, Map1)),

    {error, {request, Map2}} = nhttp_error:body_timeout(10000),
    ?assertEqual(body_timeout, maps:get(type, Map2)),
    ?assertEqual(10000, maps:get(value, Map2)),

    {error, {request, Map3}} = nhttp_error:send_error(epipe),
    ?assertEqual(send_error, maps:get(type, Map3)),
    ?assertEqual(epipe, maps:get(posix, Map3)),

    {error, {request, Map4}} = nhttp_error:recv_error(econnreset),
    ?assertEqual(recv_error, maps:get(type, Map4)),
    ?assertEqual(econnreset, maps:get(posix, Map4)),

    ?assertEqual(
        {error, {request, #{type => connection_closed}}},
        nhttp_error:connection_closed()
    ),

    {error, {request, Map5}} = nhttp_error:connection_closed(unexpected),
    ?assertEqual(connection_closed, maps:get(type, Map5)),
    ?assertEqual(unexpected, maps:get(tag, Map5)),

    {error, {request, Map6}} = nhttp_error:connection_closed(retryable),
    ?assertEqual(retryable, maps:get(tag, Map6)),

    {error, {request, MalformedMap}} = nhttp_error:malformed_response(status_line, <<>>),
    ?assertEqual(malformed_response, maps:get(type, MalformedMap)),
    ?assertEqual(status_line, maps:get(parse_error, MalformedMap)),
    ?assertEqual(<<>>, maps:get(data, MalformedMap)),

    {error, {request, TooLargeMap}} = nhttp_error:response_too_large(1000000, 100000),
    ?assertEqual(response_too_large, maps:get(type, TooLargeMap)),
    ?assertEqual(1000000, maps:get(size, TooLargeMap)),
    ?assertEqual(100000, maps:get(max_size, TooLargeMap)),

    {error, {request, Map7}} = nhttp_error:max_redirects(10),
    ?assertEqual(max_redirects_exceeded, maps:get(type, Map7)),
    ?assertEqual(10, maps:get(count, Map7)),

    {error, {request, Map8}} = nhttp_error:redirect_loop(<<"https://example.com">>),
    ?assertEqual(redirect_loop, maps:get(type, Map8)),
    ?assertEqual(<<"https://example.com">>, maps:get(url, Map8)),

    ok.

http2_constructors_test(_Config) ->
    {error, {http2, Map1}} = nhttp_error:goaway(no_error),
    ?assertEqual(goaway, maps:get(type, Map1)),
    ?assertEqual(no_error, maps:get(error_code, Map1)),
    ?assertEqual(error, maps:find(retryable, Map1)),

    {error, {http2, Map2}} = nhttp_error:goaway(enhance_your_calm, retryable),
    ?assertEqual(goaway, maps:get(type, Map2)),
    ?assertEqual(enhance_your_calm, maps:get(error_code, Map2)),
    ?assertEqual(true, maps:get(retryable, Map2)),

    {error, {http2, Map3}} = nhttp_error:stream_reset(cancel),
    ?assertEqual(stream_reset, maps:get(type, Map3)),
    ?assertEqual(cancel, maps:get(error_code, Map3)),

    ?assertEqual(
        {error, {http2, #{type => cancelled}}},
        nhttp_error:stream_cancelled()
    ),

    {error, {http2, Map4}} = nhttp_error:stream_refused(),
    ?assertEqual(refused, maps:get(type, Map4)),
    ?assertEqual(true, maps:get(retryable, Map4)),

    {error, {http2, Map5a}} = nhttp_error:stream_closed(graceful),
    ?assertEqual(stream_closed, maps:get(type, Map5a)),
    ?assertEqual(graceful, maps:get(reason, Map5a)),

    {error, {http2, Map5b}} = nhttp_error:stream_closed(some_error),
    ?assertEqual(stream_closed, maps:get(type, Map5b)),
    ?assertEqual(some_error, maps:get(reason, Map5b)),

    {error, {http2, Map5c}} = nhttp_error:rate_limited(),
    ?assertEqual(rate_limited, maps:get(type, Map5c)),
    ?assertEqual(true, maps:get(retryable, Map5c)),

    {error, {http2, Map6}} = nhttp_error:flow_control_error(window_exceeded),
    ?assertEqual(flow_control_error, maps:get(type, Map6)),
    ?assertEqual(window_exceeded, maps:get(reason, Map6)),

    ok.

pool_constructors_test(_Config) ->
    ?assertEqual(
        {error, {pool, #{type => checkout_timeout}}},
        nhttp_error:checkout_timeout()
    ),

    {error, {pool, Map1}} = nhttp_error:pool_exhausted(max_pending_requests),
    ?assertEqual(exhausted, maps:get(type, Map1)),
    ?assertEqual(max_pending_requests, maps:get(reason, Map1)),

    ?assertEqual(
        {error, {pool, #{type => no_connections_available}}},
        nhttp_error:no_connections()
    ),

    ?assertEqual(
        {error, {pool, #{type => draining}}},
        nhttp_error:pool_draining()
    ),

    ok.

file_upload_constructors_test(_Config) ->
    {error, {request, Map1}} = nhttp_error:file_error(read, enoent),
    ?assertEqual(file_error, maps:get(type, Map1)),
    ?assertEqual(read, maps:get(operation, Map1)),
    ?assertEqual(enoent, maps:get(reason, Map1)),

    {error, {request, Map2}} = nhttp_error:file_error(open, "/tmp/test.txt", eacces),
    ?assertEqual(file_error, maps:get(type, Map2)),
    ?assertEqual(open, maps:get(operation, Map2)),
    ?assertEqual("/tmp/test.txt", maps:get(path, Map2)),
    ?assertEqual(eacces, maps:get(reason, Map2)),

    {error, {request, Map3}} = nhttp_error:upload_error(invalid_stream_body),
    ?assertEqual(upload_error, maps:get(type, Map3)),
    ?assertEqual(invalid_stream_body, maps:get(reason, Map3)),

    ok.

stream_constructors_test(_Config) ->
    {error, {request, Map1}} = nhttp_error:stream_stopped(user_cancelled),
    ?assertEqual(stream_stopped, maps:get(type, Map1)),
    ?assertEqual(user_cancelled, maps:get(reason, Map1)),

    {error, {request, Map2}} = nhttp_error:stream_stopped(timeout, <<"partial data">>),
    ?assertEqual(stream_stopped, maps:get(type, Map2)),
    ?assertEqual(timeout, maps:get(reason, Map2)),
    ?assertEqual(<<"partial data">>, maps:get(acc, Map2)),

    ok.

%%%-----------------------------------------------------------------------------
%%% NORMALIZATION TESTS
%%%-----------------------------------------------------------------------------

normalize_posix_errors_test(_Config) ->
    ?assertMatch(
        {error, {connection, #{type := connect_refused, posix := econnrefused}}},
        nhttp_error:normalize({error, econnrefused})
    ),
    ?assertMatch(
        {error, {connection, #{type := connect_refused, posix := econnrefused}}},
        nhttp_error:normalize({error, {connect_error, econnrefused}})
    ),

    ?assertEqual(
        {error, {connection, #{type => connect_timeout}}},
        nhttp_error:normalize({error, etimedout})
    ),
    ?assertEqual(
        {error, {connection, #{type => connect_timeout}}},
        nhttp_error:normalize({error, timeout})
    ),
    ?assertEqual(
        {error, {connection, #{type => connect_timeout}}},
        nhttp_error:normalize({error, connect_timeout})
    ),
    ?assertEqual(
        {error, {connection, #{type => connect_timeout}}},
        nhttp_error:normalize({error, {connect_timeout, 5000}})
    ),

    ?assertMatch(
        {error, {connection, #{type := connect_failed, posix := enetunreach}}},
        nhttp_error:normalize({error, enetunreach})
    ),
    ?assertMatch(
        {error, {connection, #{type := connect_failed, posix := ehostunreach}}},
        nhttp_error:normalize({error, ehostunreach})
    ),
    ?assertMatch(
        {error, {connection, #{type := connect_failed, posix := eaddrnotavail}}},
        nhttp_error:normalize({error, eaddrnotavail})
    ),

    ?assertMatch(
        {error, {connection, #{type := connect_failed, posix := eaddrinuse}}},
        nhttp_error:normalize({error, {connect_error, eaddrinuse}})
    ),

    ?assertMatch(
        {error, {request, #{type := recv_error, posix := econnreset}}},
        nhttp_error:normalize({error, econnreset})
    ),
    ?assertMatch(
        {error, {request, #{type := send_error, posix := epipe}}},
        nhttp_error:normalize({error, epipe})
    ),

    ok.

normalize_tls_errors_test(_Config) ->
    ?assertMatch(
        {error, {connection, #{type := tls_error, reason := certificate_expired}}},
        nhttp_error:normalize({error, {tls_error, certificate_expired}})
    ),

    ?assertMatch(
        {error, {connection, #{type := tls_error, reason := handshake_failure}}},
        nhttp_error:normalize({error, {ssl, handshake_failure}})
    ),

    ?assertMatch(
        {error, {connection, #{type := tls_error, reason := {tls_alert, bad_certificate}}}},
        nhttp_error:normalize({error, {tls_alert, bad_certificate}})
    ),

    ?assertMatch(
        {error, {connection, #{type := alpn_error, reason := h2_not_supported}}},
        nhttp_error:normalize({error, {alpn_error, h2_not_supported}})
    ),
    ?assertMatch(
        {error, {connection, #{type := alpn_error, reason := no_protocol}}},
        nhttp_error:normalize({error, no_alpn_protocol})
    ),

    ok.

normalize_http2_errors_test(_Config) ->
    ?assertMatch(
        {error, {http2, #{type := goaway, error_code := no_error}}},
        nhttp_error:normalize({error, {goaway, no_error}})
    ),
    ?assertMatch(
        {error, {http2, #{type := goaway, error_code := enhance_your_calm, retryable := true}}},
        nhttp_error:normalize({error, {goaway, enhance_your_calm, retryable}})
    ),
    ?assertMatch(
        {error, {http2, #{type := goaway, error_code := protocol_error}}},
        nhttp_error:normalize({error, {http2_error, {goaway, protocol_error}}})
    ),
    ?assertMatch(
        {error, {http2, #{type := goaway, error_code := no_error}}},
        nhttp_error:normalize({error, goaway})
    ),

    ?assertMatch(
        {error, {http2, #{type := stream_reset, error_code := cancel}}},
        nhttp_error:normalize({error, {stream_reset, cancel}})
    ),
    ?assertMatch(
        {error, {http2, #{type := stream_reset, error_code := refused_stream}}},
        nhttp_error:normalize({error, {rst_stream, refused_stream}})
    ),

    ?assertEqual(
        {error, {http2, #{type => cancelled}}},
        nhttp_error:normalize({error, cancelled})
    ),
    ?assertEqual(
        {error, {http2, #{type => cancelled}}},
        nhttp_error:normalize({error, stream_cancelled})
    ),

    ?assertMatch(
        {error, {http2, #{type := refused, retryable := true}}},
        nhttp_error:normalize({error, refused_stream})
    ),
    ?assertMatch(
        {error, {http2, #{type := refused, retryable := true}}},
        nhttp_error:normalize({error, {refused, retryable}})
    ),

    ?assertMatch(
        {error, {http2, #{type := flow_control_error, reason := window_exceeded}}},
        nhttp_error:normalize({error, {flow_control_error, window_exceeded}})
    ),

    ok.

normalize_pool_errors_test(_Config) ->
    ?assertEqual(
        {error, {pool, #{type => checkout_timeout}}},
        nhttp_error:normalize({error, checkout_timeout})
    ),
    ?assertEqual(
        {error, {pool, #{type => checkout_timeout}}},
        nhttp_error:normalize({error, {checkout_timeout, 5000}})
    ),

    ?assertMatch(
        {error, {pool, #{type := exhausted, reason := full}}},
        nhttp_error:normalize({error, pool_full})
    ),
    ?assertMatch(
        {error, {pool, #{type := exhausted, reason := max_connections}}},
        nhttp_error:normalize({error, {pool_exhausted, max_connections}})
    ),

    ?assertEqual(
        {error, {pool, #{type => no_connections_available}}},
        nhttp_error:normalize({error, no_connections_available})
    ),

    ?assertMatch(
        {error, {pool, #{type := exhausted, reason := closed}}},
        nhttp_error:normalize({error, pool_closed})
    ),

    ok.

normalize_legacy_3tuple_test(_Config) ->
    ?assertEqual(
        {error, {connection, some_reason}},
        nhttp_error:normalize({error, connection, some_reason})
    ),
    ?assertEqual(
        {error, {request, {timeout, 5000}}},
        nhttp_error:normalize({error, request, {timeout, 5000}})
    ),
    ?assertEqual(
        {error, {http2, {goaway, no_error}}},
        nhttp_error:normalize({error, http2, {goaway, no_error}})
    ),
    ?assertEqual(
        {error, {pool, checkout_timeout}},
        nhttp_error:normalize({error, pool, checkout_timeout})
    ),

    ok.

normalize_idempotent_test(_Config) ->
    E1 = nhttp_error:connect_timeout(),
    ?assertEqual(E1, nhttp_error:normalize(E1)),

    E2 = nhttp_error:connect_refused(econnrefused),
    ?assertEqual(E2, nhttp_error:normalize(E2)),

    E3 = nhttp_error:goaway(no_error, retryable),
    ?assertEqual(E3, nhttp_error:normalize(E3)),

    E4 = nhttp_error:checkout_timeout(),
    ?assertEqual(E4, nhttp_error:normalize(E4)),

    E5 = nhttp_error:stream_stopped(reason, acc),
    ?assertEqual(E5, nhttp_error:normalize(E5)),

    ok.

normalize_unknown_passthrough_test(_Config) ->
    ?assertEqual(
        {error, unknown_error},
        nhttp_error:normalize({error, unknown_error})
    ),

    ?assertEqual(
        {error, some_value},
        nhttp_error:normalize(some_value)
    ),

    ok.

normalize_request_errors_test(_Config) ->
    ?assertEqual(
        {error, {request, #{type => connection_closed}}},
        nhttp_error:normalize({error, closed})
    ),
    ?assertMatch(
        {error, {request, #{type := connection_closed, tag := unexpected}}},
        nhttp_error:normalize({error, {closed, unexpected}})
    ),

    ?assertMatch(
        {error, {request, #{type := request_timeout, value := 30000}}},
        nhttp_error:normalize({error, {request_timeout, 30000}})
    ),

    ?assertMatch(
        {error, {request, #{type := body_timeout, value := 10000}}},
        nhttp_error:normalize({error, {body_timeout, 10000}})
    ),

    ?assertMatch(
        {error, {request, #{type := send_error, posix := epipe}}},
        nhttp_error:normalize({error, {send_error, epipe}})
    ),
    ?assertMatch(
        {error, {request, #{type := recv_error, posix := econnreset}}},
        nhttp_error:normalize({error, {recv_error, econnreset}})
    ),

    ?assertMatch(
        {error, {request, #{type := malformed_response, parse_error := status_line, data := <<>>}}},
        nhttp_error:normalize({error, bad_status_line})
    ),
    ?assertMatch(
        {error, {request, #{type := malformed_response, parse_error := header, data := <<>>}}},
        nhttp_error:normalize({error, bad_header})
    ),
    ?assertMatch(
        {error,
            {request, #{type := malformed_response, parse_error := body, data := <<"invalid">>}}},
        nhttp_error:normalize({error, {malformed_response, body, <<"invalid">>}})
    ),

    ?assertMatch(
        {error, {request, #{type := response_too_large, size := 2000, max_size := 1024}}},
        nhttp_error:normalize({error, {body_too_large, 2000, 1024}})
    ),
    ?assertMatch(
        {error, {request, #{type := response_too_large, size := 1000, max_size := 100}}},
        nhttp_error:normalize({error, {response_too_large, 1000, 100}})
    ),

    ok.

%%%-----------------------------------------------------------------------------
%%% CLASSIFICATION TESTS
%%%-----------------------------------------------------------------------------

is_retryable_connection_test(_Config) ->
    ?assert(nhttp_error:is_retryable(nhttp_error:connect_timeout())),
    ?assert(nhttp_error:is_retryable(nhttp_error:connect_timeout(5000))),
    ?assert(nhttp_error:is_retryable(nhttp_error:connect_refused(econnrefused))),
    ?assert(nhttp_error:is_retryable(nhttp_error:connect_failed(enetunreach))),
    ?assert(nhttp_error:is_retryable(nhttp_error:tls_error(certificate_expired))),
    ?assert(nhttp_error:is_retryable(nhttp_error:alpn_error(no_protocol))),
    ?assert(nhttp_error:is_retryable(nhttp_error:connect_not_ready())),

    ok.

is_retryable_request_test(_Config) ->
    ?assert(nhttp_error:is_retryable(nhttp_error:connection_closed())),
    ?assert(nhttp_error:is_retryable(nhttp_error:connection_closed(unexpected))),
    ?assert(nhttp_error:is_retryable(nhttp_error:connection_closed(retryable))),

    ?assert(nhttp_error:is_retryable(nhttp_error:recv_error(econnreset))),

    ?assertNot(nhttp_error:is_retryable(nhttp_error:request_timeout())),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:request_timeout(5000))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:body_timeout(5000))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:send_error(epipe))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:recv_error(epipe))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:malformed_response(status_line, <<>>))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:response_too_large(1000, 100))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:max_redirects(10))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:redirect_loop(<<"url">>))),

    ok.

is_retryable_http2_test(_Config) ->
    ?assert(nhttp_error:is_retryable(nhttp_error:goaway(no_error))),
    ?assert(nhttp_error:is_retryable(nhttp_error:goaway(enhance_your_calm, retryable))),

    ?assert(nhttp_error:is_retryable(nhttp_error:stream_refused())),

    ?assert(nhttp_error:is_retryable(nhttp_error:rate_limited())),

    ?assertNot(nhttp_error:is_retryable(nhttp_error:stream_reset(cancel))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:stream_cancelled())),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:flow_control_error(window_exceeded))),

    ?assertNot(nhttp_error:is_retryable(nhttp_error:stream_closed(graceful))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:stream_closed(some_error))),

    ok.

is_retryable_pool_test(_Config) ->
    ?assert(nhttp_error:is_retryable(nhttp_error:checkout_timeout())),

    ?assertNot(nhttp_error:is_retryable(nhttp_error:pool_exhausted(full))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:no_connections())),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:pool_draining())),

    ok.

is_retryable_raw_errors_test(_Config) ->
    ?assert(nhttp_error:is_retryable({error, econnrefused})),
    ?assert(nhttp_error:is_retryable({error, econnreset})),
    ?assert(nhttp_error:is_retryable({error, closed})),
    ?assert(nhttp_error:is_retryable({error, timeout})),

    ?assertNot(nhttp_error:is_retryable({error, unknown})),
    ?assertNot(nhttp_error:is_retryable(not_an_error)),

    ok.

is_transient_test(_Config) ->
    ?assert(nhttp_error:is_transient(nhttp_error:connection_closed())),
    ?assert(nhttp_error:is_transient(nhttp_error:connection_closed(unexpected))),

    ?assert(nhttp_error:is_transient(nhttp_error:goaway(no_error))),

    ?assert(nhttp_error:is_transient(nhttp_error:goaway(enhance_your_calm, retryable))),

    ?assert(nhttp_error:is_transient(nhttp_error:stream_refused())),

    ?assert(nhttp_error:is_transient(nhttp_error:recv_error(econnreset))),

    ?assert(nhttp_error:is_transient({error, closed})),
    ?assert(nhttp_error:is_transient({error, econnreset})),

    ?assertNot(nhttp_error:is_transient(nhttp_error:connect_timeout())),
    ?assertNot(nhttp_error:is_transient(nhttp_error:connect_refused(econnrefused))),
    ?assertNot(nhttp_error:is_transient(nhttp_error:request_timeout())),
    ?assertNot(nhttp_error:is_transient(nhttp_error:checkout_timeout())),
    ?assertNot(nhttp_error:is_transient(nhttp_error:stream_reset(cancel))),
    ?assertNot(nhttp_error:is_transient({error, unknown})),

    ok.

%%%-----------------------------------------------------------------------------
%%% UTILITY TESTS
%%%-----------------------------------------------------------------------------

category_extraction_test(_Config) ->
    ?assertEqual(connection, nhttp_error:category(nhttp_error:connect_timeout())),
    ?assertEqual(connection, nhttp_error:category(nhttp_error:connect_refused(econnrefused))),
    ?assertEqual(connection, nhttp_error:category(nhttp_error:tls_error(reason))),

    ?assertEqual(request, nhttp_error:category(nhttp_error:request_timeout())),
    ?assertEqual(request, nhttp_error:category(nhttp_error:connection_closed())),
    ?assertEqual(request, nhttp_error:category(nhttp_error:malformed_response(t, <<>>))),

    ?assertEqual(http2, nhttp_error:category(nhttp_error:goaway(no_error))),
    ?assertEqual(http2, nhttp_error:category(nhttp_error:stream_cancelled())),
    ?assertEqual(http2, nhttp_error:category(nhttp_error:stream_refused())),

    ?assertEqual(pool, nhttp_error:category(nhttp_error:checkout_timeout())),
    ?assertEqual(pool, nhttp_error:category(nhttp_error:pool_exhausted(full))),
    ?assertEqual(pool, nhttp_error:category(nhttp_error:no_connections())),

    ?assertEqual(connection, nhttp_error:category({error, econnrefused})),
    ?assertEqual(connection, nhttp_error:category({error, timeout})),
    ?assertEqual(request, nhttp_error:category({error, closed})),
    ?assertEqual(pool, nhttp_error:category({error, checkout_timeout})),

    ?assertEqual(unknown, nhttp_error:category({error, unknown_error})),
    ?assertEqual(unknown, nhttp_error:category(not_an_error)),

    ok.

format_connection_test(_Config) ->
    ?assertEqual(
        <<"connection timeout">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:connect_timeout()))
    ),

    ?assertMatch(
        <<"connection timeout after 5000ms">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:connect_timeout(5000)))
    ),

    Refused = iolist_to_binary(nhttp_error:format(nhttp_error:connect_refused(econnrefused))),
    ?assert(binary:match(Refused, <<"connection refused">>) =/= nomatch),

    Failed = iolist_to_binary(nhttp_error:format(nhttp_error:connect_failed(enetunreach))),
    ?assert(binary:match(Failed, <<"connection failed">>) =/= nomatch),

    TlsErr = iolist_to_binary(nhttp_error:format(nhttp_error:tls_error(certificate_expired))),
    ?assert(binary:match(TlsErr, <<"TLS error">>) =/= nomatch),

    AlpnErr = iolist_to_binary(nhttp_error:format(nhttp_error:alpn_error(no_protocol))),
    ?assert(binary:match(AlpnErr, <<"ALPN">>) =/= nomatch),

    ?assertEqual(
        <<"connection not ready">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:connect_not_ready()))
    ),

    ok.

format_request_test(_Config) ->
    ?assertEqual(
        <<"request timeout">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:request_timeout()))
    ),

    ReqTimeout = iolist_to_binary(nhttp_error:format(nhttp_error:request_timeout(30000))),
    ?assert(binary:match(ReqTimeout, <<"30000ms">>) =/= nomatch),

    BodyTimeout = iolist_to_binary(nhttp_error:format(nhttp_error:body_timeout(10000))),
    ?assert(binary:match(BodyTimeout, <<"body timeout">>) =/= nomatch),

    ?assertEqual(
        <<"connection closed">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:connection_closed()))
    ),

    ?assertEqual(
        <<"connection closed unexpectedly">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:connection_closed(unexpected)))
    ),

    SendErr = iolist_to_binary(nhttp_error:format(nhttp_error:send_error(epipe))),
    ?assert(binary:match(SendErr, <<"send error">>) =/= nomatch),

    RecvErr = iolist_to_binary(nhttp_error:format(nhttp_error:recv_error(econnreset))),
    ?assert(binary:match(RecvErr, <<"receive error">>) =/= nomatch),

    Malformed = iolist_to_binary(
        nhttp_error:format(nhttp_error:malformed_response(status_line, <<>>))
    ),
    ?assert(binary:match(Malformed, <<"malformed response">>) =/= nomatch),

    TooLarge = iolist_to_binary(
        nhttp_error:format(nhttp_error:response_too_large(1000000, 100000))
    ),
    ?assert(binary:match(TooLarge, <<"too large">>) =/= nomatch),

    ok.

format_http2_test(_Config) ->
    Goaway = iolist_to_binary(nhttp_error:format(nhttp_error:goaway(no_error))),
    ?assert(binary:match(Goaway, <<"GOAWAY">>) =/= nomatch),

    GoawayRetry = iolist_to_binary(
        nhttp_error:format(nhttp_error:goaway(enhance_your_calm, retryable))
    ),
    ?assert(binary:match(GoawayRetry, <<"retryable">>) =/= nomatch),

    Reset = iolist_to_binary(nhttp_error:format(nhttp_error:stream_reset(cancel))),
    ?assert(binary:match(Reset, <<"stream reset">>) =/= nomatch),

    ?assertEqual(
        <<"HTTP/2 stream cancelled">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:stream_cancelled()))
    ),

    ?assertEqual(
        <<"HTTP/2 stream refused (retryable)">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:stream_refused()))
    ),

    ?assertEqual(
        <<"HTTP/2 stream closed gracefully">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:stream_closed(graceful)))
    ),

    StreamClosed = iolist_to_binary(nhttp_error:format(nhttp_error:stream_closed(some_error))),
    ?assert(binary:match(StreamClosed, <<"stream closed">>) =/= nomatch),

    ?assertEqual(
        <<"HTTP/2 rate limited (retryable)">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:rate_limited()))
    ),

    FlowCtrl = iolist_to_binary(
        nhttp_error:format(nhttp_error:flow_control_error(window_exceeded))
    ),
    ?assert(binary:match(FlowCtrl, <<"flow control">>) =/= nomatch),

    ok.

format_pool_test(_Config) ->
    ?assertEqual(
        <<"pool checkout timeout">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:checkout_timeout()))
    ),

    Exhausted = iolist_to_binary(nhttp_error:format(nhttp_error:pool_exhausted(full))),
    ?assert(binary:match(Exhausted, <<"pool exhausted">>) =/= nomatch),

    ?assertEqual(
        <<"no connections available">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:no_connections()))
    ),

    ?assertEqual(
        <<"pool draining">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:pool_draining()))
    ),

    ok.

format_fallback_test(_Config) ->
    Unknown = iolist_to_binary(nhttp_error:format({error, some_weird_error})),
    ?assert(binary:match(Unknown, <<"error">>) =/= nomatch),

    Other = iolist_to_binary(nhttp_error:format(not_an_error)),
    ?assert(byte_size(Other) > 0),

    ok.

%%%-----------------------------------------------------------------------------
%%% SERVER ERROR TESTS
%%%-----------------------------------------------------------------------------

server_constructors_test(_Config) ->
    {error, {server, Map1}} = nhttp_error:handler_init_error(badarg),
    ?assertEqual(handler_init, maps:get(type, Map1)),
    ?assertEqual(badarg, maps:get(reason, Map1)),

    ?assertEqual(
        {error, {server, #{type => connection_closing}}},
        nhttp_error:connection_closing()
    ),

    {error, {server, Map2}} = nhttp_error:server_stream_closed(5),
    ?assertEqual(stream_closed, maps:get(type, Map2)),
    ?assertEqual(5, maps:get(stream_id, Map2)),

    {error, {server, Map3}} = nhttp_error:flow_control_blocked(0, 16384),
    ?assertEqual(flow_control_blocked, maps:get(type, Map3)),
    ?assertEqual(0, maps:get(window, Map3)),
    ?assertEqual(16384, maps:get(size, Map3)),

    {error, {server, Map4}} = nhttp_error:protocol_error(frame_size_error),
    ?assertEqual(protocol_error, maps:get(type, Map4)),
    ?assertEqual(frame_size_error, maps:get(reason, Map4)),

    {error, {server, Map5}} = nhttp_error:server_socket_error(econnreset),
    ?assertEqual(socket_error, maps:get(type, Map5)),
    ?assertEqual(econnreset, maps:get(posix, Map5)),

    {error, {server, Map6}} = nhttp_error:h2_connection_error(no_error),
    ?assertEqual(h2_connection_error, maps:get(type, Map6)),
    ?assertEqual(no_error, maps:get(error_code, Map6)),

    {error, {server, Map7}} = nhttp_error:h2_error(some_reason),
    ?assertEqual(h2_error, maps:get(type, Map7)),
    ?assertEqual(some_reason, maps:get(reason, Map7)),

    {error, {server, Map8}} = nhttp_error:ws_upgrade_error(bad_handshake),
    ?assertEqual(ws_upgrade_error, maps:get(type, Map8)),
    ?assertEqual(bad_handshake, maps:get(reason, Map8)),

    {error, {server, Map9}} = nhttp_error:ws_error(protocol_error),
    ?assertEqual(ws_error, maps:get(type, Map9)),
    ?assertEqual(protocol_error, maps:get(reason, Map9)),

    {error, {server, Map10}} = nhttp_error:listen_failed(eaddrinuse),
    ?assertEqual(listen_failed, maps:get(type, Map10)),
    ?assertEqual(eaddrinuse, maps:get(posix, Map10)),

    ?assertEqual(
        {error, {server, #{type => accept_timeout}}}, nhttp_error:accept_timeout()
    ),

    ?assertEqual(
        {error, {server, #{type => accept_closed}}}, nhttp_error:accept_closed()
    ),

    {error, {server, Map11}} = nhttp_error:accept_emfile(),
    ?assertEqual(accept_emfile, maps:get(type, Map11)),
    ?assertEqual(true, maps:get(retryable, Map11)),

    ?assertEqual(
        {error, {server, #{type => at_capacity}}}, nhttp_error:at_capacity()
    ),

    {error, {server, Map12}} = nhttp_error:missing_config(port),
    ?assertEqual(missing_config, maps:get(type, Map12)),
    ?assertEqual(port, maps:get(key, Map12)),

    ok.

normalize_server_errors_test(_Config) ->
    ?assertEqual(
        nhttp_error:handler_init_error(badarg),
        nhttp_error:normalize({error, {handler_init, badarg}})
    ),

    ?assertEqual(
        nhttp_error:connection_closing(),
        nhttp_error:normalize({error, connection_closing})
    ),

    ?assertEqual(
        nhttp_error:server_stream_closed(5),
        nhttp_error:normalize({error, {stream_closed, 5}})
    ),

    ?assertEqual(
        nhttp_error:flow_control_blocked(0, 16384),
        nhttp_error:normalize({error, {flow_control_blocked, 0, 16384}})
    ),

    ?assertEqual(
        nhttp_error:protocol_error(frame_size_error),
        nhttp_error:normalize({error, {protocol_error, frame_size_error}})
    ),

    ?assertEqual(
        nhttp_error:at_capacity(),
        nhttp_error:normalize({error, at_capacity})
    ),

    ?assertEqual(
        nhttp_error:accept_emfile(),
        nhttp_error:normalize({error, emfile})
    ),

    ?assertEqual(
        nhttp_error:missing_config(port),
        nhttp_error:normalize({error, missing_port})
    ),

    ?assertEqual(
        nhttp_error:missing_config(handler),
        nhttp_error:normalize({error, missing_handler})
    ),

    ok.

is_retryable_server_test(_Config) ->
    ?assert(nhttp_error:is_retryable(nhttp_error:at_capacity())),
    ?assert(nhttp_error:is_retryable(nhttp_error:accept_emfile())),
    ?assert(nhttp_error:is_retryable(nhttp_error:accept_timeout())),

    ?assertNot(nhttp_error:is_retryable(nhttp_error:connection_closing())),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:handler_init_error(badarg))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:protocol_error(frame_size_error))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:server_stream_closed(5))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:flow_control_blocked(0, 16384))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:listen_failed(eaddrinuse))),
    ?assertNot(nhttp_error:is_retryable(nhttp_error:missing_config(port))),

    ok.

format_server_test(_Config) ->
    Fmt1 = iolist_to_binary(nhttp_error:format(nhttp_error:handler_init_error(badarg))),
    ?assert(binary:match(Fmt1, <<"handler init">>) =/= nomatch),

    ?assertEqual(
        <<"connection closing">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:connection_closing()))
    ),

    Fmt2 = iolist_to_binary(nhttp_error:format(nhttp_error:server_stream_closed(5))),
    ?assert(binary:match(Fmt2, <<"stream">>) =/= nomatch),

    Fmt3 = iolist_to_binary(nhttp_error:format(nhttp_error:flow_control_blocked(0, 16384))),
    ?assert(binary:match(Fmt3, <<"flow control">>) =/= nomatch),

    ?assertEqual(
        <<"server at capacity">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:at_capacity()))
    ),

    ?assertEqual(
        <<"accept timeout">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:accept_timeout()))
    ),

    ?assertEqual(
        <<"accept socket closed">>,
        iolist_to_binary(nhttp_error:format(nhttp_error:accept_closed()))
    ),

    Fmt4 = iolist_to_binary(nhttp_error:format(nhttp_error:accept_emfile())),
    ?assert(binary:match(Fmt4, <<"emfile">>) =/= nomatch),

    Fmt5 = iolist_to_binary(nhttp_error:format(nhttp_error:missing_config(port))),
    ?assert(binary:match(Fmt5, <<"missing config">>) =/= nomatch),

    ok.

%%%-----------------------------------------------------------------------------
%%% ADDITIONAL COVERAGE TESTS
%%%-----------------------------------------------------------------------------

normalize_additional_server_errors_test(_Config) ->
    ?assertEqual(
        nhttp_error:server_socket_error(econnreset),
        nhttp_error:normalize({error, {socket_error, econnreset}})
    ),

    ?assertEqual(
        nhttp_error:h2_connection_error(protocol_error),
        nhttp_error:normalize({error, {h2_connection_error, protocol_error}})
    ),

    ?assertEqual(
        nhttp_error:h2_error(some_reason),
        nhttp_error:normalize({error, {h2_error, some_reason}})
    ),

    ?assertEqual(
        nhttp_error:ws_upgrade_error(bad_handshake),
        nhttp_error:normalize({error, {ws_upgrade_error, bad_handshake}})
    ),

    ?assertEqual(
        nhttp_error:ws_error(protocol_error),
        nhttp_error:normalize({error, {ws_error, protocol_error}})
    ),

    ?assertEqual(
        nhttp_error:listen_failed(eaddrinuse),
        nhttp_error:normalize({error, {listen_failed, eaddrinuse}})
    ),

    ?assertEqual(
        {error, {server, #{type => no_acceptors}}},
        nhttp_error:normalize({error, no_acceptors})
    ),

    ok.

is_retryable_normalize_branch_test(_Config) ->
    ?assert(nhttp_error:is_retryable({error, etimedout})),
    ?assert(nhttp_error:is_retryable({error, enetunreach})),
    ?assert(nhttp_error:is_retryable({error, ehostunreach})),

    ?assertNot(nhttp_error:is_retryable({error, some_random_atom})),

    ?assertNot(nhttp_error:is_retryable({error, bad_status_line})),

    ok.

is_transient_normalize_branch_test(_Config) ->
    ?assertNot(nhttp_error:is_transient({error, etimedout})),
    ?assertNot(nhttp_error:is_transient({error, enetunreach})),

    ?assertNot(nhttp_error:is_transient({error, some_random_atom})),

    ok.

format_additional_server_test(_Config) ->
    Fmt1 = iolist_to_binary(nhttp_error:format(nhttp_error:protocol_error(frame_size_error))),
    ?assert(binary:match(Fmt1, <<"protocol error">>) =/= nomatch),

    Fmt2 = iolist_to_binary(nhttp_error:format(nhttp_error:server_socket_error(econnreset))),
    ?assert(binary:match(Fmt2, <<"socket error">>) =/= nomatch),

    Fmt3 = iolist_to_binary(nhttp_error:format(nhttp_error:h2_connection_error(protocol_error))),
    ?assert(binary:match(Fmt3, <<"HTTP/2 connection error">>) =/= nomatch),

    Fmt4 = iolist_to_binary(nhttp_error:format(nhttp_error:h2_error(some_reason))),
    ?assert(binary:match(Fmt4, <<"HTTP/2 error">>) =/= nomatch),

    Fmt5 = iolist_to_binary(nhttp_error:format(nhttp_error:ws_upgrade_error(bad_handshake))),
    ?assert(binary:match(Fmt5, <<"WebSocket upgrade error">>) =/= nomatch),

    Fmt6 = iolist_to_binary(nhttp_error:format(nhttp_error:ws_error(protocol_error))),
    ?assert(binary:match(Fmt6, <<"WebSocket error">>) =/= nomatch),

    Fmt7 = iolist_to_binary(nhttp_error:format(nhttp_error:listen_failed(eaddrinuse))),
    ?assert(binary:match(Fmt7, <<"listen failed">>) =/= nomatch),

    Fmt8 = iolist_to_binary(
        nhttp_error:format({error, {server, #{type => no_acceptors}}})
    ),
    ?assert(binary:match(Fmt8, <<"no acceptors">>) =/= nomatch),

    ok.

format_additional_request_test(_Config) ->
    Fmt1 = iolist_to_binary(nhttp_error:format(nhttp_error:connection_closed(retryable))),
    ?assertEqual(<<"connection closed (retryable)">>, Fmt1),

    Fmt2 = iolist_to_binary(nhttp_error:format(nhttp_error:max_redirects(5))),
    ?assert(binary:match(Fmt2, <<"max redirects">>) =/= nomatch),
    ?assert(binary:match(Fmt2, <<"5">>) =/= nomatch),

    Fmt3 = iolist_to_binary(
        nhttp_error:format(nhttp_error:redirect_loop(<<"https://example.com">>))
    ),
    ?assert(binary:match(Fmt3, <<"redirect loop">>) =/= nomatch),

    Fmt4 = iolist_to_binary(nhttp_error:format(nhttp_error:file_error(read, enoent))),
    ?assert(binary:match(Fmt4, <<"file error">>) =/= nomatch),

    Fmt5 = iolist_to_binary(nhttp_error:format(nhttp_error:upload_error(invalid_body))),
    ?assert(binary:match(Fmt5, <<"upload error">>) =/= nomatch),

    Fmt6 = iolist_to_binary(nhttp_error:format(nhttp_error:stream_stopped(user_cancelled))),
    ?assert(binary:match(Fmt6, <<"stream stopped">>) =/= nomatch),

    ok.

format_unknown_category_test(_Config) ->
    UnknownCategoryError = {error, {unknown_category, some_reason}},
    Fmt1 = iolist_to_binary(nhttp_error:format(UnknownCategoryError)),
    ?assert(binary:match(Fmt1, <<"error:">>) =/= nomatch),
    ?assert(binary:match(Fmt1, <<"some_reason">>) =/= nomatch),

    CustomError = {error, {custom, #{type => custom_type, data => 123}}},
    Fmt2 = iolist_to_binary(nhttp_error:format(CustomError)),
    ?assert(binary:match(Fmt2, <<"error:">>) =/= nomatch),

    BareError = {error, bare_reason},
    Fmt3 = iolist_to_binary(nhttp_error:format(BareError)),
    ?assert(binary:match(Fmt3, <<"error:">>) =/= nomatch),
    ?assert(binary:match(Fmt3, <<"bare_reason">>) =/= nomatch),

    NonError = some_random_term,
    Fmt4 = iolist_to_binary(nhttp_error:format(NonError)),
    ?assert(binary:match(Fmt4, <<"some_random_term">>) =/= nomatch),

    ok.
