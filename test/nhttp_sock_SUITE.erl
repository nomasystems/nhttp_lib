%%%-----------------------------------------------------------------------------
-module(nhttp_sock_SUITE).

-moduledoc "Test suite for nhttp_sock socket abstraction.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    tcp_listen_accept/1,
    tcp_send_recv/1,
    tcp_setopts/1,
    tcp_controlling_process/1,
    tcp_peername_sockname/1,
    tcp_no_alpn/1,
    tcp_connect/1,
    tcp_connect_buffer_default/1,
    tcp_connect_buffer_override/1,
    tcp_connect_timeout/1,
    tcp_handshake_noop/1,
    ssl_listen_accept_handshake/1,
    ssl_send_recv/1,
    ssl_alpn_negotiation/1,
    ssl_no_alpn_fallback/1,
    ssl_connect/1,
    ssl_connect_buffer_default/1,
    ssl_connect_alpn/1,
    ssl_setopts/1,
    ssl_controlling_process/1,
    ssl_peername_sockname/1,
    build_ssl_opts_variants/1,
    build_client_ssl_opts_variants/1,
    normalize_host_variants/1,
    error_timeout/1,
    error_closed/1,
    error_connect_refused/1,
    ssl_pre_handshake_ops/1,
    ssl_accept_error/1,
    ssl_connect_with_sni/1
]).

%%%-----------------------------------------------------------------------------
%%% SUITE SETUP
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, tcp},
        {group, ssl},
        {group, opts},
        {group, errors}
    ].

groups() ->
    [
        {tcp, [parallel], [
            tcp_listen_accept,
            tcp_send_recv,
            tcp_setopts,
            tcp_controlling_process,
            tcp_peername_sockname,
            tcp_no_alpn,
            tcp_connect,
            tcp_connect_buffer_default,
            tcp_connect_buffer_override,
            tcp_connect_timeout,
            tcp_handshake_noop
        ]},
        {ssl, [sequence], [
            ssl_listen_accept_handshake,
            ssl_send_recv,
            ssl_alpn_negotiation,
            ssl_no_alpn_fallback,
            ssl_connect,
            ssl_connect_buffer_default,
            ssl_connect_alpn,
            ssl_setopts,
            ssl_controlling_process,
            ssl_peername_sockname,
            ssl_pre_handshake_ops,
            ssl_accept_error,
            ssl_connect_with_sni
        ]},
        {opts, [parallel], [
            build_ssl_opts_variants,
            build_client_ssl_opts_variants,
            normalize_host_variants
        ]},
        {errors, [parallel], [
            error_timeout,
            error_closed,
            error_connect_refused
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(ssl),
    Config.

end_per_suite(_Config) ->
    ok.

-doc "Accept a connection and hold it briefly, tolerating a closed listener.".
accept_and_hold(ListenSock) ->
    case nhttp_sock:accept(ListenSock, 5000) of
        {ok, ServerSock} ->
            timer:sleep(200),
            nhttp_sock:close(ServerSock);
        {error, _} ->
            ok
    end.

-doc "Find test/conf directory by deriving from this module's path.".
find_test_conf_dir() ->
    ModPath = code:which(?MODULE),
    TestDir = filename:dirname(ModPath),
    filename:join(TestDir, "conf").

init_per_group(ssl, Config) ->
    TestConfDir = find_test_conf_dir(),
    CertFile = filename:join(TestConfDir, "server.pem"),
    KeyFile = filename:join(TestConfDir, "server.key"),
    case filelib:is_file(CertFile) of
        true ->
            [{certfile, CertFile}, {keyfile, KeyFile} | Config];
        false ->
            {skip, "SSL certificates not found. Run test/conf/gen_test_certs.sh"}
    end;
init_per_group(opts, Config) ->
    Config;
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% TCP TESTS
%%%-----------------------------------------------------------------------------

tcp_listen_accept(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    ?assertEqual(tcp, nhttp_sock:transport(ListenSock)),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}]),
        Self ! {client_connected, ClientSock}
    end),

    {ok, AcceptedSock} = nhttp_sock:accept(ListenSock, 5000),
    ?assertEqual(tcp, nhttp_sock:transport(AcceptedSock)),

    receive
        {client_connected, ClientSock} ->
            gen_tcp:close(ClientSock)
    after 5000 ->
        ct:fail("Client did not connect")
    end,

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

tcp_send_recv(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}]),
        gen_tcp:send(ClientSock, <<"hello">>),
        {ok, Reply} = gen_tcp:recv(ClientSock, 0, 5000),
        Self ! {client_recv, Reply},
        gen_tcp:close(ClientSock)
    end),

    {ok, AcceptedSock} = nhttp_sock:accept(ListenSock, 5000),
    {ok, Data} = nhttp_sock:recv(AcceptedSock, 0, 5000),
    ?assertEqual(<<"hello">>, Data),

    ok = nhttp_sock:send(AcceptedSock, <<"world">>),

    receive
        {client_recv, Reply} ->
            ?assertEqual(<<"world">>, Reply)
    after 5000 ->
        ct:fail("Client did not receive reply")
    end,

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

tcp_setopts(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    spawn_link(fun() ->
        {ok, ClientSock} = gen_tcp:connect("127.0.0.1", Port, [binary]),
        gen_tcp:send(ClientSock, <<"test">>),
        timer:sleep(100),
        gen_tcp:close(ClientSock)
    end),

    {ok, AcceptedSock} = nhttp_sock:accept(ListenSock, 5000),

    ok = nhttp_sock:setopts(AcceptedSock, [{active, once}]),

    receive
        {tcp, _, Data} ->
            ?assertEqual(<<"test">>, Data)
    after 5000 ->
        ct:fail("Did not receive data")
    end,

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

tcp_controlling_process(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = gen_tcp:connect("127.0.0.1", Port, [binary]),
        timer:sleep(100),
        gen_tcp:send(ClientSock, <<"transferred">>),
        timer:sleep(100),
        gen_tcp:close(ClientSock)
    end),

    {ok, AcceptedSock} = nhttp_sock:accept(ListenSock, 5000),

    NewOwner = spawn_link(fun() ->
        receive
            go ->
                nhttp_sock:setopts(AcceptedSock, [{active, once}]),
                receive
                    {tcp, _, Data} -> Self ! {new_owner_recv, Data}
                after 5000 -> Self ! {new_owner_recv, timeout}
                end
        end
    end),

    ok = nhttp_sock:controlling_process(AcceptedSock, NewOwner),
    NewOwner ! go,

    receive
        {new_owner_recv, Data} ->
            ?assertEqual(<<"transferred">>, Data)
    after 5000 ->
        ct:fail("New owner did not receive data")
    end,

    nhttp_sock:close(ListenSock),
    ok.

tcp_peername_sockname(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {ListenAddr, Port}} = nhttp_sock:sockname(ListenSock),
    ?assert(is_tuple(ListenAddr)),

    spawn_link(fun() ->
        {ok, _} = gen_tcp:connect("127.0.0.1", Port, [binary]),
        timer:sleep(500)
    end),

    {ok, AcceptedSock} = nhttp_sock:accept(ListenSock, 5000),

    {ok, {PeerAddr, PeerPort}} = nhttp_sock:peername(AcceptedSock),
    ?assert(is_tuple(PeerAddr)),
    ?assert(is_integer(PeerPort)),

    {ok, {LocalAddr, LocalPort}} = nhttp_sock:sockname(AcceptedSock),
    ?assert(is_tuple(LocalAddr)),
    ?assertEqual(Port, LocalPort),

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

tcp_no_alpn(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    spawn_link(fun() ->
        {ok, _} = gen_tcp:connect("127.0.0.1", Port, [binary]),
        timer:sleep(100)
    end),

    {ok, AcceptedSock} = nhttp_sock:accept(ListenSock, 5000),

    ?assertEqual({error, no_alpn}, nhttp_sock:negotiated_protocol(AcceptedSock)),

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

%%%-----------------------------------------------------------------------------
%%% SSL TESTS
%%%-----------------------------------------------------------------------------

ssl_listen_accept_handshake(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    ?assertEqual(ssl, nhttp_sock:transport(ListenSock)),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile,
        alpn_preferred_protocols => [<<"h2">>, <<"http/1.1">>]
    }),

    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = ssl:connect(
            "127.0.0.1",
            Port,
            [
                binary,
                {active, false},
                {verify, verify_none},
                {alpn_advertised_protocols, [<<"h2">>]}
            ],
            5000
        ),
        Self ! {client_connected, ClientSock}
    end),

    {ok, PreHandshakeSock} = nhttp_sock:accept(ListenSock, 5000),

    {ok, AcceptedSock} = nhttp_sock:handshake(PreHandshakeSock, 5000, SslOpts),
    ?assertEqual(ssl, nhttp_sock:transport(AcceptedSock)),

    receive
        {client_connected, ClientSock} ->
            ssl:close(ClientSock)
    after 5000 ->
        ct:fail("Client did not connect")
    end,

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

ssl_send_recv(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile
    }),

    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = ssl:connect(
            "127.0.0.1",
            Port,
            [
                binary,
                {active, false},
                {verify, verify_none}
            ],
            5000
        ),
        ssl:send(ClientSock, <<"ssl hello">>),
        {ok, Reply} = ssl:recv(ClientSock, 0, 5000),
        Self ! {client_recv, Reply},
        ssl:close(ClientSock)
    end),

    {ok, PreHandshakeSock} = nhttp_sock:accept(ListenSock, 5000),
    {ok, AcceptedSock} = nhttp_sock:handshake(PreHandshakeSock, 5000, SslOpts),

    {ok, Data} = nhttp_sock:recv(AcceptedSock, 0, 5000),
    ?assertEqual(<<"ssl hello">>, Data),

    ok = nhttp_sock:send(AcceptedSock, <<"ssl world">>),

    receive
        {client_recv, Reply} ->
            ?assertEqual(<<"ssl world">>, Reply)
    after 5000 ->
        ct:fail("Client did not receive reply")
    end,

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

ssl_alpn_negotiation(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile,
        alpn_preferred_protocols => [<<"h2">>, <<"http/1.1">>]
    }),
    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = ssl:connect(
            "127.0.0.1",
            Port,
            [
                binary,
                {active, false},
                {verify, verify_none},
                {alpn_advertised_protocols, [<<"h2">>]}
            ],
            5000
        ),
        {ok, Alpn} = ssl:negotiated_protocol(ClientSock),
        Self ! {client_alpn, Alpn},
        ssl:close(ClientSock)
    end),

    {ok, PreHandshakeSock} = nhttp_sock:accept(ListenSock, 5000),
    {ok, AcceptedSock} = nhttp_sock:handshake(PreHandshakeSock, 5000, SslOpts),

    {ok, ServerAlpn} = nhttp_sock:negotiated_protocol(AcceptedSock),
    ?assertEqual(<<"h2">>, ServerAlpn),

    receive
        {client_alpn, ClientAlpn} ->
            ?assertEqual(<<"h2">>, ClientAlpn)
    after 5000 ->
        ct:fail("Client ALPN timeout")
    end,

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

ssl_no_alpn_fallback(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile,
        alpn_preferred_protocols => []
    }),
    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = ssl:connect(
            "127.0.0.1",
            Port,
            [
                binary,
                {active, false},
                {verify, verify_none}
            ],
            5000
        ),
        Self ! client_connected,
        ssl:close(ClientSock)
    end),

    {ok, PreHandshakeSock} = nhttp_sock:accept(ListenSock, 5000),
    {ok, AcceptedSock} = nhttp_sock:handshake(PreHandshakeSock, 5000, SslOpts),

    ?assertEqual({error, no_alpn}, nhttp_sock:negotiated_protocol(AcceptedSock)),

    receive
        client_connected -> ok
    after 5000 -> ct:fail("Client timeout")
    end,

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

%%%-----------------------------------------------------------------------------
%%% ERROR TESTS
%%%-----------------------------------------------------------------------------

error_timeout(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),

    Result = nhttp_sock:accept(ListenSock, 1),
    ?assertEqual({error, timeout}, Result),

    nhttp_sock:close(ListenSock),
    ok.

error_closed(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    spawn_link(fun() ->
        {ok, ClientSock} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}]),
        gen_tcp:close(ClientSock)
    end),

    {ok, AcceptedSock} = nhttp_sock:accept(ListenSock, 5000),

    timer:sleep(100),

    Result = nhttp_sock:recv(AcceptedSock, 0, 1000),
    ?assertEqual({error, closed}, Result),

    nhttp_sock:close(ListenSock),
    ok.

error_connect_refused(_Config) ->
    Result = nhttp_sock:connect("127.0.0.1", 59999, #{transport => tcp}, 1000),
    ?assertMatch({error, _}, Result),
    ok.

%%%-----------------------------------------------------------------------------
%%% TCP CLIENT TESTS
%%%-----------------------------------------------------------------------------

tcp_connect(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    Self = self(),
    spawn_link(fun() ->
        {ok, ServerSock} = nhttp_sock:accept(ListenSock, 5000),
        {ok, Data} = nhttp_sock:recv(ServerSock, 0, 5000),
        Self ! {server_recv, Data},
        nhttp_sock:send(ServerSock, <<"pong">>),
        nhttp_sock:close(ServerSock)
    end),

    {ok, ClientSock} = nhttp_sock:connect("127.0.0.1", Port, #{transport => tcp}),
    ?assertEqual(tcp, nhttp_sock:transport(ClientSock)),

    ok = nhttp_sock:send(ClientSock, <<"ping">>),
    {ok, Reply} = nhttp_sock:recv(ClientSock, 0, 5000),
    ?assertEqual(<<"pong">>, Reply),

    receive
        {server_recv, Data} ->
            ?assertEqual(<<"ping">>, Data)
    after 5000 ->
        ct:fail("Server did not receive data")
    end,

    nhttp_sock:close(ClientSock),
    nhttp_sock:close(ListenSock),
    ok.

tcp_connect_buffer_default(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    spawn_link(fun() ->
        accept_and_hold(ListenSock)
    end),

    {ok, ClientSock} = nhttp_sock:connect("127.0.0.1", Port, #{transport => tcp}),
    {ok, Opts} = inet:getopts(element(2, ClientSock), [buffer]),
    ?assert(proplists:get_value(buffer, Opts) >= 65536),

    nhttp_sock:close(ClientSock),
    nhttp_sock:close(ListenSock),
    ok.

tcp_connect_buffer_override(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    spawn_link(fun() ->
        accept_and_hold(ListenSock),
        accept_and_hold(ListenSock)
    end),

    Large = 1 bsl 20,
    {ok, BigSock} = nhttp_sock:connect("127.0.0.1", Port, #{transport => tcp, buffer => Large}),
    {ok, BigOpts} = inet:getopts(element(2, BigSock), [buffer]),
    ?assert(proplists:get_value(buffer, BigOpts) >= Large),

    {ok, TinySock} = nhttp_sock:connect("127.0.0.1", Port, #{transport => tcp, buffer => 1024}),
    {ok, TinyOpts} = inet:getopts(element(2, TinySock), [buffer]),
    ?assert(proplists:get_value(buffer, TinyOpts) < 65536),

    nhttp_sock:close(BigSock),
    nhttp_sock:close(TinySock),
    nhttp_sock:close(ListenSock),
    ok.

tcp_connect_timeout(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    Self = self(),
    spawn_link(fun() ->
        case nhttp_sock:accept(ListenSock, 5000) of
            {ok, ServerSock} ->
                Self ! server_ready,
                timer:sleep(200),
                nhttp_sock:close(ServerSock);
            {error, _} ->
                ok
        end
    end),

    {ok, ClientSock} = nhttp_sock:connect(<<"127.0.0.1">>, Port, #{transport => tcp}, 5000),
    ?assertEqual(tcp, nhttp_sock:transport(ClientSock)),

    receive
        server_ready -> ok
    after 5000 -> ct:fail("Server not ready")
    end,

    nhttp_sock:close(ClientSock),
    nhttp_sock:close(ListenSock),
    ok.

tcp_handshake_noop(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    spawn_link(fun() ->
        {ok, _} = gen_tcp:connect("127.0.0.1", Port, [binary]),
        timer:sleep(200)
    end),

    {ok, AcceptedSock} = nhttp_sock:accept(ListenSock, 5000),
    {ok, SameSock} = nhttp_sock:handshake(AcceptedSock, 5000, []),
    ?assertEqual(AcceptedSock, SameSock),

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

%%%-----------------------------------------------------------------------------
%%% SSL CLIENT TESTS
%%%-----------------------------------------------------------------------------

ssl_connect(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile
    }),

    Self = self(),
    spawn_link(fun() ->
        {ok, PreSock} = nhttp_sock:accept(ListenSock, 5000),
        {ok, ServerSock} = nhttp_sock:handshake(PreSock, 5000, SslOpts),
        {ok, Data} = nhttp_sock:recv(ServerSock, 0, 5000),
        Self ! {server_recv, Data},
        nhttp_sock:send(ServerSock, <<"ssl pong">>),
        nhttp_sock:close(ServerSock)
    end),

    {ok, ClientSock} = nhttp_sock:connect("127.0.0.1", Port, #{
        transport => ssl,
        verify => verify_none,
        alpn_advertised_protocols => []
    }),
    ?assertEqual(ssl, nhttp_sock:transport(ClientSock)),

    ok = nhttp_sock:send(ClientSock, <<"ssl ping">>),
    {ok, Reply} = nhttp_sock:recv(ClientSock, 0, 5000),
    ?assertEqual(<<"ssl pong">>, Reply),

    receive
        {server_recv, Data} ->
            ?assertEqual(<<"ssl ping">>, Data)
    after 5000 ->
        ct:fail("Server did not receive data")
    end,

    nhttp_sock:close(ClientSock),
    nhttp_sock:close(ListenSock),
    ok.

ssl_connect_buffer_default(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile
    }),

    spawn_link(fun() ->
        case nhttp_sock:accept(ListenSock, 5000) of
            {ok, PreSock} ->
                {ok, ServerSock} = nhttp_sock:handshake(PreSock, 5000, SslOpts),
                timer:sleep(200),
                nhttp_sock:close(ServerSock);
            {error, _} ->
                ok
        end
    end),

    {ok, ClientSock} = nhttp_sock:connect("127.0.0.1", Port, #{
        transport => ssl,
        verify => verify_none,
        alpn_advertised_protocols => []
    }),
    {ok, Opts} = ssl:getopts(element(2, ClientSock), [buffer]),
    ?assert(proplists:get_value(buffer, Opts) >= 65536),

    nhttp_sock:close(ClientSock),
    nhttp_sock:close(ListenSock),
    ok.

ssl_connect_alpn(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile,
        alpn_preferred_protocols => [<<"h2">>, <<"http/1.1">>]
    }),

    Self = self(),
    spawn_link(fun() ->
        {ok, PreSock} = nhttp_sock:accept(ListenSock, 5000),
        {ok, ServerSock} = nhttp_sock:handshake(PreSock, 5000, SslOpts),
        {ok, Alpn} = nhttp_sock:negotiated_protocol(ServerSock),
        Self ! {server_alpn, Alpn},
        nhttp_sock:close(ServerSock)
    end),

    {ok, ClientSock} = nhttp_sock:connect("127.0.0.1", Port, #{
        transport => ssl,
        verify => verify_none,
        alpn_advertised_protocols => [<<"h2">>]
    }),

    {ok, ClientAlpn} = nhttp_sock:negotiated_protocol(ClientSock),
    ?assertEqual(<<"h2">>, ClientAlpn),

    receive
        {server_alpn, ServerAlpn} ->
            ?assertEqual(<<"h2">>, ServerAlpn)
    after 5000 ->
        ct:fail("Server ALPN timeout")
    end,

    nhttp_sock:close(ClientSock),
    nhttp_sock:close(ListenSock),
    ok.

ssl_setopts(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile
    }),

    spawn_link(fun() ->
        {ok, ClientSock} = ssl:connect(
            "127.0.0.1",
            Port,
            [binary, {verify, verify_none}],
            5000
        ),
        ssl:send(ClientSock, <<"active test">>),
        timer:sleep(200),
        ssl:close(ClientSock)
    end),

    {ok, PreSock} = nhttp_sock:accept(ListenSock, 5000),
    {ok, AcceptedSock} = nhttp_sock:handshake(PreSock, 5000, SslOpts),

    ok = nhttp_sock:setopts(AcceptedSock, [{active, once}]),

    receive
        {ssl, _, Data} ->
            ?assertEqual(<<"active test">>, Data)
    after 5000 ->
        ct:fail("Did not receive SSL data")
    end,

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

ssl_controlling_process(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile
    }),

    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = ssl:connect(
            "127.0.0.1",
            Port,
            [binary, {verify, verify_none}],
            5000
        ),
        timer:sleep(200),
        ssl:send(ClientSock, <<"owner transfer">>),
        timer:sleep(200),
        ssl:close(ClientSock)
    end),

    {ok, PreSock} = nhttp_sock:accept(ListenSock, 5000),
    {ok, AcceptedSock} = nhttp_sock:handshake(PreSock, 5000, SslOpts),

    NewOwner = spawn_link(fun() ->
        receive
            go ->
                nhttp_sock:setopts(AcceptedSock, [{active, once}]),
                receive
                    {ssl, _, Data} -> Self ! {new_owner, Data}
                after 5000 -> Self ! {new_owner, timeout}
                end
        end
    end),

    ok = nhttp_sock:controlling_process(AcceptedSock, NewOwner),
    NewOwner ! go,

    receive
        {new_owner, Data} ->
            ?assertEqual(<<"owner transfer">>, Data)
    after 5000 ->
        ct:fail("New owner timeout")
    end,

    nhttp_sock:close(ListenSock),
    ok.

ssl_peername_sockname(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile
    }),

    spawn_link(fun() ->
        {ok, _} = ssl:connect(
            "127.0.0.1",
            Port,
            [binary, {verify, verify_none}],
            5000
        ),
        timer:sleep(500)
    end),

    {ok, PreSock} = nhttp_sock:accept(ListenSock, 5000),
    {ok, AcceptedSock} = nhttp_sock:handshake(PreSock, 5000, SslOpts),

    {ok, {PeerAddr, PeerPort}} = nhttp_sock:peername(AcceptedSock),
    ?assert(is_tuple(PeerAddr)),
    ?assert(is_integer(PeerPort)),

    {ok, {LocalAddr, LocalPort}} = nhttp_sock:sockname(AcceptedSock),
    ?assert(is_tuple(LocalAddr)),
    ?assertEqual(Port, LocalPort),

    nhttp_sock:close(AcceptedSock),
    nhttp_sock:close(ListenSock),
    ok.

%%%-----------------------------------------------------------------------------
%%% OPTIONS TESTS
%%%-----------------------------------------------------------------------------

build_ssl_opts_variants(_Config) ->
    Opts1 = nhttp_sock:build_ssl_opts(#{
        certfile => "/path/to/cert.pem",
        keyfile => "/path/to/key.pem",
        cacertfile => "/path/to/ca.pem",
        alpn_preferred_protocols => [<<"h2">>],
        verify => verify_peer,
        tls_versions => ['tlsv1.3']
    }),
    ?assert(lists:keymember(certfile, 1, Opts1)),
    ?assert(lists:keymember(keyfile, 1, Opts1)),
    ?assert(lists:keymember(cacertfile, 1, Opts1)),
    ?assert(lists:keymember(alpn_preferred_protocols, 1, Opts1)),

    Opts2 = nhttp_sock:build_ssl_opts(#{
        alpn_preferred_protocols => []
    }),
    ?assertNot(lists:keymember(alpn_preferred_protocols, 1, Opts2)),

    Opts3 = nhttp_sock:build_ssl_opts(#{}),
    ?assert(lists:keymember(verify, 1, Opts3)),
    ?assert(lists:keymember(versions, 1, Opts3)),

    ok.

build_client_ssl_opts_variants(_Config) ->
    Opts1 = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_peer
    }),
    ?assert(lists:keymember(cacerts, 1, Opts1)),

    Opts2 = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_peer,
        cacertfile => "/path/to/ca.pem"
    }),
    ?assert(lists:keymember(cacertfile, 1, Opts2)),
    ?assertNot(lists:keymember(cacerts, 1, Opts2)),

    Opts3 = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_none
    }),
    ?assertNot(lists:keymember(cacerts, 1, Opts3)),
    ?assertNot(lists:keymember(cacertfile, 1, Opts3)),

    Opts4 = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_none,
        cacertfile => "/path/to/ca.pem"
    }),
    ?assertNot(lists:keymember(cacertfile, 1, Opts4)),
    ?assertNot(lists:keymember(cacerts, 1, Opts4)),

    Opts4a = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_peer,
        cacerts => [<<"der-encoded-cert">>]
    }),
    ?assertEqual({cacerts, [<<"der-encoded-cert">>]}, lists:keyfind(cacerts, 1, Opts4a)),
    ?assertNot(lists:keymember(cacertfile, 1, Opts4a)),

    Opts4b = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_peer,
        cacerts => [<<"der-encoded-cert">>],
        cacertfile => "/path/to/ca.pem"
    }),
    ?assertEqual({cacerts, [<<"der-encoded-cert">>]}, lists:keyfind(cacerts, 1, Opts4b)),
    ?assertNot(lists:keymember(cacertfile, 1, Opts4b)),

    Opts4c = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_none,
        cacerts => [<<"der-encoded-cert">>]
    }),
    ?assertNot(lists:keymember(cacerts, 1, Opts4c)),
    ?assertNot(lists:keymember(cacertfile, 1, Opts4c)),

    Opts5 = nhttp_sock:build_client_ssl_opts(#{
        alpn_advertised_protocols => []
    }),
    ?assertNot(lists:keymember(alpn_advertised_protocols, 1, Opts5)),

    Opts6 = nhttp_sock:build_client_ssl_opts(#{
        certfile => "/path/to/cert.pem",
        keyfile => "/path/to/key.pem",
        verify => verify_none
    }),
    ?assert(lists:keymember(certfile, 1, Opts6)),
    ?assert(lists:keymember(keyfile, 1, Opts6)),

    Opts7 = nhttp_sock:build_client_ssl_opts(#{verify => verify_peer}),
    ?assertNot(lists:keymember(customize_hostname_check, 1, Opts7)),

    Opts8 = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_peer,
        wildcard_hostname => true
    }),
    {customize_hostname_check, Opts8Custom} =
        lists:keyfind(customize_hostname_check, 1, Opts8),
    ?assertEqual(
        public_key:pkix_verify_hostname_match_fun(https),
        proplists:get_value(match_fun, Opts8Custom)
    ),

    Opts9 = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_peer,
        wildcard_hostname => false
    }),
    ?assertNot(lists:keymember(customize_hostname_check, 1, Opts9)),

    Opts10 = nhttp_sock:build_client_ssl_opts(#{
        verify => verify_none,
        wildcard_hostname => true
    }),
    ?assertNot(lists:keymember(customize_hostname_check, 1, Opts10)),

    ok.

normalize_host_variants(_Config) ->
    {ok, ListenSock} = nhttp_sock:listen(#{port => 0, transport => tcp}),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    spawn_link(fun() ->
        {ok, Sock} = nhttp_sock:connect(<<"127.0.0.1">>, Port, #{transport => tcp}),
        timer:sleep(100),
        nhttp_sock:close(Sock)
    end),
    {ok, Accepted1} = nhttp_sock:accept(ListenSock, 5000),
    nhttp_sock:close(Accepted1),

    spawn_link(fun() ->
        {ok, Sock} = nhttp_sock:connect("127.0.0.1", Port, #{transport => tcp}),
        timer:sleep(100),
        nhttp_sock:close(Sock)
    end),
    {ok, Accepted2} = nhttp_sock:accept(ListenSock, 5000),
    nhttp_sock:close(Accepted2),

    spawn_link(fun() ->
        {ok, Sock} = nhttp_sock:connect({127, 0, 0, 1}, Port, #{transport => tcp}),
        timer:sleep(100),
        nhttp_sock:close(Sock)
    end),
    {ok, Accepted3} = nhttp_sock:accept(ListenSock, 5000),
    nhttp_sock:close(Accepted3),

    nhttp_sock:close(ListenSock),
    ok.

%%%-----------------------------------------------------------------------------
%%% ADDITIONAL COVERAGE TESTS
%%%-----------------------------------------------------------------------------

ssl_pre_handshake_ops(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    Self = self(),
    spawn_link(fun() ->
        {ok, ClientSock} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}]),
        Self ! client_connected,
        timer:sleep(500),
        gen_tcp:close(ClientSock)
    end),

    {ok, PreHandshakeSock} = nhttp_sock:accept(ListenSock, 5000),
    ?assertMatch({ssl_pending, _}, PreHandshakeSock),

    receive
        client_connected -> ok
    after 5000 -> ct:fail("Client did not connect")
    end,

    ok = nhttp_sock:setopts(PreHandshakeSock, [{active, false}]),
    {ok, {PeerAddr, _}} = nhttp_sock:peername(PreHandshakeSock),
    ?assert(is_tuple(PeerAddr)),
    {ok, {LocalAddr, LocalPort}} = nhttp_sock:sockname(PreHandshakeSock),
    ?assert(is_tuple(LocalAddr)),
    ?assertEqual(Port, LocalPort),
    ?assertEqual({error, no_alpn}, nhttp_sock:negotiated_protocol(PreHandshakeSock)),

    NewOwner = spawn_link(fun() ->
        receive
            {transfer_back, Pid} ->
                nhttp_sock:controlling_process(PreHandshakeSock, Pid)
        end
    end),
    ok = nhttp_sock:controlling_process(PreHandshakeSock, NewOwner),
    NewOwner ! {transfer_back, self()},
    timer:sleep(50),

    ?assertEqual({error, timeout}, nhttp_sock:recv(PreHandshakeSock, 0, 100)),
    ?assertError(function_clause, nhttp_sock:send(PreHandshakeSock, <<"x">>)),

    ok = nhttp_sock:close(PreHandshakeSock),
    nhttp_sock:close(ListenSock),
    ok.

ssl_accept_error(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),

    Result = nhttp_sock:accept(ListenSock, 1),
    ?assertEqual({error, timeout}, Result),

    nhttp_sock:close(ListenSock),
    ok.

ssl_connect_with_sni(Config) ->
    CertFile = ?config(certfile, Config),
    KeyFile = ?config(keyfile, Config),

    {ok, ListenSock} = nhttp_sock:listen(#{
        port => 0,
        transport => ssl,
        certfile => CertFile,
        keyfile => KeyFile
    }),
    {ok, {_, Port}} = nhttp_sock:sockname(ListenSock),

    SslOpts = nhttp_sock:build_ssl_opts(#{
        certfile => CertFile,
        keyfile => KeyFile
    }),

    Self = self(),

    spawn_link(fun() ->
        {ok, PreSock} = nhttp_sock:accept(ListenSock, 5000),
        {ok, ServerSock} = nhttp_sock:handshake(PreSock, 5000, SslOpts),
        Self ! {server1_ready, ServerSock}
    end),

    {ok, ClientSock1} = nhttp_sock:connect("127.0.0.1", Port, #{
        transport => ssl,
        verify => verify_none,
        server_name_indication => disable,
        alpn_advertised_protocols => []
    }),
    ?assertEqual(ssl, nhttp_sock:transport(ClientSock1)),
    receive
        {server1_ready, SS1} -> nhttp_sock:close(SS1)
    after 5000 -> ct:fail("timeout")
    end,
    nhttp_sock:close(ClientSock1),

    spawn_link(fun() ->
        {ok, PreSock} = nhttp_sock:accept(ListenSock, 5000),
        {ok, ServerSock} = nhttp_sock:handshake(PreSock, 5000, SslOpts),
        Self ! {server2_ready, ServerSock}
    end),

    {ok, ClientSock2} = nhttp_sock:connect("127.0.0.1", Port, #{
        transport => ssl,
        verify => verify_none,
        server_name_indication => "example.com",
        alpn_advertised_protocols => []
    }),
    ?assertEqual(ssl, nhttp_sock:transport(ClientSock2)),
    receive
        {server2_ready, SS2} -> nhttp_sock:close(SS2)
    after 5000 -> ct:fail("timeout")
    end,
    nhttp_sock:close(ClientSock2),

    nhttp_sock:close(ListenSock),
    ok.
