-module(nhttp_sock).

-moduledoc """
Socket abstraction layer for nhttp.

Provides a unified interface for TCP and SSL sockets. All socket operations
are tagged with transport type for pattern matching.

## Socket Types

Sockets are represented as `{tcp, gen_tcp:socket()}` or `{ssl, ssl:socket()}`.
This allows unified handling while preserving transport information.

## ALPN Negotiation

For TLS connections, use `negotiated_protocol/1` to determine which
application protocol was negotiated (e.g., `<<"h2">>` or `<<"http/1.1">>`).
""".

%%%-----------------------------------------------------------------------------
%% LISTENING
%%%-----------------------------------------------------------------------------
-export([
    accept/2,
    handshake/3,
    listen/1
]).

%%%-----------------------------------------------------------------------------
%% CONNECTING
%%%-----------------------------------------------------------------------------
-export([
    connect/3,
    connect/4
]).

%%%-----------------------------------------------------------------------------
%% SSL OPTIONS
%%%-----------------------------------------------------------------------------
-export([
    build_client_ssl_opts/1,
    build_ssl_opts/1
]).

%%%-----------------------------------------------------------------------------
%% SOCKET OPERATIONS
%%%-----------------------------------------------------------------------------
-export([
    close/1,
    controlling_process/2,
    recv/3,
    send/2,
    setopts/2
]).

%%%-----------------------------------------------------------------------------
%% INFORMATION
%%%-----------------------------------------------------------------------------
-export([
    negotiated_protocol/1,
    peername/1,
    sockname/1,
    transport/1
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-export_type([
    connect_opts/0,
    listen_opts/0,
    t/0,
    socket_error/0,
    transport/0
]).

-type transport() :: tcp | ssl.

-type t() ::
    {tcp, gen_tcp:socket()}
    | {ssl, ssl:sslsocket()}
    | {ssl_listen, gen_tcp:socket()}
    | {ssl_pending, gen_tcp:socket()}.

-type listen_opts() :: #{
    port := inet:port_number(),
    transport => transport(),
    backlog => pos_integer(),
    nodelay => boolean(),
    send_timeout => timeout(),
    buffer => pos_integer(),
    certfile => file:filename(),
    keyfile => file:filename(),
    cacertfile => file:filename(),
    alpn_preferred_protocols => [binary()],
    verify => verify_none | verify_peer,
    tls_versions => ['tlsv1.2' | 'tlsv1.3']
}.

-type connect_opts() :: #{
    transport => transport(),
    nodelay => boolean(),
    send_timeout => timeout(),
    buffer => pos_integer(),
    certfile => file:filename(),
    keyfile => file:filename(),
    cacertfile => file:filename(),
    cacerts => [public_key:der_encoded()],
    alpn_advertised_protocols => [binary()],
    verify => verify_none | verify_peer,
    server_name_indication => inet:hostname() | disable,
    tls_versions => ['tlsv1.2' | 'tlsv1.3'],
    wildcard_hostname => boolean()
}.

-type socket_error() ::
    closed
    | timeout
    | inet:posix()
    | {tls_error, ssl:error_alert() | ssl:reason()}.

%%%-----------------------------------------------------------------------------
%% MACROS
%%%-----------------------------------------------------------------------------
-define(DEFAULT_CONNECT_BUFFER, 65536).

%%%-----------------------------------------------------------------------------
%% LISTENING
%%%-----------------------------------------------------------------------------
-doc """
Accept a connection on a listening socket. A TCP listener returns
`{tcp, _}` (ready for I/O); an SSL listener returns `{ssl_pending, _}`
which requires `handshake/3` before any I/O. The outer tag always reflects
the actual transport state, so dispatch on it is safe everywhere.
""".
-spec accept(t(), timeout()) -> {ok, t()} | {error, socket_error()}.
accept({tcp, ListenSocket}, Timeout) ->
    case gen_tcp:accept(ListenSocket, Timeout) of
        {ok, Socket} -> {ok, {tcp, Socket}};
        {error, _} = Error -> Error
    end;
accept({ssl_listen, ListenSocket}, Timeout) ->
    case gen_tcp:accept(ListenSocket, Timeout) of
        {ok, TcpSocket} -> {ok, {ssl_pending, TcpSocket}};
        {error, _} = Error -> Error
    end.

-doc """
Complete the TLS handshake on a freshly accepted socket. The `{ssl_pending, _}`
tag from `accept/2` is upgraded to `{ssl, _}` on success. Calling `handshake/3`
on a pure-TCP `{tcp, _}` or an already-upgraded `{ssl, _}` socket is a no-op.
""".
-spec handshake(t(), timeout(), SslOpts) -> {ok, t()} | {error, socket_error()} when
    SslOpts :: [ssl:tls_server_option()].
handshake({tcp, _} = Socket, _Timeout, _SslOpts) ->
    {ok, Socket};
handshake({ssl, _} = Socket, _Timeout, _SslOpts) ->
    {ok, Socket};
handshake({ssl_pending, TcpSocket}, Timeout, SslOpts) ->
    case ssl:handshake(TcpSocket, SslOpts, Timeout) of
        {ok, SslSocket} -> {ok, {ssl, SslSocket}};
        {error, _} = Error -> Error
    end.

-doc "Create a listening socket with the given options.".
-spec listen(listen_opts()) -> {ok, t()} | {error, socket_error()}.
listen(Opts) ->
    Transport = maps:get(transport, Opts, tcp),
    Port = maps:get(port, Opts),
    case Transport of
        tcp -> listen_tcp(Port, Opts);
        ssl -> listen_ssl(Port, Opts)
    end.

%%%-----------------------------------------------------------------------------
%% CONNECTING
%%%-----------------------------------------------------------------------------
-doc "Connect to a remote host. Returns a connected socket or an error.".
-spec connect(Host, inet:port_number(), connect_opts()) ->
    {ok, t()} | {error, socket_error()}
when
    Host :: binary() | string() | inet:ip_address().
connect(Host, Port, Opts) ->
    connect(Host, Port, Opts, 5000).

-doc "Connect to a remote host with explicit timeout.".
-spec connect(Host, inet:port_number(), connect_opts(), timeout()) ->
    {ok, t()} | {error, socket_error()}
when
    Host :: binary() | string() | inet:ip_address().
connect(Host, Port, Opts, Timeout) ->
    Transport = maps:get(transport, Opts, tcp),
    HostStr = normalize_host(Host),
    case Transport of
        tcp -> connect_tcp(HostStr, Port, Opts, Timeout);
        ssl -> connect_ssl(HostStr, Port, Opts, Timeout)
    end.

%%%-----------------------------------------------------------------------------
%% SSL OPTIONS
%%%-----------------------------------------------------------------------------
-doc "Build SSL options for client connections.".
-spec build_client_ssl_opts(connect_opts()) -> [ssl:tls_client_option()].
build_client_ssl_opts(Opts) ->
    Certfile = maps:get(certfile, Opts, undefined),
    Keyfile = maps:get(keyfile, Opts, undefined),
    Cacertfile = maps:get(cacertfile, Opts, undefined),
    Cacerts = maps:get(cacerts, Opts, undefined),
    WildcardHostName = maps:get(wildcard_hostname, Opts, false),
    AlpnProtocols = maps:get(alpn_advertised_protocols, Opts, [<<"h2">>, <<"http/1.1">>]),
    Verify = maps:get(verify, Opts, verify_peer),
    Versions = maps:get(tls_versions, Opts, ['tlsv1.2', 'tlsv1.3']),

    BaseOpts = [
        {verify, Verify},
        {versions, Versions}
    ],
    WithAlpn =
        case AlpnProtocols of
            [] -> BaseOpts;
            _ -> [{alpn_advertised_protocols, AlpnProtocols} | BaseOpts]
        end,
    WithCacert =
        case {Verify, Cacerts, Cacertfile} of
            {verify_none, _, _} ->
                WithAlpn;
            {verify_peer, undefined, undefined} ->
                [{cacerts, public_key:cacerts_get()} | WithAlpn];
            {verify_peer, Certs, _} when Certs =/= undefined ->
                [{cacerts, Certs} | WithAlpn];
            {verify_peer, undefined, File} when File =/= undefined ->
                [{cacertfile, File} | WithAlpn]
        end,
    HostnameCheck =
        case {Verify, WildcardHostName} of
            {verify_peer, true} ->
                [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}];
            _ ->
                undefined
        end,
    WithHostnameCheck =
        maybe_add_opt(customize_hostname_check, HostnameCheck, WithCacert),
    WithCert = maybe_add_opt(certfile, Certfile, WithHostnameCheck),
    maybe_add_opt(keyfile, Keyfile, WithCert).

-doc "Build SSL options from opts map. Accepts any map containing SSL-related keys.".
-spec build_ssl_opts(map()) -> [ssl:tls_server_option()].
build_ssl_opts(Opts) ->
    Certfile = maps:get(certfile, Opts, undefined),
    Keyfile = maps:get(keyfile, Opts, undefined),
    Cacertfile = maps:get(cacertfile, Opts, undefined),
    AlpnProtocols = maps:get(alpn_preferred_protocols, Opts, [<<"h2">>, <<"http/1.1">>]),
    Verify = maps:get(verify, Opts, verify_none),
    Versions = maps:get(tls_versions, Opts, ['tlsv1.2', 'tlsv1.3']),
    BaseOpts = [
        {verify, Verify},
        {versions, Versions}
    ],
    WithAlpn =
        case AlpnProtocols of
            [] -> BaseOpts;
            _ -> [{alpn_preferred_protocols, AlpnProtocols} | BaseOpts]
        end,
    WithCert = maybe_add_opt(certfile, Certfile, WithAlpn),
    WithKey = maybe_add_opt(keyfile, Keyfile, WithCert),
    maybe_add_opt(cacertfile, Cacertfile, WithKey).

%%%-----------------------------------------------------------------------------
%% SOCKET OPERATIONS
%%%-----------------------------------------------------------------------------
-doc "Close a socket. Pre-handshake and listen sockets close at the TCP layer.".
-spec close(t()) -> ok.
close({tcp, Socket}) ->
    gen_tcp:close(Socket);
close({ssl_listen, Socket}) ->
    gen_tcp:close(Socket);
close({ssl_pending, Socket}) ->
    gen_tcp:close(Socket);
close({ssl, Socket}) ->
    ssl:close(Socket).

-doc "Transfer socket ownership to another process.".
-spec controlling_process(t(), pid()) -> ok | {error, socket_error()}.
controlling_process({tcp, Socket}, Pid) ->
    gen_tcp:controlling_process(Socket, Pid);
controlling_process({ssl_pending, Socket}, Pid) ->
    gen_tcp:controlling_process(Socket, Pid);
controlling_process({ssl, Socket}, Pid) ->
    ssl:controlling_process(Socket, Pid).

-doc """
Receive data from a socket.
`{ssl_pending, _}` is accepted: pre-handshake reads operate on the
underlying TCP socket. This is intended for byte-accurate pre-TLS
protocols (e.g. the PROXY protocol) where reading past the prefix
into the TLS ClientHello would break the handshake.
""".
-spec recv(t(), non_neg_integer(), timeout()) ->
    {ok, binary()} | {error, socket_error()}.
recv({tcp, Socket}, Length, Timeout) ->
    gen_tcp:recv(Socket, Length, Timeout);
recv({ssl_pending, Socket}, Length, Timeout) ->
    gen_tcp:recv(Socket, Length, Timeout);
recv({ssl, Socket}, Length, Timeout) ->
    ssl:recv(Socket, Length, Timeout).

-doc "Send data on a socket. Not valid on `{ssl_pending, _}`. Call `handshake/3` first.".
-spec send(t(), iodata()) -> ok | {error, socket_error()}.
send({tcp, Socket}, Data) ->
    gen_tcp:send(Socket, Data);
send({ssl, Socket}, Data) ->
    ssl:send(Socket, Data).

-doc "Set socket options.".
-spec setopts(t(), [gen_tcp:option() | ssl:tls_option()]) ->
    ok | {error, socket_error()}.
setopts({tcp, Socket}, Opts) ->
    inet:setopts(Socket, Opts);
setopts({ssl_pending, Socket}, Opts) ->
    inet:setopts(Socket, Opts);
setopts({ssl, Socket}, Opts) ->
    ssl:setopts(Socket, Opts).

%%%-----------------------------------------------------------------------------
%% SOCKET INFORMATION
%%%-----------------------------------------------------------------------------
-doc "Get the negotiated ALPN protocol. Returns `{error, no_alpn}` for non-TLS or pre-handshake sockets.".
-spec negotiated_protocol(t()) -> {ok, binary()} | {error, no_alpn}.
negotiated_protocol({tcp, _}) ->
    {error, no_alpn};
negotiated_protocol({ssl_pending, _}) ->
    {error, no_alpn};
negotiated_protocol({ssl, Socket}) ->
    case ssl:negotiated_protocol(Socket) of
        {ok, Protocol} -> {ok, Protocol};
        {error, _} -> {error, no_alpn}
    end.

-doc "Get the remote address and port.".
-spec peername(t()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, socket_error()}.
peername({tcp, Socket}) ->
    inet:peername(Socket);
peername({ssl_pending, Socket}) ->
    inet:peername(Socket);
peername({ssl, Socket}) ->
    ssl:peername(Socket).

-doc "Get the local address and port.".
-spec sockname(t()) -> {ok, {inet:ip_address(), inet:port_number()}} | {error, socket_error()}.
sockname({tcp, Socket}) ->
    inet:sockname(Socket);
sockname({ssl_listen, Socket}) ->
    inet:sockname(Socket);
sockname({ssl_pending, Socket}) ->
    inet:sockname(Socket);
sockname({ssl, Socket}) ->
    ssl:sockname(Socket).

-doc "Get the transport type of a socket. `ssl_pending` reports as `ssl`.".
-spec transport(t()) -> transport().
transport({tcp, _}) -> tcp;
transport({ssl_listen, _}) -> ssl;
transport({ssl_pending, _}) -> ssl;
transport({ssl, _}) -> ssl.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec add_sni([ssl:tls_client_option()], string(), connect_opts()) -> [ssl:tls_client_option()].
add_sni(SslOpts, Host, Opts) ->
    case maps:get(server_name_indication, Opts, undefined) of
        disable -> [{server_name_indication, disable} | SslOpts];
        undefined -> [{server_name_indication, Host} | SslOpts];
        Sni -> [{server_name_indication, Sni} | SslOpts]
    end.

-spec build_connect_tcp_opts(connect_opts()) -> [gen_tcp:connect_option()].
build_connect_tcp_opts(Opts) ->
    Nodelay = maps:get(nodelay, Opts, true),
    SendTimeout = maps:get(send_timeout, Opts, 30000),
    Buffer = maps:get(buffer, Opts, ?DEFAULT_CONNECT_BUFFER),
    [
        binary,
        {active, false},
        {nodelay, Nodelay},
        {send_timeout, SendTimeout},
        {buffer, Buffer},
        {packet, raw}
    ].

-spec build_tcp_opts(listen_opts()) -> [gen_tcp:listen_option()].
build_tcp_opts(Opts) ->
    Backlog = maps:get(backlog, Opts, 1024),
    Nodelay = maps:get(nodelay, Opts, true),
    SendTimeout = maps:get(send_timeout, Opts, 30000),
    Buffer = maps:get(buffer, Opts, 16384),
    [
        binary,
        {active, false},
        {reuseaddr, true},
        {backlog, Backlog},
        {nodelay, Nodelay},
        {send_timeout, SendTimeout},
        {buffer, Buffer},
        {packet, raw}
    ].

-spec connect_ssl(string(), inet:port_number(), connect_opts(), timeout()) ->
    {ok, t()} | {error, socket_error()}.
connect_ssl(Host, Port, Opts, Timeout) ->
    TcpOpts = build_connect_tcp_opts(Opts),
    SslOpts = build_client_ssl_opts(Opts),
    SslOptsWithSni = add_sni(SslOpts, Host, Opts),
    case gen_tcp:connect(Host, Port, TcpOpts, Timeout) of
        {ok, TcpSocket} ->
            case ssl:connect(TcpSocket, SslOptsWithSni, Timeout) of
                {ok, SslSocket} ->
                    {ok, {ssl, SslSocket}};
                {error, Reason} ->
                    gen_tcp:close(TcpSocket),
                    {error, {tls_error, Reason}}
            end;
        {error, _} = Error ->
            Error
    end.

-spec connect_tcp(string(), inet:port_number(), connect_opts(), timeout()) ->
    {ok, t()} | {error, socket_error()}.
connect_tcp(Host, Port, Opts, Timeout) ->
    TcpOpts = build_connect_tcp_opts(Opts),
    case gen_tcp:connect(Host, Port, TcpOpts, Timeout) of
        {ok, Socket} ->
            {ok, {tcp, Socket}};
        {error, _} = Error ->
            Error
    end.

-spec listen_ssl(inet:port_number(), listen_opts()) ->
    {ok, t()} | {error, socket_error()}.
listen_ssl(Port, Opts) ->
    TcpOpts = build_tcp_opts(Opts),
    case gen_tcp:listen(Port, TcpOpts) of
        {ok, Socket} -> {ok, {ssl_listen, Socket}};
        {error, _} = Error -> Error
    end.

-spec listen_tcp(inet:port_number(), listen_opts()) ->
    {ok, t()} | {error, socket_error()}.
listen_tcp(Port, Opts) ->
    TcpOpts = build_tcp_opts(Opts),
    case gen_tcp:listen(Port, TcpOpts) of
        {ok, Socket} -> {ok, {tcp, Socket}};
        {error, _} = Error -> Error
    end.

-spec maybe_add_opt(atom(), term(), [term()]) -> [term()].
maybe_add_opt(_Key, undefined, Opts) -> Opts;
maybe_add_opt(Key, Value, Opts) -> [{Key, Value} | Opts].

-spec normalize_host(binary() | string() | inet:ip_address()) -> string().
normalize_host(Host) when is_binary(Host) -> binary_to_list(Host);
normalize_host(Host) when is_list(Host) -> Host;
normalize_host(Host) when is_tuple(Host) -> inet:ntoa(Host).
