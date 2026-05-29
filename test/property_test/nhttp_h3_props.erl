%%%-----------------------------------------------------------------------------
-module(nhttp_h3_props).

-moduledoc """
HTTP/3 Connection Property Tests.

These properties are run via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP PROPERTIES
%%%-----------------------------------------------------------------------------

-spec prop_headers_roundtrip() -> triq:property().
prop_headers_roundtrip() ->
    ?FORALL(
        ExtraHeaders,
        list(custom_header_gen()),
        begin
            Headers = [
                {<<":method">>, <<"GET">>},
                {<<":scheme">>, <<"https">>},
                {<<":path">>, <<"/">>},
                {<<":authority">>, <<"example.com">>}
                | ExtraHeaders
            ],
            {ok, Client} = init_client_with_peer_settings(),
            {ok, Server} = init_server_with_settings(),
            {ok, _Client1, Actions} = nhttp_h3:send_headers(Client, 4, Headers, fin),
            [{send_fin, 4, HeadersFrame}] = Actions,
            HeadersBin = iolist_to_binary(HeadersFrame),
            case nhttp_h3:recv(Server, 4, HeadersBin, fin) of
                {ok, [{request, 4, Request, fin}], _, _} ->
                    nhttp_props_helpers:request_matches(Headers, Request);
                _ ->
                    false
            end
        end
    ).

-spec prop_settings_roundtrip() -> triq:property().
prop_settings_roundtrip() ->
    ?FORALL(
        Settings,
        h3_settings_gen(),
        begin
            {ok, Frame} = nhttp_h3_frame:settings(Settings),
            FrameBin = iolist_to_binary(Frame),
            Client = nhttp_h3:new(client, #{}),
            {ok, Client1, _} = nhttp_h3:init_local_streams(Client, #{
                control => 2, encoder => 6, decoder => 10
            }),
            ControlData = <<0, FrameBin/binary>>,
            case nhttp_h3:recv(Client1, 3, ControlData, nofin) of
                {ok, [{settings, Decoded}], _, _} ->
                    settings_equivalent(Settings, Decoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_request_stream_no_crash() -> triq:property().
prop_request_stream_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            {ok, Server} = init_server_with_settings(),
            _ = (catch nhttp_h3:recv(Server, 0, Bin, nofin)),
            true
        end
    ).

-spec prop_uni_stream_no_crash() -> triq:property().
prop_uni_stream_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            Client = nhttp_h3:new(client, #{}),
            {ok, Client1, _} = nhttp_h3:init_local_streams(Client, #{
                control => 2, encoder => 6, decoder => 10
            }),
            _ = (catch nhttp_h3:recv(Client1, 3, Bin, nofin)),
            true
        end
    ).

%%%-----------------------------------------------------------------------------
%%% GENERATORS
%%%-----------------------------------------------------------------------------

-spec custom_header_gen() -> triq:gen({binary(), binary()}).
custom_header_gen() ->
    ?LET(
        {Name, Value},
        {header_name_gen(), header_value_gen()},
        {Name, Value}
    ).

-spec header_name_gen() -> triq:gen(binary()).
header_name_gen() ->
    ?LET(
        Chars,
        non_empty(list(oneof(lists:seq($a, $z) ++ lists:seq($0, $9) ++ [$-]))),
        list_to_binary([<<"x-">>, Chars])
    ).

-spec header_value_gen() -> triq:gen(binary()).
header_value_gen() ->
    ?LET(
        Chars,
        non_empty(list(oneof(lists:seq(32, 126)))),
        list_to_binary(Chars)
    ).

-spec h3_settings_gen() -> triq_dom:domain().
h3_settings_gen() ->
    ?LET(
        SettingsList,
        list(h3_setting_gen()),
        maps:from_list(SettingsList)
    ).

-spec h3_setting_gen() -> triq_dom:domain().
h3_setting_gen() ->
    oneof([
        ?LET(V, int(0, 16383), {qpack_max_table_capacity, V}),
        ?LET(V, int(0, 100), {qpack_blocked_streams, V}),
        ?LET(V, int(0, 1073741823), {max_field_section_size, V}),
        {enable_connect_protocol, bool()}
    ]).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec init_server_with_settings() -> {ok, nhttp_h3:conn()}.
init_server_with_settings() ->
    Server = nhttp_h3:new(server, #{}),
    {ok, Server1, _} = nhttp_h3:init_local_streams(Server, #{
        control => 3, encoder => 7, decoder => 11
    }),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    {ok, _, Server2, _} = nhttp_h3:recv(Server1, 2, <<0, SettingsBin/binary>>, nofin),
    {ok, [], Server3, _} = nhttp_h3:recv(Server2, 6, <<2>>, nofin),
    {ok, [], Server4, _} = nhttp_h3:recv(Server3, 10, <<3>>, nofin),
    {ok, Server4}.

-spec init_client_with_peer_settings() -> {ok, nhttp_h3:conn()}.
init_client_with_peer_settings() ->
    Client = nhttp_h3:new(client, #{}),
    {ok, Client1, _} = nhttp_h3:init_local_streams(Client, #{
        control => 2, encoder => 6, decoder => 10
    }),
    {ok, SettingsFrame} = nhttp_h3_frame:settings(#{}),
    SettingsBin = iolist_to_binary(SettingsFrame),
    {ok, _, Client2, _} = nhttp_h3:recv(Client1, 3, <<0, SettingsBin/binary>>, nofin),
    {ok, [], Client3, _} = nhttp_h3:recv(Client2, 7, <<2>>, nofin),
    {ok, [], Client4, _} = nhttp_h3:recv(Client3, 11, <<3>>, nofin),
    {ok, Client4}.

-spec settings_equivalent(
    nhttp_h3_frame:h3_settings(), nhttp_h3_frame:h3_settings()
) -> boolean().
settings_equivalent(Original, Decoded) ->
    maps:fold(
        fun
            (max_field_section_size, infinity, Acc) ->
                Acc andalso not maps:is_key(max_field_section_size, Decoded);
            (Key, Value, Acc) ->
                Acc andalso maps:get(Key, Decoded, undefined) =:= Value
        end,
        true,
        Original
    ).
