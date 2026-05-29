%%%-----------------------------------------------------------------------------
-module(nhttp_proxy_protocol_SUITE).

-moduledoc "PROXY protocol v1/v2 parser test suite.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, v1},
        {group, v2},
        {group, accepted_versions},
        {group, framing},
        {group, malformed}
    ].

groups() ->
    [
        {v1, [parallel], [
            v1_tcp4,
            v1_tcp6,
            v1_unknown,
            v1_unknown_with_garbage,
            v1_consumes_only_header,
            v1_zero_port,
            v1_max_port
        ]},
        {v2, [parallel], [
            v2_local,
            v2_proxy_tcp4,
            v2_proxy_tcp6,
            v2_proxy_unix,
            v2_proxy_unspec,
            v2_with_tlvs,
            v2_consumes_only_header
        ]},
        {accepted_versions, [parallel], [
            accept_v1_only_rejects_v2,
            accept_v2_only_rejects_v1,
            accept_both_handles_v1,
            accept_both_handles_v2
        ]},
        {framing, [parallel], [
            partial_v1_signature_more,
            partial_v2_signature_more,
            partial_v1_body_more,
            partial_v2_header_more,
            partial_v2_payload_more,
            empty_input_more
        ]},
        {malformed, [parallel], [
            unknown_signature,
            v1_oversized_line,
            v1_bad_proto,
            v1_bad_addr,
            v1_bad_port,
            v1_v6_addr_in_tcp4,
            v2_bad_version,
            v2_bad_command,
            v2_bad_family,
            v2_bad_transport,
            v2_truncated_inet_payload,
            v2_truncated_inet6_payload,
            v2_truncated_tlv
        ]}
    ].

init_per_suite(Config) -> Config.
end_per_suite(_Config) -> ok.
init_per_group(_Group, Config) -> Config.
end_per_group(_Group, _Config) -> ok.
init_per_testcase(_TestCase, Config) -> Config.
end_per_testcase(_TestCase, _Config) -> ok.

%%%-----------------------------------------------------------------------------
%%% V1
%%%-----------------------------------------------------------------------------

v1_tcp4(_Config) ->
    Data = <<"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n">>,
    {ok, Header, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertMatch(
        #{
            version := v1,
            command := proxy,
            family := inet,
            transport := stream,
            src_addr := {192, 168, 0, 1},
            dst_addr := {192, 168, 0, 11},
            src_port := 56324,
            dst_port := 443
        },
        Header
    ).

v1_tcp6(_Config) ->
    Data = <<"PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n">>,
    {ok, Header, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertMatch(
        #{
            version := v1,
            family := inet6,
            transport := stream,
            src_addr := {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
            dst_addr := {16#2001, 16#db8, 0, 0, 0, 0, 0, 2},
            src_port := 56324,
            dst_port := 443
        },
        Header
    ).

v1_unknown(_Config) ->
    Data = <<"PROXY UNKNOWN\r\n">>,
    {ok, Header, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertMatch(#{version := v1, command := proxy, family := unspec, transport := unspec}, Header),
    ?assertNot(maps:is_key(src_addr, Header)),
    ?assertNot(maps:is_key(dst_addr, Header)).

v1_unknown_with_garbage(_Config) ->
    Data = <<"PROXY UNKNOWN ffff:f...:ffff ffff:f...:ffff 65535 65535\r\n">>,
    {ok, Header, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertMatch(#{family := unspec}, Header).

v1_consumes_only_header(_Config) ->
    Header = <<"PROXY TCP4 10.0.0.1 10.0.0.2 1000 2000\r\n">>,
    Trailing = <<"GET / HTTP/1.1\r\nHost: x\r\n\r\n">>,
    Data = <<Header/binary, Trailing/binary>>,
    {ok, _Hdr, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Header), Consumed),
    Rest = binary:part(Data, Consumed, byte_size(Data) - Consumed),
    ?assertEqual(Trailing, Rest).

v1_zero_port(_Config) ->
    Data = <<"PROXY TCP4 1.2.3.4 5.6.7.8 0 0\r\n">>,
    {ok, Header, _Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertMatch(#{src_port := 0, dst_port := 0}, Header).

v1_max_port(_Config) ->
    Data = <<"PROXY TCP4 1.2.3.4 5.6.7.8 65535 65535\r\n">>,
    {ok, Header, _Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertMatch(#{src_port := 65535, dst_port := 65535}, Header).

%%%-----------------------------------------------------------------------------
%%% V2
%%%-----------------------------------------------------------------------------

v2_local(_Config) ->
    Data = <<(v2_sig())/binary, 16#20, 16#00, 0:16/big>>,
    {ok, Header, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertMatch(#{version := v2, command := local, family := unspec, transport := unspec}, Header).

v2_proxy_tcp4(_Config) ->
    Payload =
        <<1, 2, 3, 4, 5, 6, 7, 8, 1234:16/big, 5678:16/big>>,
    Data = v2_packet(16#21, 16#11, Payload),
    {ok, Header, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertMatch(
        #{
            version := v2,
            command := proxy,
            family := inet,
            transport := stream,
            src_addr := {1, 2, 3, 4},
            dst_addr := {5, 6, 7, 8},
            src_port := 1234,
            dst_port := 5678,
            tlvs := []
        },
        Header
    ).

v2_proxy_tcp6(_Config) ->
    Payload =
        <<16#2001:16/big, 16#0db8:16/big, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16, 16#2001:16/big,
            16#0db8:16/big, 0:16, 0:16, 0:16, 0:16, 0:16, 2:16, 1234:16/big, 5678:16/big>>,
    Data = v2_packet(16#21, 16#21, Payload),
    {ok, Header, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertMatch(
        #{
            family := inet6,
            transport := stream,
            src_addr := {16#2001, 16#0db8, 0, 0, 0, 0, 0, 1},
            dst_addr := {16#2001, 16#0db8, 0, 0, 0, 0, 0, 2},
            src_port := 1234,
            dst_port := 5678
        },
        Header
    ).

v2_proxy_unix(_Config) ->
    SrcPath = <<"/var/run/src.sock", 0:91/unit:8>>,
    DstPath = <<"/var/run/dst.sock", 0:91/unit:8>>,
    Payload = <<SrcPath/binary, DstPath/binary>>,
    216 = byte_size(Payload),
    Data = v2_packet(16#21, 16#31, Payload),
    {ok, Header, _Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertMatch(
        #{
            family := unix,
            transport := stream,
            src_addr := <<"/var/run/src.sock">>,
            dst_addr := <<"/var/run/dst.sock">>
        },
        Header
    ).

v2_proxy_unspec(_Config) ->
    Data = v2_packet(16#21, 16#00, <<>>),
    {ok, Header, _Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertMatch(#{command := proxy, family := unspec, transport := unspec}, Header).

v2_with_tlvs(_Config) ->
    Tlv1 = <<16#02, 4:16/big, "test">>,
    Tlv2 = <<16#03, 2:16/big, "ok">>,
    Addrs = <<1, 2, 3, 4, 5, 6, 7, 8, 1234:16/big, 5678:16/big>>,
    Payload = <<Addrs/binary, Tlv1/binary, Tlv2/binary>>,
    Data = v2_packet(16#21, 16#11, Payload),
    {ok, Header, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Data), Consumed),
    ?assertMatch(
        #{tlvs := [{16#02, <<"test">>}, {16#03, <<"ok">>}]},
        Header
    ).

v2_consumes_only_header(_Config) ->
    Addrs = <<1, 2, 3, 4, 5, 6, 7, 8, 1234:16/big, 5678:16/big>>,
    Header = v2_packet(16#21, 16#11, Addrs),
    Trailing = <<"GET / HTTP/1.1\r\nHost: x\r\n\r\n">>,
    Data = <<Header/binary, Trailing/binary>>,
    {ok, _Hdr, Consumed} = nhttp_proxy_protocol:parse(Data),
    ?assertEqual(byte_size(Header), Consumed),
    Rest = binary:part(Data, Consumed, byte_size(Data) - Consumed),
    ?assertEqual(Trailing, Rest).

%%%-----------------------------------------------------------------------------
%%% ACCEPTED VERSIONS
%%%-----------------------------------------------------------------------------

accept_v1_only_rejects_v2(_Config) ->
    Data = v2_packet(16#20, 16#00, <<>>),
    ?assertEqual(
        {error, unsupported_version},
        nhttp_proxy_protocol:parse(Data, #{version => v1})
    ).

accept_v2_only_rejects_v1(_Config) ->
    Data = <<"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n">>,
    ?assertEqual(
        {error, unsupported_version},
        nhttp_proxy_protocol:parse(Data, #{version => v2})
    ).

accept_both_handles_v1(_Config) ->
    Data = <<"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n">>,
    {ok, #{version := v1}, _} = nhttp_proxy_protocol:parse(Data, #{version => both}).

accept_both_handles_v2(_Config) ->
    Data = v2_packet(16#20, 16#00, <<>>),
    {ok, #{version := v2}, _} = nhttp_proxy_protocol:parse(Data, #{version => both}).

%%%-----------------------------------------------------------------------------
%%% FRAMING (PARTIAL INPUTS)
%%%-----------------------------------------------------------------------------

empty_input_more(_Config) ->
    ?assertMatch({more, _}, nhttp_proxy_protocol:parse(<<>>)).

partial_v1_signature_more(_Config) ->
    ?assertMatch({more, _}, nhttp_proxy_protocol:parse(<<"P">>)),
    ?assertMatch({more, _}, nhttp_proxy_protocol:parse(<<"PROXY">>)),
    ?assertEqual({error, bad_signature}, nhttp_proxy_protocol:parse(<<"PROXX">>)).

partial_v2_signature_more(_Config) ->
    ?assertMatch({more, _}, nhttp_proxy_protocol:parse(<<13>>)),
    ?assertMatch({more, _}, nhttp_proxy_protocol:parse(<<13, 10, 13, 10>>)),
    ?assertEqual({error, bad_signature}, nhttp_proxy_protocol:parse(<<13, 10, 13, 10, 1>>)).

partial_v1_body_more(_Config) ->
    ?assertMatch({more, _}, nhttp_proxy_protocol:parse(<<"PROXY TCP4 1.2.3.4 5.6.7.8 1 2">>)).

partial_v2_header_more(_Config) ->
    Sig = v2_sig(),
    Bin = <<Sig/binary, 16#21, 16#11>>,
    ?assertMatch({more, _}, nhttp_proxy_protocol:parse(Bin)).

partial_v2_payload_more(_Config) ->
    Sig = v2_sig(),
    Bin = <<Sig/binary, 16#21, 16#11, 12:16/big, 1, 2, 3, 4>>,
    ?assertMatch({more, _}, nhttp_proxy_protocol:parse(Bin)).

%%%-----------------------------------------------------------------------------
%%% MALFORMED
%%%-----------------------------------------------------------------------------

unknown_signature(_Config) ->
    ?assertEqual({error, bad_signature}, nhttp_proxy_protocol:parse(<<"NOT A PROXY HEADER">>)).

v1_oversized_line(_Config) ->
    Pad = binary:copy(<<"X">>, 200),
    Data = <<"PROXY TCP4 1.2.3.4 5.6.7.8 1 2 ", Pad/binary, "\r\n">>,
    ?assertEqual({error, bad_v1_too_long}, nhttp_proxy_protocol:parse(Data)).

v1_bad_proto(_Config) ->
    ?assertEqual(
        {error, bad_v1_proto},
        nhttp_proxy_protocol:parse(<<"PROXY UDP 1.2.3.4 5.6.7.8 1 2\r\n">>)
    ).

v1_bad_addr(_Config) ->
    ?assertEqual(
        {error, bad_v1_addr},
        nhttp_proxy_protocol:parse(<<"PROXY TCP4 not-an-ip 5.6.7.8 1 2\r\n">>)
    ).

v1_bad_port(_Config) ->
    ?assertEqual(
        {error, bad_v1_port},
        nhttp_proxy_protocol:parse(<<"PROXY TCP4 1.2.3.4 5.6.7.8 abc 2\r\n">>)
    ),
    ?assertEqual(
        {error, bad_v1_port},
        nhttp_proxy_protocol:parse(<<"PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n">>)
    ).

v1_v6_addr_in_tcp4(_Config) ->
    ?assertEqual(
        {error, bad_v1_addr},
        nhttp_proxy_protocol:parse(<<"PROXY TCP4 2001:db8::1 1.2.3.4 1 2\r\n">>)
    ).

v2_bad_version(_Config) ->
    Data = v2_packet(16#11, 16#00, <<>>),
    ?assertEqual({error, bad_v2_version}, nhttp_proxy_protocol:parse(Data)).

v2_bad_command(_Config) ->
    Data = v2_packet(16#2F, 16#00, <<>>),
    ?assertEqual({error, bad_v2_command}, nhttp_proxy_protocol:parse(Data)).

v2_bad_family(_Config) ->
    Data = v2_packet(16#21, 16#F0, <<>>),
    ?assertEqual({error, bad_v2_family}, nhttp_proxy_protocol:parse(Data)).

v2_bad_transport(_Config) ->
    Data = v2_packet(16#21, 16#0F, <<>>),
    ?assertEqual({error, bad_v2_transport}, nhttp_proxy_protocol:parse(Data)).

v2_truncated_inet_payload(_Config) ->
    Payload = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Data = v2_packet(16#21, 16#11, Payload),
    ?assertEqual({error, bad_v2_payload}, nhttp_proxy_protocol:parse(Data)).

v2_truncated_inet6_payload(_Config) ->
    Payload = <<0:16/unit:8>>,
    Data = v2_packet(16#21, 16#21, Payload),
    ?assertEqual({error, bad_v2_payload}, nhttp_proxy_protocol:parse(Data)).

v2_truncated_tlv(_Config) ->
    Addrs = <<1, 2, 3, 4, 5, 6, 7, 8, 1234:16/big, 5678:16/big>>,
    Payload = <<Addrs/binary, 16#02, 99:16/big, "short">>,
    Data = v2_packet(16#21, 16#11, Payload),
    ?assertEqual({error, bad_v2_payload}, nhttp_proxy_protocol:parse(Data)).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

v2_sig() ->
    <<13, 10, 13, 10, 0, 13, 10, "QUIT", 10>>.

v2_packet(VerCmd, FamProto, Payload) ->
    Sig = v2_sig(),
    Len = byte_size(Payload),
    <<Sig/binary, VerCmd:8, FamProto:8, Len:16/big, Payload/binary>>.
