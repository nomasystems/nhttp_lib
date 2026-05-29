-module(nhttp_proxy_protocol).

-moduledoc """
PROXY protocol v1 and v2 parser.

The PROXY protocol preserves the original client IP/port across a
connection-terminating intermediary (load balancer, proxy). Both v1
(ASCII line) and v2 (binary frame) are supported.

The 12-byte v2 signature `\\r\\n\\r\\n\\x00\\r\\nQUIT\\n` is unambiguous
and shares no prefix with `"PROXY "`, so callers wishing to accept both
versions can probe each shape from the first byte without ambiguity.

## Usage

```erlang
case nhttp_proxy_protocol:parse(Buffer, #{version => both}) of
    {ok, Header, Consumed} ->
        Rest = binary:part(Buffer, Consumed, byte_size(Buffer) - Consumed),
        handle(Header, Rest);
    {more, _MinBytes} ->
        recv_more();
    {error, Reason} ->
        reject(Reason)
end.
```

The returned `t:header/0` map carries the parsed source/destination
addresses for the `proxy` command. The `local` command (v2 only) signals
a health-check-style connection from the proxy itself; callers should
keep the original L4 peer in that case.
""".

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-export([
    parse/1,
    parse/2
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-export_type([
    command/0,
    family/0,
    header/0,
    opts/0,
    parse_error/0,
    parse_result/0,
    transport/0,
    version/0
]).

-type version() :: v1 | v2.

-type command() :: proxy | local.

-type family() :: inet | inet6 | unix | unspec.

-type transport() :: stream | dgram | unspec.

-type accepted() :: v1 | v2 | both.

-type tlv() :: {Type :: 0..255, Value :: binary()}.

-type header() :: #{
    version := version(),
    command := command(),
    family := family(),
    transport := transport(),
    src_addr => inet:ip_address() | binary(),
    dst_addr => inet:ip_address() | binary(),
    src_port => inet:port_number(),
    dst_port => inet:port_number(),
    tlvs => [tlv()]
}.

-type opts() :: #{version => accepted()}.

-type parse_error() ::
    bad_signature
    | bad_v1_header
    | bad_v1_proto
    | bad_v1_addr
    | bad_v1_port
    | bad_v1_too_long
    | bad_v2_version
    | bad_v2_command
    | bad_v2_family
    | bad_v2_transport
    | bad_v2_payload
    | unsupported_version.

-type parse_result() ::
    {ok, header(), Consumed :: pos_integer()}
    | {more, MinBytes :: pos_integer()}
    | {error, parse_error()}.

%%%-----------------------------------------------------------------------------
%% MACROS
%%%-----------------------------------------------------------------------------
-define(V2_SIGNATURE, <<13, 10, 13, 10, 0, 13, 10, "QUIT", 10>>).
-define(V2_SIG_LEN, 12).
-define(V2_HEADER_LEN, 16).
-define(V1_PREFIX, <<"PROXY ">>).
-define(V1_PREFIX_LEN, 6).
-define(V1_MAX_LEN, 107).

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc "Equivalent to `parse(Bin, #{version => both})`.".
-spec parse(binary()) -> parse_result().
parse(<<Bin/binary>>) ->
    parse(Bin, #{}).

-doc """
Parse a PROXY protocol header from `Bin`.
`Opts` may carry `version => v1 | v2 | both` (default `both`) to restrict
the accepted protocol versions. When restricted, a header that matches a
disallowed version returns `{error, unsupported_version}`.
Returns `{ok, Header, Consumed}` on success, where `Consumed` is the
number of bytes occupied by the PROXY header (including any v1 CRLF or
v2 length prefix). Use `binary:part/3` on the original buffer to recover
the bytes that follow.
""".
-spec parse(binary(), opts()) -> parse_result().
parse(<<Bin/binary>>, Opts) ->
    Accepted = maps:get(version, Opts, both),
    classify(Bin, Accepted).

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS - DISPATCH
%%%-----------------------------------------------------------------------------
-spec allows_v1(accepted()) -> boolean().
allows_v1(v1) -> true;
allows_v1(both) -> true;
allows_v1(_) -> false.

-spec allows_v2(accepted()) -> boolean().
allows_v2(v2) -> true;
allows_v2(both) -> true;
allows_v2(_) -> false.

-spec classify(binary(), accepted()) -> parse_result().
classify(<<>>, _Accepted) ->
    {more, 1};
classify(<<13, _/binary>> = Bin, Accepted) ->
    case allows_v2(Accepted) of
        true -> match_v2(Bin);
        false -> {error, unsupported_version}
    end;
classify(<<$P, _/binary>> = Bin, Accepted) ->
    case allows_v1(Accepted) of
        true -> match_v1(Bin);
        false -> {error, unsupported_version}
    end;
classify(_Bin, _Accepted) ->
    {error, bad_signature}.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS - V2
%%%-----------------------------------------------------------------------------
-spec build_v2_header(command(), family(), transport(), binary()) -> parse_result().
build_v2_header(local, _Family, _Transport, Payload) ->
    Header = #{
        version => v2,
        command => local,
        family => unspec,
        transport => unspec
    },
    {ok, Header, ?V2_HEADER_LEN + byte_size(Payload)};
build_v2_header(proxy, unspec, Transport, Payload) ->
    Header = #{
        version => v2,
        command => proxy,
        family => unspec,
        transport => Transport
    },
    {ok, Header, ?V2_HEADER_LEN + byte_size(Payload)};
build_v2_header(proxy, inet, Transport, Payload) ->
    case Payload of
        <<S1:8, S2:8, S3:8, S4:8, D1:8, D2:8, D3:8, D4:8, SP:16/big, DP:16/big, Tail/binary>> ->
            maybe
                {ok, Tlvs} ?= parse_tlvs(Tail, []),
                Header = #{
                    version => v2,
                    command => proxy,
                    family => inet,
                    transport => Transport,
                    src_addr => {S1, S2, S3, S4},
                    dst_addr => {D1, D2, D3, D4},
                    src_port => SP,
                    dst_port => DP,
                    tlvs => Tlvs
                },
                {ok, Header, ?V2_HEADER_LEN + byte_size(Payload)}
            end;
        _ ->
            {error, bad_v2_payload}
    end;
build_v2_header(proxy, inet6, Transport, Payload) ->
    case Payload of
        <<S1:16/big, S2:16/big, S3:16/big, S4:16/big, S5:16/big, S6:16/big, S7:16/big, S8:16/big,
            D1:16/big, D2:16/big, D3:16/big, D4:16/big, D5:16/big, D6:16/big, D7:16/big, D8:16/big,
            SP:16/big, DP:16/big, Tail/binary>> ->
            maybe
                {ok, Tlvs} ?= parse_tlvs(Tail, []),
                Header = #{
                    version => v2,
                    command => proxy,
                    family => inet6,
                    transport => Transport,
                    src_addr => {S1, S2, S3, S4, S5, S6, S7, S8},
                    dst_addr => {D1, D2, D3, D4, D5, D6, D7, D8},
                    src_port => SP,
                    dst_port => DP,
                    tlvs => Tlvs
                },
                {ok, Header, ?V2_HEADER_LEN + byte_size(Payload)}
            end;
        _ ->
            {error, bad_v2_payload}
    end;
build_v2_header(proxy, unix, Transport, Payload) ->
    case Payload of
        <<Src:108/binary, Dst:108/binary, Tail/binary>> ->
            maybe
                {ok, Tlvs} ?= parse_tlvs(Tail, []),
                Header = #{
                    version => v2,
                    command => proxy,
                    family => unix,
                    transport => Transport,
                    src_addr => trim_nul(Src),
                    dst_addr => trim_nul(Dst),
                    tlvs => Tlvs
                },
                {ok, Header, ?V2_HEADER_LEN + byte_size(Payload)}
            end;
        _ ->
            {error, bad_v2_payload}
    end.

-spec decode_v2(byte(), byte(), binary()) -> parse_result().
decode_v2(VerCmd, FamProto, Payload) ->
    Version = VerCmd bsr 4,
    Command = VerCmd band 16#0F,
    Family = FamProto bsr 4,
    Transport = FamProto band 16#0F,
    case Version of
        2 ->
            maybe
                {ok, CommandAtom} ?= decode_v2_command(Command),
                {ok, FamilyAtom} ?= decode_v2_family(Family),
                {ok, TransportAtom} ?= decode_v2_transport(Transport),
                build_v2_header(CommandAtom, FamilyAtom, TransportAtom, Payload)
            end;
        _ ->
            {error, bad_v2_version}
    end.

-spec decode_v2_command(byte()) -> {ok, command()} | {error, bad_v2_command}.
decode_v2_command(0) -> {ok, local};
decode_v2_command(1) -> {ok, proxy};
decode_v2_command(_) -> {error, bad_v2_command}.

-spec decode_v2_family(byte()) -> {ok, family()} | {error, bad_v2_family}.
decode_v2_family(0) -> {ok, unspec};
decode_v2_family(1) -> {ok, inet};
decode_v2_family(2) -> {ok, inet6};
decode_v2_family(3) -> {ok, unix};
decode_v2_family(_) -> {error, bad_v2_family}.

-spec decode_v2_transport(byte()) -> {ok, transport()} | {error, bad_v2_transport}.
decode_v2_transport(0) -> {ok, unspec};
decode_v2_transport(1) -> {ok, stream};
decode_v2_transport(2) -> {ok, dgram};
decode_v2_transport(_) -> {error, bad_v2_transport}.

-spec match_v2(binary()) -> parse_result().
match_v2(<<13, 10, 13, 10, 0, 13, 10, "QUIT", 10, Rest/binary>>) ->
    parse_v2(Rest);
match_v2(<<Bin/binary>>) when byte_size(Bin) < ?V2_SIG_LEN ->
    Size = byte_size(Bin),
    Prefix = binary:part(?V2_SIGNATURE, 0, Size),
    case Bin of
        Prefix -> {more, ?V2_HEADER_LEN - Size};
        _ -> {error, bad_signature}
    end;
match_v2(_Bin) ->
    {error, bad_signature}.

-spec parse_tlvs(binary(), [tlv()]) -> {ok, [tlv()]} | {error, bad_v2_payload}.
parse_tlvs(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
parse_tlvs(<<Type:8, Len:16/big, Value:Len/binary, Rest/binary>>, Acc) ->
    parse_tlvs(Rest, [{Type, Value} | Acc]);
parse_tlvs(_Bin, _Acc) ->
    {error, bad_v2_payload}.

-spec parse_v2(binary()) -> parse_result().
parse_v2(<<VerCmd:8, FamProto:8, Len:16/big, Rest/binary>>) ->
    case Rest of
        <<Payload:Len/binary, _/binary>> ->
            decode_v2(VerCmd, FamProto, Payload);
        _ ->
            {more, Len - byte_size(Rest)}
    end;
parse_v2(<<Bin/binary>>) ->
    {more, (?V2_HEADER_LEN - ?V2_SIG_LEN) - byte_size(Bin)}.

-spec trim_nul(binary()) -> binary().
trim_nul(<<Bin/binary>>) ->
    case binary:match(Bin, <<0>>) of
        {Pos, 1} -> binary:part(Bin, 0, Pos);
        nomatch -> Bin
    end.

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS - V1
%%%-----------------------------------------------------------------------------
-spec all_digits(binary()) -> boolean().
all_digits(<<>>) -> true;
all_digits(<<C, Rest/binary>>) when C >= $0, C =< $9 -> all_digits(Rest);
all_digits(_) -> false.

-spec decode_v1_addrs(binary(), inet | inet6, pos_integer()) -> parse_result().
decode_v1_addrs(Bin, Family, Consumed) ->
    case binary:split(Bin, <<" ">>, [global]) of
        [SrcAddr, DstAddr, SrcPort, DstPort] ->
            maybe
                {ok, SrcIp} ?= parse_v1_ip(SrcAddr, Family),
                {ok, DstIp} ?= parse_v1_ip(DstAddr, Family),
                {ok, SrcP} ?= parse_v1_port(SrcPort),
                {ok, DstP} ?= parse_v1_port(DstPort),
                Header = #{
                    version => v1,
                    command => proxy,
                    family => Family,
                    transport => stream,
                    src_addr => SrcIp,
                    dst_addr => DstIp,
                    src_port => SrcP,
                    dst_port => DstP
                },
                {ok, Header, Consumed}
            end;
        _ ->
            {error, bad_v1_header}
    end.

-spec decode_v1_line(binary(), pos_integer()) -> parse_result().
decode_v1_line(<<"UNKNOWN">>, Consumed) ->
    {ok, unknown_v1_header(), Consumed};
decode_v1_line(<<"UNKNOWN ", _Tail/binary>>, Consumed) ->
    {ok, unknown_v1_header(), Consumed};
decode_v1_line(<<"TCP4 ", Rest/binary>>, Consumed) ->
    decode_v1_addrs(Rest, inet, Consumed);
decode_v1_line(<<"TCP6 ", Rest/binary>>, Consumed) ->
    decode_v1_addrs(Rest, inet6, Consumed);
decode_v1_line(_Line, _Consumed) ->
    {error, bad_v1_proto}.

-spec match_v1(binary()) -> parse_result().
match_v1(<<"PROXY ", Rest/binary>>) ->
    parse_v1(Rest);
match_v1(<<Bin/binary>>) when byte_size(Bin) < ?V1_PREFIX_LEN ->
    Size = byte_size(Bin),
    Prefix = binary:part(?V1_PREFIX, 0, Size),
    case Bin of
        Prefix -> {more, ?V1_PREFIX_LEN - Size};
        _ -> {error, bad_signature}
    end;
match_v1(_Bin) ->
    {error, bad_signature}.

-spec parse_v1(binary()) -> parse_result().
parse_v1(<<Rest/binary>>) ->
    MaxBodyLen = ?V1_MAX_LEN - ?V1_PREFIX_LEN,
    Available = min(MaxBodyLen, byte_size(Rest)),
    Window = binary:part(Rest, 0, Available),
    case binary:match(Window, <<"\r\n">>) of
        {Pos, 2} ->
            <<Line:Pos/binary, "\r\n", _/binary>> = Rest,
            decode_v1_line(Line, ?V1_PREFIX_LEN + Pos + 2);
        nomatch when byte_size(Rest) >= MaxBodyLen ->
            {error, bad_v1_too_long};
        nomatch ->
            {more, 1}
    end.

-spec parse_v1_ip(binary(), inet | inet6) -> {ok, inet:ip_address()} | {error, bad_v1_addr}.
parse_v1_ip(IpBin, Family) ->
    case inet:parse_strict_address(binary_to_list(IpBin)) of
        {ok, IP} when Family =:= inet, tuple_size(IP) =:= 4 ->
            {ok, IP};
        {ok, IP} when Family =:= inet6, tuple_size(IP) =:= 8 ->
            {ok, IP};
        _ ->
            {error, bad_v1_addr}
    end.

-spec parse_v1_port(binary()) -> {ok, inet:port_number()} | {error, bad_v1_port}.
parse_v1_port(<<>>) ->
    {error, bad_v1_port};
parse_v1_port(PortBin) ->
    case all_digits(PortBin) of
        true ->
            Port = binary_to_integer(PortBin),
            case Port =< 65535 of
                true -> {ok, Port};
                false -> {error, bad_v1_port}
            end;
        false ->
            {error, bad_v1_port}
    end.

-spec unknown_v1_header() -> header().
unknown_v1_header() ->
    #{
        version => v1,
        command => proxy,
        family => unspec,
        transport => unspec
    }.
