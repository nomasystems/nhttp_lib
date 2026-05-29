-module(nhttp_msg).

-moduledoc """
Shared message-level helpers for the HTTP/2 (RFC 9113) and HTTP/3
(RFC 9114) state machines.

These functions deal with the parts of a request/response that are
identical on both wire formats once the framing layer has produced a
list of `{Name, Value}` pseudo + regular header pairs:

- digit/length parsing (`is_digits/1`, `parse_content_length/1`)
- content-length extraction and end-of-stream validation
- pseudo-header projection (`extract_request_pseudo/1`,
  `extract_response_pseudo/1`)
- the `host` fallback used when `:authority` is empty
- trailers shape validation

The module is intentionally protocol-agnostic: errors are returned as
plain atoms and the calling protocol wraps them into the relevant wire
error format (atom for H2, descriptive binary for H3).
""".

-include("nhttp_msg.hrl").

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    build_request/3,
    build_response/2,
    check_authority_host_match/2,
    check_extended_connect/4,
    extract_content_length/1,
    extract_request_pseudo/1,
    extract_response_pseudo/1,
    host_header_or_empty/1,
    is_digits/1,
    parse_content_length/1,
    validate_content_length/3,
    validate_request_pseudo_shape/1,
    validate_trailers/1,
    validate_wire_scheme/1
]).

-export_type([
    content_length_error/0,
    extended_connect_error/0,
    request_shape/0,
    request_shape_error/0,
    trailers_error/0
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type trailers_error() :: pseudo_in_trailers.

-type content_length_error() :: content_length_mismatch.

-type extended_connect_error() :: missing_authority | bad_method | not_enabled.

-type request_shape() :: #{
    method := binary(),
    scheme := binary(),
    path := binary(),
    authority := binary() | undefined,
    host := binary() | undefined,
    protocol := binary() | undefined,
    headers := nhttp_lib:headers()
}.

-type request_shape_error() ::
    duplicate_pseudo
    | unknown_pseudo
    | pseudo_after_regular
    | forbidden_connection_header
    | multiple_host_headers
    | missing_required_pseudo
    | bad_wire_scheme
    | authority_host_mismatch.
-define(REQUEST_PSEUDO_HEADERS_SET, #{
    <<":method">> => true,
    <<":scheme">> => true,
    <<":authority">> => true,
    <<":path">> => true,
    <<":protocol">> => true
}).

%%%-----------------------------------------------------------------------------
%% API
%%%-----------------------------------------------------------------------------
-doc """
Assemble the canonical `t:nhttp_lib:request/0` map from the pseudo
plus regular header list emitted by the protocol decoders.

`Version` is stamped into the returned map; `Peer` is included as the
`peer` key when not `undefined`. Authority falls back to the `host`
header when `:authority` is empty (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
The Extended CONNECT `:protocol` (RFC 8441 / 9220) is added when
present.
""".
-spec build_request(
    nhttp_lib:version(), nhttp_lib:peer() | undefined, nhttp_lib:headers()
) -> nhttp_lib:request().
build_request(Version, Peer, Headers) ->
    {Method, Path, Scheme, Authority0, CProt, Filtered} = extract_request_pseudo(Headers),
    Authority =
        case Authority0 of
            <<>> -> host_header_or_empty(Filtered);
            _ -> Authority0
        end,
    Req0 = #{
        method => Method,
        path => Path,
        scheme => Scheme,
        authority => Authority,
        version => Version,
        headers => Filtered
    },
    Req1 =
        case CProt of
            undefined -> Req0;
            _ -> Req0#{connect_protocol => CProt}
        end,
    case Peer of
        undefined -> Req1;
        _ -> Req1#{peer => Peer}
    end.

-doc """
Assemble the canonical `t:nhttp_lib:response/0` map. `Version` is
stamped onto the map; `reason` is the empty binary (HTTP/2 and HTTP/3
do not carry a reason phrase, RFC 9113 §8.3.2, RFC 9114 §4.3.2).
""".
-spec build_response(nhttp_lib:version(), nhttp_lib:headers()) ->
    nhttp_lib:response().
build_response(Version, Headers) ->
    {Status, Filtered} = extract_response_pseudo(Headers),
    #{
        status => Status,
        version => Version,
        reason => <<>>,
        headers => Filtered
    }.

-doc """
When both `:authority` and `Host` are present they must carry the
same value (RFC 9113 §8.3.1, RFC 9114 §4.3.1). An `undefined`
component is treated as absent. Returns `{error, protocol_error}` on
mismatch.
""".
-spec check_authority_host_match(binary() | undefined, binary() | undefined) ->
    ok | {error, protocol_error}.
check_authority_host_match(undefined, _) -> ok;
check_authority_host_match(_, undefined) -> ok;
check_authority_host_match(Same, Same) -> ok;
check_authority_host_match(_, _) -> {error, protocol_error}.

-doc """
Validate the RFC 8441 / 9220 Extended CONNECT pseudo-header
combination. The four arguments are `:method`, `:protocol`,
`:authority` and the local settings map (peer settings on the server
side). The peer must advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`
to enable the feature.
Returns `ok` when the combination is acceptable (including the
common case where `:protocol` is absent), or one of three reasons
that the caller maps to the protocol-appropriate error payload:
- `missing_authority`: CONNECT without `:authority`.
- `not_enabled`: peer has not advertised `enable_connect_protocol`.
- `bad_method`: `:protocol` present with a method other than CONNECT.
""".
-spec check_extended_connect(
    binary() | undefined,
    binary() | undefined,
    binary() | undefined,
    map()
) -> ok | {error, extended_connect_error()}.
check_extended_connect(_Method, undefined, _Authority, _Settings) ->
    ok;
check_extended_connect(<<"CONNECT">>, _Protocol, undefined, _Settings) ->
    {error, missing_authority};
check_extended_connect(<<"CONNECT">>, _Protocol, _Authority, Settings) ->
    case maps:get(enable_connect_protocol, Settings, false) of
        true -> ok;
        false -> {error, not_enabled}
    end;
check_extended_connect(_Method, _Protocol, _Authority, _Settings) ->
    {error, bad_method}.

-spec do_validate_shape(nhttp_lib:headers(), map()) ->
    {ok, request_shape()} | {error, request_shape_error()}.
do_validate_shape([], State) ->
    finalise_request_shape(State);
do_validate_shape(
    [{<<$:, _/binary>> = Name, Value} | Rest], #{phase := pseudo, seen_pseudo := Seen} = State
) ->
    case maps:is_key(Name, Seen) of
        true ->
            {error, duplicate_pseudo};
        false ->
            case maps:is_key(Name, ?REQUEST_PSEUDO_HEADERS_SET) of
                false ->
                    {error, unknown_pseudo};
                true ->
                    NewState = set_pseudo_field(Name, Value, State),
                    do_validate_shape(Rest, NewState#{seen_pseudo => Seen#{Name => true}})
            end
    end;
do_validate_shape([{<<$:, _/binary>>, _} | _], #{phase := regular}) ->
    {error, pseudo_after_regular};
do_validate_shape([{Name, Value} = H | Rest], #{acc := Acc} = State) ->
    case maps:is_key(Name, ?NHTTP_MSG_CONNECTION_HEADERS_SET) of
        true ->
            {error, forbidden_connection_header};
        false ->
            case Name of
                <<"host">> ->
                    case maps:get(host, State) of
                        undefined ->
                            do_validate_shape(
                                Rest,
                                State#{phase => regular, host => Value, acc => [H | Acc]}
                            );
                        _ ->
                            {error, multiple_host_headers}
                    end;
                _ ->
                    do_validate_shape(
                        Rest, State#{phase => regular, acc => [H | Acc]}
                    )
            end
    end.

-doc """
Find the first `content-length` header in `Headers` and parse it.
Returns `undefined` when the header is absent or has a non-binary
value (defensive guard kept from the H2 implementation).
""".
-spec extract_content_length(nhttp_lib:headers()) -> non_neg_integer() | undefined.
extract_content_length([]) ->
    undefined;
extract_content_length([{<<"content-length">>, Value} | _]) when is_binary(Value) ->
    parse_content_length(Value);
extract_content_length([_ | Rest]) ->
    extract_content_length(Rest).

-doc """
Project the pseudo-header part of a request header list into typed
components and return the regular headers in their original order.
Unknown pseudo-headers (`<<":", _>>`) are dropped. The caller is
expected to have already rejected them at validation time.
""".
-spec extract_request_pseudo(nhttp_lib:headers()) ->
    {
        nhttp_lib:method() | undefined,
        binary(),
        nhttp_lib:scheme(),
        nhttp_lib:authority(),
        binary() | undefined,
        nhttp_lib:headers()
    }.
extract_request_pseudo(Headers) ->
    extract_request_pseudo(Headers, undefined, <<>>, http, <<>>, undefined, []).

-spec extract_request_pseudo(
    nhttp_lib:headers(),
    nhttp_lib:method() | undefined,
    binary(),
    nhttp_lib:scheme(),
    nhttp_lib:authority(),
    binary() | undefined,
    nhttp_lib:headers()
) ->
    {
        nhttp_lib:method() | undefined,
        binary(),
        nhttp_lib:scheme(),
        nhttp_lib:authority(),
        binary() | undefined,
        nhttp_lib:headers()
    }.
extract_request_pseudo([], Method, Path, Scheme, Authority, CProt, Acc) ->
    {Method, Path, Scheme, Authority, CProt, lists:reverse(Acc)};
extract_request_pseudo([{<<":method">>, V} | Rest], _M, P, S, A, CP, Acc) ->
    extract_request_pseudo(Rest, nhttp_lib:decode_method(V), P, S, A, CP, Acc);
extract_request_pseudo([{<<":path">>, V} | Rest], M, _P, S, A, CP, Acc) ->
    extract_request_pseudo(Rest, M, V, S, A, CP, Acc);
extract_request_pseudo([{<<":scheme">>, V} | Rest], M, P, _S, A, CP, Acc) ->
    extract_request_pseudo(Rest, M, P, nhttp_lib:decode_scheme(V), A, CP, Acc);
extract_request_pseudo([{<<":authority">>, V} | Rest], M, P, S, _A, CP, Acc) ->
    extract_request_pseudo(Rest, M, P, S, V, CP, Acc);
extract_request_pseudo([{<<":protocol">>, V} | Rest], M, P, S, A, _CP, Acc) ->
    extract_request_pseudo(Rest, M, P, S, A, V, Acc);
extract_request_pseudo([{<<":", _/binary>>, _} | Rest], M, P, S, A, CP, Acc) ->
    extract_request_pseudo(Rest, M, P, S, A, CP, Acc);
extract_request_pseudo([Header | Rest], M, P, S, A, CP, Acc) ->
    extract_request_pseudo(Rest, M, P, S, A, CP, [Header | Acc]).

-doc """
Project `:status` out of a response header list, returning the
integer status and the regular headers in their original order.
Unknown pseudo-headers are dropped (already rejected at validation).
""".
-spec extract_response_pseudo(nhttp_lib:headers()) ->
    {nhttp_lib:status() | 0, nhttp_lib:headers()}.
extract_response_pseudo(Headers) ->
    extract_response_pseudo(Headers, 0, []).

-spec extract_response_pseudo(
    nhttp_lib:headers(), nhttp_lib:status() | 0, nhttp_lib:headers()
) ->
    {nhttp_lib:status() | 0, nhttp_lib:headers()}.
extract_response_pseudo([], Status, Acc) ->
    {Status, lists:reverse(Acc)};
extract_response_pseudo([{<<":status">>, V} | Rest], _Status, Acc) ->
    extract_response_pseudo(Rest, binary_to_integer(V), Acc);
extract_response_pseudo([{<<":", _/binary>>, _} | Rest], Status, Acc) ->
    extract_response_pseudo(Rest, Status, Acc);
extract_response_pseudo([Header | Rest], Status, Acc) ->
    extract_response_pseudo(Rest, Status, [Header | Acc]).

-spec finalise_request_shape(map()) ->
    {ok, request_shape()} | {error, request_shape_error()}.
finalise_request_shape(State) ->
    #{
        method := Method,
        scheme := Scheme,
        path := Path,
        authority := Authority,
        host := Host,
        protocol := Protocol,
        acc := Acc
    } = State,
    case
        Method =/= undefined andalso Scheme =/= undefined andalso Path =/= undefined andalso
            Path =/= <<>>
    of
        false ->
            {error, missing_required_pseudo};
        true ->
            case validate_wire_scheme(Scheme) of
                {error, protocol_error} ->
                    {error, bad_wire_scheme};
                ok ->
                    case check_authority_host_match(Authority, Host) of
                        {error, protocol_error} ->
                            {error, authority_host_mismatch};
                        ok ->
                            {ok, #{
                                method => Method,
                                scheme => Scheme,
                                path => Path,
                                authority => Authority,
                                host => Host,
                                protocol => Protocol,
                                headers => lists:reverse(Acc)
                            }}
                    end
            end
    end.

-doc """
Return the `host` header value or `<<>>` when missing. Used as the
authority fallback when `:authority` is empty (RFC 9113 §8.3.1,
RFC 9114 §4.3.1).
""".
-spec host_header_or_empty(nhttp_lib:headers()) -> nhttp_lib:authority().
host_header_or_empty(Headers) ->
    case nhttp_headers:get(<<"host">>, Headers) of
        undefined -> <<>>;
        Host -> Host
    end.

-doc """
True iff every byte in `Bin` is an ASCII digit (`$0`..`$9`). Used by
`parse_content_length/1` to reject negative or otherwise malformed
values before reaching `binary_to_integer/1`.
""".
-spec is_digits(binary()) -> boolean().
is_digits(<<>>) ->
    true;
is_digits(<<C, Rest/binary>>) when C >= $0, C =< $9 ->
    is_digits(Rest);
is_digits(_) ->
    false.

-doc """
Parse a `content-length` header value. Returns the integer for a
non-negative decimal binary, or `undefined` for the empty binary or
any non-digit input. Never raises.
""".
-spec parse_content_length(binary()) -> non_neg_integer() | undefined.
parse_content_length(<<>>) ->
    undefined;
parse_content_length(Bin) ->
    case is_digits(Bin) of
        true -> binary_to_integer(Bin);
        false -> undefined
    end.

-spec set_pseudo_field(binary(), binary(), map()) -> map().
set_pseudo_field(<<":method">>, V, S) -> S#{method => V};
set_pseudo_field(<<":scheme">>, V, S) -> S#{scheme => V};
set_pseudo_field(<<":path">>, V, S) -> S#{path => V};
set_pseudo_field(<<":authority">>, V, S) -> S#{authority => V};
set_pseudo_field(<<":protocol">>, V, S) -> S#{protocol => V}.

-doc """
Check that the bytes received so far are consistent with the
advertised `content-length`. `undefined` always passes. On the final
frame the counts must match exactly; on intermediate frames the count
must not exceed the advertised length.
""".
-spec validate_content_length(
    non_neg_integer() | undefined, non_neg_integer(), nhttp_lib:fin()
) -> ok | {error, content_length_error()}.
validate_content_length(undefined, _RecvLen, _Fin) ->
    ok;
validate_content_length(ContentLength, RecvLen, fin) ->
    case ContentLength =:= RecvLen of
        true -> ok;
        false -> {error, content_length_mismatch}
    end;
validate_content_length(ContentLength, RecvLen, nofin) ->
    case RecvLen > ContentLength of
        true -> {error, content_length_mismatch};
        false -> ok
    end.

-doc """
Run the protocol-agnostic request header validation FSM (RFC 9113
§8.2 / RFC 9114 §4.2) and return a normalized intermediate shape
that protocol-specific post-passes can inspect.
The FSM enforces the rules that are byte-identical across HTTP/2 and
HTTP/3:
- Pseudo-header block precedes the regular fields.
- No duplicate pseudo-headers and no unknown pseudo names.
- No hop-by-hop / connection-specific fields (`Connection`,
  `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`).
- At most one `Host` field.
- `:method`, `:scheme` and a non-empty `:path` are present.
- `:scheme` is `http` or `https` on the wire.
- When both `:authority` and `Host` are present they must match.
Protocol-specific rules are deferred (TE policy per RFC 9113 §8.2.2
vs RFC 9114 §4.2, HTTP/3's "authority-requiring scheme needs
`:authority` or `Host`" rule, and Extended CONNECT settings). Callers
use `request_shape()` plus their own settings to finish validation.
""".
-spec validate_request_pseudo_shape(nhttp_lib:headers()) ->
    {ok, request_shape()} | {error, request_shape_error()}.
validate_request_pseudo_shape(Headers) ->
    Init = #{
        phase => pseudo,
        method => undefined,
        scheme => undefined,
        path => undefined,
        authority => undefined,
        host => undefined,
        protocol => undefined,
        seen_pseudo => #{},
        acc => []
    },
    do_validate_shape(Headers, Init).

-doc """
Trailers must not contain pseudo-headers (RFC 9113 §8.1, RFC 9114
§4.1). Returns `ok` or `{error, pseudo_in_trailers}`. Callers map the
atom to their protocol's error payload.
""".
-spec validate_trailers(nhttp_lib:headers()) -> ok | {error, trailers_error()}.
validate_trailers([]) ->
    ok;
validate_trailers([{<<$:, _/binary>>, _} | _]) ->
    {error, pseudo_in_trailers};
validate_trailers([_ | Rest]) ->
    validate_trailers(Rest).

-doc """
The `:scheme` pseudo-header must be `http` or `https` on the wire
(RFC 9113 §8.3.1, RFC 9114 §4.3.1). Returns `{error, protocol_error}`
on any other value (including `undefined`). Callers map the atom to
their preferred error payload.
""".
-spec validate_wire_scheme(binary() | undefined) -> ok | {error, protocol_error}.
validate_wire_scheme(<<"http">>) -> ok;
validate_wire_scheme(<<"https">>) -> ok;
validate_wire_scheme(_) -> {error, protocol_error}.
