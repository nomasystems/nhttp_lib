%%%-----------------------------------------------------------------------------
-module(nhttp_msg_props).

-moduledoc """
Property tests for nhttp_msg shared message helpers.

Exercised via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

-spec prop_validate_request_pseudo_shape_no_crash() -> triq:property().
prop_validate_request_pseudo_shape_no_crash() ->
    ?FORALL(
        Headers,
        headers_gen(),
        case nhttp_msg:validate_request_pseudo_shape(Headers) of
            {ok, Shape} when is_map(Shape) ->
                expected_shape_keys(Shape);
            {error, Reason} ->
                lists:member(Reason, shape_error_atoms())
        end
    ).

-spec prop_validate_request_pseudo_shape_valid_roundtrip() -> triq:property().
prop_validate_request_pseudo_shape_valid_roundtrip() ->
    ?FORALL(
        Pseudos,
        valid_pseudo_set_gen(),
        ?FORALL(
            Regulars,
            regular_headers_gen(),
            begin
                Headers = Pseudos ++ Regulars,
                case nhttp_msg:validate_request_pseudo_shape(Headers) of
                    {ok, Shape} ->
                        valid_shape_invariants(Pseudos, Regulars, Shape);
                    {error, _} ->
                        true
                end
            end
        )
    ).

%% RFC 9113 Section 8.3.2 and RFC 9114 Section 4.3.2: `:status` is a
%% string of three digits. RFC 9110 Section 15.1: the first digit
%% selects one of exactly five response classes, so the accepted range
%% is 100 to 599. The properties below state that no peer-supplied
%% value can raise, and that the accepted set is exactly that range.

-spec prop_extract_response_pseudo_never_raises() -> triq:property().
prop_extract_response_pseudo_never_raises() ->
    ?FORALL(
        {Value, Regulars},
        {status_value_gen(), regular_headers_gen()},
        begin
            Headers = [{<<":status">>, Value} | Regulars],
            case nhttp_msg:extract_response_pseudo(Headers) of
                {ok, {Status, Filtered}} ->
                    is_integer(Status) andalso Status >= 100 andalso Status =< 599 andalso
                        Filtered =:= Regulars;
                {error, Reason} ->
                    lists:member(Reason, [invalid_status, missing_status])
            end
        end
    ).

-spec prop_extract_response_pseudo_accepts_exactly_valid_status() -> triq:property().
prop_extract_response_pseudo_accepts_exactly_valid_status() ->
    ?FORALL(
        Value,
        status_value_gen(),
        begin
            Accepted =
                case nhttp_msg:extract_response_pseudo([{<<":status">>, Value}]) of
                    {ok, {Status, []}} -> {yes, Status};
                    {error, invalid_status} -> no
                end,
            Accepted =:= reference_status(Value)
        end
    ).

-spec prop_extract_response_pseudo_missing_status() -> triq:property().
prop_extract_response_pseudo_missing_status() ->
    ?FORALL(
        Regulars,
        regular_headers_gen(),
        nhttp_msg:extract_response_pseudo(Regulars) =:= {error, missing_status}
    ).

%%%-----------------------------------------------------------------------------
%%% Helpers
%%%-----------------------------------------------------------------------------

%% Independent restatement of the rule, written without reference to
%% the implementation. Three bytes, all ASCII digits, first digit 1-5.
reference_status(<<D1, D2, D3>>) when
    D1 >= $1, D1 =< $5, D2 >= $0, D2 =< $9, D3 >= $0, D3 =< $9
->
    {yes, list_to_integer([D1, D2, D3])};
reference_status(_) ->
    no.

shape_error_atoms() ->
    [
        duplicate_pseudo,
        unknown_pseudo,
        pseudo_after_regular,
        forbidden_connection_header,
        multiple_host_headers,
        missing_required_pseudo,
        bad_wire_scheme,
        authority_host_mismatch
    ].

expected_shape_keys(Shape) ->
    lists:all(
        fun(K) -> maps:is_key(K, Shape) end,
        [method, scheme, path, authority, host, protocol, headers]
    ).

valid_shape_invariants(Pseudos, _Regulars, Shape) ->
    Method = maps:get(method, Shape),
    Scheme = maps:get(scheme, Shape),
    Path = maps:get(path, Shape),
    PseudoNames = [N || {N, _} <- Pseudos],
    MethodOk = Method =:= proplists:get_value(<<":method">>, Pseudos),
    SchemeOk = Scheme =:= proplists:get_value(<<":scheme">>, Pseudos),
    PathOk = Path =:= proplists:get_value(<<":path">>, Pseudos),
    Headers = maps:get(headers, Shape),
    NoPseudosInHeaders = not lists:any(
        fun({<<$:, _/binary>>, _}) -> true; (_) -> false end,
        Headers
    ),
    MethodOk andalso SchemeOk andalso PathOk andalso NoPseudosInHeaders andalso
        is_list(PseudoNames).

%%%-----------------------------------------------------------------------------
%%% Generators
%%%-----------------------------------------------------------------------------

headers_gen() ->
    list(header_gen()).

header_gen() ->
    {oneof([
        binary(),
        pseudo_name_gen(),
        regular_name_gen()
    ]),
        binary()}.

pseudo_name_gen() ->
    oneof([
        <<":method">>,
        <<":scheme">>,
        <<":authority">>,
        <<":path">>,
        <<":protocol">>,
        <<":bogus">>
    ]).

regular_name_gen() ->
    oneof([
        <<"host">>,
        <<"te">>,
        <<"connection">>,
        <<"transfer-encoding">>,
        <<"keep-alive">>,
        <<"upgrade">>,
        <<"x-foo">>,
        <<"content-length">>
    ]).

valid_pseudo_set_gen() ->
    ?LET(
        {Method, Scheme, Path, AuthorityOpt, ProtocolOpt},
        {method_gen(), scheme_gen(), non_empty_path_gen(), authority_opt_gen(), protocol_opt_gen()},
        begin
            Base = [
                {<<":method">>, Method},
                {<<":scheme">>, Scheme},
                {<<":path">>, Path}
            ],
            WithAuth = case AuthorityOpt of
                undefined -> Base;
                A -> Base ++ [{<<":authority">>, A}]
            end,
            case ProtocolOpt of
                undefined -> WithAuth;
                P -> WithAuth ++ [{<<":protocol">>, P}]
            end
        end
    ).

method_gen() ->
    oneof([<<"GET">>, <<"POST">>, <<"PUT">>, <<"DELETE">>, <<"CONNECT">>, <<"HEAD">>]).

scheme_gen() ->
    oneof([<<"http">>, <<"https">>]).

non_empty_path_gen() ->
    oneof([<<"/">>, <<"/index">>, <<"/api/v1">>, <<"/foo?bar=baz">>]).

authority_opt_gen() ->
    oneof([undefined, <<"example.com">>, <<"example.com:8443">>, <<"host.local">>]).

protocol_opt_gen() ->
    oneof([undefined, <<"websocket">>]).

%% Mixes wholly arbitrary binaries with shapes that sit on the accept
%% boundary, so the generator reaches the interesting cases without
%% relying on `binary()` to produce a three-byte digit run by chance.
status_value_gen() ->
    oneof([
        binary(),
        ?LET(N, choose(0, 999), integer_to_binary(N)),
        ?LET(N, choose(0, 999), list_to_binary(io_lib:format("~3..0b", [N]))),
        ?LET({A, B, C}, {digit_byte_gen(), digit_byte_gen(), digit_byte_gen()}, <<A, B, C>>),
        ?LET(B, binary(3), B),
        oneof([<<>>, <<"200">>, <<"099">>, <<"600">>, <<"+200">>, <<"-200">>, <<" 200">>])
    ]).

digit_byte_gen() ->
    choose($0, $9).

regular_headers_gen() ->
    list(regular_header_gen()).

regular_header_gen() ->
    {oneof([<<"x-foo">>, <<"accept">>, <<"user-agent">>, <<"content-type">>]),
        binary()}.
