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

%%%-----------------------------------------------------------------------------
%%% Helpers
%%%-----------------------------------------------------------------------------

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

regular_headers_gen() ->
    list(regular_header_gen()).

regular_header_gen() ->
    {oneof([<<"x-foo">>, <<"accept">>, <<"user-agent">>, <<"content-type">>]),
        binary()}.
