%%%-----------------------------------------------------------------------------
-module(nhttp_headers_props).

-moduledoc """
Property tests for the field validity primitives of nhttp_headers.

Exercised via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

%%%-----------------------------------------------------------------------------
%%% PROPERTIES
%%%-----------------------------------------------------------------------------

%% RFC 9113 Section 8.2.1: an accepted field name holds no octet in
%% 0x00-0x20, 0x41-0x5A or 0x7F-0xFF, and holds a colon only as the single
%% leading colon of a pseudo-header field.
-spec prop_validate_field_name_accepts_only_the_rfc_octets() -> triq:property().
prop_validate_field_name_accepts_only_the_rfc_octets() ->
    ?FORALL(
        Name,
        field_name_gen(),
        case nhttp_headers:validate_field_name(Name) of
            ok ->
                name_holds_only_rfc_octets(Name);
            {error, uppercase_field_name} ->
                has_uppercase(Name);
            {error, invalid_field_name_char} ->
                not name_holds_only_rfc_octets(Name);
            {error, empty_field_name} ->
                Name =:= <<>> orelse Name =:= <<$:>>
        end
    ).

%% RFC 9110 Section 5.5 with the edge whitespace rule of RFC 9113
%% Section 8.2.1. The generator crosses the length that switches the scan
%% from binary:match/2 to the word scan, so both instruments answer for the
%% same values.
-spec prop_validate_field_value_agrees_with_the_octet_set() -> triq:property().
prop_validate_field_value_agrees_with_the_octet_set() ->
    ?FORALL(
        Value,
        field_value_gen(),
        case nhttp_headers:validate_field_value(Value) of
            ok ->
                not has_forbidden_octet(Value) andalso not has_edge_whitespace(Value);
            {error, field_value_edge_whitespace} ->
                has_edge_whitespace(Value);
            {error, invalid_field_value_char} ->
                has_forbidden_octet(Value) andalso not has_edge_whitespace(Value)
        end
    ).

-spec prop_lower_field_name_matches_byte_wise_lowercase() -> triq:property().
prop_lower_field_name_matches_byte_wise_lowercase() ->
    ?FORALL(
        Name,
        field_name_gen(),
        nhttp_headers:lower_field_name(Name) =:= byte_wise_lower(Name)
    ).

%% The conformant path must not allocate. A name that holds no octet in
%% 0x41-0x5A comes back as the very binary that the caller passed in.
-spec prop_lower_field_name_does_not_copy_a_lowercase_name() -> triq:property().
prop_lower_field_name_does_not_copy_a_lowercase_name() ->
    ?FORALL(
        Name,
        lowercase_name_gen(),
        erts_debug:same(Name, nhttp_headers:lower_field_name(Name))
    ).

%%%-----------------------------------------------------------------------------
%%% GENERATORS
%%%-----------------------------------------------------------------------------

%% Field names are short, and the interesting octets sit at the range edges,
%% so the generator mixes plain names with octets drawn from the whole byte
%% range and from the boundaries of every forbidden range.
-spec field_name_gen() -> triq_dom:domain().
field_name_gen() ->
    oneof([
        elements([
            <<>>,
            <<$:>>,
            <<"content-length">>,
            <<":method">>,
            <<"Content-Length">>,
            <<"a:b">>,
            <<"x-vendor">>
        ]),
        ?LET(Octets, list(name_octet_gen()), list_to_binary(Octets))
    ]).

-spec name_octet_gen() -> triq_dom:domain().
name_octet_gen() ->
    oneof([
        int(0, 255),
        elements([
            16#00,
            16#09,
            16#20,
            16#21,
            16#39,
            $:,
            16#3B,
            16#40,
            $A,
            $Z,
            16#5B,
            16#7E,
            16#7F,
            16#80,
            16#FF,
            $a,
            $z,
            $-
        ])
    ]).

%% Two filler runs surround one octet drawn from the interesting set. The run
%% lengths span the 112 octet length that switches the scan from
%% `binary:match/2' to the word scan, and the eight word stride above it, so
%% the interesting octet lands at every alignment that the word scan reads.
-spec field_value_gen() -> triq_dom:domain().
field_value_gen() ->
    oneof([
        elements([<<>>, <<"text/html">>, <<" a">>, <<"a ">>, <<"a\tb">>]),
        ?LET(
            {Head, F1, L1, Mid, F2, L2, Tail},
            {
                list(value_octet_gen()),
                filler_gen(),
                int(0, 130),
                value_octet_gen(),
                filler_gen(),
                int(0, 130),
                list(value_octet_gen())
            },
            <<
                (list_to_binary(Head))/binary,
                (binary:copy(<<F1>>, L1))/binary,
                Mid,
                (binary:copy(<<F2>>, L2))/binary,
                (list_to_binary(Tail))/binary
            >>
        )
    ]).

-spec filler_gen() -> triq_dom:domain().
filler_gen() ->
    elements([$v, $\s, $\t, 16#80, 16#FF, 16#21, 16#7E]).

-spec value_octet_gen() -> triq_dom:domain().
value_octet_gen() ->
    oneof([
        int(0, 255),
        elements([16#00, 16#09, 16#0A, 16#0D, 16#1F, 16#20, 16#21, 16#7E, 16#7F, 16#80, 16#FF])
    ]).

-spec lowercase_name_gen() -> triq_dom:domain().
lowercase_name_gen() ->
    ?LET(
        Name,
        field_name_gen(),
        byte_wise_lower(Name)
    ).

%%%-----------------------------------------------------------------------------
%%% ORACLES
%%%-----------------------------------------------------------------------------

-spec name_holds_only_rfc_octets(binary()) -> boolean().
name_holds_only_rfc_octets(<<>>) ->
    false;
name_holds_only_rfc_octets(<<$:, Rest/binary>>) ->
    Rest =/= <<>> andalso plain_name_octets(Rest);
name_holds_only_rfc_octets(Name) ->
    plain_name_octets(Name).

-spec plain_name_octets(binary()) -> boolean().
plain_name_octets(Bin) ->
    lists:all(
        fun(C) -> C > 16#20 andalso C < 16#7F andalso not (C >= $A andalso C =< $Z) end,
        binary_to_list(Bin)
    ) andalso binary:match(Bin, <<$:>>) =:= nomatch.

-spec has_uppercase(binary()) -> boolean().
has_uppercase(Bin) ->
    lists:any(fun(C) -> C >= $A andalso C =< $Z end, binary_to_list(Bin)).

-spec has_forbidden_octet(binary()) -> boolean().
has_forbidden_octet(Bin) ->
    lists:any(
        fun(C) -> (C < 16#20 andalso C =/= 16#09) orelse C =:= 16#7F end,
        binary_to_list(Bin)
    ).

-spec has_edge_whitespace(binary()) -> boolean().
has_edge_whitespace(<<>>) ->
    false;
has_edge_whitespace(Bin) ->
    is_ws(binary:first(Bin)) orelse is_ws(binary:last(Bin)).

-spec is_ws(byte()) -> boolean().
is_ws($\s) -> true;
is_ws($\t) -> true;
is_ws(_) -> false.

-spec byte_wise_lower(binary()) -> binary().
byte_wise_lower(Bin) ->
    <<<<(lower_byte(C))>> || <<C>> <= Bin>>.

-spec lower_byte(byte()) -> byte().
lower_byte(C) when C >= $A, C =< $Z -> C + 32;
lower_byte(C) -> C.
