%%%-----------------------------------------------------------------------------
-module(nhttp_cookie_props).

-moduledoc """
Cookie codec property tests (RFC 6265).

Properties:

- Encoded cookies round-trip through `decode_cookie/1` (M2).
- Encoded `Set-Cookie` headers round-trip through `decode_set_cookie/1`
  for the attributes that have a stable string representation.
- Both decoders are total: arbitrary binary inputs return `{ok, _}` or
  `{error, _}` and never crash.

These properties are run via `nhttp_props_SUITE`.
""".

-include_lib("triq/include/triq.hrl").



-spec prop_cookie_roundtrip() -> triq:property().
prop_cookie_roundtrip() ->
    ?FORALL(
        Cookies,
        non_empty(list(cookie_gen())),
        begin
            {ok, Encoded} = nhttp_cookie:encode_cookie(Cookies),
            {ok, Decoded} = nhttp_cookie:decode_cookie(Encoded),
            Decoded =:= Cookies
        end
    ).

-spec prop_set_cookie_roundtrip() -> triq:property().
prop_set_cookie_roundtrip() ->
    ?FORALL(
        SetCookie,
        set_cookie_gen(),
        begin
            {ok, Encoded} = nhttp_cookie:encode_set_cookie(SetCookie),
            case nhttp_cookie:decode_set_cookie(Encoded) of
                {ok, Decoded} -> set_cookies_equivalent(SetCookie, Decoded);
                {error, _} -> false
            end
        end
    ).

-spec prop_decode_cookie_never_crashes() -> triq:property().
prop_decode_cookie_never_crashes() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            try nhttp_cookie:decode_cookie(Bin) of
                {ok, _} -> true;
                {error, _} -> true
            catch
                _:_ -> false
            end
        end
    ).

-spec prop_decode_set_cookie_never_crashes() -> triq:property().
prop_decode_set_cookie_never_crashes() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            try nhttp_cookie:decode_set_cookie(Bin) of
                {ok, _} -> true;
                {error, _} -> true
            catch
                _:_ -> false
            end
        end
    ).


-spec set_cookies_equivalent(map(), map()) -> boolean().
set_cookies_equivalent(Original, Decoded) ->
    maps:get(name, Original) =:= maps:get(name, Decoded) andalso
        maps:get(value, Original) =:= maps:get(value, Decoded) andalso
        attr_equal(path, Original, Decoded) andalso
        attr_equal(domain, Original, Decoded) andalso
        bool_attr_equal(secure, Original, Decoded) andalso
        bool_attr_equal(http_only, Original, Decoded).

-spec attr_equal(atom(), map(), map()) -> boolean().
attr_equal(Key, Original, Decoded) ->
    maps:get(Key, Original, undefined) =:= maps:get(Key, Decoded, undefined).

-spec bool_attr_equal(atom(), map(), map()) -> boolean().
bool_attr_equal(Key, Original, Decoded) ->
    coerce_bool(maps:get(Key, Original, false)) =:=
        coerce_bool(maps:get(Key, Decoded, false)).

-spec coerce_bool(boolean()) -> boolean().
coerce_bool(true) -> true;
coerce_bool(false) -> false.


-spec cookie_gen() -> triq_dom:domain().
cookie_gen() ->
    ?LET(
        {Name, Value},
        {cookie_name_gen(), cookie_value_gen()},
        #{name => Name, value => Value}
    ).

-spec set_cookie_gen() -> triq_dom:domain().
set_cookie_gen() ->
    ?LET(
        {Name, Value, Path, Domain, Secure, HttpOnly},
        {
            cookie_name_gen(),
            cookie_value_gen(),
            optional(path_gen()),
            optional(domain_gen()),
            bool(),
            bool()
        },
        maps_from_optionals([
            {name, Name},
            {value, Value},
            {path, Path},
            {domain, Domain},
            {secure, Secure},
            {http_only, HttpOnly}
        ])
    ).

-spec optional(triq_dom:domain()) -> triq_dom:domain().
optional(Gen) ->
    oneof([undefined, Gen]).

-spec maps_from_optionals([{atom(), term()}]) -> map().
maps_from_optionals(Pairs) ->
    lists:foldl(
        fun
            ({_K, undefined}, Acc) -> Acc;
            ({K, V}, Acc) -> Acc#{K => V}
        end,
        #{},
        Pairs
    ).

-spec cookie_name_gen() -> triq_dom:domain().
cookie_name_gen() ->
    ?LET(
        Chars,
        non_empty(list(name_char_gen())),
        list_to_binary(Chars)
    ).

-spec cookie_value_gen() -> triq_dom:domain().
cookie_value_gen() ->
    ?LET(
        Chars,
        list(value_char_gen()),
        list_to_binary(Chars)
    ).

-spec name_char_gen() -> triq_dom:domain().
name_char_gen() ->
    oneof([
        int($a, $z),
        int($A, $Z),
        int($0, $9),
        elements([$_, $-, $.])
    ]).

-spec value_char_gen() -> triq_dom:domain().
value_char_gen() ->
    oneof([
        int($a, $z),
        int($A, $Z),
        int($0, $9),
        elements([$_, $-, $., $/, $:, $+, $=])
    ]).

-spec path_gen() -> triq_dom:domain().
path_gen() ->
    ?LET(
        Segments,
        non_empty(list(path_segment_gen())),
        iolist_to_binary([<<"/">>, lists:join(<<"/">>, Segments)])
    ).

-spec path_segment_gen() -> triq_dom:domain().
path_segment_gen() ->
    ?LET(
        Chars,
        non_empty(list(name_char_gen())),
        list_to_binary(Chars)
    ).

-spec domain_gen() -> triq_dom:domain().
domain_gen() ->
    ?LET(
        Labels,
        non_empty(list(domain_label_gen())),
        iolist_to_binary(lists:join(<<".">>, Labels))
    ).

-spec domain_label_gen() -> triq_dom:domain().
domain_label_gen() ->
    ?LET(
        Chars,
        non_empty(list(domain_char_gen())),
        list_to_binary(Chars)
    ).

-spec domain_char_gen() -> triq_dom:domain().
domain_char_gen() ->
    oneof([
        int($a, $z),
        int($A, $Z),
        int($0, $9),
        elements([$-])
    ]).
