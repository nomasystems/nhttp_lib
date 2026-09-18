-module(nhttp_headers).

-moduledoc """
Protocol-agnostic header utilities.

Headers carried by `t:nhttp_lib:headers/0` are an ordered list of
`{Name, Value}` binary pairs. The codec layers write names in lowercase
at parse time. This module stores the name that the caller gives and
never rewrites it. `append/3` and `set/3` store the lowercase form of
the name that they add, and leave every other entry alone.

Key invariants:

- Header names compare case-insensitively (RFC 9110 §5.1). A lookup
  matches a stored name in any case, so `get/2` with
  `<<"content-length">>` finds a stored `Content-Length`.
- Multi-valued headers keep insertion order. `get/2,3` returns the
  first match. `delete/2` removes every occurrence. `append/3`
  appends and keeps existing entries.

The module also holds one definition of the field validity rule that
RFC 9113 §8.2.1 and RFC 9114 §4.1.2 state for a receiver:
`validate_field_name/1`, `validate_field_value/1` and the wire
lowercasing of `lower_field_name/1`.
""".

-compile(
    {inline, [to_lower/1, is_tchar/1, lower_field_name/1, validate_field_name/1]}
).

-include("nhttp_ascii.hrl").

-on_load(init_patterns/0).

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    append/3,
    delete/2,
    field_value_bad_pattern/0,
    filter/2,
    get/2,
    get/3,
    has/2,
    has_forbidden_value_octet/1,
    is_tchar/1,
    is_token/1,
    lower_field_name/1,
    name_eq/2,
    non_tchar_pattern/0,
    set/3,
    to_lower/1,
    validate_field_name/1,
    validate_field_value/1
]).

-export_type([field_name_error/0, field_value_error/0]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-type field_name_error() ::
    empty_field_name | uppercase_field_name | invalid_field_name_char.

-type field_value_error() ::
    invalid_field_value_char | field_value_edge_whitespace.

-define(VALUE_WORD_SCAN_MIN, 112).

-define(W_LOW7, 16#7F7F7F7F7F7F7F).
-define(W_TAB7, 16#09090909090909).
-define(W_SUB32, 16#60606060606060).
-define(W_ONE7, 16#01010101010101).
-define(W_HIGH7, 16#80808080808080).

%%%-----------------------------------------------------------------------------
%% COMPILED PATTERNS
%%%-----------------------------------------------------------------------------
-define(PT_NON_TCHAR, {?MODULE, non_tchar_pattern}).
-define(PT_FIELD_VALUE_BAD, {?MODULE, field_value_bad_pattern}).
-define(PT_UPPER_ALPHA, {?MODULE, upper_alpha_pattern}).

-spec field_value_bad_bytes() -> [binary(), ...].
field_value_bad_bytes() ->
    ?NHTTP_FIELD_VALUE_BAD_BYTES.

-spec init_patterns() -> ok.
init_patterns() ->
    ok = persistent_term:put(?PT_NON_TCHAR, binary:compile_pattern(non_tchar_bytes())),
    ok = persistent_term:put(
        ?PT_FIELD_VALUE_BAD, binary:compile_pattern(field_value_bad_bytes())
    ),
    ok = persistent_term:put(
        ?PT_UPPER_ALPHA, binary:compile_pattern(upper_alpha_bytes())
    ),
    ok.

-spec non_tchar_bytes() -> [binary(), ...].
non_tchar_bytes() ->
    ?NHTTP_NON_TCHAR_BYTES.

-spec upper_alpha_bytes() -> [binary(), ...].
upper_alpha_bytes() ->
    [<<C>> || C <- lists:seq($A, $Z)].

%%%-----------------------------------------------------------------------------
%% PUBLIC API
%%%-----------------------------------------------------------------------------
-doc """
Append `{Name, Value}` to the end of the headers list, preserving any
existing occurrences. Useful for multi-valued headers such as
`set-cookie`. The name is stored lowercase.
""".
-spec append(binary(), binary(), nhttp_lib:headers()) -> nhttp_lib:headers().
append(Name, Value, Headers) ->
    Headers ++ [{to_lower(Name), Value}].

-doc "Remove every header whose name matches `Name`. Case-insensitive.".
-spec delete(binary(), nhttp_lib:headers()) -> nhttp_lib:headers().
delete(Name, Headers) ->
    lists:reverse(do_delete_rev(to_lower(Name), Headers, [])).

-spec do_delete_rev(binary(), nhttp_lib:headers(), nhttp_lib:headers()) -> nhttp_lib:headers().
do_delete_rev(Name, [{Name, _} | Rest], Acc) ->
    do_delete_rev(Name, Rest, Acc);
do_delete_rev(Name, [{Stored, _} = Pair | Rest], Acc) when byte_size(Stored) =:= byte_size(Name) ->
    case name_eq(Stored, Name, byte_size(Name) - 1) of
        true -> do_delete_rev(Name, Rest, Acc);
        false -> do_delete_rev(Name, Rest, [Pair | Acc])
    end;
do_delete_rev(Name, [Pair | Rest], Acc) ->
    do_delete_rev(Name, Rest, [Pair | Acc]);
do_delete_rev(_, [], Acc) ->
    Acc.

-spec do_get(binary(), nhttp_lib:headers(), Default) -> binary() | Default.
do_get(Name, [{Name, Value} | _], _Default) ->
    Value;
do_get(Name, [{Stored, Value} | Rest], Default) when byte_size(Stored) =:= byte_size(Name) ->
    case name_eq(Stored, Name, byte_size(Name) - 1) of
        true -> Value;
        false -> do_get(Name, Rest, Default)
    end;
do_get(Name, [_ | Rest], Default) ->
    do_get(Name, Rest, Default);
do_get(_, [], Default) ->
    Default.

-spec do_has(binary(), nhttp_lib:headers()) -> boolean().
do_has(Name, [{Name, _} | _]) ->
    true;
do_has(Name, [{Stored, _} | Rest]) when byte_size(Stored) =:= byte_size(Name) ->
    name_eq(Stored, Name, byte_size(Name) - 1) orelse do_has(Name, Rest);
do_has(Name, [_ | Rest]) ->
    do_has(Name, Rest);
do_has(_, []) ->
    false.

-doc """
The compiled pattern that matches every octet that RFC 9110 §5.5 forbids
in a field value: `0x00-0x1F` except `0x09`, and `0x7F`.
A caller that scans many field values reads the pattern once and passes
it to `binary:match/2` for each one.
""".
-spec field_value_bad_pattern() -> binary:cp().
field_value_bad_pattern() ->
    persistent_term:get(?PT_FIELD_VALUE_BAD).

-doc """
Keep only the headers for which `Pred(Name, Value)` returns `true`.
Order is preserved.
""".
-spec filter(fun((binary(), binary()) -> boolean()), nhttp_lib:headers()) ->
    nhttp_lib:headers().
filter(Pred, Headers) ->
    [{K, V} || {K, V} <- Headers, Pred(K, V)].

-doc "Get the first value for `Name`, or `undefined` if absent. Case-insensitive.".
-spec get(binary(), nhttp_lib:headers()) -> binary() | undefined.
get(Name, Headers) ->
    get(Name, Headers, undefined).

-doc "Get the first value for `Name`, or `Default` if absent. Case-insensitive.".
-spec get(binary(), nhttp_lib:headers(), Default) -> binary() | Default.
get(Name, Headers, Default) ->
    Lower = to_lower(Name),
    do_get(Lower, Headers, Default).

-doc "True iff a header with the given name exists. Case-insensitive.".
-spec has(binary(), nhttp_lib:headers()) -> boolean().
has(Name, Headers) ->
    Lower = to_lower(Name),
    do_has(Lower, Headers).

-doc """
True iff `Value` holds an octet that RFC 9110 §5.5 forbids in a field
value: `0x00-0x1F` except `0x09`, or `0x7F`.
The scan reads seven octets at a time and charges one reduction per call,
so it holds a constant cost per octet at every length.
`field_value_bad_pattern/0` with `binary:match/2` is cheaper below about a
hundred octets, because `binary:match/2` charges one reduction per ten
octets up to its trap. A caller that scans values of any length picks
between the two on `byte_size/1`.
""".
-spec has_forbidden_value_octet(binary()) -> boolean().
has_forbidden_value_octet(
    <<A:56, B:56, C:56, D:56, E:56, F:56, G:56, H:56, Rest/binary>>
) ->
    case
        forbidden_in_word(A) orelse forbidden_in_word(B) orelse
            forbidden_in_word(C) orelse forbidden_in_word(D) orelse
            forbidden_in_word(E) orelse forbidden_in_word(F) orelse
            forbidden_in_word(G) orelse forbidden_in_word(H)
    of
        true -> true;
        false -> has_forbidden_value_octet(Rest)
    end;
has_forbidden_value_octet(<<A:56, Rest/binary>>) ->
    case forbidden_in_word(A) of
        true -> true;
        false -> has_forbidden_value_octet(Rest)
    end;
has_forbidden_value_octet(<<C, Rest/binary>>) when C > 16#1F, C =/= 16#7F ->
    has_forbidden_value_octet(Rest);
has_forbidden_value_octet(<<16#09, Rest/binary>>) ->
    has_forbidden_value_octet(Rest);
has_forbidden_value_octet(<<_, _/binary>>) ->
    true;
has_forbidden_value_octet(<<>>) ->
    false.

-doc """
True iff `C` is a `tchar`, the character set that RFC 9110 §5.6.2 allows
in a `token`.
RFC 6265 §4.1.1 defines `cookie-name` in terms of the RFC 2616 §2.2
`token`, which admits the same octets, so cookie names are checked with
this predicate too.
""".
-spec is_tchar(byte()) -> boolean().
is_tchar(C) when C >= $a, C =< $z -> true;
is_tchar(C) when C >= $A, C =< $Z -> true;
is_tchar(C) when C >= $0, C =< $9 -> true;
is_tchar($!) -> true;
is_tchar($#) -> true;
is_tchar($$) -> true;
is_tchar($%) -> true;
is_tchar($&) -> true;
is_tchar($') -> true;
is_tchar($*) -> true;
is_tchar($+) -> true;
is_tchar($-) -> true;
is_tchar($.) -> true;
is_tchar($^) -> true;
is_tchar($_) -> true;
is_tchar($`) -> true;
is_tchar($|) -> true;
is_tchar($~) -> true;
is_tchar(_) -> false.

-doc """
True iff `Bin` is a `token` per RFC 9110 §5.6.2: `token = 1*tchar`. An
empty binary is not a token.
""".
-spec is_token(binary()) -> boolean().
is_token(<<>>) ->
    false;
is_token(Bin) ->
    binary:match(Bin, persistent_term:get(?PT_NON_TCHAR)) =:= nomatch.

-doc """
Lowercase a field name for the wire, without a copy when the name already
holds no uppercase octet.
RFC 9114 §4.2 requires that characters in field names are converted to
lowercase before their encoding, and RFC 9113 §8.2.1 forbids `0x41-0x5A`
in a field name on the wire. The scan runs before the copy, so a name
that is already lowercase comes back as the very binary that the caller
passed in.
Non-ASCII upper-half octets pass through unchanged, as they do in
`to_lower/1`. This function does not validate the name. Pair it with
`validate_field_name/1` when the name arrives from a peer.
""".
-spec lower_field_name(binary()) -> binary().
lower_field_name(Name) ->
    case has_upper_octet(Name) of
        false -> Name;
        true -> <<<<(to_lower_byte(C))>> || <<C>> <= Name>>
    end.

-doc """
True iff two field names name the same field. Field names compare
case-insensitively (RFC 9110 §5.1), so `<<"Content-Length">>` and
`<<"content-length">>` name the same field.
A caller that asks about a fixed set of names walks the list once and
compares each stored name with this function.
""".
-spec name_eq(binary(), binary()) -> boolean().
name_eq(Name, Name) ->
    true;
name_eq(Name, Other) when byte_size(Name) =:= byte_size(Other) ->
    name_eq(Name, Other, byte_size(Name) - 1);
name_eq(_Name, _Other) ->
    false.

-doc """
The compiled pattern that matches every octet that is not a `tchar`.
A caller that scans many tokens reads the pattern once and passes it to
`binary:match/2` for each one.
""".
-spec non_tchar_pattern() -> binary:cp().
non_tchar_pattern() ->
    persistent_term:get(?PT_NON_TCHAR).

-doc """
Replace every occurrence of `Name` with a single `{Name, Value}` entry.
The name is stored lowercase. The replacement is appended to the end of
the headers list when no prior occurrence exists.
""".
-spec set(binary(), binary(), nhttp_lib:headers()) -> nhttp_lib:headers().
set(Name, Value, Headers) ->
    Lower = to_lower(Name),
    lists:reverse(do_delete_rev(Lower, Headers, []), [{Lower, Value}]).

-doc """
Lowercase an ASCII binary using HTTP header semantics. RFC 9110 §5.1:
field names are ASCII, so non-ASCII upper-half bytes pass through
unchanged.
""".
-spec to_lower(binary()) -> binary().
to_lower(<<"host">>) -> <<"host">>;
to_lower(<<"connection">>) -> <<"connection">>;
to_lower(<<"content-type">>) -> <<"content-type">>;
to_lower(<<"content-length">>) -> <<"content-length">>;
to_lower(<<"transfer-encoding">>) -> <<"transfer-encoding">>;
to_lower(<<"accept">>) -> <<"accept">>;
to_lower(<<"accept-encoding">>) -> <<"accept-encoding">>;
to_lower(<<"accept-language">>) -> <<"accept-language">>;
to_lower(<<"user-agent">>) -> <<"user-agent">>;
to_lower(<<"cookie">>) -> <<"cookie">>;
to_lower(<<"authorization">>) -> <<"authorization">>;
to_lower(<<"cache-control">>) -> <<"cache-control">>;
to_lower(<<"if-none-match">>) -> <<"if-none-match">>;
to_lower(<<"if-modified-since">>) -> <<"if-modified-since">>;
to_lower(<<"origin">>) -> <<"origin">>;
to_lower(<<"referer">>) -> <<"referer">>;
to_lower(<<"content-encoding">>) -> <<"content-encoding">>;
to_lower(<<"set-cookie">>) -> <<"set-cookie">>;
to_lower(<<"keep-alive">>) -> <<"keep-alive">>;
to_lower(<<"location">>) -> <<"location">>;
to_lower(<<"etag">>) -> <<"etag">>;
to_lower(<<"last-modified">>) -> <<"last-modified">>;
to_lower(<<"expires">>) -> <<"expires">>;
to_lower(<<"date">>) -> <<"date">>;
to_lower(<<"server">>) -> <<"server">>;
to_lower(<<"vary">>) -> <<"vary">>;
to_lower(<<"access-control-allow-origin">>) -> <<"access-control-allow-origin">>;
to_lower(<<"access-control-allow-methods">>) -> <<"access-control-allow-methods">>;
to_lower(<<"access-control-allow-headers">>) -> <<"access-control-allow-headers">>;
to_lower(<<"close">>) -> <<"close">>;
to_lower(<<"upgrade">>) -> <<"upgrade">>;
to_lower(<<"Host">>) -> <<"host">>;
to_lower(<<"Connection">>) -> <<"connection">>;
to_lower(<<"Content-Type">>) -> <<"content-type">>;
to_lower(<<"Content-Length">>) -> <<"content-length">>;
to_lower(<<"Transfer-Encoding">>) -> <<"transfer-encoding">>;
to_lower(<<"Accept">>) -> <<"accept">>;
to_lower(<<"Accept-Encoding">>) -> <<"accept-encoding">>;
to_lower(<<"Accept-Language">>) -> <<"accept-language">>;
to_lower(<<"User-Agent">>) -> <<"user-agent">>;
to_lower(<<"Cookie">>) -> <<"cookie">>;
to_lower(<<"Authorization">>) -> <<"authorization">>;
to_lower(<<"Cache-Control">>) -> <<"cache-control">>;
to_lower(<<"If-None-Match">>) -> <<"if-none-match">>;
to_lower(<<"If-Modified-Since">>) -> <<"if-modified-since">>;
to_lower(<<"Origin">>) -> <<"origin">>;
to_lower(<<"Referer">>) -> <<"referer">>;
to_lower(<<"Content-Encoding">>) -> <<"content-encoding">>;
to_lower(<<"Set-Cookie">>) -> <<"set-cookie">>;
to_lower(<<"Keep-Alive">>) -> <<"keep-alive">>;
to_lower(<<"Location">>) -> <<"location">>;
to_lower(<<"ETag">>) -> <<"etag">>;
to_lower(<<"Last-Modified">>) -> <<"last-modified">>;
to_lower(<<"Expires">>) -> <<"expires">>;
to_lower(<<"Date">>) -> <<"date">>;
to_lower(<<"Server">>) -> <<"server">>;
to_lower(<<"Vary">>) -> <<"vary">>;
to_lower(<<"Access-Control-Allow-Origin">>) -> <<"access-control-allow-origin">>;
to_lower(<<"Access-Control-Allow-Methods">>) -> <<"access-control-allow-methods">>;
to_lower(<<"Access-Control-Allow-Headers">>) -> <<"access-control-allow-headers">>;
to_lower(<<"Close">>) -> <<"close">>;
to_lower(<<"Upgrade">>) -> <<"upgrade">>;
to_lower(<<>>) -> <<>>;
to_lower(Bin) -> <<<<(to_lower_byte(C))>> || <<C>> <= Bin>>.

-doc """
Validate a field name against the minimal rule that RFC 9113 §8.2.1
states as a MUST, and that RFC 9114 §4.1.2 repeats for HTTP/3.
A field name must not hold an octet in `0x00-0x20`, `0x41-0x5A` or
`0x7F-0xFF`. A field name must not hold a colon, except the single
leading colon of a pseudo-header field (RFC 9113 §8.3). An empty name,
and a name that is a bare colon and therefore names no pseudo-header
field, are refused as `empty_field_name`.
`uppercase_field_name` names the case that RFC 9114 §4.1.2 lists apart
from the other invalid characters. It is reported when the first
offending octet is in `0x41-0x5A`.
This is the minimal rule, not the `token` rule of RFC 9110 §5.6.2, which
RFC 9113 §8.2.1 states as a SHOULD. Use `is_token/1` for the stricter
test.
""".
-spec validate_field_name(binary()) -> ok | {error, field_name_error()}.
validate_field_name(<<>>) -> {error, empty_field_name};
validate_field_name(<<$:>>) -> {error, empty_field_name};
validate_field_name(<<$:, Rest/binary>>) -> name_octets(Rest);
validate_field_name(Name) -> name_octets(Name).

-doc """
Validate a field value against RFC 9110 §5.5 and the edge whitespace rule
that RFC 9113 §8.2.1 states as a MUST.
The refused octet set is `0x00-0x1F` except `0x09`, plus `0x7F`. That set
is a superset of the NUL, LF and CR that RFC 9113 §8.2.1 names, because
RFC 9113 §8.2.1 asks for validation against RFC 9110 §5.5. A value that
starts or ends with SP or HTAB is refused as `field_value_edge_whitespace`,
which `field-content` of RFC 9110 §5.5 forbids and RFC 9113 §8.2.1 states
again. An empty value is accepted, because `field-value` of RFC 9110 §5.5
is `*field-content`.
""".
-spec validate_field_value(binary()) -> ok | {error, field_value_error()}.
validate_field_value(<<>>) ->
    ok;
validate_field_value(Value) ->
    maybe
        ok ?= value_edges(Value),
        value_octets(Value)
    end.

-compile({inline, [name_eq/3]}).
-spec name_eq(binary(), binary(), integer()) -> boolean().
name_eq(_Stored, _Other, -1) ->
    true;
name_eq(Stored, Other, I) ->
    byte_name_eq(binary:at(Stored, I), binary:at(Other, I)) andalso
        name_eq(Stored, Other, I - 1).

-compile({inline, [byte_name_eq/2]}).
-spec byte_name_eq(byte(), byte()) -> boolean().
byte_name_eq(C, C) -> true;
byte_name_eq(C, D) -> to_lower_byte(C) =:= to_lower_byte(D).

-compile({inline, [to_lower_byte/1]}).
-spec has_upper_octet(binary()) -> boolean().
has_upper_octet(Name) ->
    binary:match(Name, persistent_term:get(?PT_UPPER_ALPHA)) =/= nomatch.

-spec name_octets(binary()) -> ok | {error, field_name_error()}.
name_octets(<<C, Rest/binary>>) when
    C >= 16#21, C =< 16#39;
    C >= 16#3B, C =< 16#40;
    C >= 16#5B, C =< 16#7E
->
    name_octets(Rest);
name_octets(<<C, _/binary>>) when C >= $A, C =< $Z ->
    {error, uppercase_field_name};
name_octets(<<_, _/binary>>) ->
    {error, invalid_field_name_char};
name_octets(<<>>) ->
    ok.

-spec to_lower_byte(byte()) -> byte().
to_lower_byte(C) when C >= $A, C =< $Z -> C + 32;
to_lower_byte(C) -> C.

-compile({inline, [value_edges/1]}).
-spec value_edges(binary()) -> ok | {error, field_value_error()}.
value_edges(<<>>) ->
    ok;
value_edges(Value) ->
    Skip = byte_size(Value) - 1,
    case Value of
        <<C, _/binary>> when C =:= $\s; C =:= $\t ->
            {error, field_value_edge_whitespace};
        <<_:Skip/binary, C>> when C =:= $\s; C =:= $\t ->
            {error, field_value_edge_whitespace};
        _ ->
            ok
    end.

-spec value_octets(binary()) -> ok | {error, field_value_error()}.
value_octets(Value) when byte_size(Value) < ?VALUE_WORD_SCAN_MIN ->
    case binary:match(Value, persistent_term:get(?PT_FIELD_VALUE_BAD)) of
        nomatch -> ok;
        _ -> {error, invalid_field_value_char}
    end;
value_octets(Value) ->
    case has_forbidden_value_octet(Value) of
        false -> ok;
        true -> {error, invalid_field_value_char}
    end.

-compile({inline, [forbidden_in_word/1]}).
-spec forbidden_in_word(non_neg_integer()) -> boolean().
forbidden_in_word(W) ->
    U = W band ?W_LOW7,
    V = U bxor ?W_TAB7,
    Low = (V + ?W_LOW7) band (bnot (V + ?W_SUB32)),
    (((Low bor (U + ?W_ONE7)) band (bnot W)) band ?W_HIGH7) =/= 0.
