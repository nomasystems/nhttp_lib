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
""".

-compile(
    {inline, [to_lower/1, is_tchar/1]}
).

%%%-----------------------------------------------------------------------------
%% EXPORTS
%%%-----------------------------------------------------------------------------
-export([
    append/3,
    delete/2,
    filter/2,
    get/2,
    get/3,
    has/2,
    is_tchar/1,
    is_token/1,
    name_eq/2,
    non_tchar_pattern/0,
    set/3,
    to_lower/1
]).

%%%-----------------------------------------------------------------------------
%% COMPILED PATTERNS
%%%-----------------------------------------------------------------------------
-define(PT_NON_TCHAR, {?MODULE, non_tchar_pattern}).

-on_load(init_patterns/0).

-spec init_patterns() -> ok.
init_patterns() ->
    ok = persistent_term:put(?PT_NON_TCHAR, binary:compile_pattern(non_tchar_bytes())),
    ok.

-spec non_tchar_bytes() -> [binary(), ...].
non_tchar_bytes() ->
    [<<C>> || C <- lists:seq(0, 255), not is_tchar(C)].

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
    Lower = to_lower(Name),
    do_delete(Lower, Headers, []).

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
True iff two field names name the same field. Field names compare
case-insensitively (RFC 9110 §5.1), so `<<"Content-Length">>` and
`<<"content-length">>` name the same field.

A caller that asks about a fixed set of names walks the list once and
compares each stored name with this function, which keeps `to_lower/1`
off the path.
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

A caller that scans many tokens in one pass reads the pattern once and
passes it to `binary:match/2` for each one, which keeps the
`persistent_term` lookup off the per-token path.
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
    do_delete(Lower, Headers, []) ++ [{Lower, Value}].

-doc """
Lowercase an ASCII binary using HTTP header semantics. Common header
names hit a binary-pattern fast path; everything else falls through to
a comprehension. RFC 9110 §5.1: field names are ASCII, so non-ASCII
upper-half bytes pass through unchanged.
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

%%%-----------------------------------------------------------------------------
%%%-----------------------------------------------------------------------------
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec do_delete(binary(), nhttp_lib:headers(), nhttp_lib:headers()) -> nhttp_lib:headers().
do_delete(Name, [{Name, _} | Rest], Acc) ->
    do_delete(Name, Rest, Acc);
do_delete(Name, [{Stored, _} = Pair | Rest], Acc) when byte_size(Stored) =:= byte_size(Name) ->
    case name_eq(Stored, Name, byte_size(Name) - 1) of
        true -> do_delete(Name, Rest, Acc);
        false -> do_delete(Name, Rest, [Pair | Acc])
    end;
do_delete(Name, [Pair | Rest], Acc) ->
    do_delete(Name, Rest, [Pair | Acc]);
do_delete(_, [], Acc) ->
    lists:reverse(Acc).

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
-spec to_lower_byte(byte()) -> byte().
to_lower_byte(C) when C >= $A, C =< $Z -> C + 32;
to_lower_byte(C) -> C.
