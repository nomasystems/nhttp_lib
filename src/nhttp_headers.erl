-module(nhttp_headers).

-moduledoc """
Protocol-agnostic header utilities.

Headers carried by `t:nhttp_lib:headers/0` are an ordered list of
`{Name, Value}` binary pairs. The codec layers normalise names to
lowercase at parse time. Application code should construct headers
with lowercase names; the lookup functions in this module accept any
casing and normalise internally so mixed-case calls are still safe.

Key invariants:

- Header names compare case-insensitively (RFC 9110 §5.1). All
  lookup functions in this module call `to_lower/1` on the input
  name before matching.
- Multi-valued headers retain insertion order. `get/2,3` returns the
  first match; `delete/2` removes every occurrence; `append/3`
  appends without removing existing entries.
""".

-compile(
    {inline, [to_lower/1]}
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
    set/3,
    to_lower/1
]).

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
%% INTERNAL
%%%-----------------------------------------------------------------------------
-spec do_delete(binary(), nhttp_lib:headers(), nhttp_lib:headers()) -> nhttp_lib:headers().
do_delete(Name, [{Name, _} | Rest], Acc) -> do_delete(Name, Rest, Acc);
do_delete(Name, [Pair | Rest], Acc) -> do_delete(Name, Rest, [Pair | Acc]);
do_delete(_, [], Acc) -> lists:reverse(Acc).

-spec do_get(binary(), nhttp_lib:headers(), Default) -> binary() | Default.
do_get(Name, [{Name, Value} | _], _Default) -> Value;
do_get(Name, [_ | Rest], Default) -> do_get(Name, Rest, Default);
do_get(_, [], Default) -> Default.

-spec do_has(binary(), nhttp_lib:headers()) -> boolean().
do_has(Name, [{Name, _} | _]) -> true;
do_has(Name, [_ | Rest]) -> do_has(Name, Rest);
do_has(_, []) -> false.

-compile({inline, [to_lower_byte/1]}).
-spec to_lower_byte(byte()) -> byte().
to_lower_byte(C) when C >= $A, C =< $Z -> C + 32;
to_lower_byte(C) -> C.
