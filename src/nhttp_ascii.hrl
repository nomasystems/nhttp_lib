-define(NHTTP_TCHAR_LIST,
    "!#$%&'*+-.^_`|~"
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
).

-define(NHTTP_NON_TCHAR_BYTES, [
    <<C>>
 || C <- lists:seq(16#00, 16#FF), not lists:member(C, ?NHTTP_TCHAR_LIST)
]).

-define(NHTTP_FIELD_VALUE_BAD_BYTES,
    [<<C>> || C <- lists:seq(16#00, 16#1F), C =/= $\t] ++ [<<16#7F>>]
).
