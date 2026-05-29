%%%-----------------------------------------------------------------------------
%%% Shared HTTP/2 + HTTP/3 message-level macros.
%%%
%%% The connection-specific headers set is byte-identical across
%%% RFC 9113 (HTTP/2, §8.2.2) and RFC 9114 (HTTP/3, §4.2). Both
%%% protocols' response validators consult it directly; keep it here
%%% so the two state machines cannot drift.
%%%-----------------------------------------------------------------------------

-define(NHTTP_MSG_CONNECTION_HEADERS_SET, #{
    <<"connection">> => true,
    <<"keep-alive">> => true,
    <<"proxy-connection">> => true,
    <<"transfer-encoding">> => true,
    <<"upgrade">> => true
}).
