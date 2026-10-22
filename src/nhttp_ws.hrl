%%%-----------------------------------------------------------------------------
%%% WebSocket opcodes that nhttp_ws and nhttp_ws_frame both read
%%% (RFC 6455 Section 5.2).
%%%-----------------------------------------------------------------------------

-define(WS_OP_TEXT, 1).
-define(WS_OP_BINARY, 2).
-define(WS_OP_CLOSE, 8).
-define(WS_OP_PING, 9).
-define(WS_OP_PONG, 10).
