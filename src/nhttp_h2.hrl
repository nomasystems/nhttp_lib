%%%-----------------------------------------------------------------------------
%%% HTTP/2 wire constants that nhttp_h2 and nhttp_h2_frame both read.
%%%
%%% RFC 9113 values only. Library policy stays in nhttp_h2.erl. The preface
%%% is a string so that `<<?H2_PREFACE, _/binary>>` is a pattern and
%%% `<<?H2_PREFACE>>` is the value.
%%%-----------------------------------------------------------------------------

-define(H2_PREFACE, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").
-define(H2_PREFACE_LEN, byte_size(<<?H2_PREFACE>>)).
-define(H2_INVALID_PREFACE, <<"Invalid connection preface (RFC 9113 Section 3.4)">>).
-define(H2_MAX_WINDOW_SIZE, 16#7fffffff).
-define(H2_MIN_MAX_FRAME_SIZE, 16#4000).
-define(H2_MAX_MAX_FRAME_SIZE, 16#ffffff).
-define(H2_INITIAL_MAX_FRAME_SIZE, 16384).
