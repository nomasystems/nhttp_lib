%%%-----------------------------------------------------------------------------
%%% QPACK constants that the dynamic table, the encoder and the decoder share.
%%%
%%% An entry of the dynamic table counts 32 octets on top of its name and
%%% value (RFC 9204 Section 3.2.1).
%%%-----------------------------------------------------------------------------

-define(QPACK_ENTRY_OVERHEAD, 32).
