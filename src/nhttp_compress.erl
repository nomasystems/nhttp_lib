-module(nhttp_compress).

-moduledoc """
HTTP compression utilities for nhttp.

Supports gzip and deflate content encoding for request/response bodies.
Compression is configurable and can be disabled.

Configuration options:
- `compression` => boolean() (default: true)
- `compression_level` => 1..9 (default: 6)
- `compression_threshold` => non_neg_integer() (default: 1024)
- `compress_mime_types` => [binary()] (default: text/*, application/json, etc.)
""".

%%%-----------------------------------------------------------------------------
%% COMPRESSION
%%%-----------------------------------------------------------------------------
-export([
    compress/3,
    decompress/2,
    decompress/3
]).

%%%-----------------------------------------------------------------------------
%% NEGOTIATION
%%%-----------------------------------------------------------------------------
-export([
    default_mime_types/0,
    encoding_header/1,
    negotiate_encoding/1,
    should_compress/3,
    should_compress/4
]).

%%%-----------------------------------------------------------------------------
%% TYPES
%%%-----------------------------------------------------------------------------
-export_type([compress_opts/0, encoding/0, zlib_error/0]).

-type encoding() :: gzip | deflate | identity.

-type compress_opts() :: #{
    compression => boolean(),
    compression_level => 1..9,
    compression_threshold => non_neg_integer(),
    compress_mime_types => [binary()]
}.

-type zlib_error() ::
    data_error
    | buf_error
    | stream_error
    | badarg
    | enomem
    | max_output_exceeded
    | {unknown, term()}.

%%%-----------------------------------------------------------------------------
%% MACROS
%%%-----------------------------------------------------------------------------
-define(DEFAULT_COMPRESSION_THRESHOLD, 1024).
-define(ZLIB_GZIP_WINDOW_BITS, 16 + 15).
-define(DEFAULT_MAX_DECOMPRESSED_SIZE, 16 * 1024 * 1024).

%%%-----------------------------------------------------------------------------
%% COMPRESSION
%%%-----------------------------------------------------------------------------
-doc "Compress data using the specified encoding. Returns `{ok, CompressedData}` or `{error, Reason}`.".
-spec compress(Data :: iodata(), Encoding :: gzip | deflate, Level :: 1..9) ->
    {ok, binary()} | {error, zlib_error()}.
compress(Data, gzip, Level) ->
    compress_gzip(Data, Level);
compress(Data, deflate, Level) ->
    compress_deflate(Data, Level);
compress(Data, identity, _Level) ->
    {ok, iolist_to_binary(Data)}.

-doc """
Decompress data using the specified encoding. Caps inflated output at
`?DEFAULT_MAX_DECOMPRESSED_SIZE` (16 MiB) to defend against decompression
bombs. Use `decompress/3` to override.
""".
-spec decompress(Data :: binary(), Encoding :: encoding()) ->
    {ok, binary()} | {error, zlib_error()}.
decompress(Data, Encoding) ->
    decompress(Data, Encoding, ?DEFAULT_MAX_DECOMPRESSED_SIZE).

-doc """
Decompress data with an explicit cap on the inflated output. Returns
`{error, max_output_exceeded}` if decoding would produce more than `Max`
bytes; pass `infinity` to disable the cap.
""".
-spec decompress(Data :: binary(), Encoding :: encoding(), Max) ->
    {ok, binary()} | {error, zlib_error()}
when
    Max :: pos_integer() | infinity.
decompress(Data, gzip, Max) ->
    decompress_gzip(Data, Max);
decompress(Data, deflate, Max) ->
    decompress_deflate(Data, Max);
decompress(Data, identity, Max) ->
    case Max =:= infinity orelse byte_size(Data) =< Max of
        true -> {ok, Data};
        false -> {error, max_output_exceeded}
    end.

%%%-----------------------------------------------------------------------------
%% NEGOTIATION
%%%-----------------------------------------------------------------------------
-doc "Return default MIME types eligible for compression.".
-spec default_mime_types() -> [binary()].
default_mime_types() ->
    [
        <<"text/html">>,
        <<"text/plain">>,
        <<"text/css">>,
        <<"text/javascript">>,
        <<"text/xml">>,
        <<"application/json">>,
        <<"application/javascript">>,
        <<"application/xml">>,
        <<"application/xhtml+xml">>,
        <<"image/svg+xml">>
    ].

-doc "Convert encoding atom to header value.".
-spec encoding_header(encoding()) -> binary().
encoding_header(gzip) -> <<"gzip">>;
encoding_header(deflate) -> <<"deflate">>;
encoding_header(identity) -> <<"identity">>.

-doc "Negotiate encoding based on Accept-Encoding header. Returns the best encoding the client accepts that we support.".
-spec negotiate_encoding(Headers :: [{binary(), binary()}]) -> encoding().
negotiate_encoding(Headers) ->
    case nhttp_headers:get(<<"accept-encoding">>, Headers) of
        undefined ->
            identity;
        AcceptEncoding ->
            Encodings = parse_accept_encoding(AcceptEncoding),
            select_best_encoding(Encodings)
    end.

-doc """
Check if response should be compressed using the default threshold
(`?DEFAULT_COMPRESSION_THRESHOLD`). Equivalent to
`should_compress(ContentType, Size, MimeTypes, ?DEFAULT_COMPRESSION_THRESHOLD)`.
""".
-spec should_compress(
    ContentType :: binary() | undefined,
    Size :: non_neg_integer(),
    MimeTypes :: [binary()]
) -> boolean().
should_compress(ContentType, Size, MimeTypes) ->
    should_compress(ContentType, Size, MimeTypes, ?DEFAULT_COMPRESSION_THRESHOLD).

-doc "Check if response should be compressed. Returns true when body size meets the threshold and Content-Type matches the compressible MIME types.".
-spec should_compress(
    ContentType :: binary() | undefined,
    Size :: non_neg_integer(),
    MimeTypes :: [binary()],
    Threshold :: non_neg_integer()
) -> boolean().
should_compress(undefined, _Size, _MimeTypes, _Threshold) ->
    false;
should_compress(_ContentType, Size, _MimeTypes, Threshold) when Size < Threshold ->
    false;
should_compress(ContentType, _Size, MimeTypes, _Threshold) ->
    is_compressible_type(ContentType, MimeTypes).

%%%-----------------------------------------------------------------------------
%% INTERNAL FUNCTIONS
%%%-----------------------------------------------------------------------------
-spec check_inflate_size(non_neg_integer(), iolist(), pos_integer() | infinity) ->
    ok | {error, max_output_exceeded}.
check_inflate_size(_Total, _Out, infinity) ->
    ok;
check_inflate_size(Total, Out, Max) ->
    case Total + iolist_size(Out) > Max of
        true -> {error, max_output_exceeded};
        false -> ok
    end.

-spec compress_deflate(iodata(), 1..9) -> {ok, binary()} | {error, zlib_error()}.
compress_deflate(Data, Level) ->
    with_zlib_stream(fun(Z) -> do_compress_deflate(Z, Data, Level) end).

-spec compress_gzip(iodata(), 1..9) -> {ok, binary()} | {error, zlib_error()}.
compress_gzip(Data, Level) ->
    with_zlib_stream(fun(Z) -> do_compress_gzip(Z, Data, Level) end).

-spec decompress_deflate(binary(), pos_integer() | infinity) ->
    {ok, binary()} | {error, zlib_error()}.
decompress_deflate(Data, Max) ->
    with_zlib_stream(fun(Z) -> do_decompress_deflate(Z, Data, Max) end).

-spec decompress_gzip(binary(), pos_integer() | infinity) ->
    {ok, binary()} | {error, zlib_error()}.
decompress_gzip(Data, Max) ->
    with_zlib_stream(fun(Z) -> do_decompress_gzip(Z, Data, Max) end).

-spec do_compress_deflate(zlib:zstream(), iodata(), 1..9) ->
    {ok, binary()} | {error, zlib_error()}.
do_compress_deflate(Z, Data, Level) ->
    maybe
        ok ?= zlib_deflate_init(Z, Level),
        {ok, Compressed} ?= zlib_deflate(Z, Data),
        ok ?= zlib_deflate_end(Z),
        {ok, iolist_to_binary(Compressed)}
    end.

-spec do_compress_gzip(zlib:zstream(), iodata(), 1..9) ->
    {ok, binary()} | {error, zlib_error()}.
do_compress_gzip(Z, Data, Level) ->
    maybe
        ok ?= zlib_deflate_init_gzip(Z, Level),
        {ok, Compressed} ?= zlib_deflate(Z, Data),
        ok ?= zlib_deflate_end(Z),
        {ok, iolist_to_binary(Compressed)}
    end.

-spec do_decompress_deflate(zlib:zstream(), binary(), pos_integer() | infinity) ->
    {ok, binary()} | {error, zlib_error()}.
do_decompress_deflate(Z, Data, Max) ->
    maybe
        ok ?= zlib_inflate_init(Z),
        {ok, Decompressed} ?= zlib_safe_inflate(Z, Data, Max),
        ok ?= zlib_inflate_end(Z),
        {ok, iolist_to_binary(Decompressed)}
    end.

-spec do_decompress_gzip(zlib:zstream(), binary(), pos_integer() | infinity) ->
    {ok, binary()} | {error, zlib_error()}.
do_decompress_gzip(Z, Data, Max) ->
    maybe
        ok ?= zlib_inflate_init_gzip(Z),
        {ok, Decompressed} ?= zlib_safe_inflate(Z, Data, Max),
        ok ?= zlib_inflate_end(Z),
        {ok, iolist_to_binary(Decompressed)}
    end.

-spec encoding_to_atom(binary()) -> encoding().
encoding_to_atom(<<"gzip">>) -> gzip;
encoding_to_atom(<<"x-gzip">>) -> gzip;
encoding_to_atom(<<"deflate">>) -> deflate;
encoding_to_atom(<<"*">>) -> gzip;
encoding_to_atom(_) -> identity.

-spec extract_base_mime(binary()) -> binary().
extract_base_mime(ContentType) ->
    case binary:split(ContentType, <<";">>) of
        [BaseMime | _] -> string:trim(BaseMime);
        [] -> ContentType
    end.

-spec is_compressible_type(binary(), [binary()]) -> boolean().
is_compressible_type(ContentType, MimeTypes) ->
    Lower = nhttp_headers:to_lower(extract_base_mime(ContentType)),
    lists:any(fun(Pattern) -> mime_matches(Lower, Pattern) end, MimeTypes).

-spec mime_matches(binary(), binary()) -> boolean().
mime_matches(ContentType, Pattern) ->
    case nhttp_headers:to_lower(Pattern) of
        <<"text/*">> ->
            case ContentType of
                <<"text/", _/binary>> -> true;
                _ -> false
            end;
        <<"application/*">> ->
            case ContentType of
                <<"application/", _/binary>> -> true;
                _ -> false
            end;
        LowerPattern ->
            ContentType =:= LowerPattern
    end.

-spec parse_accept_encoding(binary()) -> [{binary(), float()}].
parse_accept_encoding(AcceptEncoding) ->
    Parts = binary:split(AcceptEncoding, <<",">>, [global, trim_all]),
    lists:filtermap(fun parse_encoding_part/1, Parts).

-spec parse_encoding_part(binary()) -> {true, {binary(), float()}} | false.
parse_encoding_part(Part) ->
    Trimmed = string:trim(Part),
    case binary:split(Trimmed, <<";">>) of
        [Encoding] ->
            {true, {nhttp_headers:to_lower(Encoding), 1.0}};
        [Encoding, QValue] ->
            case parse_quality(QValue) of
                {ok, Q} -> {true, {nhttp_headers:to_lower(Encoding), Q}};
                {error, _} -> false
            end;
        _ ->
            false
    end.

-spec parse_quality(binary()) -> {ok, float()} | {error, badarg}.
parse_quality(QValue) ->
    Trimmed = string:trim(QValue),
    parse_quality_value(Trimmed).

-spec parse_quality_value(binary()) -> {ok, float()} | {error, badarg}.
parse_quality_value(<<"q=", Rest/binary>>) ->
    parse_qvalue(Rest);
parse_quality_value(_) ->
    {error, badarg}.

-spec parse_qvalue(binary()) -> {ok, float()} | {error, badarg}.
parse_qvalue(<<"1">>) ->
    {ok, 1.0};
parse_qvalue(<<"1.0">>) ->
    {ok, 1.0};
parse_qvalue(<<"0">>) ->
    {ok, 0.0};
parse_qvalue(<<"0.0">>) ->
    {ok, 0.0};
parse_qvalue(<<"0.", D1>>) when D1 >= $0, D1 =< $9 ->
    {ok, (D1 - $0) / 10.0};
parse_qvalue(<<"0.", D1, D2>>) when D1 >= $0, D1 =< $9, D2 >= $0, D2 =< $9 ->
    {ok, ((D1 - $0) * 10 + (D2 - $0)) / 100.0};
parse_qvalue(<<"0.", D1, D2, D3>>) when
    D1 >= $0,
    D1 =< $9,
    D2 >= $0,
    D2 =< $9,
    D3 >= $0,
    D3 =< $9
->
    {ok, ((D1 - $0) * 100 + (D2 - $0) * 10 + (D3 - $0)) / 1000.0};
parse_qvalue(_) ->
    {error, badarg}.

-spec select_best_encoding([{binary(), float()}]) -> encoding().
select_best_encoding(Encodings) ->
    Filtered = [{E, Q} || {E, Q} <- Encodings, Q > 0.0],
    Sorted = lists:sort(fun({_, Q1}, {_, Q2}) -> Q1 > Q2 end, Filtered),
    select_first_supported(Sorted).

-spec select_first_supported([{binary(), float()}]) -> encoding().
select_first_supported([]) ->
    identity;
select_first_supported([{Encoding, _Q} | Rest]) ->
    case encoding_to_atom(Encoding) of
        identity -> select_first_supported(Rest);
        Atom -> Atom
    end.

-spec with_zlib_stream(fun((zlib:zstream()) -> {ok, binary()} | {error, zlib_error()})) ->
    {ok, binary()} | {error, zlib_error()}.
with_zlib_stream(Fun) ->
    case zlib_open() of
        {ok, Z} ->
            try
                Fun(Z)
            after
                _ = zlib_close(Z)
            end;
        {error, _} = Error ->
            Error
    end.

-spec zlib_close(zlib:zstream()) -> ok | {error, zlib_error()}.
zlib_close(Z) ->
    try
        zlib:close(Z),
        ok
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_deflate(zlib:zstream(), iodata()) -> {ok, iolist()} | {error, zlib_error()}.
zlib_deflate(Z, Data) ->
    try
        {ok, zlib:deflate(Z, Data, finish)}
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_deflate_end(zlib:zstream()) -> ok | {error, zlib_error()}.
zlib_deflate_end(Z) ->
    try
        ok = zlib:deflateEnd(Z),
        ok
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_deflate_init(zlib:zstream(), 1..9) -> ok | {error, zlib_error()}.
zlib_deflate_init(Z, Level) ->
    try
        ok = zlib:deflateInit(Z, Level),
        ok
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_deflate_init_gzip(zlib:zstream(), 1..9) -> ok | {error, zlib_error()}.
zlib_deflate_init_gzip(Z, Level) ->
    try
        ok = zlib:deflateInit(Z, Level, deflated, ?ZLIB_GZIP_WINDOW_BITS, 8, default),
        ok
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_inflate_end(zlib:zstream()) -> ok | {error, zlib_error()}.
zlib_inflate_end(Z) ->
    try
        ok = zlib:inflateEnd(Z),
        ok
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_inflate_init(zlib:zstream()) -> ok | {error, zlib_error()}.
zlib_inflate_init(Z) ->
    try
        ok = zlib:inflateInit(Z),
        ok
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_inflate_init_gzip(zlib:zstream()) -> ok | {error, zlib_error()}.
zlib_inflate_init_gzip(Z) ->
    try
        ok = zlib:inflateInit(Z, ?ZLIB_GZIP_WINDOW_BITS),
        ok
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_open() -> {ok, zlib:zstream()} | {error, zlib_error()}.
zlib_open() ->
    try
        {ok, zlib:open()}
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_safe_inflate(zlib:zstream(), binary(), pos_integer() | infinity) ->
    {ok, iolist()} | {error, zlib_error()}.
zlib_safe_inflate(Z, Data, Max) ->
    try
        zlib_safe_inflate_loop(Z, {first, Data}, Max, 0, [])
    catch
        error:Reason -> {error, Reason}
    end.

-spec zlib_safe_inflate_loop(
    zlib:zstream(),
    {first, binary()} | drain,
    pos_integer() | infinity,
    non_neg_integer(),
    [iolist()]
) ->
    {ok, iolist()} | {error, zlib_error()}.
zlib_safe_inflate_loop(Z, Step, Max, Total, Acc) ->
    Input =
        case Step of
            {first, Data} -> Data;
            drain -> <<>>
        end,
    case zlib:safeInflate(Z, Input) of
        {finished, Out} ->
            case check_inflate_size(Total, Out, Max) of
                ok -> {ok, lists:reverse([Out | Acc])};
                {error, _} = E -> E
            end;
        {continue, Out} ->
            case check_inflate_size(Total, Out, Max) of
                ok ->
                    NewTotal = Total + iolist_size(Out),
                    zlib_safe_inflate_loop(Z, drain, Max, NewTotal, [Out | Acc]);
                {error, _} = E ->
                    E
            end
    end.
