%%%-----------------------------------------------------------------------------
-module(nhttp_compress_props).

-moduledoc """
Property tests for `nhttp_compress` (gzip/deflate content compression).

Properties:
- compress + decompress is identity for both gzip and deflate.
- decompress respects the `max_output` cap (zip-bomb defence).
- decompress on truncated input returns `{error, _}`, never a crash.

These properties are run via `nhttp_props_SUITE`.
""".

-include_lib("triq/include/triq.hrl").

-spec prop_compress_roundtrip_gzip() -> triq:property().
prop_compress_roundtrip_gzip() ->
    ?FORALL(
        {Data, Level},
        {binary(), int(1, 9)},
        begin
            {ok, Compressed} = nhttp_compress:compress(Data, gzip, Level),
            case nhttp_compress:decompress(Compressed, gzip) of
                {ok, Decompressed} -> Decompressed =:= Data;
                _ -> false
            end
        end
    ).

-spec prop_compress_roundtrip_deflate() -> triq:property().
prop_compress_roundtrip_deflate() ->
    ?FORALL(
        {Data, Level},
        {binary(), int(1, 9)},
        begin
            {ok, Compressed} = nhttp_compress:compress(Data, deflate, Level),
            case nhttp_compress:decompress(Compressed, deflate) of
                {ok, Decompressed} -> Decompressed =:= Data;
                _ -> false
            end
        end
    ).

-spec prop_decompress_max_output_gzip() -> triq:property().
prop_decompress_max_output_gzip() ->
    ?FORALL(
        Repeats,
        int(1024, 65536),
        begin
            Data = binary:copy(<<"a">>, Repeats),
            {ok, Compressed} = nhttp_compress:compress(Data, gzip, 9),
            Max = Repeats - 1,
            case nhttp_compress:decompress(Compressed, gzip, Max) of
                {error, max_output_exceeded} -> true;
                _ -> false
            end
        end
    ).

-spec prop_decompress_within_max_output_gzip() -> triq:property().
prop_decompress_within_max_output_gzip() ->
    ?FORALL(
        Data,
        binary(),
        begin
            {ok, Compressed} = nhttp_compress:compress(Data, gzip, 6),
            Max = max(1, byte_size(Data)),
            case nhttp_compress:decompress(Compressed, gzip, Max) of
                {ok, Out} -> Out =:= Data;
                _ -> false
            end
        end
    ).

-spec prop_decompress_truncated_no_crash() -> triq:property().
prop_decompress_truncated_no_crash() ->
    ?FORALL(
        {Data, Encoding, TruncateAt},
        {non_empty(binary()), oneof([gzip, deflate]), int(0, 1024)},
        begin
            {ok, Compressed} = nhttp_compress:compress(Data, Encoding, 6),
            Size = byte_size(Compressed),
            CutAt = min(TruncateAt, max(0, Size - 1)),
            Truncated = binary:part(Compressed, 0, CutAt),
            case nhttp_compress:decompress(Truncated, Encoding) of
                {ok, _} -> true;
                {error, _} -> true
            end
        end
    ).

-spec prop_decompress_random_binary_no_crash() -> triq:property().
prop_decompress_random_binary_no_crash() ->
    ?FORALL(
        {Bin, Encoding},
        {binary(), oneof([gzip, deflate])},
        begin
            case nhttp_compress:decompress(Bin, Encoding) of
                {ok, _} -> true;
                {error, _} -> true
            end
        end
    ).
