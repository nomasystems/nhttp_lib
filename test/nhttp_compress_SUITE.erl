%%%-----------------------------------------------------------------------------
-module(nhttp_compress_SUITE).

-moduledoc "Test suite for nhttp_compress module. Tests gzip and deflate compression/decompression.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2
]).

-export([
    compress_gzip/1,
    compress_deflate/1,
    compress_identity/1,
    compress_roundtrip_gzip/1,
    compress_roundtrip_deflate/1,
    compress_large_data/1,
    compress_empty/1,
    compress_various_levels/1,
    decompress_gzip/1,
    decompress_deflate/1,
    decompress_identity/1,
    decompress_invalid_gzip/1,
    decompress_invalid_deflate/1,
    decompress_gzip_bomb/1,
    decompress_deflate_bomb/1,
    decompress_identity_too_large/1,
    decompress_infinity_lifts_cap/1,
    cap_gzip_at_max/1,
    cap_gzip_over_max/1,
    cap_deflate_at_max/1,
    cap_deflate_over_max/1,
    cap_identity_at_max/1,
    cap_identity_over_max/1,
    trailing_gzip_concatenated_members/1,
    trailing_gzip_appended_bytes/1,
    trailing_gzip_single_appended_byte/1,
    trailing_deflate_concatenated_streams/1,
    trailing_deflate_appended_bytes/1,
    trailing_corrupt_stream_is_data_error/1,
    bomb_gzip_refused_by_default_cap/1,
    bomb_deflate_refused_by_default_cap/1,
    bomb_gzip_infinity_decompresses_fully/1,
    bomb_memory_stays_bounded/1,
    negotiate_gzip/1,
    negotiate_deflate/1,
    negotiate_identity/1,
    negotiate_quality/1,
    negotiate_wildcard/1,
    negotiate_multiple/1,
    negotiate_q_zero/1,
    negotiate_empty/1,
    negotiate_x_gzip/1,
    negotiate_quality_formats/1,
    negotiate_invalid_quality/1,
    negotiate_only_identity/1,
    should_compress_text_html/1,
    should_compress_json/1,
    should_compress_below_threshold/1,
    should_compress_undefined_type/1,
    should_compress_binary_type/1,
    should_compress_text_wildcard/1,
    should_compress_case_insensitive/1,
    should_compress_all_default_types/1,
    should_compress_svg/1,
    should_compress_application_wildcard/1,
    should_compress_exact_match/1,
    should_compress_content_type_with_params/1,
    default_mime_types/1,
    encoding_header/1
]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, compression},
        {group, decompression},
        {group, cap_boundary},
        {group, trailing_input},
        {group, bomb},
        {group, negotiation},
        {group, should_compress},
        {group, helpers}
    ].

groups() ->
    [
        {compression, [parallel], [
            compress_gzip,
            compress_deflate,
            compress_identity,
            compress_roundtrip_gzip,
            compress_roundtrip_deflate,
            compress_large_data,
            compress_empty,
            compress_various_levels
        ]},
        {decompression, [parallel], [
            decompress_gzip,
            decompress_deflate,
            decompress_identity,
            decompress_invalid_gzip,
            decompress_invalid_deflate,
            decompress_gzip_bomb,
            decompress_deflate_bomb,
            decompress_identity_too_large,
            decompress_infinity_lifts_cap
        ]},
        {cap_boundary, [parallel], [
            cap_gzip_at_max,
            cap_gzip_over_max,
            cap_deflate_at_max,
            cap_deflate_over_max,
            cap_identity_at_max,
            cap_identity_over_max
        ]},
        {trailing_input, [parallel], [
            trailing_gzip_concatenated_members,
            trailing_gzip_appended_bytes,
            trailing_gzip_single_appended_byte,
            trailing_deflate_concatenated_streams,
            trailing_deflate_appended_bytes,
            trailing_corrupt_stream_is_data_error
        ]},
        {bomb, [], [
            bomb_gzip_refused_by_default_cap,
            bomb_deflate_refused_by_default_cap,
            bomb_gzip_infinity_decompresses_fully,
            bomb_memory_stays_bounded
        ]},
        {negotiation, [parallel], [
            negotiate_gzip,
            negotiate_deflate,
            negotiate_identity,
            negotiate_quality,
            negotiate_wildcard,
            negotiate_multiple,
            negotiate_q_zero,
            negotiate_empty,
            negotiate_x_gzip,
            negotiate_quality_formats,
            negotiate_invalid_quality,
            negotiate_only_identity
        ]},
        {should_compress, [parallel], [
            should_compress_text_html,
            should_compress_json,
            should_compress_below_threshold,
            should_compress_undefined_type,
            should_compress_binary_type,
            should_compress_text_wildcard,
            should_compress_case_insensitive,
            should_compress_all_default_types,
            should_compress_svg,
            should_compress_application_wildcard,
            should_compress_exact_match,
            should_compress_content_type_with_params
        ]},
        {helpers, [parallel], [
            default_mime_types,
            encoding_header
        ]}
    ].

-define(BOMB_SIZE, (32 * 1024 * 1024)).
-define(BOMB_MEMORY_HEADROOM, (?BOMB_SIZE div 10)).
-define(BOMB_TIME_LIMIT_MS, 10000).

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(bomb, Config) ->
    Payload = binary:copy(<<0>>, ?BOMB_SIZE),
    {ok, GzipBomb} = nhttp_compress:compress(Payload, gzip, 9),
    {ok, DeflateBomb} = nhttp_compress:compress(Payload, deflate, 9),
    [{gzip_bomb, GzipBomb}, {deflate_bomb, DeflateBomb} | Config];
init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% COMPRESSION TESTS
%%%-----------------------------------------------------------------------------

compress_gzip(_Config) ->
    Data = <<"Hello, World!">>,
    {ok, Compressed} = nhttp_compress:compress(Data, gzip, 6),
    ?assert(is_binary(Compressed)),
    ?assert(byte_size(Compressed) > 0),
    ?assertMatch(<<16#1f, 16#8b, _/binary>>, Compressed).

compress_deflate(_Config) ->
    Data = <<"Hello, World!">>,
    {ok, Compressed} = nhttp_compress:compress(Data, deflate, 6),
    ?assert(is_binary(Compressed)),
    ?assert(byte_size(Compressed) > 0).

compress_identity(_Config) ->
    Data = <<"Hello, World!">>,
    {ok, Result} = nhttp_compress:compress(Data, identity, 6),
    ?assertEqual(Data, Result).

compress_roundtrip_gzip(_Config) ->
    Data = <<"This is a test of gzip compression roundtrip.">>,
    {ok, Compressed} = nhttp_compress:compress(Data, gzip, 6),
    {ok, Decompressed} = nhttp_compress:decompress(Compressed, gzip),
    ?assertEqual(Data, Decompressed).

compress_roundtrip_deflate(_Config) ->
    Data = <<"This is a test of deflate compression roundtrip.">>,
    {ok, Compressed} = nhttp_compress:compress(Data, deflate, 6),
    {ok, Decompressed} = nhttp_compress:decompress(Compressed, deflate),
    ?assertEqual(Data, Decompressed).

compress_large_data(_Config) ->
    Data = binary:copy(<<"ABCDEFGHIJ">>, 10000),
    {ok, Compressed} = nhttp_compress:compress(Data, gzip, 6),
    ?assert(byte_size(Compressed) < byte_size(Data) div 2),
    {ok, Decompressed} = nhttp_compress:decompress(Compressed, gzip),
    ?assertEqual(Data, Decompressed).

compress_empty(_Config) ->
    Data = <<>>,
    {ok, Compressed} = nhttp_compress:compress(Data, gzip, 6),
    ?assert(is_binary(Compressed)),
    {ok, Decompressed} = nhttp_compress:decompress(Compressed, gzip),
    ?assertEqual(Data, Decompressed).

compress_various_levels(_Config) ->
    Data = binary:copy(<<"Test data for compression levels. ">>, 100),
    lists:foreach(
        fun(Level) ->
            {ok, Compressed} = nhttp_compress:compress(Data, gzip, Level),
            {ok, Decompressed} = nhttp_compress:decompress(Compressed, gzip),
            ?assertEqual(Data, Decompressed)
        end,
        [1, 3, 6, 9]
    ).

%%%-----------------------------------------------------------------------------
%%% DECOMPRESSION TESTS
%%%-----------------------------------------------------------------------------

decompress_gzip(_Config) ->
    Original = <<"Decompress test data">>,
    {ok, Compressed} = nhttp_compress:compress(Original, gzip, 6),
    {ok, Decompressed} = nhttp_compress:decompress(Compressed, gzip),
    ?assertEqual(Original, Decompressed).

decompress_deflate(_Config) ->
    Original = <<"Decompress test data">>,
    {ok, Compressed} = nhttp_compress:compress(Original, deflate, 6),
    {ok, Decompressed} = nhttp_compress:decompress(Compressed, deflate),
    ?assertEqual(Original, Decompressed).

decompress_identity(_Config) ->
    Data = <<"Raw data">>,
    {ok, Result} = nhttp_compress:decompress(Data, identity),
    ?assertEqual(Data, Result).

decompress_invalid_gzip(_Config) ->
    InvalidData = <<"not gzip data">>,
    ?assertMatch({error, _}, nhttp_compress:decompress(InvalidData, gzip)).

decompress_invalid_deflate(_Config) ->
    InvalidData = <<"not deflate data">>,
    ?assertMatch({error, _}, nhttp_compress:decompress(InvalidData, deflate)).

decompress_gzip_bomb(_Config) ->
    Bomb = binary:copy(<<0>>, 1024 * 1024),
    {ok, Compressed} = nhttp_compress:compress(Bomb, gzip, 9),
    true = byte_size(Compressed) < byte_size(Bomb),
    ?assertEqual(
        {error, max_output_exceeded},
        nhttp_compress:decompress(Compressed, gzip, 1024)
    ).

decompress_deflate_bomb(_Config) ->
    Bomb = binary:copy(<<0>>, 1024 * 1024),
    {ok, Compressed} = nhttp_compress:compress(Bomb, deflate, 9),
    ?assertEqual(
        {error, max_output_exceeded},
        nhttp_compress:decompress(Compressed, deflate, 1024)
    ).

decompress_identity_too_large(_Config) ->
    Data = binary:copy(<<"x">>, 200),
    ?assertEqual(
        {error, max_output_exceeded},
        nhttp_compress:decompress(Data, identity, 100)
    ).

decompress_infinity_lifts_cap(_Config) ->
    Bomb = binary:copy(<<0>>, 64 * 1024),
    {ok, Compressed} = nhttp_compress:compress(Bomb, gzip, 9),
    {ok, Decompressed} = nhttp_compress:decompress(Compressed, gzip, infinity),
    ?assertEqual(Bomb, Decompressed).

%%%-----------------------------------------------------------------------------
%%% ACCEPT-ENCODING NEGOTIATION TESTS
%%%-----------------------------------------------------------------------------

negotiate_gzip(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"gzip">>}],
    ?assertEqual(gzip, nhttp_compress:negotiate_encoding(Headers)).

negotiate_deflate(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"deflate">>}],
    ?assertEqual(deflate, nhttp_compress:negotiate_encoding(Headers)).

negotiate_identity(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"identity">>}],
    ?assertEqual(identity, nhttp_compress:negotiate_encoding(Headers)).

negotiate_quality(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"gzip;q=0.5, deflate;q=0.9">>}],
    ?assertEqual(deflate, nhttp_compress:negotiate_encoding(Headers)).

negotiate_wildcard(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"*">>}],
    ?assertEqual(gzip, nhttp_compress:negotiate_encoding(Headers)).

negotiate_multiple(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"gzip, deflate">>}],
    Result = nhttp_compress:negotiate_encoding(Headers),
    ?assert(Result =:= gzip orelse Result =:= deflate).

negotiate_q_zero(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"gzip;q=0, deflate">>}],
    ?assertEqual(deflate, nhttp_compress:negotiate_encoding(Headers)).

negotiate_empty(_Config) ->
    Headers = [{<<"host">>, <<"example.com">>}],
    ?assertEqual(identity, nhttp_compress:negotiate_encoding(Headers)).

negotiate_x_gzip(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"x-gzip">>}],
    ?assertEqual(gzip, nhttp_compress:negotiate_encoding(Headers)).

negotiate_quality_formats(_Config) ->
    Headers1 = [{<<"accept-encoding">>, <<"gzip;q=0.5">>}],
    ?assertEqual(gzip, nhttp_compress:negotiate_encoding(Headers1)),

    Headers2 = [{<<"accept-encoding">>, <<"deflate;q=0.75">>}],
    ?assertEqual(deflate, nhttp_compress:negotiate_encoding(Headers2)),

    Headers3 = [{<<"accept-encoding">>, <<"gzip;q=0.123">>}],
    ?assertEqual(gzip, nhttp_compress:negotiate_encoding(Headers3)),

    Headers4 = [{<<"accept-encoding">>, <<"gzip;q=1">>}],
    ?assertEqual(gzip, nhttp_compress:negotiate_encoding(Headers4)),

    Headers5 = [{<<"accept-encoding">>, <<"deflate;q=1.0">>}],
    ?assertEqual(deflate, nhttp_compress:negotiate_encoding(Headers5)),

    Headers6 = [{<<"accept-encoding">>, <<"gzip;q=0, deflate">>}],
    ?assertEqual(deflate, nhttp_compress:negotiate_encoding(Headers6)),

    Headers7 = [{<<"accept-encoding">>, <<"gzip;q=0.0, deflate">>}],
    ?assertEqual(deflate, nhttp_compress:negotiate_encoding(Headers7)).

%%%-----------------------------------------------------------------------------
%%% SHOULD_COMPRESS TESTS
%%%-----------------------------------------------------------------------------

should_compress_text_html(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    ?assertEqual(true, nhttp_compress:should_compress(<<"text/html">>, 2000, MimeTypes)).

should_compress_json(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    ?assertEqual(true, nhttp_compress:should_compress(<<"application/json">>, 2000, MimeTypes)),
    ?assertEqual(
        true, nhttp_compress:should_compress(<<"application/json; charset=utf-8">>, 2000, MimeTypes)
    ).

should_compress_below_threshold(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    ?assertEqual(false, nhttp_compress:should_compress(<<"text/html">>, 500, MimeTypes)).

should_compress_undefined_type(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    ?assertEqual(false, nhttp_compress:should_compress(undefined, 2000, MimeTypes)).

should_compress_binary_type(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    ?assertEqual(false, nhttp_compress:should_compress(<<"image/png">>, 2000, MimeTypes)),
    ?assertEqual(
        false, nhttp_compress:should_compress(<<"application/octet-stream">>, 2000, MimeTypes)
    ).

should_compress_text_wildcard(_Config) ->
    MimeTypes = [<<"text/*">>],
    ?assertEqual(true, nhttp_compress:should_compress(<<"text/html">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"text/plain">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"text/css">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"text/javascript">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"text/xml">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"text/custom">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Text/Html">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"TEXT/HTML">>, 2000, MimeTypes)).

should_compress_case_insensitive(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Text/Html">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"TEXT/HTML">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Text/Plain">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"TEXT/PLAIN">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Text/Css">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"TEXT/CSS">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Text/Javascript">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"TEXT/JAVASCRIPT">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Text/Xml">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"TEXT/XML">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Application/Json">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"APPLICATION/JSON">>, 2000, MimeTypes)),
    ?assertEqual(
        true, nhttp_compress:should_compress(<<"Application/Javascript">>, 2000, MimeTypes)
    ),
    ?assertEqual(
        true, nhttp_compress:should_compress(<<"APPLICATION/JAVASCRIPT">>, 2000, MimeTypes)
    ),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Application/Xml">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"APPLICATION/XML">>, 2000, MimeTypes)),
    ?assertEqual(
        true, nhttp_compress:should_compress(<<"Application/Xhtml+Xml">>, 2000, MimeTypes)
    ),
    ?assertEqual(
        true, nhttp_compress:should_compress(<<"APPLICATION/XHTML+XML">>, 2000, MimeTypes)
    ).

should_compress_all_default_types(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    lists:foreach(
        fun(Type) ->
            ?assertEqual(true, nhttp_compress:should_compress(Type, 2000, MimeTypes))
        end,
        MimeTypes
    ).

should_compress_svg(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    ?assertEqual(true, nhttp_compress:should_compress(<<"image/svg+xml">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Image/Svg+Xml">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"IMAGE/SVG+XML">>, 2000, MimeTypes)).

%%%-----------------------------------------------------------------------------
%%% HELPER TESTS
%%%-----------------------------------------------------------------------------

default_mime_types(_Config) ->
    Types = nhttp_compress:default_mime_types(),
    ?assert(is_list(Types)),
    ?assert(length(Types) > 0),
    ?assert(lists:member(<<"text/html">>, Types)),
    ?assert(lists:member(<<"application/json">>, Types)).

encoding_header(_Config) ->
    ?assertEqual(<<"gzip">>, nhttp_compress:encoding_header(gzip)),
    ?assertEqual(<<"deflate">>, nhttp_compress:encoding_header(deflate)),
    ?assertEqual(<<"identity">>, nhttp_compress:encoding_header(identity)).

%%%-----------------------------------------------------------------------------
%%% ADDITIONAL COVERAGE TESTS
%%%-----------------------------------------------------------------------------

negotiate_invalid_quality(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"gzip;q=invalid, deflate">>}],
    ?assertEqual(deflate, nhttp_compress:negotiate_encoding(Headers)).

negotiate_only_identity(_Config) ->
    Headers = [{<<"accept-encoding">>, <<"gzip;q=0">>}],
    ?assertEqual(identity, nhttp_compress:negotiate_encoding(Headers)).

should_compress_application_wildcard(_Config) ->
    MimeTypes = [<<"application/*">>],
    ?assertEqual(true, nhttp_compress:should_compress(<<"application/json">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"Application/Xml">>, 2000, MimeTypes)),
    ?assertEqual(true, nhttp_compress:should_compress(<<"APPLICATION/PDF">>, 2000, MimeTypes)),
    ?assertEqual(false, nhttp_compress:should_compress(<<"text/html">>, 2000, MimeTypes)).

should_compress_exact_match(_Config) ->
    MimeTypes = [<<"custom/type">>],
    ?assertEqual(true, nhttp_compress:should_compress(<<"custom/type">>, 2000, MimeTypes)),
    ?assertEqual(false, nhttp_compress:should_compress(<<"custom/other">>, 2000, MimeTypes)).

should_compress_content_type_with_params(_Config) ->
    MimeTypes = nhttp_compress:default_mime_types(),
    ?assertEqual(
        true,
        nhttp_compress:should_compress(<<"text/html; charset=utf-8">>, 2000, MimeTypes)
    ),
    ?assertEqual(
        true,
        nhttp_compress:should_compress(
            <<"application/json; charset=utf-8; boundary=something">>, 2000, MimeTypes
        )
    ).

%%%-----------------------------------------------------------------------------
%%% CAP BOUNDARY TESTS
%%%-----------------------------------------------------------------------------

cap_gzip_at_max(_Config) ->
    Data = binary:copy(<<"x">>, 4096),
    {ok, Compressed} = nhttp_compress:compress(Data, gzip, 9),
    ?assertEqual({ok, Data}, nhttp_compress:decompress(Compressed, gzip, 4096)).

cap_gzip_over_max(_Config) ->
    Data = binary:copy(<<"x">>, 4096),
    {ok, Compressed} = nhttp_compress:compress(Data, gzip, 9),
    ?assertEqual(
        {error, max_output_exceeded},
        nhttp_compress:decompress(Compressed, gzip, 4095)
    ).

cap_deflate_at_max(_Config) ->
    Data = binary:copy(<<"x">>, 4096),
    {ok, Compressed} = nhttp_compress:compress(Data, deflate, 9),
    ?assertEqual({ok, Data}, nhttp_compress:decompress(Compressed, deflate, 4096)).

cap_deflate_over_max(_Config) ->
    Data = binary:copy(<<"x">>, 4096),
    {ok, Compressed} = nhttp_compress:compress(Data, deflate, 9),
    ?assertEqual(
        {error, max_output_exceeded},
        nhttp_compress:decompress(Compressed, deflate, 4095)
    ).

cap_identity_at_max(_Config) ->
    Data = binary:copy(<<"x">>, 4096),
    ?assertEqual({ok, Data}, nhttp_compress:decompress(Data, identity, 4096)).

cap_identity_over_max(_Config) ->
    Data = binary:copy(<<"x">>, 4096),
    ?assertEqual(
        {error, max_output_exceeded},
        nhttp_compress:decompress(Data, identity, 4095)
    ).

%%%-----------------------------------------------------------------------------
%%% TRAILING INPUT TESTS
%%%-----------------------------------------------------------------------------

trailing_gzip_concatenated_members(_Config) ->
    {ok, First} = nhttp_compress:compress(<<"first">>, gzip, 6),
    {ok, Second} = nhttp_compress:compress(<<"second">>, gzip, 6),
    ?assertEqual(
        {error, trailing_data},
        nhttp_compress:decompress(<<First/binary, Second/binary>>, gzip)
    ).

trailing_gzip_appended_bytes(_Config) ->
    {ok, Compressed} = nhttp_compress:compress(<<"payload">>, gzip, 6),
    ?assertEqual(
        {error, trailing_data},
        nhttp_compress:decompress(<<Compressed/binary, "appended">>, gzip)
    ).

trailing_gzip_single_appended_byte(_Config) ->
    {ok, Compressed} = nhttp_compress:compress(<<"payload">>, gzip, 6),
    ?assertEqual(
        {error, trailing_data},
        nhttp_compress:decompress(<<Compressed/binary, 0>>, gzip)
    ).

trailing_deflate_concatenated_streams(_Config) ->
    {ok, First} = nhttp_compress:compress(<<"first">>, deflate, 6),
    {ok, Second} = nhttp_compress:compress(<<"second">>, deflate, 6),
    ?assertEqual(
        {error, trailing_data},
        nhttp_compress:decompress(<<First/binary, Second/binary>>, deflate)
    ).

trailing_deflate_appended_bytes(_Config) ->
    {ok, Compressed} = nhttp_compress:compress(<<"payload">>, deflate, 6),
    ?assertEqual(
        {error, trailing_data},
        nhttp_compress:decompress(<<Compressed/binary, "appended">>, deflate)
    ).

trailing_corrupt_stream_is_data_error(_Config) ->
    Data = binary:copy(<<"corruption target ">>, 4096),
    {ok, Compressed} = nhttp_compress:compress(Data, gzip, 6),
    <<Head:64/binary, Byte:8, Tail/binary>> = Compressed,
    Corrupt = <<Head/binary, (Byte bxor 16#FF):8, Tail/binary>>,
    ?assertEqual({error, data_error}, nhttp_compress:decompress(Corrupt, gzip)).

%%%-----------------------------------------------------------------------------
%%% DECOMPRESSION BOMB TESTS
%%%-----------------------------------------------------------------------------

bomb_gzip_refused_by_default_cap(Config) ->
    Bomb = proplists:get_value(gzip_bomb, Config),
    ?assert(byte_size(Bomb) * 100 < ?BOMB_SIZE),
    ?assertEqual({error, max_output_exceeded}, nhttp_compress:decompress(Bomb, gzip)).

bomb_deflate_refused_by_default_cap(Config) ->
    Bomb = proplists:get_value(deflate_bomb, Config),
    ?assert(byte_size(Bomb) * 100 < ?BOMB_SIZE),
    ?assertEqual({error, max_output_exceeded}, nhttp_compress:decompress(Bomb, deflate)).

bomb_gzip_infinity_decompresses_fully(Config) ->
    Bomb = proplists:get_value(gzip_bomb, Config),
    {ok, Inflated} = nhttp_compress:decompress(Bomb, gzip, infinity),
    ?assertEqual(?BOMB_SIZE, byte_size(Inflated)),
    ?assertEqual(binary:copy(<<0>>, ?BOMB_SIZE), Inflated).

bomb_memory_stays_bounded(Config) ->
    Bomb = proplists:get_value(deflate_bomb, Config),
    _ = erlang:garbage_collect(),
    Baseline = erlang:memory(binary),
    Sampler = start_binary_memory_sampler(Baseline),
    {Elapsed, Result} = timer:tc(fun() -> nhttp_compress:decompress(Bomb, deflate, 1024) end),
    Peak = stop_binary_memory_sampler(Sampler),
    ct:pal("peak binary memory ~p bytes, headroom ~p bytes, uncompressed ~p bytes", [
        Peak, ?BOMB_MEMORY_HEADROOM, ?BOMB_SIZE
    ]),
    ?assertEqual({error, max_output_exceeded}, Result),
    ?assert(Peak < ?BOMB_MEMORY_HEADROOM),
    ?assert(Elapsed div 1000 < ?BOMB_TIME_LIMIT_MS).

start_binary_memory_sampler(Baseline) ->
    Owner = self(),
    spawn_link(fun() -> sample_binary_memory(Owner, Baseline, 0) end).

stop_binary_memory_sampler(Sampler) ->
    Sampler ! {stop, self()},
    receive
        {peak, Sampler, Peak} -> Peak
    after 5000 -> error(sampler_timeout)
    end.

sample_binary_memory(Owner, Baseline, Peak) ->
    receive
        {stop, From} ->
            From ! {peak, self(), Peak}
    after 0 ->
        Used = max(0, erlang:memory(binary) - Baseline),
        timer:sleep(1),
        sample_binary_memory(Owner, Baseline, max(Peak, Used))
    end.
