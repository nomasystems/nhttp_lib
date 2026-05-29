%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_interop_SUITE).

-moduledoc """
QPACK interop format test suite.

Tests QIF parsing/writing, binary interop format encoding/decoding,
and full encode-then-decode roundtrips through the interop layer.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, qif_parsing},
        {group, binary_format},
        {group, full_roundtrip}
    ].

groups() ->
    [
        {qif_parsing, [parallel], [
            parse_empty,
            parse_single_section,
            parse_multiple_sections,
            parse_with_comments,
            parse_skip_malformed_lines,
            qif_roundtrip
        ]},
        {binary_format, [parallel], [
            encode_static_only,
            encode_with_dynamic_table,
            decode_empty_file,
            decode_multiple_blocks
        ]},
        {full_roundtrip, [], [
            roundtrip_static_headers,
            roundtrip_dynamic_headers,
            roundtrip_multiple_sections,
            roundtrip_huffman
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%-----------------------------------------------------------------------------
%%% QIF PARSING TESTS
%%%-----------------------------------------------------------------------------

parse_empty(_Config) ->
    {ok, []} = nhttp_qpack_interop:parse_qif(<<>>).

parse_single_section(_Config) ->
    Qif = <<":method\tGET\n:path\t/\n">>,
    {ok, Sections} = nhttp_qpack_interop:parse_qif(Qif),
    ?assertEqual(
        [[{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}]],
        Sections
    ).

parse_multiple_sections(_Config) ->
    Qif = <<":method\tGET\n:path\t/\n\n:method\tPOST\n:path\t/form\n">>,
    {ok, [Section1, Section2]} = nhttp_qpack_interop:parse_qif(Qif),
    ?assertEqual(
        [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
        Section1
    ),
    ?assertEqual(
        [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/form">>}],
        Section2
    ).

parse_with_comments(_Config) ->
    Qif = <<"# Request 1\n:method\tGET\n# A comment\n:path\t/\n">>,
    {ok, [[{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}]]} =
        nhttp_qpack_interop:parse_qif(Qif).

parse_skip_malformed_lines(_Config) ->
    Qif = <<"badline\n:method\tGET\nalso bad\n:path\t/\n">>,
    {ok, [[{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}]]} =
        nhttp_qpack_interop:parse_qif(Qif).

qif_roundtrip(_Config) ->
    Original = [
        [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
        [{<<":status">>, <<"200">>}]
    ],
    {ok, IoData} = nhttp_qpack_interop:write_qif(Original),
    Bin = iolist_to_binary(IoData),
    {ok, Parsed} = nhttp_qpack_interop:parse_qif(Bin),
    ?assertEqual(Original, Parsed).

%%%-----------------------------------------------------------------------------
%%% BINARY FORMAT TESTS
%%%-----------------------------------------------------------------------------

encode_static_only(_Config) ->
    Sections = [
        [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}]
    ],
    Config = #{max_table_capacity => 0},
    {ok, IoData} = nhttp_qpack_interop:encode_to_file(
        Sections, Config
    ),
    Bin = iolist_to_binary(IoData),
    ?assert(byte_size(Bin) > 0),
    {ok, Decoded} = nhttp_qpack_interop:decode_from_file(
        Bin, Config
    ),
    ?assertEqual(Sections, Decoded).

encode_with_dynamic_table(_Config) ->
    Sections = [
        [{<<"x-custom">>, <<"val1">>}],
        [{<<"x-custom">>, <<"val1">>}]
    ],
    Config = #{max_table_capacity => 4096},
    {ok, IoData} = nhttp_qpack_interop:encode_to_file(
        Sections, Config
    ),
    Bin = iolist_to_binary(IoData),
    ?assert(byte_size(Bin) > 0).

decode_empty_file(_Config) ->
    {ok, []} = nhttp_qpack_interop:decode_from_file(<<>>, #{}).

decode_multiple_blocks(_Config) ->
    CapInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_set_capacity(4096)
    ),
    InsertInstr = iolist_to_binary(
        nhttp_qpack_encoder_instruction:encode_insert_literal_name(
            <<"x-test">>, <<"hello">>, false
        )
    ),
    EncData = <<CapInstr/binary, InsertInstr/binary>>,
    Prefix = iolist_to_binary(
        nhttp_qpack_field_line:encode_prefix(1, 1, 128)
    ),
    Rep = iolist_to_binary(
        nhttp_qpack_field_line:encode_representation(
            {indexed, dynamic, 0}, false
        )
    ),
    FieldBin = <<Prefix/binary, Rep/binary>>,
    EncBlock = <<0:64/big, (byte_size(EncData)):32/big, EncData/binary>>,
    FDBlock = <<1:64/big, (byte_size(FieldBin)):32/big, FieldBin/binary>>,
    FileBin = <<EncBlock/binary, FDBlock/binary>>,
    Config = #{max_table_capacity => 4096},
    {ok, Decoded} = nhttp_qpack_interop:decode_from_file(
        FileBin, Config
    ),
    ?assertEqual([[{<<"x-test">>, <<"hello">>}]], Decoded).

%%%-----------------------------------------------------------------------------
%%% FULL ROUNDTRIP TESTS
%%%-----------------------------------------------------------------------------

roundtrip_static_headers(_Config) ->
    Sections = [
        [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
        [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/api">>}]
    ],
    Config = #{max_table_capacity => 0},
    roundtrip_interop(Sections, Config).

roundtrip_dynamic_headers(_Config) ->
    Sections = [
        [
            {<<":method">>, <<"GET">>},
            {<<"x-request-id">>, <<"abc123">>}
        ],
        [
            {<<":method">>, <<"GET">>},
            {<<"x-request-id">>, <<"def456">>}
        ]
    ],
    Config = #{max_table_capacity => 4096},
    roundtrip_interop(Sections, Config).

roundtrip_multiple_sections(_Config) ->
    Sections = [
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/">>},
            {<<":authority">>, <<"example.com">>}
        ],
        [
            {<<":method">>, <<"GET">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/style.css">>},
            {<<":authority">>, <<"example.com">>}
        ],
        [
            {<<":method">>, <<"POST">>},
            {<<":scheme">>, <<"https">>},
            {<<":path">>, <<"/api/data">>},
            {<<":authority">>, <<"example.com">>},
            {<<"content-type">>, <<"application/json">>}
        ]
    ],
    Config = #{max_table_capacity => 4096},
    roundtrip_interop(Sections, Config).

roundtrip_huffman(_Config) ->
    Sections = [
        [
            {<<":method">>, <<"GET">>},
            {<<":path">>, <<"/">>},
            {<<"accept">>, <<"text/html">>}
        ]
    ],
    Config = #{max_table_capacity => 4096, huffman => true},
    roundtrip_interop(Sections, Config).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec roundtrip_interop(
    nhttp_qpack_interop:qif(), nhttp_qpack_interop:interop_config()
) -> ok.
roundtrip_interop(Sections, Config) ->
    {ok, IoData} = nhttp_qpack_interop:encode_to_file(
        Sections, Config
    ),
    Bin = iolist_to_binary(IoData),
    {ok, Decoded} = nhttp_qpack_interop:decode_from_file(
        Bin, Config
    ),
    ?assertEqual(Sections, Decoded).
