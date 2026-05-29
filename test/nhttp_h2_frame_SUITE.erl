%%%-----------------------------------------------------------------------------
-module(nhttp_h2_frame_SUITE).

-moduledoc "HTTP/2 frame encoding/decoding test suite.".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, encoding},
        {group, decoding},
        {group, roundtrip},
        {group, validation},
        {group, settings},
        {group, incomplete}
    ].

groups() ->
    [
        {encoding, [parallel], [
            encode_data,
            encode_headers,
            encode_headers_with_priority,
            encode_priority,
            encode_rst_stream,
            encode_settings,
            encode_settings_ack,
            encode_push_promise,
            encode_ping,
            encode_ping_ack,
            encode_goaway,
            encode_window_update_connection,
            encode_window_update_stream,
            encode_continuation,
            encode_headers_with_continuation
        ]},
        {decoding, [parallel], [
            decode_preface,
            decode_data,
            decode_data_with_padding,
            decode_headers,
            decode_headers_with_padding,
            decode_headers_with_priority,
            decode_headers_with_padding_and_priority,
            decode_priority,
            decode_rst_stream,
            decode_settings,
            decode_settings_ack,
            decode_push_promise,
            decode_push_promise_with_padding,
            decode_ping,
            decode_ping_ack,
            decode_goaway,
            decode_goaway_with_debug,
            decode_window_update_connection,
            decode_window_update_stream,
            decode_continuation,
            decode_unknown_frame_ignored
        ]},
        {roundtrip, [parallel], [
            roundtrip_data,
            roundtrip_headers,
            roundtrip_headers_with_priority,
            roundtrip_priority,
            roundtrip_rst_stream,
            roundtrip_settings,
            roundtrip_ping,
            roundtrip_goaway,
            roundtrip_window_update,
            roundtrip_continuation
        ]},
        {validation, [parallel], [
            reject_data_stream_id_zero,
            reject_headers_stream_id_zero,
            reject_headers_self_dependency,
            reject_priority_stream_id_zero,
            reject_priority_self_dependency,
            reject_priority_wrong_length,
            reject_rst_stream_stream_id_zero,
            reject_rst_stream_wrong_length,
            reject_settings_stream_id_nonzero,
            reject_settings_ack_nonzero_length,
            reject_settings_invalid_length,
            reject_settings_invalid_enable_push,
            reject_settings_invalid_initial_window_size,
            reject_settings_invalid_max_frame_size,
            reject_push_promise_stream_id_zero,
            reject_ping_stream_id_nonzero,
            reject_ping_wrong_length,
            reject_goaway_stream_id_nonzero,
            reject_goaway_wrong_length,
            reject_window_update_wrong_length,
            reject_window_update_zero_increment_connection,
            reject_window_update_zero_increment_stream,
            reject_continuation_stream_id_zero,
            reject_frame_exceeds_max_size,
            reject_invalid_padding
        ]},
        {settings, [parallel], [
            settings_header_table_size,
            settings_enable_push,
            settings_max_concurrent_streams,
            settings_initial_window_size,
            settings_max_frame_size,
            settings_max_header_list_size,
            settings_enable_connect_protocol,
            settings_unknown_ignored
        ]},
        {incomplete, [parallel], [
            incomplete_frame_header,
            incomplete_frame_payload,
            incomplete_returns_min_bytes
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
%%% ENCODING TESTS
%%%-----------------------------------------------------------------------------

encode_data(_Config) ->
    {ok, Frame} = nhttp_h2_frame:data(1, fin, <<"hello">>),
    Bin = iolist_to_binary(Frame),
    ?assertMatch(<<5:24, 0:8, 1:8, 0:1, 1:31, "hello">>, Bin).

encode_headers(_Config) ->
    {ok, Frame} = nhttp_h2_frame:headers(1, fin, fin, <<"header block">>),
    Bin = iolist_to_binary(Frame),
    ?assertMatch(<<12:24, 1:8, 5:8, 0:1, 1:31, "header block">>, Bin).

encode_headers_with_priority(_Config) ->
    Priority = #{exclusive => true, stream_dependency => 0, weight => 16},
    {ok, Frame} = nhttp_h2_frame:headers(3, nofin, fin, Priority, <<"hdr">>),
    Bin = iolist_to_binary(Frame),
    ?assertMatch(<<8:24, 1:8, 16#24:8, 0:1, 3:31, 1:1, 0:31, 15:8, "hdr">>, Bin).

encode_priority(_Config) ->
    Priority = #{exclusive => false, stream_dependency => 1, weight => 256},
    {ok, Frame} = nhttp_h2_frame:priority(3, Priority),
    ?assertMatch(<<5:24, 2:8, 0:8, 0:1, 3:31, 0:1, 1:31, 255:8>>, Frame).

encode_rst_stream(_Config) ->
    {ok, Frame} = nhttp_h2_frame:rst_stream(1, cancel),
    ?assertMatch(<<4:24, 3:8, 0:8, 0:1, 1:31, 8:32>>, Frame).

encode_settings(_Config) ->
    Settings = #{initial_window_size => 65535, max_concurrent_streams => 100},
    {ok, Frame} = nhttp_h2_frame:settings(Settings),
    Bin = iolist_to_binary(Frame),
    <<12:24, 4:8, 0:8, 0:32, Payload:12/binary>> = Bin,
    {ok, Decoded} = nhttp_h2_frame:decode_settings_payload(Payload),
    ?assertEqual(65535, maps:get(initial_window_size, Decoded)),
    ?assertEqual(100, maps:get(max_concurrent_streams, Decoded)).

encode_settings_ack(_Config) ->
    {ok, Frame} = nhttp_h2_frame:settings_ack(),
    ?assertEqual(<<0:24, 4:8, 1:8, 0:32>>, Frame).

encode_push_promise(_Config) ->
    {ok, Frame} = nhttp_h2_frame:push_promise(1, 2, fin, <<"headers">>),
    Bin = iolist_to_binary(Frame),
    ?assertMatch(<<11:24, 5:8, 4:8, 0:1, 1:31, 0:1, 2:31, "headers">>, Bin).

encode_ping(_Config) ->
    OpaqueData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, Frame} = nhttp_h2_frame:ping(OpaqueData),
    ?assertEqual(<<8:24, 6:8, 0:8, 0:32, 1, 2, 3, 4, 5, 6, 7, 8>>, Frame).

encode_ping_ack(_Config) ->
    OpaqueData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, Frame} = nhttp_h2_frame:ping_ack(OpaqueData),
    ?assertEqual(<<8:24, 6:8, 1:8, 0:32, 1, 2, 3, 4, 5, 6, 7, 8>>, Frame).

encode_goaway(_Config) ->
    {ok, Frame} = nhttp_h2_frame:goaway(5, protocol_error, <<"debug">>),
    Bin = iolist_to_binary(Frame),
    ?assertMatch(<<13:24, 7:8, 0:8, 0:32, 0:1, 5:31, 1:32, "debug">>, Bin).

encode_window_update_connection(_Config) ->
    {ok, Frame} = nhttp_h2_frame:window_update(1000),
    ?assertEqual(<<4:24, 8:8, 0:8, 0:32, 0:1, 1000:31>>, Frame).

encode_window_update_stream(_Config) ->
    {ok, Frame} = nhttp_h2_frame:window_update(1, 2000),
    ?assertEqual(<<4:24, 8:8, 0:8, 0:1, 1:31, 0:1, 2000:31>>, Frame).

encode_continuation(_Config) ->
    {ok, Frame} = nhttp_h2_frame:continuation(1, fin, <<"more headers">>),
    Bin = iolist_to_binary(Frame),
    ?assertMatch(<<12:24, 9:8, 4:8, 0:1, 1:31, "more headers">>, Bin).

encode_headers_with_continuation(_Config) ->
    HeaderBlock = binary:copy(<<"x">>, 100),
    MaxFrameSize = 30,
    {ok, Frames} = nhttp_h2_frame:headers_with_continuation(1, fin, HeaderBlock, MaxFrameSize),
    Bin = iolist_to_binary(Frames),
    {ok, {headers, 1, fin, nofin, Block1}, Consumed1} = nhttp_h2_frame:decode(Bin),
    Rest1 = nhttp_h2_frame:split_at(Bin, Consumed1),
    {ok, {continuation, 1, nofin, Block2}, Consumed2} = nhttp_h2_frame:decode(Rest1),
    Rest2 = nhttp_h2_frame:split_at(Rest1, Consumed2),
    {ok, {continuation, 1, nofin, Block3}, Consumed3} = nhttp_h2_frame:decode(Rest2),
    Rest3 = nhttp_h2_frame:split_at(Rest2, Consumed3),
    {ok, {continuation, 1, fin, Block4}, Consumed4} = nhttp_h2_frame:decode(Rest3),
    ?assertEqual(Consumed4, byte_size(Rest3)),
    Reassembled = <<Block1/binary, Block2/binary, Block3/binary, Block4/binary>>,
    ?assertEqual(HeaderBlock, Reassembled).

%%%-----------------------------------------------------------------------------
%%% DECODING TESTS
%%%-----------------------------------------------------------------------------

decode_preface(_Config) ->
    Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
    {ok, preface, 24} = nhttp_h2_frame:decode(Preface),
    WithExtra = <<Preface/binary, "extra">>,
    {ok, preface, 24} = nhttp_h2_frame:decode(WithExtra),
    <<"extra">> = nhttp_h2_frame:split_at(WithExtra, 24).

decode_data(_Config) ->
    Frame = <<5:24, 0:8, 1:8, 0:1, 1:31, "hello">>,
    {ok, {data, 1, fin, <<"hello">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_data_with_padding(_Config) ->
    Frame = <<8:24, 0:8, 16#09:8, 0:1, 1:31, 2:8, "hello", 0:16>>,
    {ok, {data, 1, fin, <<"hello">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_headers(_Config) ->
    Frame = <<5:24, 1:8, 5:8, 0:1, 1:31, "block">>,
    {ok, {headers, 1, fin, fin, <<"block">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_headers_with_padding(_Config) ->
    Frame = <<8:24, 1:8, 16#0D:8, 0:1, 1:31, 2:8, "block", 0:16>>,
    {ok, {headers, 1, fin, fin, <<"block">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_headers_with_priority(_Config) ->
    Frame = <<10:24, 1:8, 16#25:8, 0:1, 3:31, 1:1, 0:31, 15:8, "block">>,
    {ok, {headers, 3, fin, fin, Priority, <<"block">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(#{exclusive => true, stream_dependency => 0, weight => 16}, Priority),
    ?assertEqual(byte_size(Frame), Consumed).

decode_headers_with_padding_and_priority(_Config) ->
    Frame = <<13:24, 1:8, 16#2D:8, 0:1, 3:31, 2:8, 0:1, 0:31, 15:8, "block", 0:16>>,
    {ok, {headers, 3, fin, fin, Priority, <<"block">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(#{exclusive => false, stream_dependency => 0, weight => 16}, Priority),
    ?assertEqual(byte_size(Frame), Consumed).

decode_priority(_Config) ->
    Frame = <<5:24, 2:8, 0:8, 0:1, 3:31, 1:1, 1:31, 255:8>>,
    {ok, {priority, 3, Priority}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(#{exclusive => true, stream_dependency => 1, weight => 256}, Priority),
    ?assertEqual(byte_size(Frame), Consumed).

decode_rst_stream(_Config) ->
    Frame = <<4:24, 3:8, 0:8, 0:1, 1:31, 8:32>>,
    {ok, {rst_stream, 1, cancel}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_settings(_Config) ->
    Payload = <<4:16, 65535:32, 3:16, 100:32>>,
    Frame = <<12:24, 4:8, 0:8, 0:32, Payload/binary>>,
    {ok, {settings, Settings}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(65535, maps:get(initial_window_size, Settings)),
    ?assertEqual(100, maps:get(max_concurrent_streams, Settings)),
    ?assertEqual(byte_size(Frame), Consumed).

decode_settings_ack(_Config) ->
    Frame = <<0:24, 4:8, 1:8, 0:32>>,
    {ok, settings_ack, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_push_promise(_Config) ->
    Frame = <<11:24, 5:8, 4:8, 0:1, 1:31, 0:1, 2:31, "headers">>,
    {ok, {push_promise, 1, fin, 2, <<"headers">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_push_promise_with_padding(_Config) ->
    Frame = <<14:24, 5:8, 16#0C:8, 0:1, 1:31, 2:8, 0:1, 2:31, "headers", 0:16>>,
    {ok, {push_promise, 1, fin, 2, <<"headers">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_ping(_Config) ->
    Frame = <<8:24, 6:8, 0:8, 0:32, 1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, {ping, <<1, 2, 3, 4, 5, 6, 7, 8>>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_ping_ack(_Config) ->
    Frame = <<8:24, 6:8, 1:8, 0:32, 1, 2, 3, 4, 5, 6, 7, 8>>,
    {ok, {ping_ack, <<1, 2, 3, 4, 5, 6, 7, 8>>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_goaway(_Config) ->
    Frame = <<8:24, 7:8, 0:8, 0:32, 0:1, 5:31, 1:32>>,
    {ok, {goaway, 5, protocol_error, <<>>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_goaway_with_debug(_Config) ->
    Frame = <<13:24, 7:8, 0:8, 0:32, 0:1, 5:31, 1:32, "debug">>,
    {ok, {goaway, 5, protocol_error, <<"debug">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_window_update_connection(_Config) ->
    Frame = <<4:24, 8:8, 0:8, 0:32, 0:1, 1000:31>>,
    {ok, {window_update, 1000}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_window_update_stream(_Config) ->
    Frame = <<4:24, 8:8, 0:8, 0:1, 1:31, 0:1, 2000:31>>,
    {ok, {window_update, 1, 2000}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_continuation(_Config) ->
    Frame = <<5:24, 9:8, 4:8, 0:1, 1:31, "block">>,
    {ok, {continuation, 1, fin, <<"block">>}, Consumed} = nhttp_h2_frame:decode(Frame),
    ?assertEqual(byte_size(Frame), Consumed).

decode_unknown_frame_ignored(_Config) ->
    UnknownFrame = <<5:24, 10:8, 0:8, 0:1, 1:31, "xxxxx">>,
    {ok, {unknown, 10}, Consumed} = nhttp_h2_frame:decode(UnknownFrame),
    ?assertEqual(byte_size(UnknownFrame), Consumed).

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP TESTS
%%%-----------------------------------------------------------------------------

roundtrip_data(_Config) ->
    Original = {data, 1, fin, <<"payload data">>},
    {ok, Frame} = nhttp_h2_frame:data(1, fin, <<"payload data">>),
    Encoded = iolist_to_binary(Frame),
    {ok, Decoded, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(Original, Decoded),
    ?assertEqual(byte_size(Encoded), Consumed).

roundtrip_headers(_Config) ->
    Original = {headers, 1, nofin, fin, <<"header block">>},
    {ok, Frame} = nhttp_h2_frame:headers(1, nofin, fin, <<"header block">>),
    Encoded = iolist_to_binary(Frame),
    {ok, Decoded, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(Original, Decoded),
    ?assertEqual(byte_size(Encoded), Consumed).

roundtrip_headers_with_priority(_Config) ->
    Priority = #{exclusive => true, stream_dependency => 0, weight => 16},
    Original = {headers, 3, fin, fin, Priority, <<"hdr">>},
    {ok, Frame} = nhttp_h2_frame:headers(3, fin, fin, Priority, <<"hdr">>),
    Encoded = iolist_to_binary(Frame),
    {ok, Decoded, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(Original, Decoded),
    ?assertEqual(byte_size(Encoded), Consumed).

roundtrip_priority(_Config) ->
    Priority = #{exclusive => false, stream_dependency => 5, weight => 100},
    Original = {priority, 3, Priority},
    {ok, Encoded} = nhttp_h2_frame:priority(3, Priority),
    {ok, Decoded, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(Original, Decoded),
    ?assertEqual(byte_size(Encoded), Consumed).

roundtrip_rst_stream(_Config) ->
    Original = {rst_stream, 1, cancel},
    {ok, Encoded} = nhttp_h2_frame:rst_stream(1, cancel),
    {ok, Decoded, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(Original, Decoded),
    ?assertEqual(byte_size(Encoded), Consumed).

roundtrip_settings(_Config) ->
    Settings = #{
        initial_window_size => 1048576,
        max_concurrent_streams => 200,
        enable_push => false
    },
    {ok, Frame} = nhttp_h2_frame:settings(Settings),
    Encoded = iolist_to_binary(Frame),
    {ok, {settings, Decoded}, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(1048576, maps:get(initial_window_size, Decoded)),
    ?assertEqual(200, maps:get(max_concurrent_streams, Decoded)),
    ?assertEqual(false, maps:get(enable_push, Decoded)),
    ?assertEqual(byte_size(Encoded), Consumed).

roundtrip_ping(_Config) ->
    OpaqueData = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Original = {ping, OpaqueData},
    {ok, Encoded} = nhttp_h2_frame:ping(OpaqueData),
    {ok, Decoded, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(Original, Decoded),
    ?assertEqual(byte_size(Encoded), Consumed).

roundtrip_goaway(_Config) ->
    Original = {goaway, 10, internal_error, <<"error info">>},
    {ok, Frame} = nhttp_h2_frame:goaway(10, internal_error, <<"error info">>),
    Encoded = iolist_to_binary(Frame),
    {ok, Decoded, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(Original, Decoded),
    ?assertEqual(byte_size(Encoded), Consumed).

roundtrip_window_update(_Config) ->
    {ok, WuConn} = nhttp_h2_frame:window_update(1000),
    {ok, {window_update, 1000}, ConsumedConn} = nhttp_h2_frame:decode(WuConn),
    ?assertEqual(byte_size(WuConn), ConsumedConn),
    {ok, WuStream} = nhttp_h2_frame:window_update(1, 2000),
    {ok, {window_update, 1, 2000}, ConsumedStream} = nhttp_h2_frame:decode(WuStream),
    ?assertEqual(byte_size(WuStream), ConsumedStream).

roundtrip_continuation(_Config) ->
    Original = {continuation, 1, fin, <<"more headers">>},
    {ok, Frame} = nhttp_h2_frame:continuation(1, fin, <<"more headers">>),
    Encoded = iolist_to_binary(Frame),
    {ok, Decoded, Consumed} = nhttp_h2_frame:decode(Encoded),
    ?assertEqual(Original, Decoded),
    ?assertEqual(byte_size(Encoded), Consumed).

%%%-----------------------------------------------------------------------------
%%% VALIDATION TESTS
%%%-----------------------------------------------------------------------------

reject_data_stream_id_zero(_Config) ->
    Frame = <<5:24, 0:8, 0:8, 0:32, "hello">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_headers_stream_id_zero(_Config) ->
    Frame = <<5:24, 1:8, 4:8, 0:32, "block">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_headers_self_dependency(_Config) ->
    Frame = <<10:24, 1:8, 16#24:8, 0:1, 1:31, 0:1, 1:31, 15:8, "block">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_priority_stream_id_zero(_Config) ->
    Frame = <<5:24, 2:8, 0:8, 0:32, 0:1, 1:31, 15:8>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_priority_self_dependency(_Config) ->
    Frame = <<5:24, 2:8, 0:8, 0:1, 1:31, 0:1, 1:31, 15:8>>,
    {error, {stream_error, 1, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_priority_wrong_length(_Config) ->
    Frame = <<4:24, 2:8, 0:8, 0:1, 1:31, 0:1, 1:31>>,
    {error, {stream_error, 1, frame_size_error, _}} = nhttp_h2_frame:decode(Frame).

reject_rst_stream_stream_id_zero(_Config) ->
    Frame = <<4:24, 3:8, 0:8, 0:32, 0:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_rst_stream_wrong_length(_Config) ->
    Frame = <<5:24, 3:8, 0:8, 0:1, 1:31, 0:40>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame).

reject_settings_stream_id_nonzero(_Config) ->
    Frame = <<0:24, 4:8, 0:8, 0:1, 1:31>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_settings_ack_nonzero_length(_Config) ->
    Frame = <<6:24, 4:8, 1:8, 0:32, 1:16, 100:32>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame).

reject_settings_invalid_length(_Config) ->
    Frame = <<5:24, 4:8, 0:8, 0:32, "12345">>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame).

reject_settings_invalid_enable_push(_Config) ->
    Frame = <<6:24, 4:8, 0:8, 0:32, 2:16, 2:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_settings_invalid_initial_window_size(_Config) ->
    Frame = <<6:24, 4:8, 0:8, 0:32, 4:16, 16#80000000:32>>,
    {error, {connection_error, flow_control_error, _}} = nhttp_h2_frame:decode(Frame).

reject_settings_invalid_max_frame_size(_Config) ->
    Frame = <<6:24, 4:8, 0:8, 0:32, 5:16, 16#3FFF:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame),
    Frame2 = <<6:24, 4:8, 0:8, 0:32, 5:16, 16#1000000:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame2).

reject_push_promise_stream_id_zero(_Config) ->
    Frame = <<4:24, 5:8, 4:8, 0:32, 0:1, 2:31>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_ping_stream_id_nonzero(_Config) ->
    Frame = <<8:24, 6:8, 0:8, 0:1, 1:31, 0:64>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_ping_wrong_length(_Config) ->
    Frame = <<7:24, 6:8, 0:8, 0:32, 0:56>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame).

reject_goaway_stream_id_nonzero(_Config) ->
    Frame = <<8:24, 7:8, 0:8, 0:1, 1:31, 0:1, 0:31, 0:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_goaway_wrong_length(_Config) ->
    Frame = <<7:24, 7:8, 0:8, 0:32, 0:56>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame).

reject_window_update_wrong_length(_Config) ->
    Frame = <<5:24, 8:8, 0:8, 0:32, 0:40>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame).

reject_window_update_zero_increment_connection(_Config) ->
    Frame = <<4:24, 8:8, 0:8, 0:32, 0:32>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_window_update_zero_increment_stream(_Config) ->
    Frame = <<4:24, 8:8, 0:8, 0:1, 1:31, 0:32>>,
    {error, {stream_error, 1, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_continuation_stream_id_zero(_Config) ->
    Frame = <<5:24, 9:8, 4:8, 0:32, "block">>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

reject_frame_exceeds_max_size(_Config) ->
    Frame = <<16400:24, 0:8, 0:8, 0:1, 1:31, 0:16400/unit:8>>,
    {error, {connection_error, frame_size_error, _}} = nhttp_h2_frame:decode(Frame, 16384).

reject_invalid_padding(_Config) ->
    Frame = <<8:24, 0:8, 16#09:8, 0:1, 1:31, 2:8, "hello", 1, 0>>,
    {error, {connection_error, protocol_error, _}} = nhttp_h2_frame:decode(Frame).

%%%-----------------------------------------------------------------------------
%%% SETTINGS TESTS
%%%-----------------------------------------------------------------------------

settings_header_table_size(_Config) ->
    Payload = <<1:16, 8192:32>>,
    {ok, Settings} = nhttp_h2_frame:decode_settings_payload(Payload),
    ?assertEqual(8192, maps:get(header_table_size, Settings)).

settings_enable_push(_Config) ->
    {ok, S1} = nhttp_h2_frame:decode_settings_payload(<<2:16, 0:32>>),
    ?assertEqual(false, maps:get(enable_push, S1)),
    {ok, S2} = nhttp_h2_frame:decode_settings_payload(<<2:16, 1:32>>),
    ?assertEqual(true, maps:get(enable_push, S2)).

settings_max_concurrent_streams(_Config) ->
    {ok, Settings} = nhttp_h2_frame:decode_settings_payload(<<3:16, 100:32>>),
    ?assertEqual(100, maps:get(max_concurrent_streams, Settings)).

settings_initial_window_size(_Config) ->
    {ok, Settings} = nhttp_h2_frame:decode_settings_payload(<<4:16, 1048576:32>>),
    ?assertEqual(1048576, maps:get(initial_window_size, Settings)).

settings_max_frame_size(_Config) ->
    {ok, Settings} = nhttp_h2_frame:decode_settings_payload(<<5:16, 32768:32>>),
    ?assertEqual(32768, maps:get(max_frame_size, Settings)).

settings_max_header_list_size(_Config) ->
    {ok, Settings} = nhttp_h2_frame:decode_settings_payload(<<6:16, 65536:32>>),
    ?assertEqual(65536, maps:get(max_header_list_size, Settings)).

settings_enable_connect_protocol(_Config) ->
    {ok, S1} = nhttp_h2_frame:decode_settings_payload(<<8:16, 0:32>>),
    ?assertEqual(false, maps:get(enable_connect_protocol, S1)),
    {ok, S2} = nhttp_h2_frame:decode_settings_payload(<<8:16, 1:32>>),
    ?assertEqual(true, maps:get(enable_connect_protocol, S2)).

settings_unknown_ignored(_Config) ->
    {ok, Settings} = nhttp_h2_frame:decode_settings_payload(<<99:16, 12345:32>>),
    ?assertEqual(#{}, Settings).

%%%-----------------------------------------------------------------------------
%%% INCOMPLETE FRAME TESTS
%%%-----------------------------------------------------------------------------

incomplete_frame_header(_Config) ->
    {more, 9} = nhttp_h2_frame:decode(<<>>),
    {more, 5} = nhttp_h2_frame:decode(<<0, 0, 5, 0>>),
    {more, 1} = nhttp_h2_frame:decode(<<0, 0, 5, 0, 0, 0, 0, 0>>).

incomplete_frame_payload(_Config) ->
    {more, 5} = nhttp_h2_frame:decode(<<10:24, 0:8, 0:8, 0:1, 1:31, "hello">>).

incomplete_returns_min_bytes(_Config) ->
    {more, N1} = nhttp_h2_frame:decode(<<>>),
    ?assertEqual(9, N1),
    {more, N2} = nhttp_h2_frame:decode(<<0, 0, 100, 0, 0, 0, 0, 0, 0>>),
    ?assertEqual(100, N2).
