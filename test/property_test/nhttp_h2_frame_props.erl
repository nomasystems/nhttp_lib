%%%-----------------------------------------------------------------------------
-module(nhttp_h2_frame_props).

-moduledoc """
HTTP/2 Frame Codec Property Tests.

These properties are run via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").



-spec prop_data_roundtrip() -> triq:property().
prop_data_roundtrip() ->
    ?FORALL(
        {StreamId, EndStream, Payload},
        {stream_id_gen(), fin_gen(), binary()},
        begin
            {ok, Frame} = nhttp_h2_frame:data(StreamId, EndStream, Payload),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {data, StreamId, EndStream, Payload}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_headers_roundtrip() -> triq:property().
prop_headers_roundtrip() ->
    ?FORALL(
        {StreamId, EndStream, EndHeaders, HeaderBlock},
        {stream_id_gen(), fin_gen(), fin_gen(), binary()},
        begin
            {ok, Frame} = nhttp_h2_frame:headers(StreamId, EndStream, EndHeaders, HeaderBlock),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {headers, StreamId, EndStream, EndHeaders, HeaderBlock}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_headers_priority_roundtrip() -> triq:property().
prop_headers_priority_roundtrip() ->
    ?FORALL(
        {StreamId, EndStream, EndHeaders, Priority, HeaderBlock},
        {stream_id_gen(), fin_gen(), fin_gen(), priority_gen(), binary()},
        begin
            SafePriority = ensure_no_self_dependency(StreamId, Priority),
            {ok, Frame} = nhttp_h2_frame:headers(
                StreamId, EndStream, EndHeaders, SafePriority, HeaderBlock
            ),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {headers, StreamId, EndStream, EndHeaders, SafePriority, HeaderBlock},
                    Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_priority_roundtrip() -> triq:property().
prop_priority_roundtrip() ->
    ?FORALL(
        {StreamId, Priority},
        {stream_id_gen(), priority_gen()},
        begin
            SafePriority = ensure_no_self_dependency(StreamId, Priority),
            {ok, Encoded} = nhttp_h2_frame:priority(StreamId, SafePriority),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {priority, StreamId, SafePriority}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_rst_stream_roundtrip() -> triq:property().
prop_rst_stream_roundtrip() ->
    ?FORALL(
        {StreamId, ErrorCode},
        {stream_id_gen(), error_code_gen()},
        begin
            {ok, Encoded} = nhttp_h2_frame:rst_stream(StreamId, ErrorCode),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {rst_stream, StreamId, ErrorCode}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_settings_roundtrip() -> triq:property().
prop_settings_roundtrip() ->
    ?FORALL(
        Settings,
        settings_gen(),
        begin
            {ok, Frame} = nhttp_h2_frame:settings(Settings),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {settings, DecodedSettings}, Consumed} ->
                    Consumed =:= byte_size(Encoded) andalso
                        settings_equivalent(Settings, DecodedSettings);
                _ ->
                    false
            end
        end
    ).

-spec prop_push_promise_roundtrip() -> triq:property().
prop_push_promise_roundtrip() ->
    ?FORALL(
        {StreamId, PromisedStreamId, EndHeaders, HeaderBlock},
        {stream_id_gen(), stream_id_gen(), fin_gen(), binary()},
        begin
            {ok, Frame} = nhttp_h2_frame:push_promise(
                StreamId, PromisedStreamId, EndHeaders, HeaderBlock
            ),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {push_promise, StreamId, EndHeaders, PromisedStreamId, HeaderBlock}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_ping_roundtrip() -> triq:property().
prop_ping_roundtrip() ->
    ?FORALL(
        OpaqueData,
        binary(8),
        begin
            {ok, Encoded} = nhttp_h2_frame:ping(OpaqueData),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {ping, OpaqueData}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_goaway_roundtrip() -> triq:property().
prop_goaway_roundtrip() ->
    ?FORALL(
        {LastStreamId, ErrorCode, DebugData},
        {non_neg_integer(), error_code_gen(), binary()},
        begin
            SafeLastStreamId = LastStreamId band 16#7FFFFFFF,
            {ok, Frame} = nhttp_h2_frame:goaway(SafeLastStreamId, ErrorCode, DebugData),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {goaway, SafeLastStreamId, ErrorCode, DebugData}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_window_update_conn_roundtrip() -> triq:property().
prop_window_update_conn_roundtrip() ->
    ?FORALL(
        Increment,
        window_increment_gen(),
        begin
            {ok, Encoded} = nhttp_h2_frame:window_update(Increment),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {window_update, Increment}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_window_update_stream_roundtrip() -> triq:property().
prop_window_update_stream_roundtrip() ->
    ?FORALL(
        {StreamId, Increment},
        {stream_id_gen(), window_increment_gen()},
        begin
            {ok, Encoded} = nhttp_h2_frame:window_update(StreamId, Increment),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {window_update, StreamId, Increment}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_continuation_roundtrip() -> triq:property().
prop_continuation_roundtrip() ->
    ?FORALL(
        {StreamId, EndHeaders, HeaderBlock},
        {stream_id_gen(), fin_gen(), binary()},
        begin
            {ok, Frame} = nhttp_h2_frame:continuation(StreamId, EndHeaders, HeaderBlock),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, {continuation, StreamId, EndHeaders, HeaderBlock}, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).


-spec prop_split_at() -> triq:property().
prop_split_at() ->
    ?FORALL(
        {StreamId, Payload, ExtraData},
        {stream_id_gen(), binary(), binary()},
        begin
            {ok, Frame} = nhttp_h2_frame:data(StreamId, fin, Payload),
            Encoded = iolist_to_binary(Frame),
            FullData = <<Encoded/binary, ExtraData/binary>>,
            case nhttp_h2_frame:decode(FullData) of
                {ok, _Frame, Consumed} ->
                    Rest = nhttp_h2_frame:split_at(FullData, Consumed),
                    Rest =:= ExtraData;
                _ ->
                    false
            end
        end
    ).

-spec prop_decode_all() -> triq:property().
prop_decode_all() ->
    ?FORALL(
        Frames,
        non_empty(list(frame_gen())),
        begin
            EncodedList = [iolist_to_binary(encode_frame(F)) || F <- Frames],
            Combined = iolist_to_binary(EncodedList),

            case nhttp_h2_frame:decode_all(Combined) of
                {ok, DecodedFrames, TotalConsumed} ->
                    TotalConsumed =:= byte_size(Combined) andalso
                        length(DecodedFrames) =:= length(Frames) andalso
                        frames_equivalent(Frames, DecodedFrames);
                _ ->
                    false
            end
        end
    ).

-spec prop_bytes_consumed_correct() -> triq:property().
prop_bytes_consumed_correct() ->
    ?FORALL(
        Frame,
        frame_gen(),
        begin
            Encoded = iolist_to_binary(encode_frame(Frame)),
            case nhttp_h2_frame:decode(Encoded) of
                {ok, _DecodedFrame, Consumed} ->
                    Consumed =:= byte_size(Encoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_incomplete_returns_more() -> triq:property().
prop_incomplete_returns_more() ->
    ?FORALL(
        {Frame, CutAt},
        {frame_gen(), pos_integer()},
        begin
            Encoded = iolist_to_binary(encode_frame(Frame)),
            FrameSize = byte_size(Encoded),
            ActualCut = (CutAt rem FrameSize) + 1,
            case ActualCut < FrameSize of
                true ->
                    <<Partial:ActualCut/binary, _/binary>> = Encoded,
                    case nhttp_h2_frame:decode(Partial) of
                        {more, MinBytes} when MinBytes > 0 ->
                            true;
                        _ ->
                            false
                    end;
                false ->
                    true
            end
        end
    ).

-spec prop_preface_roundtrip() -> triq:property().
prop_preface_roundtrip() ->
    ?FORALL(
        ExtraData,
        binary(),
        begin
            {ok, Preface} = nhttp_h2_frame:preface(),
            FullData = <<Preface/binary, ExtraData/binary>>,
            case nhttp_h2_frame:decode(FullData) of
                {ok, preface, 24} ->
                    Rest = nhttp_h2_frame:split_at(FullData, 24),
                    Rest =:= ExtraData;
                _ ->
                    false
            end
        end
    ).


-spec stream_id_gen() -> triq_dom:domain().
stream_id_gen() ->
    int(1, 16#7FFFFFFF).

-spec fin_gen() -> triq_dom:domain().
fin_gen() ->
    oneof([fin, nofin]).

-spec priority_gen() -> triq_dom:domain().
priority_gen() ->
    ?LET(
        {Exclusive, DepStreamId, Weight},
        {bool(), int(0, 16#7FFFFFFF), int(1, 256)},
        #{exclusive => Exclusive, stream_dependency => DepStreamId, weight => Weight}
    ).

-spec error_code_gen() -> triq_dom:domain().
error_code_gen() ->
    oneof([
        no_error,
        protocol_error,
        internal_error,
        flow_control_error,
        settings_timeout,
        stream_closed,
        frame_size_error,
        refused_stream,
        cancel,
        compression_error,
        connect_error,
        enhance_your_calm,
        inadequate_security,
        http_1_1_required
    ]).

-spec settings_gen() -> triq_dom:domain().
settings_gen() ->
    ?LET(
        SettingsList,
        list(setting_gen()),
        maps:from_list(SettingsList)
    ).

-spec setting_gen() -> triq_dom:domain().
setting_gen() ->
    oneof([
        ?LET(V, int(0, 16#FFFFFFFF), {header_table_size, V}),
        {enable_push, bool()},
        ?LET(V, int(1, 16#FFFFFFFF), {max_concurrent_streams, V}),
        ?LET(V, int(1, 16#7FFFFFFF), {initial_window_size, V}),
        ?LET(V, int(16#4000, 16#FFFFFF), {max_frame_size, V}),
        ?LET(V, int(1, 16#FFFFFFFF), {max_header_list_size, V}),
        {enable_connect_protocol, bool()}
    ]).

-spec window_increment_gen() -> triq_dom:domain().
window_increment_gen() ->
    int(1, 16#7FFFFFFF).

-spec frame_gen() -> triq_dom:domain().
frame_gen() ->
    oneof([
        data_frame_gen(),
        headers_frame_gen(),
        priority_frame_gen(),
        rst_stream_frame_gen(),
        ping_frame_gen(),
        goaway_frame_gen(),
        window_update_conn_frame_gen(),
        window_update_stream_frame_gen(),
        continuation_frame_gen()
    ]).

-spec data_frame_gen() -> triq_dom:domain().
data_frame_gen() ->
    ?LET(
        {StreamId, EndStream, Payload},
        {stream_id_gen(), fin_gen(), binary()},
        {data, StreamId, EndStream, Payload}
    ).

-spec headers_frame_gen() -> triq_dom:domain().
headers_frame_gen() ->
    ?LET(
        {StreamId, EndStream, EndHeaders, HeaderBlock},
        {stream_id_gen(), fin_gen(), fin_gen(), binary()},
        {headers, StreamId, EndStream, EndHeaders, HeaderBlock}
    ).

-spec priority_frame_gen() -> triq_dom:domain().
priority_frame_gen() ->
    ?LET(
        {StreamId, Priority},
        {stream_id_gen(), priority_gen()},
        begin
            SafePriority = ensure_no_self_dependency(StreamId, Priority),
            {priority, StreamId, SafePriority}
        end
    ).

-spec rst_stream_frame_gen() -> triq_dom:domain().
rst_stream_frame_gen() ->
    ?LET(
        {StreamId, ErrorCode},
        {stream_id_gen(), error_code_gen()},
        {rst_stream, StreamId, ErrorCode}
    ).

-spec ping_frame_gen() -> triq_dom:domain().
ping_frame_gen() ->
    ?LET(
        OpaqueData,
        binary(8),
        {ping, OpaqueData}
    ).

-spec goaway_frame_gen() -> triq_dom:domain().
goaway_frame_gen() ->
    ?LET(
        {LastStreamId, ErrorCode, DebugData},
        {int(0, 16#7FFFFFFF), error_code_gen(), binary()},
        {goaway, LastStreamId, ErrorCode, DebugData}
    ).

-spec window_update_conn_frame_gen() -> triq_dom:domain().
window_update_conn_frame_gen() ->
    ?LET(
        Increment,
        window_increment_gen(),
        {window_update, Increment}
    ).

-spec window_update_stream_frame_gen() -> triq_dom:domain().
window_update_stream_frame_gen() ->
    ?LET(
        {StreamId, Increment},
        {stream_id_gen(), window_increment_gen()},
        {window_update, StreamId, Increment}
    ).

-spec continuation_frame_gen() -> triq_dom:domain().
continuation_frame_gen() ->
    ?LET(
        {StreamId, EndHeaders, HeaderBlock},
        {stream_id_gen(), fin_gen(), binary()},
        {continuation, StreamId, EndHeaders, HeaderBlock}
    ).


-spec ensure_no_self_dependency(pos_integer(), nhttp_h2:priority()) -> nhttp_h2:priority().
ensure_no_self_dependency(StreamId, Priority = #{stream_dependency := Dep}) when Dep =:= StreamId ->
    Priority#{stream_dependency => 0};
ensure_no_self_dependency(_StreamId, Priority) ->
    Priority.

-spec encode_frame(tuple()) -> iodata().
encode_frame({data, StreamId, EndStream, Payload}) ->
    {ok, Frame} = nhttp_h2_frame:data(StreamId, EndStream, Payload),
    Frame;
encode_frame({headers, StreamId, EndStream, EndHeaders, HeaderBlock}) ->
    {ok, Frame} = nhttp_h2_frame:headers(StreamId, EndStream, EndHeaders, HeaderBlock),
    Frame;
encode_frame({headers, StreamId, EndStream, EndHeaders, Priority, HeaderBlock}) ->
    {ok, Frame} = nhttp_h2_frame:headers(StreamId, EndStream, EndHeaders, Priority, HeaderBlock),
    Frame;
encode_frame({priority, StreamId, Priority}) ->
    {ok, Frame} = nhttp_h2_frame:priority(StreamId, Priority),
    Frame;
encode_frame({rst_stream, StreamId, ErrorCode}) ->
    {ok, Frame} = nhttp_h2_frame:rst_stream(StreamId, ErrorCode),
    Frame;
encode_frame({ping, OpaqueData}) ->
    {ok, Frame} = nhttp_h2_frame:ping(OpaqueData),
    Frame;
encode_frame({goaway, LastStreamId, ErrorCode, DebugData}) ->
    {ok, Frame} = nhttp_h2_frame:goaway(LastStreamId, ErrorCode, DebugData),
    Frame;
encode_frame({window_update, Increment}) ->
    {ok, Frame} = nhttp_h2_frame:window_update(Increment),
    Frame;
encode_frame({window_update, StreamId, Increment}) ->
    {ok, Frame} = nhttp_h2_frame:window_update(StreamId, Increment),
    Frame;
encode_frame({continuation, StreamId, EndHeaders, HeaderBlock}) ->
    {ok, Frame} = nhttp_h2_frame:continuation(StreamId, EndHeaders, HeaderBlock),
    Frame.

-spec settings_equivalent(nhttp_h2:settings(), nhttp_h2:settings()) -> boolean().
settings_equivalent(Original, Decoded) ->
    maps:fold(
        fun
            (max_concurrent_streams, infinity, Acc) ->
                Acc andalso not maps:is_key(max_concurrent_streams, Decoded);
            (max_header_list_size, infinity, Acc) ->
                Acc andalso not maps:is_key(max_header_list_size, Decoded);
            (Key, Value, Acc) ->
                Acc andalso maps:get(Key, Decoded, undefined) =:= Value
        end,
        true,
        Original
    ).

-spec frames_equivalent([tuple()], [tuple()]) -> boolean().
frames_equivalent([], []) ->
    true;
frames_equivalent([F1 | Rest1], [F2 | Rest2]) ->
    frame_equivalent(F1, F2) andalso frames_equivalent(Rest1, Rest2);
frames_equivalent(_, _) ->
    false.

-spec frame_equivalent(tuple(), tuple()) -> boolean().
frame_equivalent({data, S, E, P}, {data, S, E, P}) -> true;
frame_equivalent({headers, S, ES, EH, HB}, {headers, S, ES, EH, HB}) -> true;
frame_equivalent({headers, S, ES, EH, Pr, HB}, {headers, S, ES, EH, Pr, HB}) -> true;
frame_equivalent({priority, S, P}, {priority, S, P}) -> true;
frame_equivalent({rst_stream, S, E}, {rst_stream, S, E}) -> true;
frame_equivalent({ping, D}, {ping, D}) -> true;
frame_equivalent({goaway, L, E, D}, {goaway, L, E, D}) -> true;
frame_equivalent({window_update, I}, {window_update, I}) -> true;
frame_equivalent({window_update, S, I}, {window_update, S, I}) -> true;
frame_equivalent({continuation, S, E, H}, {continuation, S, E, H}) -> true;
frame_equivalent(_, _) -> false.


-spec prop_random_binary_no_crash() -> triq:property().
prop_random_binary_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            _ = (catch nhttp_h2_frame:decode(Bin)),
            _ = (catch nhttp_h2_frame:decode(Bin, 16384)),
            true
        end
    ).

-spec prop_frame_bad_length_no_crash() -> triq:property().
prop_frame_bad_length_no_crash() ->
    ?FORALL(
        {Type, Flags, StreamId, Payload, BadLen},
        {int(0, 255), byte(), non_neg_integer(), binary(), int(0, 16777215)},
        begin
            Frame = <<BadLen:24, Type:8, Flags:8, 0:1, StreamId:31, Payload/binary>>,
            _ = (catch nhttp_h2_frame:decode(Frame)),
            _ = (catch nhttp_h2_frame:decode(Frame, 16384)),
            true
        end
    ).

-spec prop_frame_corrupted_payload_no_crash() -> triq:property().
prop_frame_corrupted_payload_no_crash() ->
    ?FORALL(
        {Frame, Corruption},
        {valid_frame_binary_gen(), binary()},
        begin
            case byte_size(Frame) >= 9 of
                true ->
                    <<Header:9/binary, _Payload/binary>> = Frame,
                    Corrupted = <<Header/binary, Corruption/binary>>,
                    _ = (catch nhttp_h2_frame:decode(Corrupted)),
                    _ = (catch nhttp_h2_frame:decode(Corrupted, 16384)),
                    true;
                false ->
                    true
            end
        end
    ).

-spec prop_oversized_frame_no_crash() -> triq:property().
prop_oversized_frame_no_crash() ->
    ?FORALL(
        {Type, Flags, StreamId, Size},
        {int(0, 9), byte(), int(0, 16#7FFFFFFF), int(16385, 100000)},
        begin
            Payload = binary:copy(<<0>>, min(Size, 50000)),
            Frame = <<(byte_size(Payload)):24, Type:8, Flags:8, 0:1, StreamId:31, Payload/binary>>,
            _ = (catch nhttp_h2_frame:decode(Frame, 16384)),
            true
        end
    ).

-spec valid_frame_binary_gen() -> triq_dom:domain().
valid_frame_binary_gen() ->
    ?LET(
        FrameTuple,
        frame_gen(),
        begin
            iolist_to_binary(encode_frame(FrameTuple))
        end
    ).
