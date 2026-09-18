%%%-----------------------------------------------------------------------------
-module(nhttp_h2_props).

-moduledoc """
HTTP/2 Protocol Layer Property Tests.

These properties are run via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

-spec prop_headers_roundtrip() -> triq:property().
prop_headers_roundtrip() ->
    ?FORALL(
        Headers,
        request_headers_gen(),
        begin
            ClientConn0 = nhttp_h2:new(client),
            {ok, StreamId, ClientConn1} = nhttp_h2:open_stream(ClientConn0),
            {ok, _ClientConn2, Frame} = nhttp_h2:send_headers(ClientConn1, StreamId, Headers, fin),

            ServerConn0 = nhttp_h2:new(server),
            {ok, ClientPreface} = nhttp_h2_frame:preface(),
            Data = <<ClientPreface/binary, (iolist_to_binary(Frame))/binary>>,
            case nhttp_h2:recv(ServerConn0, Data) of
                {ok, [{request, StreamId, Request, fin}], _ServerConn1} ->
                    nhttp_props_helpers:request_matches(Headers, Request);
                _ ->
                    false
            end
        end
    ).

-spec prop_data_roundtrip() -> triq:property().
prop_data_roundtrip() ->
    ?FORALL(
        Data,
        data_gen(),
        begin
            ClientConn0 = nhttp_h2:new(client),
            {ok, StreamId, ClientConn1} = nhttp_h2:open_stream(ClientConn0),
            Headers = [
                {<<":method">>, <<"POST">>}, {<<":scheme">>, <<"https">>}, {<<":path">>, <<"/">>}
            ],
            {ok, ClientConn2, HeaderFrame} = nhttp_h2:send_headers(
                ClientConn1, StreamId, Headers, nofin
            ),
            {ok, _ClientConn3, DataFrames} = nhttp_h2:send_data(ClientConn2, StreamId, Data, fin),
            ServerConn0 = nhttp_h2:new(server),
            {ok, ClientPreface} = nhttp_h2_frame:preface(),
            HeaderData = <<ClientPreface/binary, (iolist_to_binary(HeaderFrame))/binary>>,
            {ok, _, ServerConn1} = nhttp_h2:recv(ServerConn0, HeaderData),
            case nhttp_h2:recv(ServerConn1, iolist_to_binary(DataFrames)) of
                {ok, Events, _} ->
                    data_events_carry(Events, StreamId, Data);
                {ok, Events, _, _} ->
                    data_events_carry(Events, StreamId, Data);
                _ ->
                    false
            end
        end
    ).

-spec data_events_carry([nhttp_h2:event()], nhttp_lib:stream_id(), binary()) -> boolean().
data_events_carry(Events, StreamId, Data) ->
    Fins = [Fin || {data, Id, _, Fin} <- Events, Id =:= StreamId],
    Payloads = [Payload || {data, Id, Payload, _} <- Events, Id =:= StreamId],
    length(Events) =:= length(Fins) andalso
        Fins =:= lists:duplicate(length(Fins) - 1, nofin) ++ [fin] andalso
        iolist_to_binary(Payloads) =:= Data.

-spec prop_request_response_roundtrip() -> triq:property().
prop_request_response_roundtrip() ->
    ?FORALL(
        {ReqHeaders, RespHeaders},
        {request_headers_gen(), response_headers_gen()},
        begin
            ClientConn0 = nhttp_h2:new(client),
            {ok, StreamId, ClientConn1} = nhttp_h2:open_stream(ClientConn0),
            {ok, ClientConn2, ReqFrame} = nhttp_h2:send_headers(
                ClientConn1, StreamId, ReqHeaders, fin
            ),

            ServerConn0 = nhttp_h2:new(server),
            {ok, ClientPreface} = nhttp_h2_frame:preface(),
            ReqData = <<ClientPreface/binary, (iolist_to_binary(ReqFrame))/binary>>,
            case nhttp_h2:recv(ServerConn0, ReqData) of
                {ok, [{request, StreamId, Request, fin}], ServerConn1} ->
                    {ok, _ServerConn2, RespFrame} = nhttp_h2:send_headers(
                        ServerConn1, StreamId, RespHeaders, fin
                    ),
                    case nhttp_h2:recv(ClientConn2, iolist_to_binary(RespFrame)) of
                        {ok, [{response, StreamId, Response, fin}], _ClientConn3} ->
                            nhttp_props_helpers:request_matches(ReqHeaders, Request) andalso
                                response_matches(RespHeaders, Response);
                        _ ->
                            false
                    end;
                _ ->
                    false
            end
        end
    ).


-spec prop_stream_state_machine() -> triq:property().
prop_stream_state_machine() ->
    ?FORALL(
        EndStream,
        oneof([fin, nofin]),
        begin
            Conn0 = nhttp_h2:new(client),
            {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
            Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
            {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, EndStream),
            case EndStream of
                fin ->
                    case nhttp_h2:send_data(Conn2, StreamId, <<"test">>, nofin) of
                        {error, _} -> true;
                        _ -> false
                    end;
                nofin ->
                    case nhttp_h2:send_data(Conn2, StreamId, <<"test">>, nofin) of
                        {ok, _, _} -> true;
                        _ -> false
                    end
            end
        end
    ).

-spec prop_stream_id_increment() -> triq:property().
prop_stream_id_increment() ->
    ?FORALL(
        N,
        int(1, 20),
        begin
            Conn0 = nhttp_h2:new(client),
            {StreamIds, _} = lists:foldl(
                fun(_, {Ids, Conn}) ->
                    {ok, Id, NewConn} = nhttp_h2:open_stream(Conn),
                    {[Id | Ids], NewConn}
                end,
                {[], Conn0},
                lists:seq(1, N)
            ),
            ReversedIds = lists:reverse(StreamIds),
            AllOdd = lists:all(fun(Id) -> Id rem 2 =:= 1 end, ReversedIds),
            ExpectedIds = [2 * I - 1 || I <- lists:seq(1, N)],
            AllOdd andalso ReversedIds =:= ExpectedIds
        end
    ).


-spec prop_flow_control_window() -> triq:property().
prop_flow_control_window() ->
    ?FORALL(
        Increment,
        int(1, 1000000),
        begin
            Conn0 = nhttp_h2:new(client),
            {ok, Frame} = nhttp_h2_frame:window_update(Increment),
            case nhttp_h2:recv(Conn0, iolist_to_binary(Frame)) of
                {ok, [{window_update, 0, Increment}], Conn1} ->
                    is_tuple(Conn1);
                {error, {connection_error, flow_control_error, _}} ->
                    Increment + 65535 > 16#7fffffff
            end
        end
    ).

-spec prop_flow_control_consumes() -> triq:property().
prop_flow_control_consumes() ->
    ?FORALL(
        DataSize,
        int(1, 1000),
        begin
            Conn0 = nhttp_h2:new(client),
            {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
            Headers = [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/">>}],
            {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
            Data = binary:copy(<<0>>, DataSize),
            case nhttp_h2:send_data(Conn2, StreamId, Data, fin) of
                {ok, _Conn3, Frame} ->
                    iolist_size(Frame) > 0;
                {error, _} ->
                    true
            end
        end
    ).


-spec prop_settings_roundtrip() -> triq:property().
prop_settings_roundtrip() ->
    ?FORALL(
        Settings,
        settings_gen(),
        begin
            Conn0 = nhttp_h2:new(client),
            {ok, Frame} = nhttp_h2_frame:settings(Settings),
            case nhttp_h2:recv(Conn0, iolist_to_binary(Frame)) of
                {ok, [{settings, RecvSettings}], _Conn1, _AckFrame} ->
                    maps:fold(
                        fun(Key, Value, Acc) ->
                            Acc andalso maps:get(Key, RecvSettings, undefined) =:= Value
                        end,
                        true,
                        Settings
                    );
                _ ->
                    false
            end
        end
    ).

-spec prop_settings_update_peer() -> triq:property().
prop_settings_update_peer() ->
    ?FORALL(
        WindowSize,
        int(1, 16#7fffffff),
        begin
            Conn0 = nhttp_h2:new(client),
            Settings = #{initial_window_size => WindowSize},
            {ok, Frame} = nhttp_h2_frame:settings(Settings),
            case nhttp_h2:recv(Conn0, iolist_to_binary(Frame)) of
                {ok, [{settings, RecvSettings}], _Conn1, _} ->
                    maps:get(initial_window_size, RecvSettings) =:= WindowSize;
                _ ->
                    false
            end
        end
    ).


-spec response_matches([{binary(), binary()}], nhttp_lib:response()) -> boolean().
response_matches(Headers, Response) ->
    {Status, Filtered} = split_response_pseudos(Headers),
    maps:get(status, Response) =:= binary_to_integer(Status) andalso
        maps:get(headers, Response) =:= Filtered.

-spec split_response_pseudos([{binary(), binary()}]) ->
    {binary(), [{binary(), binary()}]}.
split_response_pseudos(Headers) ->
    split_response_pseudos(Headers, <<"0">>, []).

split_response_pseudos([], Status, Acc) ->
    {Status, lists:reverse(Acc)};
split_response_pseudos([{<<":status">>, V} | T], _, Acc) ->
    split_response_pseudos(T, V, Acc);
split_response_pseudos([H | T], Status, Acc) ->
    split_response_pseudos(T, Status, [H | Acc]).

-spec request_headers_gen() -> triq_dom:domain().
request_headers_gen() ->
    ?LET(
        {Method, Scheme, Path, ExtraHeaders},
        {method_gen(), scheme_gen(), path_gen(), extra_headers_gen()},
        [{<<":method">>, Method}, {<<":scheme">>, Scheme}, {<<":path">>, Path}] ++ ExtraHeaders
    ).

-spec prop_continuation_sequence() -> triq:property().
prop_continuation_sequence() ->
    ?FORALL(
        {ReqHeaders, NumChunks},
        {request_headers_gen(), int(1, 1000)},
        begin
            {ok, HpEnc} = nhttp_hpack:new(),
            {ok, Encoded, _} = nhttp_hpack:encode(ReqHeaders, HpEnc),
            HeaderBlock = iolist_to_binary(Encoded),
            StreamId = 1,
            Frames = split_into_headers_continuation(HeaderBlock, StreamId, NumChunks),
            ServerConn0 = nhttp_h2:new(server),
            {ok, ClientPreface} = nhttp_h2_frame:preface(),
            Data = <<ClientPreface/binary, (iolist_to_binary(Frames))/binary>>,
            case nhttp_h2:recv(ServerConn0, Data) of
                {ok, Events, _ServerConn1} ->
                    %% Either a single request event reassembled, or 0 events (more bytes needed).
                    case lists:filter(fun(E) -> element(1, E) =:= request end, Events) of
                        [{request, StreamId, Request, fin}] -> nhttp_props_helpers:request_matches(ReqHeaders, Request);
                        [] -> true;
                        _ -> false
                    end;
                {ok, Events, _ServerConn1, _Out} ->
                    case lists:filter(fun(E) -> element(1, E) =:= request end, Events) of
                        [{request, StreamId, Request, fin}] -> nhttp_props_helpers:request_matches(ReqHeaders, Request);
                        [] -> true;
                        _ -> false
                    end;
                {error, _} ->
                    true
            end
        end
    ).

-spec split_into_headers_continuation(binary(), nhttp_lib:stream_id(), pos_integer()) ->
    [iodata()].
split_into_headers_continuation(Block, StreamId, NumChunks) ->
    Size = byte_size(Block),
    case NumChunks >= Size of
        true -> split_headers_byte_by_byte(Block, StreamId);
        false -> split_headers_n_chunks(Block, StreamId, NumChunks)
    end.

-spec split_headers_byte_by_byte(binary(), nhttp_lib:stream_id()) -> [iodata()].
split_headers_byte_by_byte(<<>>, StreamId) ->
    [headers_frame(StreamId, fin, fin, <<>>)];
split_headers_byte_by_byte(<<B>>, StreamId) ->
    [headers_frame(StreamId, fin, fin, <<B>>)];
split_headers_byte_by_byte(<<B, Rest/binary>>, StreamId) ->
    First = headers_frame(StreamId, fin, nofin, <<B>>),
    Conts = byte_continuations(Rest, StreamId, []),
    [First | Conts].

-spec byte_continuations(binary(), nhttp_lib:stream_id(), [iodata()]) -> [iodata()].
byte_continuations(<<B>>, StreamId, Acc) ->
    lists:reverse([continuation_frame(StreamId, fin, <<B>>) | Acc]);
byte_continuations(<<B, Rest/binary>>, StreamId, Acc) ->
    byte_continuations(Rest, StreamId, [continuation_frame(StreamId, nofin, <<B>>) | Acc]).

-spec split_headers_n_chunks(binary(), nhttp_lib:stream_id(), pos_integer()) -> [iodata()].
split_headers_n_chunks(Block, StreamId, NumChunks) ->
    Size = byte_size(Block),
    ChunkSize = max(1, Size div NumChunks),
    Chunks = chunk_binary(Block, ChunkSize),
    case Chunks of
        [Single] ->
            [headers_frame(StreamId, fin, fin, Single)];
        [First | Rest] ->
            FirstFrame = headers_frame(StreamId, fin, nofin, First),
            ContFrames = encode_continuations(Rest, StreamId, []),
            [FirstFrame | ContFrames]
    end.

-spec chunk_binary(binary(), pos_integer()) -> [binary()].
chunk_binary(<<>>, _ChunkSize) ->
    [<<>>];
chunk_binary(Bin, ChunkSize) when byte_size(Bin) =< ChunkSize ->
    [Bin];
chunk_binary(Bin, ChunkSize) ->
    <<Head:ChunkSize/binary, Rest/binary>> = Bin,
    [Head | chunk_binary(Rest, ChunkSize)].

-spec encode_continuations([binary()], nhttp_lib:stream_id(), [iodata()]) -> [iodata()].
encode_continuations([Last], StreamId, Acc) ->
    lists:reverse([continuation_frame(StreamId, fin, Last) | Acc]);
encode_continuations([Chunk | Rest], StreamId, Acc) ->
    encode_continuations(Rest, StreamId, [continuation_frame(StreamId, nofin, Chunk) | Acc]).

-spec headers_frame(nhttp_lib:stream_id(), fin | nofin, fin | nofin, binary()) -> iodata().
headers_frame(StreamId, EndStream, EndHeaders, Block) ->
    {ok, Frame} = nhttp_h2_frame:headers(StreamId, EndStream, EndHeaders, Block),
    Frame.

-spec continuation_frame(nhttp_lib:stream_id(), fin | nofin, binary()) -> iodata().
continuation_frame(StreamId, EndHeaders, Block) ->
    {ok, Frame} = nhttp_h2_frame:continuation(StreamId, EndHeaders, Block),
    Frame.

-spec response_headers_gen() -> triq_dom:domain().
response_headers_gen() ->
    ?LET(
        {Status, ExtraHeaders},
        {nhttp_props_helpers:status_gen(), extra_headers_gen()},
        [{<<":status">>, Status}] ++ ExtraHeaders
    ).

-spec method_gen() -> triq_dom:domain().
method_gen() ->
    oneof([<<"GET">>, <<"POST">>, <<"PUT">>, <<"DELETE">>, <<"HEAD">>, <<"OPTIONS">>]).

-spec scheme_gen() -> triq_dom:domain().
scheme_gen() ->
    oneof([<<"https">>, <<"http">>]).

-spec path_gen() -> triq_dom:domain().
path_gen() ->
    oneof([
        <<"/">>,
        <<"/index.html">>,
        <<"/api/v1">>,
        <<"/users/123">>,
        ?LET(
            Segments,
            non_empty(list(path_segment_gen())),
            begin
                Limited = lists:sublist(Segments, 4),
                iolist_to_binary([<<"/">>, lists:join(<<"/">>, Limited)])
            end
        )
    ]).

-spec path_segment_gen() -> triq_dom:domain().
path_segment_gen() ->
    ?LET(
        Chars,
        non_empty(list(int($a, $z))),
        list_to_binary(lists:sublist(Chars, 10))
    ).

-spec extra_headers_gen() -> triq_dom:domain().
extra_headers_gen() ->
    ?LET(
        N,
        int(0, 5),
        [extra_header_gen() || _ <- lists:seq(1, N)]
    ).

-spec extra_header_gen() -> triq_dom:domain().
extra_header_gen() ->
    oneof([
        {<<"accept">>, <<"*/*">>},
        {<<"accept-encoding">>, <<"gzip, deflate">>},
        {<<"content-type">>, <<"application/json">>},
        {<<"user-agent">>, <<"nhttp/1.0">>},
        {<<"cache-control">>, <<"no-cache">>},
        custom_header_gen()
    ]).

-spec custom_header_gen() -> triq_dom:domain().
custom_header_gen() ->
    ?LET(
        {Name, Value},
        {header_name_gen(), header_value_gen()},
        {Name, Value}
    ).

-spec header_name_gen() -> triq_dom:domain().
header_name_gen() ->
    ?LET(
        Chars,
        non_empty(list(int($a, $z))),
        begin
            Limited = lists:sublist(Chars, 20),
            list_to_binary([<<"x-">>, Limited])
        end
    ).

%% RFC 9110 Section 5.5: `field-content' neither starts nor ends with SP or
%% HTAB. RFC 9113 Section 8.2.1 makes a value that does malformed, so the
%% roundtrip generator must not draw one.
-spec header_value_gen() -> triq_dom:domain().
header_value_gen() ->
    ?LET(
        Chars,
        list(header_value_char_gen()),
        string:trim(list_to_binary(lists:sublist(Chars, 50)), both, [$\s])
    ).

-spec header_value_char_gen() -> triq_dom:domain().
header_value_char_gen() ->
    frequency([
        {10, int($a, $z)},
        {5, int($A, $Z)},
        {3, int($0, $9)},
        {2, oneof([$\s, $-, $_, $.])}
    ]).

-spec data_gen() -> triq_dom:domain().
data_gen() ->
    ?LET(
        Size,
        int(0, 65535),
        binary(Size)
    ).

-spec settings_gen() -> triq_dom:domain().
settings_gen() ->
    ?LET(
        Settings,
        list(setting_gen()),
        maps:from_list(Settings)
    ).

-spec setting_gen() -> triq_dom:domain().
setting_gen() ->
    oneof([
        {header_table_size, int(0, 65535)},
        {max_concurrent_streams, int(1, 1000)},
        {initial_window_size, int(1, 16#7fffffff)},
        {max_frame_size, int(16384, 16777215)}
    ]).

-spec prop_send_within_credit() -> triq:property().
prop_send_within_credit() ->
    ?FORALL(
        Ops,
        list(flow_op_gen()),
        begin
            Conn0 = nhttp_h2:new(client),
            {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
            Headers = [
                {<<":method">>, <<"POST">>}, {<<":scheme">>, <<"https">>}, {<<":path">>, <<"/">>}
            ],
            {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
            Initial = 65535,
            {Sent, StreamCredit, ConnCredit, Conn3} = lists:foldl(
                fun(Op, Acc) -> apply_flow_op(Op, StreamId, Acc) end,
                {0, Initial, Initial, Conn2},
                Ops
            ),
            {ok, StreamWindow} = nhttp_h2:stream_send_window(Conn3, StreamId),
            Sent =< StreamCredit andalso
                Sent =< ConnCredit andalso
                StreamWindow =:= StreamCredit - Sent andalso
                nhttp_h2:connection_send_window(Conn3) =:= ConnCredit - Sent
        end
    ).

-spec flow_op_gen() -> triq_dom:domain().
flow_op_gen() ->
    oneof([
        {send, int(0, 40000)},
        {stream_credit, int(1, 100000)},
        {connection_credit, int(1, 100000)}
    ]).

-spec apply_flow_op(
    {send | stream_credit | connection_credit, non_neg_integer()},
    nhttp_lib:stream_id(),
    {non_neg_integer(), non_neg_integer(), non_neg_integer(), nhttp_h2:conn()}
) -> {non_neg_integer(), non_neg_integer(), non_neg_integer(), nhttp_h2:conn()}.
apply_flow_op({send, Size}, StreamId, {Sent, StreamCredit, ConnCredit, Conn}) ->
    Data = binary:copy(<<0>>, Size),
    case nhttp_h2:send_data(Conn, StreamId, Data, nofin) of
        {ok, NewConn, Frame} ->
            {Sent + payload_size(Frame), StreamCredit, ConnCredit, NewConn};
        {partial, NewConn, Frame, _Rest, nofin, _Window} ->
            {Sent + payload_size(Frame), StreamCredit, ConnCredit, NewConn}
    end;
apply_flow_op({stream_credit, Increment}, StreamId, {Sent, StreamCredit, ConnCredit, Conn}) ->
    {ok, Frame} = nhttp_h2_frame:window_update(StreamId, Increment),
    {ok, [{window_update, StreamId, Increment}], NewConn} =
        nhttp_h2:recv(Conn, iolist_to_binary(Frame)),
    {Sent, StreamCredit + Increment, ConnCredit, NewConn};
apply_flow_op({connection_credit, Increment}, _StreamId, {Sent, StreamCredit, ConnCredit, Conn}) ->
    {ok, Frame} = nhttp_h2_frame:window_update(Increment),
    {ok, [{window_update, 0, Increment}], NewConn} =
        nhttp_h2:recv(Conn, iolist_to_binary(Frame)),
    {Sent, StreamCredit, ConnCredit + Increment, NewConn}.

-spec payload_size(iodata()) -> non_neg_integer().
payload_size(Frames) ->
    lists:sum([byte_size(Payload) || {_, _, Payload} <- decode_data_frames(Frames)]).

-spec prop_send_data_conserves_body() -> triq:property().
prop_send_data_conserves_body() ->
    ?FORALL(
        {{Parent, Body}, ConnCredit, StreamCredit},
        {body_gen(), int(0, 100000), int(0, 100000)},
        begin
            Conn0 = nhttp_h2:new(client),
            {ok, StreamId, Conn1} = nhttp_h2:open_stream(Conn0),
            Headers = [
                {<<":method">>, <<"POST">>}, {<<":scheme">>, <<"https">>}, {<<":path">>, <<"/">>}
            ],
            {ok, Conn2, _} = nhttp_h2:send_headers(Conn1, StreamId, Headers, nofin),
            {_, _, _, Conn3} = apply_flow_op(
                {connection_credit, ConnCredit + 1}, StreamId, {0, 0, 0, Conn2}
            ),
            {_, _, _, Conn4} = apply_flow_op(
                {stream_credit, StreamCredit + 1}, StreamId, {0, 0, 0, Conn3}
            ),
            Window = min(65536 + ConnCredit, 65536 + StreamCredit),
            Size = byte_size(Parent),
            case nhttp_h2:send_data(Conn4, StreamId, Body, fin) of
                {ok, _, Frames} ->
                    Decoded = decode_data_frames(Frames),
                    Size =< Window andalso
                        length(Decoded) =:= max(1, ceil_div(Size, 16384)) andalso
                        fins(Decoded) =:= lists:duplicate(length(Decoded) - 1, nofin) ++ [fin] andalso
                        payloads(Decoded) =:= Parent andalso
                        shares_parent(Frames, Parent);
                {partial, _, Frames, Rest, fin, 0} ->
                    Decoded = decode_data_frames(Frames),
                    Payloads = payloads(Decoded),
                    Size > Window andalso
                        length(Decoded) =:= ceil_div(Window, 16384) andalso
                        fins(Decoded) =:= lists:duplicate(length(Decoded), nofin) andalso
                        byte_size(Payloads) =:= Window andalso
                        <<Payloads/binary, Rest/binary>> =:= Parent andalso
                        shares_parent(Frames, Parent) andalso
                        remainder_retention(Rest, Parent, Body)
            end
        end
    ).

-spec body_gen() -> triq_dom:domain().
body_gen() ->
    ?LET(
        {Size, Seed, Cuts, Form},
        {int(0, 150000), int(0, 255), list(int(0, 150000)), oneof([binary, flat, nested])},
        begin
            Parent = numbered_parent(Size, Seed),
            {Parent, body_form(Form, Parent, lists:usort([Cut || Cut <- Cuts, Cut < Size]))}
        end
    ).

-spec numbered_parent(non_neg_integer(), 0..255) -> binary().
numbered_parent(Size, Seed) ->
    Pattern = list_to_binary([(Seed + I) rem 256 || I <- lists:seq(0, 255)]),
    binary:copy(binary:part(binary:copy(Pattern, Size div 256 + 1), 0, Size)).

-spec body_form(binary | flat | nested, binary(), [non_neg_integer()]) -> iodata().
body_form(binary, Parent, _Cuts) ->
    Parent;
body_form(flat, Parent, Cuts) ->
    pieces(Parent, Cuts);
body_form(nested, Parent, Cuts) ->
    [nest(Piece) || Piece <- pieces(Parent, Cuts)].

-spec pieces(binary(), [non_neg_integer()]) -> [binary()].
pieces(Parent, Cuts) ->
    Bounds = lists:zip([0 | Cuts], Cuts ++ [byte_size(Parent)]),
    [binary:part(Parent, From, To - From) || {From, To} <- Bounds].

-spec nest(binary()) -> iodata().
nest(Piece) when byte_size(Piece) =< 8 ->
    binary_to_list(Piece);
nest(Piece) ->
    [[Piece]].

-spec ceil_div(non_neg_integer(), pos_integer()) -> non_neg_integer().
ceil_div(N, D) ->
    (N + D - 1) div D.

-spec decode_data_frames(iodata()) -> [{nhttp_lib:stream_id(), nhttp_h2:fin(), binary()}].
decode_data_frames(Frames) ->
    decode_data_frames_bin(iolist_to_binary(Frames)).

-spec decode_data_frames_bin(binary()) -> [{nhttp_lib:stream_id(), nhttp_h2:fin(), binary()}].
decode_data_frames_bin(<<>>) ->
    [];
decode_data_frames_bin(Bin) ->
    {ok, {data, StreamId, Fin, Payload}, Consumed} = nhttp_h2_frame:decode(Bin),
    <<_:Consumed/binary, Rest/binary>> = Bin,
    [{StreamId, Fin, Payload} | decode_data_frames_bin(Rest)].

-spec fins([{nhttp_lib:stream_id(), nhttp_h2:fin(), binary()}]) -> [nhttp_h2:fin()].
fins(Decoded) ->
    [Fin || {_, Fin, _} <- Decoded].

-spec payloads([{nhttp_lib:stream_id(), nhttp_h2:fin(), binary()}]) -> binary().
payloads(Decoded) ->
    iolist_to_binary([Payload || {_, _, Payload} <- Decoded]).

-spec shares_parent(iodata(), binary()) -> boolean().
shares_parent(Frames, Parent) ->
    lists:all(
        fun(Bin) -> binary:referenced_byte_size(Bin) =:= byte_size(Parent) end,
        [Bin || Bin <- binaries(Frames, []), byte_size(Bin) > 64]
    ).

-spec binaries(iodata(), [binary()]) -> [binary()].
binaries(Bin, Acc) when is_binary(Bin) ->
    [Bin | Acc];
binaries([Head | Tail], Acc) ->
    binaries(Tail, binaries(Head, Acc));
binaries([], Acc) ->
    Acc;
binaries(Byte, Acc) when is_integer(Byte) ->
    Acc.

-spec remainder_retention(binary(), binary(), iodata()) -> boolean().
remainder_retention(Rest, Parent, Body) ->
    RestSize = byte_size(Rest),
    ParentSize = byte_size(Parent),
    Referenced = binary:referenced_byte_size(Rest),
    if
        RestSize =< 64 ->
            Referenced =:= own_size(Rest);
        ParentSize > 4 * RestSize ->
            Referenced =:= own_size(Rest);
        is_binary(Body) ->
            Referenced =:= ParentSize;
        true ->
            Referenced =:= own_size(Rest) orelse Referenced =:= ParentSize
    end.

-spec own_size(binary()) -> non_neg_integer().
own_size(Bin) ->
    binary:referenced_byte_size(binary:copy(Bin)).
