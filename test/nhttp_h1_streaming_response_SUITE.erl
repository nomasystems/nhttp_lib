%%%-----------------------------------------------------------------------------
-module(nhttp_h1_streaming_response_SUITE).

-moduledoc """
Tests for the streaming HTTP/1.1 response body parser:

- `nhttp_h1:body_stream_from_response/3`
- `nhttp_h1:parse_response_body/2`
- `nhttp_h1:finalize_response_body/1`
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        {group, body_stream_from_response},
        {group, parse_response_body_length},
        {group, parse_response_body_chunked},
        {group, parse_response_body_until_close},
        {group, finalize_response_body}
    ].

groups() ->
    [
        {body_stream_from_response, [parallel], [
            head_method_returns_none,
            status_204_returns_none,
            status_304_returns_none,
            status_100_returns_none,
            status_199_returns_none,
            chunked_overrides_content_length,
            content_length_zero_returns_length_zero,
            content_length_n_returns_length_n,
            no_framing_returns_until_close,
            head_with_content_length_still_none
        ]},
        {parse_response_body_length, [parallel], [
            length_complete_in_one_call,
            length_partial_then_complete,
            length_more_signals_min_bytes,
            length_excess_bytes_in_buffer,
            length_zero_returns_fin
        ]},
        {parse_response_body_chunked, [parallel], [
            chunked_single_chunk,
            chunked_multiple_chunks,
            chunked_with_trailers,
            chunked_partial_size_line,
            chunked_partial_data,
            chunked_invalid_size
        ]},
        {parse_response_body_until_close, [parallel], [
            until_close_data_emitted_eagerly,
            until_close_empty_buffer_more,
            until_close_finalize_returns_fin
        ]},
        {finalize_response_body, [parallel], [
            finalize_none_returns_fin,
            finalize_length_zero_returns_fin,
            finalize_length_remaining_returns_unexpected_eof,
            finalize_chunked_mid_body_returns_unexpected_eof,
            finalize_until_close_returns_fin
        ]}
    ].

%%%-----------------------------------------------------------------------------
%%% body_stream_from_response/3
%%%-----------------------------------------------------------------------------

head_method_returns_none(_Config) ->
    ?assertEqual(none, nhttp_h1:body_stream_from_response(head, 200, [])).

status_204_returns_none(_Config) ->
    ?assertEqual(none, nhttp_h1:body_stream_from_response(get, 204, [])).

status_304_returns_none(_Config) ->
    ?assertEqual(none, nhttp_h1:body_stream_from_response(get, 304, [])).

status_100_returns_none(_Config) ->
    ?assertEqual(none, nhttp_h1:body_stream_from_response(get, 100, [])).

status_199_returns_none(_Config) ->
    ?assertEqual(none, nhttp_h1:body_stream_from_response(get, 199, [])).

chunked_overrides_content_length(_Config) ->
    Headers = [{<<"transfer-encoding">>, <<"chunked">>}],
    Stream = nhttp_h1:body_stream_from_response(get, 200, Headers),
    ?assertMatch({chunked, _}, Stream).

content_length_zero_returns_length_zero(_Config) ->
    Headers = [{<<"content-length">>, <<"0">>}],
    ?assertEqual(
        {length, 0},
        nhttp_h1:body_stream_from_response(get, 200, Headers)
    ).

content_length_n_returns_length_n(_Config) ->
    Headers = [{<<"content-length">>, <<"42">>}],
    ?assertEqual(
        {length, 42},
        nhttp_h1:body_stream_from_response(get, 200, Headers)
    ).

no_framing_returns_until_close(_Config) ->
    ?assertEqual(
        until_close,
        nhttp_h1:body_stream_from_response(get, 200, [])
    ).

head_with_content_length_still_none(_Config) ->
    Headers = [{<<"content-length">>, <<"100">>}],
    ?assertEqual(
        none,
        nhttp_h1:body_stream_from_response(head, 200, Headers)
    ).

%%%-----------------------------------------------------------------------------
%%% parse_response_body/2: content-length
%%%-----------------------------------------------------------------------------

length_complete_in_one_call(_Config) ->
    Stream = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"content-length">>, <<"5">>}]
    ),
    Result = nhttp_h1:parse_response_body(<<"hello">>, Stream),
    ?assertMatch({ok, [{data, <<"hello">>}, {fin, []}], none, 5}, Result).

length_partial_then_complete(_Config) ->
    Stream0 = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"content-length">>, <<"10">>}]
    ),
    {ok, Chunks1, Stream1, Consumed1} =
        nhttp_h1:parse_response_body(<<"hello">>, Stream0),
    ?assertEqual([{data, <<"hello">>}], Chunks1),
    ?assertEqual({length, 5}, Stream1),
    ?assertEqual(5, Consumed1),
    {ok, Chunks2, Stream2, Consumed2} =
        nhttp_h1:parse_response_body(<<"world">>, Stream1),
    ?assertEqual([{data, <<"world">>}, {fin, []}], Chunks2),
    ?assertEqual(none, Stream2),
    ?assertEqual(5, Consumed2).

length_more_signals_min_bytes(_Config) ->
    Stream = {length, 10},
    ?assertEqual(
        {more, 10, {length, 10}},
        nhttp_h1:parse_response_body(<<>>, Stream)
    ).

length_excess_bytes_in_buffer(_Config) ->
    Stream = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"content-length">>, <<"5">>}]
    ),
    {ok, Chunks, NewStream, Consumed} =
        nhttp_h1:parse_response_body(<<"hello, more bytes here">>, Stream),
    ?assertEqual([{data, <<"hello">>}, {fin, []}], Chunks),
    ?assertEqual(none, NewStream),
    ?assertEqual(5, Consumed).

length_zero_returns_fin(_Config) ->
    Result = nhttp_h1:parse_response_body(<<>>, {length, 0}),
    ?assertMatch({ok, [{fin, []}], none, 0}, Result).

%%%-----------------------------------------------------------------------------
%%% parse_response_body/2: chunked
%%%-----------------------------------------------------------------------------

chunked_single_chunk(_Config) ->
    Stream = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"transfer-encoding">>, <<"chunked">>}]
    ),
    Wire = <<"5\r\nhello\r\n0\r\n\r\n">>,
    {ok, Chunks, Stream1, Consumed} =
        nhttp_h1:parse_response_body(Wire, Stream),
    ?assertEqual(
        [{data, <<"hello">>}, {fin, []}],
        Chunks
    ),
    ?assertEqual(none, Stream1),
    ?assertEqual(byte_size(Wire), Consumed).

chunked_multiple_chunks(_Config) ->
    Stream = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"transfer-encoding">>, <<"chunked">>}]
    ),
    Wire = <<"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n">>,
    {ok, Chunks, Stream1, Consumed} =
        nhttp_h1:parse_response_body(Wire, Stream),
    Datas = [Bin || {data, Bin} <- Chunks],
    ?assertEqual(<<"hello world">>, iolist_to_binary(Datas)),
    ?assertMatch([_, _, {fin, []}], Chunks),
    ?assertEqual(none, Stream1),
    ?assertEqual(byte_size(Wire), Consumed).

chunked_with_trailers(_Config) ->
    Stream = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"transfer-encoding">>, <<"chunked">>}]
    ),
    Wire = <<"5\r\nhello\r\n0\r\nx-trailer: yes\r\n\r\n">>,
    {ok, Chunks, _, _} = nhttp_h1:parse_response_body(Wire, Stream),
    Trailers =
        case lists:last(Chunks) of
            {fin, T} -> T
        end,
    ?assertEqual([{<<"x-trailer">>, <<"yes">>}], Trailers).

chunked_partial_size_line(_Config) ->
    Stream0 = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"transfer-encoding">>, <<"chunked">>}]
    ),
    Result = nhttp_h1:parse_response_body(<<"5">>, Stream0),
    ?assertMatch({more, _, {chunked, _}}, Result).

chunked_partial_data(_Config) ->
    Stream0 = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"transfer-encoding">>, <<"chunked">>}]
    ),
    {ok, Chunks1, Stream1, _Consumed1} =
        nhttp_h1:parse_response_body(<<"5\r\nhel">>, Stream0),
    ?assertEqual([{data, <<"hel">>}], Chunks1),
    {ok, Chunks2, Stream2, _Consumed2} =
        nhttp_h1:parse_response_body(<<"lo\r\n0\r\n\r\n">>, Stream1),
    Datas = [Bin || {data, Bin} <- Chunks1 ++ Chunks2],
    ?assertEqual(<<"hello">>, iolist_to_binary(Datas)),
    ?assertEqual(none, Stream2).

chunked_invalid_size(_Config) ->
    Stream = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"transfer-encoding">>, <<"chunked">>}]
    ),
    Result = nhttp_h1:parse_response_body(<<"zz\r\n">>, Stream),
    ?assertMatch({error, invalid_chunk_size}, Result).

%%%-----------------------------------------------------------------------------
%%% parse_response_body/2: until_close
%%%-----------------------------------------------------------------------------

until_close_data_emitted_eagerly(_Config) ->
    Stream = nhttp_h1:body_stream_from_response(get, 200, []),
    ?assertEqual(until_close, Stream),
    {ok, Chunks, NewStream, Consumed} =
        nhttp_h1:parse_response_body(<<"some bytes">>, Stream),
    ?assertEqual([{data, <<"some bytes">>}], Chunks),
    ?assertEqual(until_close, NewStream),
    ?assertEqual(10, Consumed).

until_close_empty_buffer_more(_Config) ->
    Result = nhttp_h1:parse_response_body(<<>>, until_close),
    ?assertEqual({more, 1, until_close}, Result).

until_close_finalize_returns_fin(_Config) ->
    Stream = until_close,
    {ok, Chunks1, Stream1, _} =
        nhttp_h1:parse_response_body(<<"chunk1">>, Stream),
    {ok, Chunks2, Stream2, _} =
        nhttp_h1:parse_response_body(<<"chunk2">>, Stream1),
    {ok, FinChunks} = nhttp_h1:finalize_response_body(Stream2),
    Datas = [Bin || {data, Bin} <- Chunks1 ++ Chunks2],
    ?assertEqual(<<"chunk1chunk2">>, iolist_to_binary(Datas)),
    ?assertEqual([{fin, []}], FinChunks).

%%%-----------------------------------------------------------------------------
%%% finalize_response_body/1
%%%-----------------------------------------------------------------------------

finalize_none_returns_fin(_Config) ->
    ?assertEqual({ok, [{fin, []}]}, nhttp_h1:finalize_response_body(none)).

finalize_length_zero_returns_fin(_Config) ->
    ?assertEqual(
        {ok, [{fin, []}]},
        nhttp_h1:finalize_response_body({length, 0})
    ).

finalize_length_remaining_returns_unexpected_eof(_Config) ->
    ?assertEqual(
        {error, unexpected_eof},
        nhttp_h1:finalize_response_body({length, 5})
    ).

finalize_chunked_mid_body_returns_unexpected_eof(_Config) ->
    Stream = nhttp_h1:body_stream_from_response(
        get, 200, [{<<"transfer-encoding">>, <<"chunked">>}]
    ),
    ?assertEqual(
        {error, unexpected_eof},
        nhttp_h1:finalize_response_body(Stream)
    ).

finalize_until_close_returns_fin(_Config) ->
    ?assertEqual(
        {ok, [{fin, []}]},
        nhttp_h1:finalize_response_body(until_close)
    ).
