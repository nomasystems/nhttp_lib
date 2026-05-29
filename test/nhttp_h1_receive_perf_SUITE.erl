%%%-----------------------------------------------------------------------------
-module(nhttp_h1_receive_perf_SUITE).

-moduledoc """
Linearity regression guard for the HTTP/1.1 receive strategy.

A client receive loop reassembling a content-length body from many TCP
fragments can do this two ways:

- **whole-buffer re-parse** (the old `nhttpc_conn` strategy): on every
  delivery, concatenate the new bytes onto the accumulated buffer and call
  `nhttp_h1:parse_response/2` over the whole thing. While the body is
  incomplete this re-concatenates the entire buffer and re-parses the status
  line and all headers from offset 0 again. Cost is **O(N²/chunk)** in bytes
  copied and **O(K)** header re-parses for K fragments.
- **streaming** (the current strategy): parse the head once with
  `nhttp_h1:parse_response_head/2`, then feed each fragment to
  `nhttp_h1:parse_response_body/2`, accumulate body slices, and join once.
  The empty-buffer fast path engages between deliveries, so no whole-buffer
  copy happens. Cost is **O(N)** in bytes copied and **1** header parse.

These tests measure the two cost drivers deterministically (bytes copied by
concatenation/join, and header-parse invocations) rather than wall-clock, so
they are stable in CI. `report/1` runs the same strategies with timing for
manual benchmarking.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

-define(BODY_SIZE, 1048576).
-define(CHUNK, 16384).

%%%-----------------------------------------------------------------------------
%%% CT CALLBACKS
%%%-----------------------------------------------------------------------------

all() ->
    [
        both_strategies_reassemble_identical_body,
        streaming_copies_are_linear_in_fragments,
        streaming_does_one_header_parse,
        whole_buffer_copies_are_superlinear_in_fragments,
        whole_buffer_reparses_headers_per_fragment,
        streaming_beats_whole_buffer_at_scale
    ].

%%%-----------------------------------------------------------------------------
%%% CORRECTNESS GUARD
%%%-----------------------------------------------------------------------------

both_strategies_reassemble_identical_body(_Config) ->
    {_Head, Body, Raw} = build_response(?BODY_SIZE),
    Fragments = fragment(Raw, ?CHUNK),
    #{body := OldBody} = run_whole_buffer(Fragments),
    #{body := NewBody} = run_streaming(Fragments),
    ?assertEqual(Body, OldBody),
    ?assertEqual(Body, NewBody).

%%%-----------------------------------------------------------------------------
%%% STREAMING IS LINEAR
%%%-----------------------------------------------------------------------------

streaming_copies_are_linear_in_fragments(_Config) ->
    %% Same body, 16x more fragments. Linear work stays ~flat (only the
    %% one-shot O(N) join contributes); quadratic work would grow ~16x.
    Few = byte_size_copied(run_streaming(fragment_n(?BODY_SIZE, 64))),
    Many = byte_size_copied(run_streaming(fragment_n(?BODY_SIZE, 1024))),
    ?assert(Few > 0),
    ?assert(
        Many =< Few * 2,
        lists:flatten(
            io_lib:format("streaming copies grew non-linearly: 64->~p 1024->~p", [Few, Many])
        )
    ).

streaming_does_one_header_parse(_Config) ->
    #{header_parses := Parses} = run_streaming(fragment_n(?BODY_SIZE, 1024)),
    ?assertEqual(1, Parses).

%%%-----------------------------------------------------------------------------
%%% WHOLE-BUFFER IS QUADRATIC (documents the regression that was fixed)
%%%-----------------------------------------------------------------------------

whole_buffer_copies_are_superlinear_in_fragments(_Config) ->
    Few = byte_size_copied(run_whole_buffer(fragment_n(?BODY_SIZE, 64))),
    Many = byte_size_copied(run_whole_buffer(fragment_n(?BODY_SIZE, 1024))),
    %% 16x the fragments must cost far more than 2x (it is ~16x); guard well
    %% clear of the linear regime so this only fires if the quadratic concat
    %% is reintroduced into this reference strategy.
    ?assert(
        Many >= Few * 8,
        lists:flatten(
            io_lib:format("whole-buffer copies did not scale with K: 64->~p 1024->~p", [Few, Many])
        )
    ).

whole_buffer_reparses_headers_per_fragment(_Config) ->
    Fragments = fragment_n(?BODY_SIZE, 256),
    #{header_parses := Parses} = run_whole_buffer(Fragments),
    ?assert(
        Parses >= length(Fragments),
        lists:flatten(
            io_lib:format("expected >= ~p header parses, got ~p", [length(Fragments), Parses])
        )
    ).

%%%-----------------------------------------------------------------------------
%%% STREAMING WINS
%%%-----------------------------------------------------------------------------

streaming_beats_whole_buffer_at_scale(_Config) ->
    Fragments = fragment_n(?BODY_SIZE, 1024),
    Old = byte_size_copied(run_whole_buffer(Fragments)),
    New = byte_size_copied(run_streaming(Fragments)),
    ?assert(
        Old >= New * 10,
        lists:flatten(
            io_lib:format("streaming not substantially cheaper: old=~p new=~p", [Old, New])
        )
    ).

%%%-----------------------------------------------------------------------------
%%% MICROBENCHMARK (manual: ct:run or nhttp_h1_receive_perf_SUITE:report/1)
%%%-----------------------------------------------------------------------------

-doc """
Print a wall-clock and bytes-copied table comparing both strategies for a
fixed `BodySize` across a range of fragment counts. Run from a shell:

```erlang
nhttp_h1_receive_perf_SUITE:report(1048576).
```
""".
-spec report(non_neg_integer()) -> ok.
report(BodySize) ->
    Ks = [16, 64, 256, 1024, 4096],
    io:format("~n~-8s ~-14s ~-14s ~-14s ~-14s~n", [
        "K", "old_us", "new_us", "old_bytes", "new_bytes"
    ]),
    lists:foreach(
        fun(K) ->
            Fragments = fragment_n(BodySize, K),
            {OldUs, OldRes} = timer:tc(fun() -> run_whole_buffer(Fragments) end),
            {NewUs, NewRes} = timer:tc(fun() -> run_streaming(Fragments) end),
            io:format("~-8w ~-14w ~-14w ~-14w ~-14w~n", [
                K, OldUs, NewUs, byte_size_copied(OldRes), byte_size_copied(NewRes)
            ])
        end,
        Ks
    ),
    ok.

%%%-----------------------------------------------------------------------------
%%% RECEIVE STRATEGIES (faithful models of the conn receive loop)
%%%-----------------------------------------------------------------------------

-doc "Old strategy: re-concatenate the whole buffer and re-parse on every fragment.".
-spec run_whole_buffer([binary()]) ->
    #{
        body := binary(), bytes_copied := non_neg_integer(), header_parses := non_neg_integer()
    }.
run_whole_buffer(Fragments) ->
    whole_buffer(Fragments, <<>>, 0, 0).

whole_buffer([Frag | Rest], Buffer, Copied, Parses) ->
    Combined = combine(Buffer, Frag),
    Copied1 = Copied + combine_cost(Buffer, Frag),
    case nhttp_h1:parse_response(Combined, #{}) of
        {ok, Resp, _Consumed} ->
            #{
                body => maps:get(body, Resp),
                bytes_copied => Copied1,
                header_parses => Parses + 1
            };
        {more, _} ->
            whole_buffer(Rest, Combined, Copied1, Parses + 1)
    end.

-doc "New strategy: parse the head once, stream the body, join once.".
-spec run_streaming([binary()]) ->
    #{
        body := binary(), bytes_copied := non_neg_integer(), header_parses := non_neg_integer()
    }.
run_streaming([Frag0 | Rest]) ->
    case nhttp_h1:parse_response_head(Frag0, #{}) of
        {ok, Status, _Reason, _Version, Headers, BodyRest} ->
            Stream = nhttp_h1:body_stream_from_response(get, Status, Headers),
            stream_body(Rest, BodyRest, Stream, [], 0);
        {more, _} ->
            stream_head(Rest, Frag0, combine_cost(<<>>, Frag0))
    end.

stream_head([Frag | Rest], Buffer, Copied) ->
    Combined = combine(Buffer, Frag),
    Copied1 = Copied + combine_cost(Buffer, Frag),
    case nhttp_h1:parse_response_head(Combined, #{}) of
        {ok, Status, _Reason, _Version, Headers, BodyRest} ->
            Stream = nhttp_h1:body_stream_from_response(get, Status, Headers),
            stream_body(Rest, BodyRest, Stream, [], Copied1);
        {more, _} ->
            stream_head(Rest, Combined, Copied1)
    end.

stream_body(Fragments, Buffer, Stream, Acc, Copied) ->
    case nhttp_h1:parse_response_body(Buffer, Stream) of
        {ok, Chunks, NewStream, Consumed} ->
            Rest = nhttp_h1:split_at(Buffer, Consumed),
            case apply_chunks(Chunks, Acc) of
                {fin, Acc1} ->
                    Body = iolist_to_binary(lists:reverse(Acc1)),
                    #{
                        body => Body,
                        bytes_copied => Copied + byte_size(Body),
                        header_parses => 1
                    };
                {cont, Acc1} ->
                    next_body(Fragments, Rest, NewStream, Acc1, Copied)
            end;
        {more, _Min, NewStream} ->
            next_body(Fragments, Buffer, NewStream, Acc, Copied)
    end.

next_body([Frag | Rest], Leftover, Stream, Acc, Copied) ->
    Combined = combine(Leftover, Frag),
    Copied1 = Copied + combine_cost(Leftover, Frag),
    stream_body(Rest, Combined, Stream, Acc, Copied1);
next_body([], _Leftover, _Stream, Acc, Copied) ->
    Body = iolist_to_binary(lists:reverse(Acc)),
    #{body => Body, bytes_copied => Copied + byte_size(Body), header_parses => 1}.

apply_chunks([], Acc) ->
    {cont, Acc};
apply_chunks([{data, Bin} | Rest], Acc) ->
    apply_chunks(Rest, [Bin | Acc]);
apply_chunks([{fin, _Trailers} | _], Acc) ->
    {fin, Acc}.

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec byte_size_copied(#{bytes_copied := non_neg_integer(), _ => _}) -> non_neg_integer().
byte_size_copied(#{bytes_copied := Copied}) ->
    Copied.

-doc "Bytes physically copied by `combine_buffer/2`: the empty-buffer fast path copies nothing.".
-spec combine_cost(binary(), binary()) -> non_neg_integer().
combine_cost(<<>>, _Bytes) ->
    0;
combine_cost(Buffer, Bytes) ->
    byte_size(Buffer) + byte_size(Bytes).

-spec combine(binary(), binary()) -> binary().
combine(<<>>, Bytes) ->
    Bytes;
combine(Buffer, Bytes) ->
    <<Buffer/binary, Bytes/binary>>.

-spec build_response(non_neg_integer()) -> {binary(), binary(), binary()}.
build_response(BodySize) ->
    Body = binary:copy(<<"x">>, BodySize),
    CL = integer_to_binary(BodySize),
    Head =
        <<"HTTP/1.1 200 OK\r\n", "server: nhttp_bench\r\n",
            "content-type: application/octet-stream\r\n", "content-length: ", CL/binary, "\r\n",
            "\r\n">>,
    {Head, Body, <<Head/binary, Body/binary>>}.

-doc "Split a raw response into fragments of at most `ChunkSize` bytes.".
-spec fragment(binary(), pos_integer()) -> [binary()].
fragment(Bin, ChunkSize) when ChunkSize > 0 ->
    fragment(Bin, ChunkSize, []).

fragment(<<>>, _ChunkSize, Acc) ->
    lists:reverse(Acc);
fragment(Bin, ChunkSize, Acc) when byte_size(Bin) =< ChunkSize ->
    lists:reverse([Bin | Acc]);
fragment(Bin, ChunkSize, Acc) ->
    <<Chunk:ChunkSize/binary, Rest/binary>> = Bin,
    fragment(Rest, ChunkSize, [Chunk | Acc]).

-doc "Build a response of `BodySize` bytes and split it into roughly `K` fragments.".
-spec fragment_n(non_neg_integer(), pos_integer()) -> [binary()].
fragment_n(BodySize, K) ->
    {_Head, _Body, Raw} = build_response(BodySize),
    ChunkSize = max(1, byte_size(Raw) div K),
    fragment(Raw, ChunkSize).
