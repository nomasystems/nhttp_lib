%%%-----------------------------------------------------------------------------
-module(nhttp_fuzz_gen).

-moduledoc """
Deterministic byte mutator and structure-aware generator for the fuzz harness.

Every function takes an explicit `rand` state and returns the next one, so a
campaign is a pure function of its seed. The suite fixes the seed, and
`make fuzz` takes one as a parameter.

Three sources feed the harness, in the order of their yield:

- Corpus mutation. `mutate/3` reads a seed and flips, truncates, splices, or
  repeats bytes in it.
- Structure-aware generation. `structured/2` builds a frame header with a
  plausible type and a hostile length.
- Uniform random bytes. `random_bytes/2`.
""".

-export([
    new/1,
    mutate/3,
    random_bytes/2,
    structured/2
]).

-export_type([state/0]).

-type state() :: rand:state().

-type op() ::
    flip_bit
    | replace_byte
    | special_byte
    | truncate
    | grow
    | insert_slice
    | delete_slice
    | splice
    | repeat_slice
    | extreme_int.

%%%-----------------------------------------------------------------------------
%%% STATE
%%%-----------------------------------------------------------------------------
-doc "Build a generator state from an integer seed.".
-spec new(integer()) -> state().
new(Seed) ->
    rand:seed_s(exsss, {Seed, Seed bsr 16, (Seed bsl 3) + 7}).

%%%-----------------------------------------------------------------------------
%%% MUTATION
%%%-----------------------------------------------------------------------------
-doc """
Apply one mutation operator to `Bin`.

`Corpus` supplies the partner for the splice operator. An empty corpus falls
back to an operator that needs no partner.
""".
-spec mutate(binary(), [binary()], state()) -> {binary(), state()}.
mutate(Bin, Corpus, S0) ->
    {Op, S1} = pick(ops(Bin), S0),
    apply_op(Op, Bin, Corpus, S1).

-spec ops(binary()) -> [op(), ...].
ops(<<>>) ->
    [grow, insert_slice, splice];
ops(_Bin) ->
    [
        flip_bit,
        replace_byte,
        special_byte,
        truncate,
        grow,
        insert_slice,
        delete_slice,
        splice,
        repeat_slice,
        extreme_int
    ].

-spec apply_op(op(), binary(), [binary()], state()) -> {binary(), state()}.
apply_op(flip_bit, Bin, _Corpus, S0) ->
    {Pos, S1} = uniform0(byte_size(Bin), S0),
    {Bit, S2} = uniform0(8, S1),
    <<Pre:Pos/binary, B:8, Post/binary>> = Bin,
    {<<Pre/binary, (B bxor (1 bsl Bit)):8, Post/binary>>, S2};
apply_op(replace_byte, Bin, _Corpus, S0) ->
    {Pos, S1} = uniform0(byte_size(Bin), S0),
    {B, S2} = uniform0(256, S1),
    <<Pre:Pos/binary, _:8, Post/binary>> = Bin,
    {<<Pre/binary, B:8, Post/binary>>, S2};
apply_op(special_byte, Bin, _Corpus, S0) ->
    {Pos, S1} = uniform0(byte_size(Bin), S0),
    {B, S2} = pick(specials(), S1),
    <<Pre:Pos/binary, _:8, Post/binary>> = Bin,
    {<<Pre/binary, B:8, Post/binary>>, S2};
apply_op(truncate, Bin, _Corpus, S0) ->
    {Len, S1} = uniform0(byte_size(Bin), S0),
    {binary:part(Bin, 0, Len), S1};
apply_op(grow, Bin, _Corpus, S0) ->
    {N, S1} = uniform(16, S0),
    {Tail, S2} = random_bytes(N, S1),
    {<<Bin/binary, Tail/binary>>, S2};
apply_op(insert_slice, Bin, _Corpus, S0) ->
    {Pos, S1} = uniform0(byte_size(Bin) + 1, S0),
    {N, S2} = uniform(8, S1),
    {Ins, S3} = random_bytes(N, S2),
    <<Pre:Pos/binary, Post/binary>> = Bin,
    {<<Pre/binary, Ins/binary, Post/binary>>, S3};
apply_op(delete_slice, Bin, _Corpus, S0) ->
    Size = byte_size(Bin),
    {Pos, S1} = uniform0(Size, S0),
    {Len, S2} = uniform(Size - Pos, S1),
    <<Pre:Pos/binary, _:Len/binary, Post/binary>> = Bin,
    {<<Pre/binary, Post/binary>>, S2};
apply_op(splice, Bin, [], S0) ->
    apply_op(grow, Bin, [], S0);
apply_op(splice, Bin, Corpus, S0) ->
    {Other, S1} = pick(Corpus, S0),
    {Head, S2} = uniform0(byte_size(Bin) + 1, S1),
    {Tail, S3} = uniform0(byte_size(Other) + 1, S2),
    Prefix = binary:part(Bin, 0, Head),
    Suffix = binary:part(Other, Tail, byte_size(Other) - Tail),
    {<<Prefix/binary, Suffix/binary>>, S3};
apply_op(repeat_slice, Bin, _Corpus, S0) ->
    Size = byte_size(Bin),
    {Pos, S1} = uniform0(Size, S0),
    {Len, S2} = uniform(min(Size - Pos, 32), S1),
    {Times, S3} = uniform(4, S2),
    Slice = binary:copy(binary:part(Bin, Pos, Len), Times),
    <<Pre:Pos/binary, Post/binary>> = Bin,
    {<<Pre/binary, Slice/binary, Post/binary>>, S3};
apply_op(extreme_int, Bin, Corpus, S0) ->
    {Width, S1} = pick([2, 3, 4, 8], S0),
    Size = byte_size(Bin),
    case Size >= Width of
        false ->
            apply_op(grow, Bin, Corpus, S1);
        true ->
            {Pos, S2} = uniform0(Size - Width + 1, S1),
            {Value, S3} = pick(extremes(Width), S2),
            Bits = Width * 8,
            <<Pre:Pos/binary, _:Width/binary, Post/binary>> = Bin,
            {<<Pre/binary, Value:Bits, Post/binary>>, S3}
    end.

-spec specials() -> [byte(), ...].
specials() ->
    [0, 1, 9, 10, 13, 32, $:, $;, $,, $/, $%, $", 126, 127, 16#80, 16#C0, 16#FE, 16#FF].

-spec extremes(pos_integer()) -> [non_neg_integer(), ...].
extremes(Width) ->
    Bits = Width * 8,
    Max = (1 bsl Bits) - 1,
    Half = Max bsr 1,
    [0, 1, 126, 127, 128, Half, Half + 1, Max - 1, Max].

%%%-----------------------------------------------------------------------------
%%% RANDOM BYTES
%%%-----------------------------------------------------------------------------
-doc "Draw `N` uniform random bytes.".
-spec random_bytes(non_neg_integer(), state()) -> {binary(), state()}.
random_bytes(0, S) ->
    {<<>>, S};
random_bytes(N, S) when N > 0 ->
    rand:bytes_s(N, S).

%%%-----------------------------------------------------------------------------
%%% STRUCTURE AWARE GENERATION
%%%-----------------------------------------------------------------------------
-doc """
Build one input that has the shape the target expects, with a hostile value in
a length, a type, or a token field.
""".
-spec structured(nhttp_fuzz_target:target(), state()) -> {binary(), state()}.
structured(ws_frame, S0) ->
    ws_frame(S0);
structured(h2_frame, S0) ->
    h2_frame(S0);
structured(h3_frame, S0) ->
    h3_frame(S0);
structured(qpack, S0) ->
    qpack_section(S0);
structured(h1, S0) ->
    h1_message(S0).

%%%-----------------------------------------------------------------------------
%%% WEBSOCKET (RFC 6455 SECTION 5.2)
%%%-----------------------------------------------------------------------------
-spec ws_frame(state()) -> {binary(), state()}.
ws_frame(S0) ->
    {Fin, S1} = uniform0(2, S0),
    {Rsv, S2} = pick([0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7], S1),
    {Opcode, S3} = pick([0, 1, 2, 8, 9, 10, 0, 1, 2, 8, 9, 10, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15], S2),
    {Mask, S4} = uniform0(2, S3),
    {PayloadLen, S5} = uniform0(40, S4),
    {Payload, S6} = random_bytes(PayloadLen, S5),
    {Kind, S7} = pick([short, ext16, ext64], S6),
    {Declared, S8} = ws_declared(Kind, PayloadLen, S7),
    {MaskKey, S9} = ws_mask_key(Mask, S8),
    Header = ws_header(Kind, Fin, Rsv, Opcode, Mask, Declared),
    {<<Header/binary, MaskKey/binary, Payload/binary>>, S9}.

-spec ws_declared(short | ext16 | ext64, non_neg_integer(), state()) ->
    {non_neg_integer(), state()}.
ws_declared(short, PayloadLen, S) ->
    pick([min(PayloadLen, 125), 0, 1, 125], S);
ws_declared(ext16, PayloadLen, S) ->
    pick([PayloadLen, 0, 125, 126, 16#FFFE, 16#FFFF], S);
ws_declared(ext64, PayloadLen, S) ->
    pick([PayloadLen, 0, 16#10000, 16#7FFFFFFF, 1 bsl 62, (1 bsl 63) - 1, (1 bsl 64) - 1], S).

-spec ws_header(short | ext16 | ext64, 0..1, 0..7, 0..15, 0..1, non_neg_integer()) -> binary().
ws_header(short, Fin, Rsv, Opcode, Mask, Len) ->
    <<Fin:1, Rsv:3, Opcode:4, Mask:1, Len:7>>;
ws_header(ext16, Fin, Rsv, Opcode, Mask, Len) ->
    <<Fin:1, Rsv:3, Opcode:4, Mask:1, 126:7, Len:16>>;
ws_header(ext64, Fin, Rsv, Opcode, Mask, Len) ->
    <<Fin:1, Rsv:3, Opcode:4, Mask:1, 127:7, Len:64>>.

-spec ws_mask_key(0..1, state()) -> {binary(), state()}.
ws_mask_key(0, S) ->
    {<<>>, S};
ws_mask_key(1, S) ->
    random_bytes(4, S).

%%%-----------------------------------------------------------------------------
%%% HTTP/2 FRAME (RFC 9113 SECTION 4.1)
%%%-----------------------------------------------------------------------------
-spec h2_frame(state()) -> {binary(), state()}.
h2_frame(S0) ->
    {PayloadLen, S1} = uniform0(48, S0),
    {Payload, S2} = random_bytes(PayloadLen, S1),
    {Declared, S3} = pick([PayloadLen, 0, 1, 4, 5, 8, 16383, 16384, 16385, 16#FFFFFE, 16#FFFFFF], S2),
    {Type, S4} = pick([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16#7F, 16#FF], S3),
    {Flags, S5} = uniform0(256, S4),
    {StreamId, S6} = pick([0, 1, 2, 3, 16#7FFFFFFE, 16#7FFFFFFF], S5),
    {Prefix, S7} = pick([<<>>, <<>>, <<>>, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>], S6),
    Frame = <<Declared:24, Type:8, Flags:8, 0:1, StreamId:31, Payload/binary>>,
    {<<Prefix/binary, Frame/binary>>, S7}.

%%%-----------------------------------------------------------------------------
%%% HTTP/3 FRAME (RFC 9114 SECTION 7.1)
%%%-----------------------------------------------------------------------------
-spec h3_frame(state()) -> {binary(), state()}.
h3_frame(S0) ->
    {PayloadLen, S1} = uniform0(48, S0),
    {Payload, S2} = random_bytes(PayloadLen, S1),
    {Type, S3} = pick(h3_varints(), S2),
    {Declared, S4} = pick([PayloadLen | h3_varints()], S3),
    Header = <<(nquic_varint:encode(Type))/binary, (nquic_varint:encode(Declared))/binary>>,
    {<<Header/binary, Payload/binary>>, S4}.

-spec h3_varints() -> [non_neg_integer(), ...].
h3_varints() ->
    [0, 1, 3, 4, 5, 7, 16#0D, 16#21, 62, 63, 64, 16382, 16383, 16384, 16#3FFFFFFF, 16#3FFFFFFFFFFFFFFF].

%%%-----------------------------------------------------------------------------
%%% QPACK FIELD SECTION (RFC 9204 SECTION 4.5)
%%%
%%% The bytes are laid out here rather than taken from `nhttp_qpack_field_line',
%%% so that a defect in the encoder cannot narrow what the generator reaches.
%%% Names and values are drawn from a set that mixes conformant octets with the
%%% ones that RFC 9113 Section 8.2.1 refuses.
%%%-----------------------------------------------------------------------------
-spec qpack_section(state()) -> {binary(), state()}.
qpack_section(S0) ->
    {EncodedRIC, S1} = pick([0, 0, 0, 1, 2, 3, 17, 128, 254], S0),
    {Sign, S2} = uniform0(2, S1),
    {DeltaBase, S3} = pick([0, 0, 1, 2, 3, 17, 126], S2),
    {Count, S4} = uniform0(5, S3),
    {Reps, S5} = qpack_reps(Count, S4, []),
    Prefix = <<EncodedRIC:8, Sign:1, DeltaBase:7>>,
    {<<Prefix/binary, (iolist_to_binary(Reps))/binary>>, S5}.

-spec qpack_reps(non_neg_integer(), state(), [binary()]) -> {[binary()], state()}.
qpack_reps(0, S, Acc) ->
    {lists:reverse(Acc), S};
qpack_reps(N, S0, Acc) ->
    {Rep, S1} = qpack_rep(S0),
    qpack_reps(N - 1, S1, [Rep | Acc]).

-spec qpack_rep(state()) -> {binary(), state()}.
qpack_rep(S0) ->
    {Kind, S1} = pick(
        [indexed_static, indexed_dynamic, indexed_post_base, name_ref, post_base_name_ref, literal],
        S0
    ),
    qpack_rep(Kind, S1).

-spec qpack_rep(atom(), state()) -> {binary(), state()}.
qpack_rep(indexed_static, S0) ->
    {Index, S1} = pick([0, 1, 17, 62, 63], S0),
    {<<2#11:2, Index:6>>, S1};
qpack_rep(indexed_dynamic, S0) ->
    {Index, S1} = pick([0, 1, 2, 62, 63], S0),
    {<<2#10:2, Index:6>>, S1};
qpack_rep(indexed_post_base, S0) ->
    {Index, S1} = pick([0, 1, 14, 15], S0),
    {<<2#0001:4, Index:4>>, S1};
qpack_rep(name_ref, S0) ->
    {Never, S1} = uniform0(2, S0),
    {Table, S2} = uniform0(2, S1),
    {Index, S3} = pick([0, 1, 14, 15], S2),
    {Value, S4} = qpack_value(S3),
    {<<2#01:2, Never:1, Table:1, Index:4, (qpack_string(Value))/binary>>, S4};
qpack_rep(post_base_name_ref, S0) ->
    {Never, S1} = uniform0(2, S0),
    {Index, S2} = pick([0, 1, 6, 7], S1),
    {Value, S3} = qpack_value(S2),
    {<<2#0000:4, Never:1, Index:3, (qpack_string(Value))/binary>>, S3};
qpack_rep(literal, S0) ->
    {Never, S1} = uniform0(2, S0),
    {Name, S2} = qpack_name(S1),
    {Value, S3} = qpack_value(S2),
    Head = <<2#001:3, Never:1, 0:1, (byte_size(Name)):3>>,
    {<<Head/binary, Name/binary, (qpack_string(Value))/binary>>, S3}.

-spec qpack_name(state()) -> {binary(), state()}.
qpack_name(S) ->
    pick(
        [
            <<"x-a">>,
            <<":path">>,
            <<"cookie">>,
            <<"X-A">>,
            <<"x a">>,
            <<"x:a">>,
            <<>>,
            <<"x", 0, "a">>,
            <<"x", 127, "a">>,
            <<"x", 16#FF, "a">>
        ],
        S
    ).

-spec qpack_value(state()) -> {binary(), state()}.
qpack_value(S) ->
    pick(
        [
            <<"v">>,
            <<>>,
            <<"a b">>,
            <<"a\rb">>,
            <<"a\nb">>,
            <<"a", 0, "b">>,
            <<" v">>,
            <<"v\t">>,
            <<"v", 127>>
        ],
        S
    ).

%% A string literal with the Huffman bit clear and a 7 bit prefixed length
%% (RFC 9204 Section 4.1.2). Every drawn value is below 127 octets.
-spec qpack_string(binary()) -> binary().
qpack_string(Value) ->
    <<0:1, (byte_size(Value)):7, Value/binary>>.

%%%-----------------------------------------------------------------------------
%%% HTTP/1.1 MESSAGE (RFC 9112 SECTION 2.1)
%%%-----------------------------------------------------------------------------
-spec h1_message(state()) -> {binary(), state()}.
h1_message(S0) ->
    {Start, S1} = h1_start_line(S0),
    {Count, S2} = uniform0(4, S1),
    {Fields, S3} = h1_fields(Count, S2),
    {Body, S4} = pick(h1_bodies(), S3),
    {<<Start/binary, Fields/binary, "\r\n", Body/binary>>, S4}.

-spec h1_start_line(state()) -> {binary(), state()}.
h1_start_line(S0) ->
    case pick([request, response], S0) of
        {request, S1} ->
            {Method, S2} = pick(h1_methods(), S1),
            {Target, S3} = pick(h1_targets(), S2),
            {Version, S4} = pick(h1_versions(), S3),
            {<<Method/binary, " ", Target/binary, " ", Version/binary, "\r\n">>, S4};
        {response, S1} ->
            {Version, S2} = pick(h1_versions(), S1),
            {Status, S3} = pick(h1_statuses(), S2),
            {Reason, S4} = pick([<<"OK">>, <<"OK">>, <<"Not Found">>, <<>>, <<"\t">>], S3),
            {<<Version/binary, " ", Status/binary, " ", Reason/binary, "\r\n">>, S4}
    end.

-doc """
A field block of benign lines with at most one hostile line spliced into it.

One defect per message is the shape that isolates the defect. A message where
every field is hostile is refused on the first one, and proves nothing about
the fields behind it.
""".
-spec h1_fields(non_neg_integer(), state()) -> {binary(), state()}.
h1_fields(Count, S0) ->
    {Benign, S1} = h1_benign_lines(Count, S0, []),
    {Hostile, S2} = h1_hostile_line(S1),
    {Lines, S3} = h1_inject(Hostile, Benign, S2),
    {iolist_to_binary([[Line, "\r\n"] || Line <- Lines]), S3}.

-spec h1_benign_lines(non_neg_integer(), state(), [binary()]) -> {[binary()], state()}.
h1_benign_lines(0, S, Acc) ->
    {Acc, S};
h1_benign_lines(N, S0, Acc) ->
    {Line, S1} = pick(h1_benign_fields(), S0),
    h1_benign_lines(N - 1, S1, [Line | Acc]).

-spec h1_hostile_line(state()) -> {none | binary(), state()}.
h1_hostile_line(S0) ->
    case pick([yes, no], S0) of
        {no, S1} -> {none, S1};
        {yes, S1} -> pick(h1_hostile_fields(), S1)
    end.

-spec h1_inject(none | binary(), [binary()], state()) -> {[binary()], state()}.
h1_inject(none, Lines, S) ->
    {Lines, S};
h1_inject(Line, Lines, S0) ->
    {Pos, S1} = uniform0(length(Lines) + 1, S0),
    {Before, After} = lists:split(Pos, Lines),
    {Before ++ [Line | After], S1}.

-doc "The valid tokens repeat, so about half of the start lines are well formed.".
-spec h1_methods() -> [binary(), ...].
h1_methods() ->
    [
        <<"GET">>,
        <<"POST">>,
        <<"HEAD">>,
        <<"OPTIONS">>,
        <<"GET">>,
        <<"POST">>,
        <<"GET">>,
        <<"POST">>,
        <<>>,
        <<"G\tET">>,
        <<"GET", 0>>,
        <<"G ET">>,
        <<"GET\r\nX">>,
        <<16#80, 16#81>>,
        <<"get">>
    ].

-spec h1_targets() -> [binary(), ...].
h1_targets() ->
    [
        <<"/">>,
        <<"/a">>,
        <<"/">>,
        <<"/a">>,
        <<"/">>,
        <<"/a">>,
        <<"/">>,
        <<>>,
        <<"*">>,
        <<"/a b">>,
        <<"http://x/">>,
        <<"/", 0, "x">>,
        <<"/x\r\nX: y">>,
        <<"//">>,
        <<"/%">>
    ].

-spec h1_versions() -> [binary(), ...].
h1_versions() ->
    [
        <<"HTTP/1.1">>,
        <<"HTTP/1.0">>,
        <<"HTTP/1.1">>,
        <<"HTTP/1.1">>,
        <<"HTTP/1.1">>,
        <<"HTTP/9.9">>,
        <<"HTTP/">>,
        <<>>,
        <<"HTTP/1.1 ">>,
        <<"ICE/1.0">>
    ].

-spec h1_statuses() -> [binary(), ...].
h1_statuses() ->
    [
        <<"200">>,
        <<"200">>,
        <<"404">>,
        <<"500">>,
        <<"099">>,
        <<"1000">>,
        <<"-1">>,
        <<"+200">>,
        <<"2 0">>,
        <<"abc">>,
        <<>>,
        <<"0x1f4">>
    ].

-spec h1_benign_fields() -> [binary(), ...].
h1_benign_fields() ->
    [
        <<"Host: x">>,
        <<"Accept: */*">>,
        <<"User-Agent: fuzz">>,
        <<"Connection: keep-alive">>,
        <<"Content-Type: text/plain">>,
        <<"Cookie: a=b; c=d">>,
        <<"Content-Length: 0">>
    ].

-spec h1_hostile_fields() -> [binary(), ...].
h1_hostile_fields() ->
    [
        <<"Content-Length: -1">>,
        <<"Content-Length: +1">>,
        <<"Content-Length: 99999999999999999999999999">>,
        <<"Content-Length: 1\r\nContent-Length: 2">>,
        <<"Content-Length: 5, 5">>,
        <<"Transfer-Encoding: chunked">>,
        <<"Transfer-Encoding: chunked, chunked">>,
        <<"Transfer-Encoding: gzip">>,
        <<"Transfer-Encoding: chunked\r\nContent-Length: 5">>,
        <<"Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip">>,
        <<"Cookie: a=\"b\r\nX: y\"">>,
        <<"Set-Cookie: a=b\r\nX: y">>,
        <<"X: ", 0>>,
        <<"X", 0, ": y">>,
        <<": y">>,
        <<"X:">>,
        <<" X: y">>,
        <<"X : y">>,
        <<"Content-Encoding: gzip">>,
        <<"Connection: keep-alive, close">>
    ].

-spec h1_bodies() -> [binary(), ...].
h1_bodies() ->
    [
        <<>>,
        <<>>,
        <<>>,
        <<"hello">>,
        <<"0\r\n\r\n">>,
        <<"5\r\nhello\r\n0\r\n\r\n">>,
        <<"-1\r\n">>,
        <<"+5\r\nhello\r\n">>,
        <<"FFFFFFFFFFFFFFFF\r\n">>,
        <<"5\r\nhi\r\n">>,
        <<"0\r\nX: y\r\n\r\n">>,
        <<"\r\n">>
    ].


%%%-----------------------------------------------------------------------------
%%% RANDOM PRIMITIVES
%%%-----------------------------------------------------------------------------
-spec uniform(pos_integer(), state()) -> {pos_integer(), state()}.
uniform(N, S) when N >= 1 ->
    rand:uniform_s(N, S).

-spec uniform0(pos_integer(), state()) -> {non_neg_integer(), state()}.
uniform0(N, S) when N >= 1 ->
    {X, S1} = rand:uniform_s(N, S),
    {X - 1, S1}.

-spec pick([T, ...], state()) -> {T, state()}.
pick(List, S0) ->
    {I, S1} = uniform(length(List), S0),
    {lists:nth(I, List), S1}.
