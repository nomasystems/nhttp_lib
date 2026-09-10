%%%-----------------------------------------------------------------------------
-module(nhttp_fuzz_target).

-moduledoc """
Oracles and corpus storage for the five wire-facing parsers.

The library is pure, so the oracle is simple. For any binary input, a parser
returns one of the shapes that its `-spec` declares. It does not raise, and it
does not ask the caller to spin.

Three properties hold for every target:

1. No exception escapes.
2. The return matches the declared result type, down to the tag of the value.
3. A `{more, N}` return has `N >= 1` and stays inside the bound that the
   target's limits imply. A `BytesConsumed` return is inside the input, and a
   `Rest` return is a proper suffix of the input that is strictly shorter.

A pass also reports which of the three declared shapes the parser took. The
suite counts them, because a generator that never gets past the first octet
exercises nothing.

A campaign writes what it finds into `test/fuzz/crashes/<target>/`, which the
suite does not replay. The corpus lives under `test/fuzz/corpus/<target>/` as
`.hex` files. A file
holds hexadecimal bytes, and a line that starts with `#` is a comment that
names the behaviour the seed covers. Hexadecimal text keeps a permanent git
artefact readable in a diff.
""".

-export([
    all/0,
    check/2,
    consumed_result/4,
    rest_result/4,
    check_more/2,
    check_rest/2,
    corpus_root/0,
    corpus_dir/1,
    crashes_dir/1,
    load_corpus/1,
    read_seed/1,
    write_crash/3,
    format_hex/1
]).

-export_type([target/0, outcome/0, finding/0]).

-type target() :: h1 | h2_frame | h3_frame | hpack | qpack | ws_frame.

-doc """
Which declared shape the parser returned. `parsed` is `{ok, _, _}`,
`incomplete` is `{more, _}`, and `refused` is `{error, _}`.
""".
-type outcome() :: parsed | incomplete | refused.

-type finding() ::
    {crash, error | exit | throw, term(), [term()]}
    | {undeclared_return, term()}
    | {bytes_consumed_out_of_range, term(), non_neg_integer()}
    | {non_positive_more, term()}
    | {more_exceeds_bound, pos_integer(), pos_integer()}
    | {rest_not_shorter, non_neg_integer(), non_neg_integer()}
    | {rest_not_a_suffix, non_neg_integer(), non_neg_integer()}
    | {bad_value_shape, term()}.

-type result() :: {ok, outcome()} | {error, finding()}.
-type bound() :: pos_integer() | infinity.
-type shape() :: fun((term()) -> boolean()).

%% RFC 9113 Section 6.5.2 default, and the 9-octet frame header of Section 4.1.
-define(H2_MAX_FRAME_SIZE, 16384).
-define(H2_FRAME_HEADER_SIZE, 9).

%% RFC 6455 Section 5.2: a 2-octet header, an 8-octet length, a 4-octet key.
-define(WS_CAP, 65536).
-define(WS_MAX_HEADER, 14).

-define(H1_PEER, {{127, 0, 0, 1}, 12345}).

%% A capacity and a blocked stream budget above zero, so that the dynamic
%% table, the eviction path and the blocked stream path are all reachable.
-define(QPACK_CONFIG, #{max_table_capacity => 4096, max_blocked_streams => 8}).

%% RFC 9113 Section 6.5.2 default table size, and a decoded list bound that
%% keeps the `header_list_too_large` path reachable from a short input.
-define(HPACK_TABLE_SIZE, 4096).
-define(HPACK_DECODE_OPTS, #{max_list_size => 65536}).

%%%-----------------------------------------------------------------------------
%%% TARGETS
%%%-----------------------------------------------------------------------------
-doc "Every target the harness drives, in the order the task file lists them.".
-spec all() -> [target(), ...].
all() ->
    [h1, h2_frame, h3_frame, hpack, qpack, ws_frame].

-doc """
Drive one target with `Bin` and check every return against its `-spec`.

The HTTP/1.1 target drives `parse_request/2` and `parse_response/2`, because
the status line is where the integer conversion of `nhttp_msg:parse_status/1`
is reachable from the wire. The WebSocket target drives both roles, with and
without a frame size cap, because the cap is what bounds a `{more, N}`.
""".
-spec check(target(), binary()) -> result().
check(h1, Bin) ->
    Size = byte_size(Bin),
    Opts = h1_opts(),
    combine([
        fun() ->
            consumed_result(
                fun() -> nhttp_h1:parse_request(Bin, Opts) end, Size, infinity, fun is_request/1
            )
        end,
        fun() ->
            consumed_result(
                fun() -> nhttp_h1:parse_response(Bin, Opts) end, Size, infinity, fun is_response/1
            )
        end
    ]);
check(h2_frame, Bin) ->
    consumed_result(
        fun() -> nhttp_h2_frame:decode(Bin, ?H2_MAX_FRAME_SIZE) end,
        byte_size(Bin),
        ?H2_MAX_FRAME_SIZE + ?H2_FRAME_HEADER_SIZE,
        fun is_h2_frame/1
    );
check(h3_frame, Bin) ->
    rest_result(fun() -> nhttp_h3_frame:decode(Bin) end, Bin, infinity, fun is_h3_frame/1);
check(hpack, Bin) ->
    hpack_block(Bin);
check(qpack, Bin) ->
    maybe
        {ok, Dec} ?= qpack_feed_encoder(Bin),
        qpack_field_section(Dec, Bin)
    end;
check(ws_frame, Bin) ->
    Capped = #{max_frame_size => ?WS_CAP},
    Bound = ?WS_CAP + ?WS_MAX_HEADER,
    combine([
        fun() -> ws_raw(Bin, client, #{}, infinity) end,
        fun() -> ws_raw(Bin, server, #{}, infinity) end,
        fun() -> ws_raw(Bin, client, Capped, Bound) end,
        fun() -> ws_raw(Bin, server, Capped, Bound) end
    ]).

-spec h1_opts() -> nhttp_h1:opts().
h1_opts() ->
    #{scheme => http, peer => ?H1_PEER}.

-doc "Run every call of a target. The first finding wins, else the deepest outcome.".
-spec combine([fun(() -> result()), ...]) -> result().
combine(Calls) ->
    combine(Calls, refused).

-spec combine([fun(() -> result())], outcome()) -> result().
combine([], Deepest) ->
    {ok, Deepest};
combine([Call | Rest], Deepest) ->
    case Call() of
        {ok, Outcome} -> combine(Rest, deepest(Outcome, Deepest));
        {error, _Finding} = Error -> Error
    end.

-spec deepest(outcome(), outcome()) -> outcome().
deepest(parsed, _) -> parsed;
deepest(_, parsed) -> parsed;
deepest(incomplete, _) -> incomplete;
deepest(_, incomplete) -> incomplete;
deepest(refused, refused) -> refused.

%%%-----------------------------------------------------------------------------
%%% RESULT SHAPE CHECKS
%%%-----------------------------------------------------------------------------
-doc """
Check a parser that reports progress as a byte count.

`nhttp_h1:parse_request/2` and `nhttp_h2_frame:decode/2` both declare
`{ok, T, BytesConsumed :: pos_integer()} | {more, MinBytes :: pos_integer()}
| {error, Reason}`.
""".
-spec consumed_result(fun(() -> term()), non_neg_integer(), bound(), shape()) -> result().
consumed_result(Fun, Size, MoreBound, Shape) ->
    try Fun() of
        {ok, Value, N} when is_integer(N), N >= 1, N =< Size ->
            check_shape(Value, Shape);
        {ok, _Value, N} ->
            {error, {bytes_consumed_out_of_range, N, Size}};
        {more, N} ->
            check_more(N, MoreBound);
        {error, _Reason} ->
            {ok, refused};
        Other ->
            {error, {undeclared_return, Other}}
    catch
        Class:Reason:Stack -> {error, {crash, Class, Reason, Stack}}
    end.

-doc """
Check a parser that reports progress as the unparsed tail.

`nhttp_h3_frame:decode/1` declares `{ok, T, Rest :: binary()}
| {more, pos_integer()} | {error, Reason}`.
""".
-spec rest_result(fun(() -> term()), binary(), bound(), shape()) -> result().
rest_result(Fun, Bin, MoreBound, Shape) ->
    try Fun() of
        {ok, Value, Rest} when is_binary(Rest) ->
            maybe
                {ok, parsed} ?= check_shape(Value, Shape),
                check_rest(Bin, Rest)
            end;
        {more, N} ->
            check_more(N, MoreBound);
        {error, _Reason} ->
            {ok, refused};
        Other ->
            {error, {undeclared_return, Other}}
    catch
        Class:Reason:Stack -> {error, {crash, Class, Reason, Stack}}
    end.

-doc """
Feed one input to the QPACK encoder stream and return the decoder it leaves.

The encoder stream carries no outcome of its own, because it buffers what it
cannot yet parse and reports `{ok, _, []}` for almost every input. It is
driven for its crash and shape oracle, and for the dynamic table state that it
hands to the field section decode.
""".
-spec qpack_feed_encoder(binary()) -> {ok, nhttp_qpack:decoder()} | {error, finding()}.
qpack_feed_encoder(Bin) ->
    {ok, Dec0} = nhttp_qpack:new_decoder(?QPACK_CONFIG),
    try nhttp_qpack:feed_encoder_stream(Dec0, Bin) of
        {ok, Dec1, Unblocked} ->
            case is_unblocked_list(Unblocked) of
                true -> {ok, Dec1};
                false -> {error, {bad_value_shape, Unblocked}}
            end;
        {error, _Reason} ->
            {ok, Dec0};
        Other ->
            {error, {undeclared_return, Other}}
    catch
        Class:Reason:Stack -> {error, {crash, Class, Reason, Stack}}
    end.

-doc """
Check `nhttp_hpack:decode/3`, which declares
`{ok, Headers, State} | {invalid_field, Reason, State} | {error, Reason}`.

`{invalid_field, _, _}` is a refusal that still carries a usable state, the
shape that RFC 9113 Section 4.3 asks for. The state it returns must decode a
following block, so the check drives the same input twice.
""".
-spec hpack_block(binary()) -> result().
hpack_block(Bin) ->
    {ok, State0} = nhttp_hpack:new(?HPACK_TABLE_SIZE),
    maybe
        {ok, State1, _} ?= hpack_decode(State0, Bin),
        {ok, _State2, Outcome} ?= hpack_decode(State1, Bin),
        {ok, Outcome}
    end.

-spec hpack_decode(nhttp_hpack:state(), binary()) ->
    {ok, nhttp_hpack:state(), outcome()} | {error, finding()}.
hpack_decode(State, Bin) ->
    try nhttp_hpack:decode(Bin, State, ?HPACK_DECODE_OPTS) of
        {ok, Headers, NewState} ->
            case is_field_lines(Headers) of
                true -> {ok, NewState, parsed};
                false -> {error, {bad_value_shape, Headers}}
            end;
        {invalid_field, Reason, NewState} when
            Reason =:= uppercase_header_name;
            Reason =:= invalid_header_name;
            Reason =:= invalid_header_value
        ->
            {ok, NewState, refused};
        {error, _Reason} ->
            {ok, State, refused};
        Other ->
            {error, {undeclared_return, Other}}
    catch
        Class:Reason:Stack -> {error, {crash, Class, Reason, Stack}}
    end.

-doc """
Check `nhttp_qpack:decode_field_section/3`, which declares
`{ok, Decoder, DecoderStreamData :: iodata(), [{binary(), binary()}]}
| {blocked, Decoder} | {error, Reason}`.

`{blocked, _}` is the incomplete shape: the section names a dynamic table
entry that the encoder stream has not delivered.
""".
-spec qpack_field_section(nhttp_qpack:decoder(), binary()) -> result().
qpack_field_section(Dec, Bin) ->
    try nhttp_qpack:decode_field_section(Dec, 0, Bin) of
        {ok, _Dec1, DecData, FieldLines} ->
            case is_iodata(DecData) andalso is_field_lines(FieldLines) of
                true -> {ok, parsed};
                false -> {error, {bad_value_shape, {DecData, FieldLines}}}
            end;
        {blocked, _Dec1} ->
            {ok, incomplete};
        {error, _Reason} ->
            {ok, refused};
        Other ->
            {error, {undeclared_return, Other}}
    catch
        Class:Reason:Stack -> {error, {crash, Class, Reason, Stack}}
    end.

-spec ws_raw(binary(), client | server, nhttp_ws_frame:frame_limits(), bound()) -> result().
ws_raw(Bin, Role, Limits, MoreBound) ->
    try nhttp_ws_frame:decode_raw(Bin, Role, Limits) of
        {ok, Fin, Opcode, Payload, Rest} when
            is_integer(Fin),
            Fin >= 0,
            Fin =< 1,
            is_integer(Opcode),
            Opcode >= 0,
            Opcode =< 15,
            is_binary(Payload),
            is_binary(Rest)
        ->
            check_rest(Bin, Rest);
        {ok, _Fin, _Opcode, _Payload, _Rest} = Other ->
            {error, {bad_value_shape, Other}};
        {more, N} ->
            check_more(N, MoreBound);
        {error, _Reason} ->
            {ok, refused};
        Other ->
            {error, {undeclared_return, Other}}
    catch
        Class:Reason:Stack -> {error, {crash, Class, Reason, Stack}}
    end.

-doc "A `{more, N}` return must ask for at least one byte, and never for more than the bound.".
-spec check_more(term(), bound()) -> result().
check_more(N, infinity) when is_integer(N), N >= 1 ->
    {ok, incomplete};
check_more(N, Bound) when is_integer(N), N >= 1, N =< Bound ->
    {ok, incomplete};
check_more(N, Bound) when is_integer(N), N >= 1 ->
    {error, {more_exceeds_bound, N, Bound}};
check_more(N, _Bound) ->
    {error, {non_positive_more, N}}.

-doc "An unparsed tail must be a proper suffix of the input and strictly shorter than it.".
-spec check_rest(binary(), binary()) -> result().
check_rest(Bin, Rest) when byte_size(Rest) >= byte_size(Bin) ->
    {error, {rest_not_shorter, byte_size(Rest), byte_size(Bin)}};
check_rest(Bin, Rest) when
    binary_part(Bin, byte_size(Bin) - byte_size(Rest), byte_size(Rest)) =:= Rest
->
    {ok, parsed};
check_rest(Bin, Rest) ->
    {error, {rest_not_a_suffix, byte_size(Rest), byte_size(Bin)}}.

-spec check_shape(term(), shape()) -> result().
check_shape(Value, Shape) ->
    case Shape(Value) of
        true -> {ok, parsed};
        false -> {error, {bad_value_shape, Value}}
    end.

%%%-----------------------------------------------------------------------------
%%% DECLARED VALUE SHAPES
%%%
%%% A parser that returns a value outside its own union is as much a defect as
%%% one that raises, so every tag is named here rather than accepted by
%%% `is_tuple/1`.
%%%-----------------------------------------------------------------------------
-spec is_request(term()) -> boolean().
is_request(#{method := _, path := _, scheme := _, authority := _, headers := H}) -> is_list(H);
is_request(_) -> false.

-spec is_response(term()) -> boolean().
is_response(#{status := S, headers := H}) -> is_integer(S) andalso is_list(H);
is_response(_) -> false.

-spec is_h2_frame(term()) -> boolean().
is_h2_frame(preface) -> true;
is_h2_frame(settings_ack) -> true;
is_h2_frame({data, _StreamId, _Fin, Payload}) -> is_binary(Payload);
is_h2_frame({headers, _StreamId, _Fin, _EndHeaders, Block}) -> is_binary(Block);
is_h2_frame({headers, _StreamId, _Fin, _EndHeaders, _Priority, Block}) -> is_binary(Block);
is_h2_frame({priority, _StreamId, _Priority}) -> true;
is_h2_frame({rst_stream, _StreamId, _ErrorCode}) -> true;
is_h2_frame({settings, Settings}) -> is_map(Settings);
is_h2_frame({push_promise, _StreamId, _Fin, _PromisedId, Block}) -> is_binary(Block);
is_h2_frame({ping, Data}) -> is_binary(Data);
is_h2_frame({ping_ack, Data}) -> is_binary(Data);
is_h2_frame({goaway, _LastStreamId, _ErrorCode, Debug}) -> is_binary(Debug);
is_h2_frame({window_update, Increment}) -> is_integer(Increment);
is_h2_frame({window_update, _StreamId, Increment}) -> is_integer(Increment);
is_h2_frame({continuation, _StreamId, _EndHeaders, Block}) -> is_binary(Block);
is_h2_frame({unknown, Type}) -> is_integer(Type);
is_h2_frame(_) -> false.

-spec is_field_lines(term()) -> boolean().
is_field_lines(Lines) when is_list(Lines) -> lists:all(fun is_field_line/1, Lines);
is_field_lines(_) -> false.

-spec is_field_line(term()) -> boolean().
is_field_line({Name, Value}) -> is_binary(Name) andalso is_binary(Value);
is_field_line(_) -> false.

-spec is_unblocked_list(term()) -> boolean().
is_unblocked_list(Results) when is_list(Results) -> lists:all(fun is_unblocked/1, Results);
is_unblocked_list(_) -> false.

-spec is_unblocked(term()) -> boolean().
is_unblocked({StreamId, DecData, Lines}) ->
    is_integer(StreamId) andalso is_iodata(DecData) andalso is_field_lines(Lines);
is_unblocked(_) ->
    false.

-spec is_iodata(term()) -> boolean().
is_iodata(Term) ->
    try iolist_size(Term) of
        _ -> true
    catch
        _:_ -> false
    end.

-spec is_h3_frame(term()) -> boolean().
is_h3_frame({data, Payload}) -> is_binary(Payload);
is_h3_frame({headers, Block}) -> is_binary(Block);
is_h3_frame({cancel_push, PushId}) -> is_integer(PushId);
is_h3_frame({settings, Settings}) -> is_map(Settings);
is_h3_frame({push_promise, PushId, Section}) -> is_integer(PushId) andalso is_binary(Section);
is_h3_frame({goaway, Id}) -> is_integer(Id);
is_h3_frame({max_push_id, PushId}) -> is_integer(PushId);
is_h3_frame({unknown, Type, Payload}) -> is_integer(Type) andalso is_binary(Payload);
is_h3_frame(_) -> false.

%%%-----------------------------------------------------------------------------
%%% CORPUS
%%%-----------------------------------------------------------------------------
-doc "Absolute path of the corpus tree.".
-spec corpus_root() -> file:filename().
corpus_root() ->
    filename:join([project_root(), "test", "fuzz", "corpus"]).

-doc "Absolute path of one target's corpus directory.".
-spec corpus_dir(target()) -> file:filename().
corpus_dir(Target) ->
    filename:join(corpus_root(), atom_to_list(Target)).

-doc "Read every seed of one target, sorted by file name.".
-spec load_corpus(target()) -> [{file:filename(), binary()}].
load_corpus(Target) ->
    Files = lists:sort(filelib:wildcard(filename:join(corpus_dir(Target), "*.hex"))),
    [{File, read_seed(File)} || File <- Files].

-doc "Read one `.hex` seed file. Comment lines and white space are dropped.".
-spec read_seed(file:filename()) -> binary().
read_seed(Path) ->
    {ok, Text} = file:read_file(Path),
    Lines = binary:split(Text, [<<"\n">>], [global]),
    Hex = <<<<(strip_space(Line))/binary>> || Line <- Lines, not is_comment(Line)>>,
    binary:decode_hex(Hex).

-doc "Absolute path of one target's quarantine directory.".
-spec crashes_dir(target()) -> file:filename().
crashes_dir(Target) ->
    filename:join([project_root(), "test", "fuzz", "crashes", atom_to_list(Target)]).

-doc """
Write a crashing input into the target's quarantine directory and return the
path.

A campaign writes here, not into the corpus. The corpus is a CI gate, so a
known crasher inside it makes `make test` red in every session until the fix
lands. The fix promotes its reproduction into `corpus/`, where it becomes the
regression check.
""".
-spec write_crash(target(), binary(), iodata()) -> file:filename().
write_crash(Target, Input, Comment) ->
    Dir = crashes_dir(Target),
    ok = filelib:ensure_path(Dir),
    Digest = binary:encode_hex(binary:part(crypto:hash(sha256, Input), 0, 8), lowercase),
    Path = filename:join(Dir, "crash_" ++ binary_to_list(Digest) ++ ".hex"),
    ok = file:write_file(Path, ["# ", Comment, "\n", format_hex(Input), "\n"]),
    Path.

-doc "Render bytes as hexadecimal text, wrapped at 64 characters.".
-spec format_hex(binary()) -> iodata().
format_hex(Bin) ->
    wrap(binary:encode_hex(Bin, lowercase)).

-spec wrap(binary()) -> [binary()].
wrap(<<Head:64/binary, Tail/binary>>) ->
    [Head, <<"\n">> | wrap(Tail)];
wrap(Tail) ->
    [Tail].

-spec is_comment(binary()) -> boolean().
is_comment(<<"#", _/binary>>) -> true;
is_comment(_) -> false.

-spec strip_space(binary()) -> binary().
strip_space(Line) ->
    <<<<C>> || <<C>> <= Line, C =/= $\s, C =/= $\t, C =/= $\r>>.

%%%-----------------------------------------------------------------------------
%%% PROJECT ROOT
%%%-----------------------------------------------------------------------------
-spec project_root() -> file:filename().
project_root() ->
    find_project_root(filename:dirname(code:which(?MODULE))).

-spec find_project_root(file:filename()) -> file:filename().
find_project_root(Dir) ->
    case filelib:is_file(filename:join(Dir, "rebar.config")) of
        true ->
            Dir;
        false ->
            case filename:dirname(Dir) of
                Dir -> Dir;
                Parent -> find_project_root(Parent)
            end
    end.
