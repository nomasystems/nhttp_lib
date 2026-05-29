%%%-----------------------------------------------------------------------------
-module(nhttp_hpack_props).

-moduledoc """
HPACK Header Compression Property Tests.

These properties are run via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

-spec prop_roundtrip() -> triq:property().
prop_roundtrip() ->
    ?FORALL(
        Headers,
        headers_gen(),
        begin
            {ok, EncState} = nhttp_hpack:new(),
            {ok, DecState} = nhttp_hpack:new(),
            {ok, Encoded, _} = nhttp_hpack:encode(Headers, EncState),
            case nhttp_hpack:decode(iolist_to_binary(Encoded), DecState) of
                {ok, Decoded, _} ->
                    Headers =:= Decoded;
                {error, _} ->
                    false
            end
        end
    ).

-spec prop_roundtrip_huffman() -> triq:property().
prop_roundtrip_huffman() ->
    ?FORALL(
        Headers,
        headers_gen(),
        begin
            {ok, EncState} = nhttp_hpack:new(),
            {ok, DecState} = nhttp_hpack:new(),
            Opts = #{huffman => true},
            {ok, Encoded, _} = nhttp_hpack:encode(Headers, EncState, Opts),
            case nhttp_hpack:decode(iolist_to_binary(Encoded), DecState) of
                {ok, Decoded, _} ->
                    Headers =:= Decoded;
                {error, _} ->
                    false
            end
        end
    ).

-spec prop_roundtrip_sequential() -> triq:property().
prop_roundtrip_sequential() ->
    ?FORALL(
        HeadersList,
        non_empty(list(headers_gen())),
        begin
            TruncatedList = lists:sublist(HeadersList, 10),
            {ok, EncState0} = nhttp_hpack:new(),
            {ok, DecState0} = nhttp_hpack:new(),
            verify_sequential(TruncatedList, EncState0, DecState0)
        end
    ).


-spec prop_table_size_bounded() -> triq:property().
prop_table_size_bounded() ->
    ?FORALL(
        {MaxSize, Headers},
        {int(64, 4096), headers_gen()},
        begin
            {ok, State0} = nhttp_hpack:new(MaxSize),
            {ok, _, State1} = nhttp_hpack:encode(Headers, State0),
            nhttp_hpack:table_size(State1) =< MaxSize
        end
    ).

-spec prop_table_size_update() -> triq:property().
prop_table_size_update() ->
    ?FORALL(
        {OldSize, NewSize, Headers},
        {int(256, 4096), int(0, 4096), headers_gen()},
        begin
            {ok, State0} = nhttp_hpack:new(OldSize),
            {ok, _, State1} = nhttp_hpack:encode(Headers, State0),
            {ok, State2} = nhttp_hpack:set_max_table_size(NewSize, State1),
            nhttp_hpack:table_size(State2) =< NewSize
        end
    ).

-spec prop_empty_after_zero_size() -> triq:property().
prop_empty_after_zero_size() ->
    ?FORALL(
        Headers,
        non_empty(headers_gen()),
        begin
            {ok, State0} = nhttp_hpack:new(),
            {ok, _, State1} = nhttp_hpack:encode(Headers, State0),
            {ok, State2} = nhttp_hpack:set_max_table_size(0, State1),
            nhttp_hpack:is_empty(State2) andalso nhttp_hpack:table_size(State2) =:= 0
        end
    ).


-spec prop_huffman_roundtrip() -> triq:property().
prop_huffman_roundtrip() ->
    ?FORALL(
        Data,
        binary(),
        begin
            Encoded = nhttp_huffman:encode(Data),
            case nhttp_huffman:decode(Encoded) of
                {ok, Decoded} ->
                    Data =:= Decoded;
                _ ->
                    false
            end
        end
    ).

-spec prop_huffman_compression() -> triq:property().
prop_huffman_compression() ->
    ?FORALL(
        Value,
        http_text_gen(),
        begin
            Encoded = nhttp_huffman:encode(Value),
            case nhttp_huffman:decode(Encoded) of
                {ok, Value} -> true;
                _ -> false
            end
        end
    ).


-spec headers_gen() -> triq_dom:domain().
headers_gen() ->
    ?LET(
        N,
        int(1, 10),
        [header_gen() || _ <- lists:seq(1, N)]
    ).

-spec header_gen() -> triq_dom:domain().
header_gen() ->
    frequency([
        {3, pseudo_header_gen()},
        {7, regular_header_gen()}
    ]).

-spec pseudo_header_gen() -> triq_dom:domain().
pseudo_header_gen() ->
    oneof([
        {<<":method">>, oneof([<<"GET">>, <<"POST">>, <<"PUT">>, <<"DELETE">>, <<"HEAD">>])},
        {<<":path">>, path_gen()},
        {<<":scheme">>, oneof([<<"http">>, <<"https">>])},
        {<<":authority">>, authority_gen()},
        {<<":status">>, nhttp_props_helpers:status_gen()}
    ]).

-spec regular_header_gen() -> triq_dom:domain().
regular_header_gen() ->
    frequency([
        {5, common_header_gen()},
        {5, custom_header_gen()}
    ]).

-spec common_header_gen() -> triq_dom:domain().
common_header_gen() ->
    oneof([
        {<<"accept">>, accept_gen()},
        {<<"accept-encoding">>, oneof([<<"gzip">>, <<"gzip, deflate">>, <<"br">>])},
        {<<"accept-language">>, oneof([<<"en-US">>, <<"en">>, <<"en-GB">>])},
        {<<"cache-control">>, oneof([<<"no-cache">>, <<"max-age=3600">>, <<"private">>])},
        {<<"content-type">>, content_type_gen()},
        {<<"content-length">>, ?LET(N, int(0, 99999), integer_to_binary(N))},
        {<<"host">>, authority_gen()},
        {<<"user-agent">>, user_agent_gen()},
        {<<"date">>, date_gen()},
        {<<"cookie">>, cookie_gen()},
        {<<"set-cookie">>, set_cookie_gen()}
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
        non_empty(list(header_name_char_gen())),
        begin
            Limited = lists:sublist(Chars, 30),
            list_to_binary([$x, $- | Limited])
        end
    ).

-spec header_name_char_gen() -> triq_dom:domain().
header_name_char_gen() ->
    frequency([
        {10, int($a, $z)},
        {3, int($0, $9)},
        {2, $-}
    ]).

-spec header_value_gen() -> triq_dom:domain().
header_value_gen() ->
    ?LET(
        Chars,
        list(header_value_char_gen()),
        list_to_binary(lists:sublist(Chars, 100))
    ).

-spec header_value_char_gen() -> triq_dom:domain().
header_value_char_gen() ->
    frequency([
        {10, int($a, $z)},
        {10, int($A, $Z)},
        {5, int($0, $9)},
        {3, oneof([$\s, $-, $_, $., $/, $:, $;, $=, $,])}
    ]).

-spec http_text_gen() -> triq_dom:domain().
http_text_gen() ->
    ?LET(
        Chars,
        non_empty(list(http_text_char_gen())),
        list_to_binary(lists:sublist(Chars, 200))
    ).

-spec http_text_char_gen() -> triq_dom:domain().
http_text_char_gen() ->
    frequency([
        {10, int($a, $z)},
        {5, int($A, $Z)},
        {3, int($0, $9)},
        {2, oneof([$\s, $-, $_, $., $/, $:, $;, $=, $,, $$, $@])}
    ]).

-spec path_gen() -> triq_dom:domain().
path_gen() ->
    oneof([
        <<"/">>,
        <<"/index.html">>,
        <<"/api/v1">>,
        ?LET(
            Segments,
            non_empty(list(path_segment_gen())),
            begin
                Limited = lists:sublist(Segments, 5),
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

-spec authority_gen() -> triq_dom:domain().
authority_gen() ->
    oneof([
        <<"example.com">>,
        <<"www.example.com">>,
        <<"localhost:8080">>,
        ?LET(
            {Sub, Domain},
            {oneof([<<"www">>, <<"api">>, <<"cdn">>]), oneof([<<"example">>, <<"test">>])},
            <<Sub/binary, ".", Domain/binary, ".com">>
        )
    ]).

-spec accept_gen() -> triq_dom:domain().
accept_gen() ->
    oneof([
        <<"*/*">>,
        <<"text/html">>,
        <<"application/json">>,
        <<"text/html, application/json">>
    ]).

-spec content_type_gen() -> triq_dom:domain().
content_type_gen() ->
    oneof([
        <<"text/html">>,
        <<"text/html; charset=utf-8">>,
        <<"application/json">>,
        <<"application/x-www-form-urlencoded">>,
        <<"multipart/form-data">>
    ]).

-spec user_agent_gen() -> triq_dom:domain().
user_agent_gen() ->
    oneof([
        <<"Mozilla/5.0">>,
        <<"curl/7.68.0">>,
        <<"nhttp/1.0">>
    ]).

-spec date_gen() -> triq_dom:domain().
date_gen() ->
    oneof([
        <<"Mon, 21 Oct 2013 20:13:21 GMT">>,
        <<"Tue, 15 Nov 2024 10:00:00 GMT">>,
        <<"Wed, 01 Jan 2025 00:00:00 GMT">>
    ]).

-spec cookie_gen() -> triq_dom:domain().
cookie_gen() ->
    ?LET(
        {Name, Value},
        {cookie_name_gen(), cookie_value_gen()},
        <<Name/binary, "=", Value/binary>>
    ).

-spec cookie_name_gen() -> triq_dom:domain().
cookie_name_gen() ->
    oneof([<<"session">>, <<"user">>, <<"csrf">>, <<"id">>]).

-spec cookie_value_gen() -> triq_dom:domain().
cookie_value_gen() ->
    ?LET(
        Chars,
        non_empty(list(int($a, $z))),
        list_to_binary(lists:sublist(Chars, 20))
    ).

-spec set_cookie_gen() -> triq_dom:domain().
set_cookie_gen() ->
    ?LET(
        Cookie,
        cookie_gen(),
        <<Cookie/binary, "; Path=/">>
    ).


-spec verify_sequential([nhttp_hpack:headers()], nhttp_hpack:state(), nhttp_hpack:state()) ->
    boolean().
verify_sequential([], _, _) ->
    true;
verify_sequential([Headers | Rest], EncState0, DecState0) ->
    {ok, Encoded, EncState1} = nhttp_hpack:encode(Headers, EncState0),
    case nhttp_hpack:decode(iolist_to_binary(Encoded), DecState0) of
        {ok, Decoded, DecState1} when Decoded =:= Headers ->
            verify_sequential(Rest, EncState1, DecState1);
        _ ->
            false
    end.


-spec prop_random_binary_no_crash() -> triq:property().
prop_random_binary_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            {ok, State} = nhttp_hpack:new(),
            _ = (catch nhttp_hpack:decode(Bin, State)),
            true
        end
    ).

-spec prop_hpack_bounded_after_error() -> triq:property().
prop_hpack_bounded_after_error() ->
    ?FORALL(
        {Headers, BadPrefix},
        {headers_gen(), non_empty(binary())},
        begin
            {ok, EncState} = nhttp_hpack:new(),
            {ok, DecState} = nhttp_hpack:new(),
            {ok, Encoded, _} = nhttp_hpack:encode(Headers, EncState),
            EncodedBin = iolist_to_binary(Encoded),
            BadInput = <<BadPrefix/binary, EncodedBin/binary>>,
            SizeBefore = nhttp_hpack:table_size(DecState),
            case nhttp_hpack:decode(BadInput, DecState) of
                {error, _} ->
                    %% Original DecState must still parse valid input correctly.
                    case nhttp_hpack:decode(EncodedBin, DecState) of
                        {ok, Decoded, NewSt} ->
                            Decoded =:= Headers andalso
                                nhttp_hpack:table_size(DecState) =:= SizeBefore andalso
                                nhttp_hpack:table_size(NewSt) >= SizeBefore;
                        _ ->
                            false
                    end;
                {ok, _, _} ->
                    %% Bad prefix happened to form valid HPACK in concatenation; skip.
                    true
            end
        end
    ).

-spec prop_huffman_random_no_crash() -> triq:property().
prop_huffman_random_no_crash() ->
    ?FORALL(
        {Bin, _BitLen},
        huffman_decode_input_gen(),
        case nhttp_huffman:decode(Bin) of
            {ok, _Decoded} -> true;
            {error, invalid_huffman} -> true
        end
    ).

-spec huffman_decode_input_gen() -> triq_dom:domain({binary(), non_neg_integer()}).
huffman_decode_input_gen() ->
    ?LET(
        Bin,
        binary(),
        ?LET(BitLen, int(0, byte_size(Bin) * 8 + 32), {Bin, BitLen})
    ).

-spec prop_malformed_index_no_crash() -> triq:property().
prop_malformed_index_no_crash() ->
    ?FORALL(
        {Index, Rest},
        {int(0, 16#7FFFFFFF), binary()},
        begin
            {ok, State} = nhttp_hpack:new(),
            Encoded =
                case Index < 127 of
                    true ->
                        <<(16#80 bor Index):8, Rest/binary>>;
                    false ->
                        <<16#FF:8, (encode_varint(Index - 127))/binary, Rest/binary>>
                end,
            _ = (catch nhttp_hpack:decode(Encoded, State)),
            true
        end
    ).

-spec encode_varint(non_neg_integer()) -> binary().
encode_varint(N) when N < 128 ->
    <<N:8>>;
encode_varint(N) ->
    <<(16#80 bor (N band 16#7F)):8, (encode_varint(N bsr 7))/binary>>.
