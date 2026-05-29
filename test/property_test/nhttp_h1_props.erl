%%%-----------------------------------------------------------------------------
-module(nhttp_h1_props).

-moduledoc """
HTTP/1.1 Codec Property Tests.

These properties are run via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").



-spec prop_request_roundtrip() -> triq:property().
prop_request_roundtrip() ->
    ?FORALL(
        Req,
        h1_req_gen(),
        begin
            EncodedList = nhttp_h1:encode_request(Req),
            Encoded = iolist_to_binary(EncodedList),
            case nhttp_h1:parse_request(Encoded) of
                {ok, ParsedReq, Consumed} when Consumed =:= byte_size(Encoded) ->
                    requests_equivalent(Req, ParsedReq);
                {ok, _ParsedReq, _Consumed} ->
                    false;
                {more, _} ->
                    false;
                {error, _Reason} ->
                    false
            end
        end
    ).

-spec prop_response_roundtrip() -> triq:property().
prop_response_roundtrip() ->
    ?FORALL(
        Resp,
        h1_resp_gen(),
        begin
            EncodedList = nhttp_h1:encode_response(Resp),
            Encoded = iolist_to_binary(EncodedList),
            case nhttp_h1:parse_response(Encoded) of
                {ok, ParsedResp, Consumed} when Consumed =:= byte_size(Encoded) ->
                    responses_equivalent(Resp, ParsedResp);
                {ok, _ParsedResp, _Consumed} ->
                    false;
                {more, _} ->
                    false;
                {error, _Reason} ->
                    false
            end
        end
    ).

-spec prop_chunked_roundtrip() -> triq:property().
prop_chunked_roundtrip() ->
    ?FORALL(
        Chunks,
        non_empty(list(non_empty(binary()))),
        begin
            NonEmptyChunks = [C || C <- Chunks, byte_size(C) > 0],
            case NonEmptyChunks of
                [] ->
                    true;
                _ ->
                    EncodedChunks = [nhttp_h1:encode_chunk(C) || C <- NonEmptyChunks],
                    LastChunk = nhttp_h1:encode_last_chunk(),
                    FullBody = iolist_to_binary([EncodedChunks, LastChunk]),

                    Header = <<"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n">>,
                    FullResponse = <<Header/binary, FullBody/binary>>,

                    case nhttp_h1:parse_response(FullResponse) of
                        {ok, #{body := ParsedBody}, Consumed} when
                            Consumed =:= byte_size(FullResponse)
                        ->
                            ExpectedBody = iolist_to_binary(NonEmptyChunks),
                            ParsedBody =:= ExpectedBody;
                        _ ->
                            false
                    end
            end
        end
    ).

-spec prop_split_at() -> triq:property().
prop_split_at() ->
    ?FORALL(
        {Req, ExtraData},
        {h1_req_gen(), binary()},
        begin
            EncodedList = nhttp_h1:encode_request(Req),
            Encoded = iolist_to_binary(EncodedList),
            FullData = <<Encoded/binary, ExtraData/binary>>,
            case nhttp_h1:parse_request(FullData) of
                {ok, _ParsedReq, Consumed} ->
                    Rest = nhttp_h1:split_at(FullData, Consumed),
                    Rest =:= ExtraData;
                {more, _} ->
                    false;
                {error, _} ->
                    false
            end
        end
    ).


-spec h1_req_gen() -> triq_dom:domain().
h1_req_gen() ->
    ?LET(
        {Method, Path, Headers, Body},
        {method_gen(), path_gen(), headers_gen(), body_gen()},
        #{
            method => Method,
            path => Path,
            version => http1_1,
            headers => [{<<"Host">>, <<"example.com">>} | Headers],
            body => Body
        }
    ).

-spec h1_resp_gen() -> triq_dom:domain().
h1_resp_gen() ->
    ?LET(
        {Status, Reason, Headers, Body},
        {status_gen(), reason_gen(), headers_gen(), body_gen()},
        #{
            version => http1_1,
            status => Status,
            reason => Reason,
            headers => Headers,
            body => Body
        }
    ).

-spec method_gen() -> triq_dom:domain().
method_gen() ->
    oneof([get, post, put, delete, head, options, patch]).

-spec path_gen() -> triq_dom:domain().
path_gen() ->
    ?LET(
        Segments,
        list(path_segment_gen()),
        case Segments of
            [] -> <<"/">>;
            _ -> iolist_to_binary([<<"/">>, lists:join(<<"/">>, Segments)])
        end
    ).

-spec path_segment_gen() -> triq_dom:domain().
path_segment_gen() ->
    ?LET(
        Chars,
        non_empty(list(path_char_gen())),
        list_to_binary(Chars)
    ).

-spec path_char_gen() -> triq_dom:domain().
path_char_gen() ->
    oneof([
        int($a, $z),
        int($A, $Z),
        int($0, $9),
        elements([$_, $-, $.])
    ]).

-spec status_gen() -> triq_dom:domain().
status_gen() ->
    oneof([200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]).

-spec reason_gen() -> triq_dom:domain().
reason_gen() ->
    oneof([
        <<"OK">>,
        <<"Created">>,
        <<"No Content">>,
        <<"Moved Permanently">>,
        <<"Found">>,
        <<"Not Modified">>,
        <<"Bad Request">>,
        <<"Unauthorized">>,
        <<"Forbidden">>,
        <<"Not Found">>,
        <<"Internal Server Error">>,
        <<"Bad Gateway">>,
        <<"Service Unavailable">>
    ]).

-spec headers_gen() -> triq_dom:domain().
headers_gen() ->
    list(header_gen()).

-spec header_gen() -> triq_dom:domain().
header_gen() ->
    ?LET(
        {Name, Value},
        {header_name_gen(), header_value_gen()},
        {Name, Value}
    ).

-spec header_name_gen() -> triq_dom:domain().
header_name_gen() ->
    oneof([
        <<"Accept">>,
        <<"Accept-Encoding">>,
        <<"Accept-Language">>,
        <<"Cache-Control">>,
        <<"Content-Type">>,
        <<"User-Agent">>,
        <<"X-Request-Id">>,
        <<"X-Custom-Header">>
    ]).

-spec header_value_gen() -> triq_dom:domain().
header_value_gen() ->
    ?LET(
        Chars,
        non_empty(list(header_value_char_gen())),
        list_to_binary(Chars)
    ).

-spec header_value_char_gen() -> triq_dom:domain().
header_value_char_gen() ->
    int(32, 126).

-spec body_gen() -> triq_dom:domain().
body_gen() ->
    oneof([
        <<>>,
        binary(),
        ?LET(Size, int(1, 1024), binary(Size))
    ]).


-spec requests_equivalent(nhttp_h1:req(), nhttp_h1:req()) -> boolean().
requests_equivalent(
    #{method := M1, path := P1, body := B1},
    #{method := M2, path := P2, body := B2}
) ->
    M1 =:= M2 andalso P1 =:= P2 andalso B1 =:= B2.

-spec responses_equivalent(nhttp_h1:resp(), nhttp_h1:resp()) -> boolean().
responses_equivalent(
    #{status := S1, body := B1},
    #{status := S2, body := B2}
) ->
    S1 =:= S2 andalso B1 =:= B2.

-spec prop_random_request_no_crash() -> triq:property().
prop_random_request_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            _ = (catch nhttp_h1:parse_request(Bin)),
            true
        end
    ).

-spec prop_random_response_no_crash() -> triq:property().
prop_random_response_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            _ = (catch nhttp_h1:parse_response(Bin)),
            true
        end
    ).

-spec prop_reject_header_name_injection() -> triq:property().
prop_reject_header_name_injection() ->
    ?FORALL(
        {Prefix, Inject, Suffix, Value},
        {valid_token_gen(), non_tchar_byte_gen(), valid_token_tail_gen(), valid_token_gen()},
        begin
            BadName = <<Prefix/binary, Inject:8, Suffix/binary>>,
            Req =
                <<"GET / HTTP/1.1\r\nHost: example.com\r\n", BadName/binary, ": ", Value/binary,
                    "\r\n\r\n">>,
            case nhttp_h1:parse_request(Req) of
                {error, _} -> true;
                _ -> false
            end
        end
    ).

-spec prop_reject_header_value_bare_controls() -> triq:property().
prop_reject_header_value_bare_controls() ->
    ?FORALL(
        {Prefix, Inject, Suffix, Name},
        {valid_value_gen(), bare_control_byte_gen(), valid_value_gen(), valid_token_gen()},
        begin
            BadValue = <<Prefix/binary, Inject:8, Suffix/binary>>,
            Req =
                <<"GET / HTTP/1.1\r\nHost: example.com\r\n", Name/binary, ": ", BadValue/binary,
                    "\r\n\r\n">>,
            case nhttp_h1:parse_request(Req) of
                {error, _} -> true;
                _ -> false
            end
        end
    ).

-spec valid_token_gen() -> triq_dom:domain().
valid_token_gen() ->
    ?LET(Chars, non_empty(list(tchar_byte_gen())), list_to_binary(Chars)).

-spec valid_token_tail_gen() -> triq_dom:domain().
valid_token_tail_gen() ->
    ?LET(Chars, list(tchar_byte_gen()), list_to_binary(Chars)).

-spec valid_value_gen() -> triq_dom:domain().
valid_value_gen() ->
    ?LET(Chars, list(int(33, 126)), list_to_binary(Chars)).

-spec tchar_byte_gen() -> triq_dom:domain().
tchar_byte_gen() ->
    oneof([
        int($a, $z),
        int($A, $Z),
        int($0, $9),
        elements([$!, $#, $$, $%, $&, $', $*, $+, $-, $., $^, $_, $`, $|, $~])
    ]).

-spec non_tchar_byte_gen() -> triq_dom:domain().
non_tchar_byte_gen() ->
    elements([$\r, $\n, 0, $\s, $\t, $", $(, $), $,, $/, $;, $<, $=, $>, $?, $@, ${, $}]).

-spec bare_control_byte_gen() -> triq_dom:domain().
bare_control_byte_gen() ->
    elements([$\r, $\n, 0]).

-spec prop_malformed_request_line_no_crash() -> triq:property().
prop_malformed_request_line_no_crash() ->
    ?FORALL(
        {Method, Path, Version, Sep1, Sep2, Trailer},
        {binary(), binary(), binary(), binary(), binary(), binary()},
        begin
            RequestLine =
                <<Method/binary, Sep1/binary, Path/binary, Sep2/binary, Version/binary,
                    Trailer/binary, "\r\n\r\n">>,
            _ = (catch nhttp_h1:parse_request(RequestLine)),
            true
        end
    ).

-spec prop_oversized_headers_no_crash() -> triq:property().
prop_oversized_headers_no_crash() ->
    ?FORALL(
        {Count, KeySize, ValueSize},
        {int(1, 100), int(1, 1000), int(1, 10000)},
        begin
            Headers = [
                <<
                    (binary:copy(<<"x">>, min(KeySize, 100)))/binary,
                    ": ",
                    (binary:copy(<<"v">>, min(ValueSize, 1000)))/binary,
                    "\r\n"
                >>
             || _ <- lists:seq(1, min(Count, 50))
            ],
            Request =
                <<"GET / HTTP/1.1\r\nHost: localhost\r\n", (iolist_to_binary(Headers))/binary,
                    "\r\n">>,
            _ = (catch nhttp_h1:parse_request(Request)),
            true
        end
    ).

-spec prop_no_smuggling() -> triq:property().
prop_no_smuggling() ->
    ?FORALL(
        Scenario,
        framing_scenario_gen(),
        begin
            HeaderLines = scenario_to_headers(Scenario),
            Req =
                <<"POST / HTTP/1.1\r\nHost: example.com\r\n", HeaderLines/binary, "\r\nDATA">>,
            Conflicting = is_conflicting_scenario(Scenario),
            case nhttp_h1:parse_request(Req) of
                {ok, _, _} -> not Conflicting;
                {more, _} -> not Conflicting;
                {error, _} -> Conflicting
            end
        end
    ).

-spec framing_scenario_gen() -> triq_dom:domain().
framing_scenario_gen() ->
    ?LET(
        {TECasing, CLs},
        {oneof([none, lower, upper, mixed]), list(content_length_value_gen())},
        {TECasing, CLs}
    ).

-spec content_length_value_gen() -> triq_dom:domain().
content_length_value_gen() ->
    oneof([<<"0">>, <<"4">>, <<"100">>]).

-spec scenario_to_headers({none | lower | upper | mixed, [binary()]}) -> binary().
scenario_to_headers({TECasing, CLs}) ->
    TEPart = te_header(TECasing),
    CLPart = iolist_to_binary([<<"Content-Length: ", V/binary, "\r\n">> || V <- CLs]),
    <<TEPart/binary, CLPart/binary>>.

-spec te_header(none | lower | upper | mixed) -> binary().
te_header(none) -> <<>>;
te_header(lower) -> <<"transfer-encoding: chunked\r\n">>;
te_header(upper) -> <<"TRANSFER-ENCODING: CHUNKED\r\n">>;
te_header(mixed) -> <<"Transfer-Encoding: Chunked\r\n">>.

-spec is_conflicting_scenario({none | lower | upper | mixed, [binary()]}) -> boolean().
is_conflicting_scenario({none, CLs}) ->
    length(lists:usort(CLs)) > 1;
is_conflicting_scenario({_TECasing, []}) ->
    false;
is_conflicting_scenario({_TECasing, _CLs}) ->
    true.

-spec prop_chunked_extensions_and_trailers() -> triq:property().
prop_chunked_extensions_and_trailers() ->
    ?FORALL(
        {Chunks, Trailers, ExtMode},
        {list(non_empty(binary())), list(trailer_pair_gen()), oneof([none, valid_ext, garbage])},
        begin
            Body = iolist_to_binary([
                [encode_chunk_with_ext(C, ExtMode) || C <- Chunks],
                encode_last_chunk(ExtMode, Trailers)
            ]),
            St = chunked_stream(),
            case nhttp_h1:parse_request_body(Body, St) of
                {ok, _Out, _NewSt, _Consumed} -> true;
                {more, _, _} -> true;
                {error, _} -> true
            end
        end
    ).

-spec prop_chunked_roundtrip_with_trailers() -> triq:property().
prop_chunked_roundtrip_with_trailers() ->
    ?FORALL(
        {Chunks, Trailers},
        {non_empty(list(non_empty(binary()))), list(trailer_pair_gen())},
        begin
            Body = iolist_to_binary([
                [encode_chunk_with_ext(C, valid_ext) || C <- Chunks],
                encode_last_chunk(valid_ext, Trailers)
            ]),
            St = chunked_stream(),
            case nhttp_h1:parse_request_body(Body, St) of
                {ok, Out, none, Consumed} when Consumed =:= byte_size(Body) ->
                    ExpectedBody = iolist_to_binary(Chunks),
                    ActualBody = iolist_to_binary([D || {data, D} <- Out]),
                    {fin, ParsedTrailers} = lists:last(Out),
                    ExpectedTrailers = [
                        {nhttp_headers:to_lower(N), V}
                     || {N, V} <- Trailers
                    ],
                    ExpectedBody =:= ActualBody andalso ParsedTrailers =:= ExpectedTrailers;
                _ ->
                    false
            end
        end
    ).

-spec encode_chunk_with_ext(binary(), none | valid_ext | garbage) -> iodata().
encode_chunk_with_ext(Chunk, none) ->
    [integer_to_binary(byte_size(Chunk), 16), <<"\r\n">>, Chunk, <<"\r\n">>];
encode_chunk_with_ext(Chunk, valid_ext) ->
    [integer_to_binary(byte_size(Chunk), 16), <<";ext=value\r\n">>, Chunk, <<"\r\n">>];
encode_chunk_with_ext(Chunk, garbage) ->
    [integer_to_binary(byte_size(Chunk), 16), <<"X\r\n">>, Chunk, <<"\r\n">>].

-spec encode_last_chunk(none | valid_ext | garbage, [{binary(), binary()}]) -> iodata().
encode_last_chunk(Mode, Trailers) ->
    Tail =
        case Mode of
            valid_ext -> <<"0;final=true\r\n">>;
            garbage -> <<"0X\r\n">>;
            none -> <<"0\r\n">>
        end,
    TrailerBytes = [[N, <<": ">>, V, <<"\r\n">>] || {N, V} <- Trailers],
    [Tail, TrailerBytes, <<"\r\n">>].

-spec chunked_stream() -> nhttp_h1:body_stream().
chunked_stream() ->
    nhttp_h1:body_stream_from_response(
        get, 200, [{<<"transfer-encoding">>, <<"chunked">>}]
    ).

-spec trailer_pair_gen() -> triq_dom:domain().
trailer_pair_gen() ->
    ?LET(
        {Name, Value},
        {valid_token_gen(), valid_value_gen()},
        {Name, Value}
    ).
