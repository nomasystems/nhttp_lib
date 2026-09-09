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
            {ok, EncodedList} = nhttp_h1:encode_request(Req),
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
            {ok, EncodedList} = nhttp_h1:encode_response(Resp),
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
            {ok, EncodedList} = nhttp_h1:encode_request(Req),
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


-spec prop_encode_response_single_terminator() -> triq:property().
prop_encode_response_single_terminator() ->
    ?FORALL(
        Headers,
        list({any_field_name_gen(), any_field_value_gen()}),
        begin
            Resp = #{
                version => http1_1,
                status => 200,
                reason => <<"OK">>,
                headers => Headers,
                body => <<>>
            },
            case nhttp_h1:encode_response(Resp) of
                {error, _Reason} ->
                    true;
                {ok, Io} ->
                    count_terminators(iolist_to_binary(Io)) =:= 1
            end
        end
    ).

-spec any_field_name_gen() -> triq_dom:domain().
any_field_name_gen() ->
    oneof([header_name_gen(), hostile_binary_gen()]).

-spec any_field_value_gen() -> triq_dom:domain().
any_field_value_gen() ->
    oneof([header_value_gen(), hostile_binary_gen()]).

-spec hostile_binary_gen() -> triq_dom:domain().
hostile_binary_gen() ->
    ?LET(
        Chars,
        list(oneof([int(0, 255), elements([$\r, $\n, 0, 16#7F, $:, $\s])])),
        list_to_binary(Chars)
    ).

-spec count_terminators(binary()) -> non_neg_integer().
count_terminators(Bin) ->
    count_terminators(Bin, 0).

-spec count_terminators(binary(), non_neg_integer()) -> non_neg_integer().
count_terminators(<<>>, N) ->
    N;
count_terminators(<<"\r\n\r\n", _/binary>> = Bin, N) ->
    <<_, Rest/binary>> = Bin,
    count_terminators(Rest, N + 1);
count_terminators(<<_, Rest/binary>>, N) ->
    count_terminators(Rest, N).

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
            body => body_for_status(Status, Body)
        }
    ).

-spec body_for_status(nhttp_lib:status(), binary()) -> binary().
body_for_status(Status, _Body) when
    Status >= 100, Status =< 199; Status =:= 204; Status =:= 304
->
    <<>>;
body_for_status(_Status, Body) ->
    Body.

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

-spec prop_request_method_is_token() -> triq:property().
prop_request_method_is_token() ->
    ?FORALL(
        {MethodBin, Path},
        {method_fuzz_gen(), elements([<<"/">>, <<"/p">>, <<"/a/b?q=1">>])},
        begin
            Req = <<MethodBin/binary, " ", Path/binary, " HTTP/1.1\r\nHost: x\r\n\r\n">>,
            case nhttp_h1:parse_request(Req) of
                {ok, #{method := Method}, _} -> method_is_rfc9110_token(Method);
                _ -> true
            end
        end
    ).

%% RFC 9110 Section 8.6: Content-Length = 1*DIGIT. RFC 9110 Section 5.5 strips
%% leading and trailing OWS before the field value is read.
-spec prop_content_length_is_digits() -> triq:property().
prop_content_length_is_digits() ->
    ?FORALL(
        Value,
        content_length_fuzz_gen(),
        begin
            Req =
                <<"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: ", Value/binary, "\r\n\r\n">>,
            Valid = is_content_length_abnf(trim_ows(Value)),
            case nhttp_h1:parse_request(Req) of
                {ok, _, _} -> Valid;
                {more, _} -> Valid;
                {error, invalid_content_length} -> not Valid;
                {error, _} -> false
            end
        end
    ).

-spec content_length_fuzz_gen() -> triq_dom:domain().
content_length_fuzz_gen() ->
    oneof([
        signed_content_length_gen(),
        affixed_content_length_gen(),
        free_content_length_gen()
    ]).

%% A bare fuzz generator almost never lands on "+5", the one shape that a
%% binary_to_integer/1 based parser accepts and the ABNF does not.
-spec signed_content_length_gen() -> triq_dom:domain().
signed_content_length_gen() ->
    ?LET(
        {Sign, Digits},
        {elements([<<"+">>, <<"-">>]), elements([<<"0">>, <<"5">>, <<"42">>, <<"007">>])},
        <<Sign/binary, Digits/binary>>
    ).

-spec affixed_content_length_gen() -> triq_dom:domain().
affixed_content_length_gen() ->
    ?LET(
        {Prefix, Digits, Suffix},
        {
            elements([<<>>, <<"+">>, <<"-">>, <<" ">>, <<"\t">>, <<"0x">>, <<"00">>]),
            elements([<<>>, <<"0">>, <<"5">>, <<"42">>]),
            elements([<<>>, <<" ">>, <<"\t">>, <<".0">>, <<",5">>, <<239, 188, 149>>])
        },
        <<Prefix/binary, Digits/binary, Suffix/binary>>
    ).

%% RFC 9110 Section 5.3: a recipient combines multiple field lines with the
%% same name into one comma-separated list, in order of receipt. The framing
%% decision must therefore not depend on how the sender split the field.
-spec prop_transfer_encoding_field_lines_join() -> triq:property().
prop_transfer_encoding_field_lines_join() ->
    ?FORALL(
        Lines,
        non_empty(list(transfer_coding_line_gen())),
        te_framing(Lines) =:= te_framing([join_field_lines(Lines)])
    ).

-spec transfer_coding_line_gen() -> triq_dom:domain().
transfer_coding_line_gen() ->
    elements([
        <<"chunked">>,
        <<"Chunked">>,
        <<" chunked\t">>,
        <<"gzip">>,
        <<"deflate">>,
        <<"identity">>,
        <<"gzip, chunked">>,
        <<"chunked, gzip">>,
        <<"chunked, chunked">>,
        <<>>,
        <<",">>
    ]).

-spec join_field_lines([binary()]) -> binary().
join_field_lines(Lines) ->
    iolist_to_binary(lists:join(<<", ">>, Lines)).

-spec te_framing([binary()]) -> term().
te_framing(Lines) ->
    Field = [[<<"Transfer-Encoding: ">>, Line, <<"\r\n">>] || Line <- Lines],
    Bin = iolist_to_binary([<<"POST / HTTP/1.1\r\nHost: x\r\n">>, Field, <<"\r\n0\r\n\r\n">>]),
    case nhttp_h1:parse_request_headers(Bin, #{}) of
        {ok, _Req, {chunked, _St}, _Consumed} -> chunked;
        {ok, _Req, Stream, _Consumed} -> Stream;
        Other -> Other
    end.

-spec free_content_length_gen() -> triq_dom:domain().
free_content_length_gen() ->
    ?LET(
        Chars,
        list(content_length_byte_gen()),
        list_to_binary(lists:sublist(Chars, 6))
    ).

-spec content_length_byte_gen() -> triq_dom:domain().
content_length_byte_gen() ->
    oneof([
        int($0, $9),
        elements([$+, $-, $\s, $\t, $., $,, $x, $a, $O, 16#EF])
    ]).

-spec is_content_length_abnf(binary()) -> boolean().
is_content_length_abnf(<<>>) ->
    false;
is_content_length_abnf(Bin) ->
    lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(Bin)).

-spec trim_ows(binary()) -> binary().
trim_ows(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t ->
    trim_ows(Rest);
trim_ows(<<>>) ->
    <<>>;
trim_ows(Bin) ->
    case binary:last(Bin) of
        C when C =:= $\s; C =:= $\t ->
            trim_ows(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ ->
            Bin
    end.

-spec method_fuzz_gen() -> triq_dom:domain().
method_fuzz_gen() ->
    ?LET(
        Chars,
        non_empty(list(oneof([tchar_byte_gen(), non_tchar_byte_gen(), int(0, 255)]))),
        list_to_binary(lists:sublist(Chars, 16))
    ).

-spec method_is_rfc9110_token(nhttp_lib:method()) -> boolean().
method_is_rfc9110_token(Method) when is_atom(Method) ->
    lists:member(Method, [get, head, post, put, delete, connect, options, trace, patch]);
method_is_rfc9110_token(<<>>) ->
    false;
method_is_rfc9110_token(Method) when is_binary(Method) ->
    lists:all(fun is_tchar_byte/1, binary_to_list(Method)).

-spec is_tchar_byte(byte()) -> boolean().
is_tchar_byte(C) when C >= $a, C =< $z -> true;
is_tchar_byte(C) when C >= $A, C =< $Z -> true;
is_tchar_byte(C) when C >= $0, C =< $9 -> true;
is_tchar_byte(C) -> lists:member(C, [$!, $#, $$, $%, $&, $', $*, $+, $-, $., $^, $_, $`, $|, $~]).

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

%% RFC 9110 Section 5.5 and RFC 9112 Section 11.1. The encoder reads a field
%% value with one of two instruments, and the length picks between them. The
%% property compares the encoder against the octet set at every length, so a
%% disagreement between the two instruments fails it.
-spec prop_field_value_scan_agrees_with_the_octet_set() -> triq:property().
prop_field_value_scan_agrees_with_the_octet_set() ->
    ?FORALL(
        Value,
        field_value_scan_gen(),
        begin
            Resp = #{status => 200, reason => <<"OK">>, headers => [{<<"x">>, Value}]},
            Clean = binary:match(Value, field_value_bad_pattern()) =:= nomatch,
            case nhttp_h1:encode_response(Resp) of
                {ok, _} -> Clean;
                {error, {invalid_field_value, Reported}} -> Reported =:= Value andalso not Clean;
                _ -> false
            end
        end
    ).

-spec field_value_bad_pattern() -> binary:cp().
field_value_bad_pattern() ->
    binary:compile_pattern([<<C>> || C <- lists:seq(16#00, 16#1F), C =/= $\t] ++ [<<16#7F>>]).

-spec field_value_scan_gen() -> triq_dom:domain().
field_value_scan_gen() ->
    ?LET(
        {Len, Filler, Mutations},
        {int(0, 300), elements([$v, $\t, $\s, 16#80, 16#FF]), list({int(0, 299), int(0, 255)})},
        mutate_octets(binary:copy(<<Filler>>, Len), Mutations)
    ).

-spec mutate_octets(binary(), [{non_neg_integer(), byte()}]) -> binary().
mutate_octets(Bin, []) ->
    Bin;
mutate_octets(<<>>, _Mutations) ->
    <<>>;
mutate_octets(Bin, [{Pos, Octet} | Rest]) ->
    At = Pos rem byte_size(Bin),
    <<Head:At/binary, _, Tail/binary>> = Bin,
    mutate_octets(<<Head/binary, Octet, Tail/binary>>, Rest).
