%%%-----------------------------------------------------------------------------
-module(nhttp_qpack_props).

-moduledoc """
QPACK property-based tests.

These properties are run via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP PROPERTIES
%%%-----------------------------------------------------------------------------

-spec prop_roundtrip_static() -> triq:property().
prop_roundtrip_static() ->
    ?FORALL(
        Headers,
        static_headers_gen(),
        begin
            {ok, Enc} = nhttp_qpack:new_encoder(#{}),
            {ok, Dec} = nhttp_qpack:new_decoder(#{}),
            {ok, _Enc1, _EncStream, FieldData} =
                nhttp_qpack:encode_field_section(Enc, 0, Headers),
            FieldBin = iolist_to_binary(FieldData),
            case nhttp_qpack:decode_field_section(Dec, 0, FieldBin) of
                {ok, _Dec1, _DecStream, Decoded} ->
                    Headers =:= Decoded;
                _ ->
                    false
            end
        end
    ).

-spec prop_roundtrip_dynamic() -> triq:property().
prop_roundtrip_dynamic() ->
    Config = #{
        max_table_capacity => 4096,
        max_blocked_streams => 100
    },
    ?FORALL(
        Headers,
        mixed_headers_gen(),
        begin
            {ok, Enc} = nhttp_qpack:new_encoder(Config),
            {ok, Dec} = nhttp_qpack:new_decoder(Config),
            {ok, _Enc1, EncStream, FieldData} =
                nhttp_qpack:encode_field_section(Enc, 0, Headers),
            EncBin = iolist_to_binary(EncStream),
            Dec1 =
                case byte_size(EncBin) of
                    0 ->
                        Dec;
                    _ ->
                        {ok, D, _} =
                            nhttp_qpack:feed_encoder_stream(
                                Dec, EncBin
                            ),
                        D
                end,
            FieldBin = iolist_to_binary(FieldData),
            case
                nhttp_qpack:decode_field_section(
                    Dec1, 0, FieldBin
                )
            of
                {ok, _Dec2, _DecStream, Decoded} ->
                    Headers =:= Decoded;
                _ ->
                    false
            end
        end
    ).

-spec prop_sequential_roundtrip() -> triq:property().
prop_sequential_roundtrip() ->
    Config = #{
        max_table_capacity => 4096,
        max_blocked_streams => 100
    },
    ?FORALL(
        HeadersList,
        list(mixed_headers_gen()),
        begin
            {ok, Enc0} = nhttp_qpack:new_encoder(Config),
            {ok, Dec0} = nhttp_qpack:new_decoder(Config),
            encode_decode_all(HeadersList, Enc0, Dec0, 0)
        end
    ).

-spec prop_decode_no_crash() -> triq:property().
prop_decode_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            {ok, Dec} = nhttp_qpack:new_decoder(#{}),
            _ =
                (catch nhttp_qpack:decode_field_section(
                    Dec, 0, Bin
                )),
            true
        end
    ).

-spec prop_encoder_stream_no_crash() -> triq:property().
prop_encoder_stream_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            Config = #{max_table_capacity => 4096},
            {ok, Dec} = nhttp_qpack:new_decoder(Config),
            _ =
                (catch nhttp_qpack:feed_encoder_stream(Dec, Bin)),
            true
        end
    ).

-spec prop_field_section_before_encoder_stream() -> triq:property().
prop_field_section_before_encoder_stream() ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 100},
    ?FORALL(
        Headers,
        mixed_headers_gen(),
        begin
            {ok, Enc} = nhttp_qpack:new_encoder(Config),
            {ok, Dec0} = nhttp_qpack:new_decoder(Config),
            {ok, _Enc1, EncStream, FieldData} =
                nhttp_qpack:encode_field_section(Enc, 0, Headers),
            EncBin = iolist_to_binary(EncStream),
            FieldBin = iolist_to_binary(FieldData),
            case nhttp_qpack:decode_field_section(Dec0, 0, FieldBin) of
                {ok, _Dec1, _DecStream, Decoded} ->
                    Decoded =:= Headers;
                {blocked, Dec1} ->
                    case nhttp_qpack:feed_encoder_stream(Dec1, EncBin) of
                        {ok, _Dec2, Unblocked} ->
                            lists:any(
                                fun({StreamId, _DecStreamOut, OutHeaders}) ->
                                    StreamId =:= 0 andalso OutHeaders =:= Headers
                                end,
                                Unblocked
                            );
                        _ ->
                            false
                    end;
                _ ->
                    false
            end
        end
    ).

-spec prop_multi_stream_acknowledgement() -> triq:property().
prop_multi_stream_acknowledgement() ->
    Config = #{max_table_capacity => 4096, max_blocked_streams => 100},
    ?FORALL(
        StreamPayloads,
        non_empty(list(mixed_headers_gen())),
        begin
            {ok, Enc0} = nhttp_qpack:new_encoder(Config),
            {ok, Dec0} = nhttp_qpack:new_decoder(Config),
            transcript_complete(StreamPayloads, Enc0, Dec0, 0)
        end
    ).

-spec transcript_complete(
    [[{binary(), binary()}]],
    nhttp_qpack:encoder(),
    nhttp_qpack:decoder(),
    non_neg_integer()
) -> boolean().
transcript_complete([], _Enc, _Dec, _StreamId) ->
    true;
transcript_complete([Headers | Rest], Enc, Dec, StreamId) ->
    {ok, Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(Enc, StreamId, Headers),
    EncBin = iolist_to_binary(EncStream),
    {ok, Dec1, _UnblockedFromEncoder} =
        case byte_size(EncBin) of
            0 -> {ok, Dec, []};
            _ -> nhttp_qpack:feed_encoder_stream(Dec, EncBin)
        end,
    FieldBin = iolist_to_binary(FieldData),
    case nhttp_qpack:decode_field_section(Dec1, StreamId, FieldBin) of
        {ok, Dec2, DecStream, Decoded} when Decoded =:= Headers ->
            DecBin = iolist_to_binary(DecStream),
            {ok, Enc2} =
                case byte_size(DecBin) of
                    0 -> {ok, Enc1};
                    _ -> nhttp_qpack:feed_decoder_stream(Enc1, DecBin)
                end,
            transcript_complete(Rest, Enc2, Dec2, StreamId + 4);
        _ ->
            false
    end.

-spec prop_interop_roundtrip() -> triq:property().
prop_interop_roundtrip() ->
    Config = #{max_table_capacity => 4096},
    ?FORALL(
        HeadersList,
        non_empty(list(mixed_headers_gen())),
        begin
            {ok, IoData} = nhttp_qpack_interop:encode_to_file(
                HeadersList, Config
            ),
            Bin = iolist_to_binary(IoData),
            case nhttp_qpack_interop:decode_from_file(Bin, Config) of
                {ok, Decoded} ->
                    HeadersList =:= Decoded;
                _ ->
                    false
            end
        end
    ).

%%%-----------------------------------------------------------------------------
%%% GENERATORS
%%%-----------------------------------------------------------------------------

-spec static_headers_gen() -> triq:gen([{binary(), binary()}]).
static_headers_gen() ->
    non_empty(
        list(
            oneof([
                {<<":method">>, <<"GET">>},
                {<<":method">>, <<"POST">>},
                {<<":path">>, <<"/">>},
                {<<":scheme">>, <<"https">>},
                {<<":status">>, <<"200">>},
                {<<":status">>, <<"404">>}
            ])
        )
    ).

-spec mixed_headers_gen() -> triq:gen([{binary(), binary()}]).
mixed_headers_gen() ->
    non_empty(
        list(
            oneof([
                {<<":method">>, <<"GET">>},
                {<<":path">>, <<"/">>},
                {<<":scheme">>, <<"https">>},
                {<<"x-custom">>, header_value_gen()},
                {<<"x-request-id">>, header_value_gen()},
                {header_name_gen(), header_value_gen()}
            ])
        )
    ).

-spec header_name_gen() -> triq:gen(binary()).
header_name_gen() ->
    ?LET(
        Chars,
        non_empty(
            list(
                oneof(
                    lists:seq($a, $z) ++
                        lists:seq($0, $9) ++
                        [$-]
                )
            )
        ),
        list_to_binary(Chars)
    ).

-spec header_value_gen() -> triq:gen(binary()).
header_value_gen() ->
    ?LET(
        Chars,
        non_empty(list(oneof(lists:seq(32, 126)))),
        list_to_binary(Chars)
    ).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec encode_decode_all(
    [[{binary(), binary()}]],
    nhttp_qpack:encoder(),
    nhttp_qpack:decoder(),
    non_neg_integer()
) -> boolean().
encode_decode_all([], _Enc, _Dec, _StreamId) ->
    true;
encode_decode_all(
    [Headers | Rest], Enc, Dec, StreamId
) ->
    {ok, Enc1, EncStream, FieldData} =
        nhttp_qpack:encode_field_section(
            Enc, StreamId, Headers
        ),
    EncBin = iolist_to_binary(EncStream),
    Dec1 =
        case byte_size(EncBin) of
            0 ->
                Dec;
            _ ->
                {ok, D, _} =
                    nhttp_qpack:feed_encoder_stream(Dec, EncBin),
                D
        end,
    FieldBin = iolist_to_binary(FieldData),
    case nhttp_qpack:decode_field_section(Dec1, StreamId, FieldBin) of
        {ok, Dec2, DecStream, Decoded} ->
            case Headers =:= Decoded of
                true ->
                    DecBin = iolist_to_binary(DecStream),
                    Enc2 =
                        case byte_size(DecBin) of
                            0 ->
                                Enc1;
                            _ ->
                                {ok, E} =
                                    nhttp_qpack:feed_decoder_stream(
                                        Enc1, DecBin
                                    ),
                                E
                        end,
                    encode_decode_all(
                        Rest, Enc2, Dec2, StreamId + 4
                    );
                false ->
                    false
            end;
        _ ->
            false
    end.
