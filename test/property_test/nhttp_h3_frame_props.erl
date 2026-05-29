%%%-----------------------------------------------------------------------------
-module(nhttp_h3_frame_props).

-moduledoc """
HTTP/3 Frame Codec Property Tests.

These properties are run via nhttp_props_SUITE.
""".

-include_lib("triq/include/triq.hrl").

%%%-----------------------------------------------------------------------------
%%% ROUNDTRIP PROPERTIES
%%%-----------------------------------------------------------------------------

-spec prop_data_roundtrip() -> triq:property().
prop_data_roundtrip() ->
    ?FORALL(
        Payload,
        binary(),
        begin
            {ok, Frame} = nhttp_h3_frame:data(Payload),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h3_frame:decode(Encoded) of
                {ok, {data, Payload}, <<>>} -> true;
                _ -> false
            end
        end
    ).

-spec prop_headers_roundtrip() -> triq:property().
prop_headers_roundtrip() ->
    ?FORALL(
        FieldSection,
        binary(),
        begin
            {ok, Frame} = nhttp_h3_frame:headers(FieldSection),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h3_frame:decode(Encoded) of
                {ok, {headers, FieldSection}, <<>>} -> true;
                _ -> false
            end
        end
    ).

-spec prop_cancel_push_roundtrip() -> triq:property().
prop_cancel_push_roundtrip() ->
    ?FORALL(
        PushId,
        varint_gen(),
        begin
            {ok, Frame} = nhttp_h3_frame:cancel_push(PushId),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h3_frame:decode(Encoded) of
                {ok, {cancel_push, PushId}, <<>>} -> true;
                _ -> false
            end
        end
    ).

-spec prop_settings_roundtrip() -> triq:property().
prop_settings_roundtrip() ->
    ?FORALL(
        Settings,
        h3_settings_gen(),
        begin
            {ok, Frame} = nhttp_h3_frame:settings(Settings),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h3_frame:decode(Encoded) of
                {ok, {settings, Decoded}, <<>>} ->
                    settings_equivalent(Settings, Decoded);
                _ ->
                    false
            end
        end
    ).

-spec prop_push_promise_roundtrip() -> triq:property().
prop_push_promise_roundtrip() ->
    ?FORALL(
        {PushId, FieldSection},
        {varint_gen(), binary()},
        begin
            {ok, Frame} = nhttp_h3_frame:push_promise(PushId, FieldSection),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h3_frame:decode(Encoded) of
                {ok, {push_promise, PushId, FieldSection}, <<>>} -> true;
                _ -> false
            end
        end
    ).

-spec prop_goaway_roundtrip() -> triq:property().
prop_goaway_roundtrip() ->
    ?FORALL(
        Id,
        varint_gen(),
        begin
            {ok, Frame} = nhttp_h3_frame:goaway(Id),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h3_frame:decode(Encoded) of
                {ok, {goaway, Id}, <<>>} -> true;
                _ -> false
            end
        end
    ).

-spec prop_max_push_id_roundtrip() -> triq:property().
prop_max_push_id_roundtrip() ->
    ?FORALL(
        PushId,
        varint_gen(),
        begin
            {ok, Frame} = nhttp_h3_frame:max_push_id(PushId),
            Encoded = iolist_to_binary(Frame),
            case nhttp_h3_frame:decode(Encoded) of
                {ok, {max_push_id, PushId}, <<>>} -> true;
                _ -> false
            end
        end
    ).

%%%-----------------------------------------------------------------------------
%%% STRUCTURAL PROPERTIES
%%%-----------------------------------------------------------------------------

-spec prop_decode_returns_tail() -> triq:property().
prop_decode_returns_tail() ->
    ?FORALL(
        {Frame, ExtraData},
        {h3_frame_gen(), binary()},
        begin
            Encoded = iolist_to_binary(encode_frame(Frame)),
            Full = <<Encoded/binary, ExtraData/binary>>,
            case nhttp_h3_frame:decode(Full) of
                {ok, _, Tail} -> Tail =:= ExtraData;
                _ -> false
            end
        end
    ).

-spec prop_incomplete_returns_more() -> triq:property().
prop_incomplete_returns_more() ->
    ?FORALL(
        {Frame, CutAt},
        {h3_frame_gen(), pos_integer()},
        begin
            Encoded = iolist_to_binary(encode_frame(Frame)),
            FrameSize = byte_size(Encoded),
            ActualCut = (CutAt rem FrameSize) + 1,
            case ActualCut < FrameSize of
                true ->
                    <<Partial:ActualCut/binary, _/binary>> = Encoded,
                    case nhttp_h3_frame:decode(Partial) of
                        {more, N} when N > 0 -> true;
                        _ -> false
                    end;
                false ->
                    true
            end
        end
    ).

%%%-----------------------------------------------------------------------------
%%% FUZZ TESTS
%%%-----------------------------------------------------------------------------

-spec prop_random_binary_no_crash() -> triq:property().
prop_random_binary_no_crash() ->
    ?FORALL(
        Bin,
        binary(),
        begin
            _ = (catch nhttp_h3_frame:decode(Bin)),
            true
        end
    ).

%%%-----------------------------------------------------------------------------
%%% GENERATORS
%%%-----------------------------------------------------------------------------

-spec varint_gen() -> triq_dom:domain().
varint_gen() ->
    oneof([
        int(0, 63),
        int(64, 16383),
        int(16384, 1073741823)
    ]).

-spec h3_settings_gen() -> triq_dom:domain().
h3_settings_gen() ->
    ?LET(
        SettingsList,
        list(h3_setting_gen()),
        maps:from_list(SettingsList)
    ).

-spec h3_setting_gen() -> triq_dom:domain().
h3_setting_gen() ->
    oneof([
        ?LET(V, varint_gen(), {qpack_max_table_capacity, V}),
        ?LET(V, varint_gen(), {qpack_blocked_streams, V}),
        ?LET(V, varint_gen(), {max_field_section_size, V}),
        {enable_connect_protocol, bool()}
    ]).

-spec h3_frame_gen() -> triq_dom:domain().
h3_frame_gen() ->
    oneof([
        ?LET(P, binary(), {data, P}),
        ?LET(P, binary(), {headers, P}),
        ?LET(Id, varint_gen(), {cancel_push, Id}),
        ?LET(S, h3_settings_gen(), {settings, S}),
        ?LET({Id, P}, {varint_gen(), binary()}, {push_promise, Id, P}),
        ?LET(Id, varint_gen(), {goaway, Id}),
        ?LET(Id, varint_gen(), {max_push_id, Id})
    ]).

%%%-----------------------------------------------------------------------------
%%% HELPERS
%%%-----------------------------------------------------------------------------

-spec encode_frame(tuple()) -> iodata().
encode_frame({data, Payload}) ->
    {ok, F} = nhttp_h3_frame:data(Payload), F;
encode_frame({headers, FieldSection}) ->
    {ok, F} = nhttp_h3_frame:headers(FieldSection), F;
encode_frame({cancel_push, PushId}) ->
    {ok, F} = nhttp_h3_frame:cancel_push(PushId), F;
encode_frame({settings, Settings}) ->
    {ok, F} = nhttp_h3_frame:settings(Settings), F;
encode_frame({push_promise, PushId, FieldSection}) ->
    {ok, F} = nhttp_h3_frame:push_promise(PushId, FieldSection), F;
encode_frame({goaway, Id}) ->
    {ok, F} = nhttp_h3_frame:goaway(Id), F;
encode_frame({max_push_id, PushId}) ->
    {ok, F} = nhttp_h3_frame:max_push_id(PushId), F.

-spec settings_equivalent(
    nhttp_h3_frame:h3_settings(), nhttp_h3_frame:h3_settings()
) -> boolean().
settings_equivalent(Original, Decoded) ->
    maps:fold(
        fun
            (max_field_section_size, infinity, Acc) ->
                Acc andalso not maps:is_key(max_field_section_size, Decoded);
            (Key, Value, Acc) ->
                Acc andalso maps:get(Key, Decoded, undefined) =:= Value
        end,
        true,
        Original
    ).
