-module(request_handler).

%% Application callbacks
-export([init/2]).
-export([terminate/3]).

-define(USERNAME, <<"admin">>).
-define(PASSWORD, <<"password">>).

%% Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%====================================================================
%% API functions
%%====================================================================

init(Req, State) ->
    Path = cowboy_req:path_info(Req),
    Method = cowboy_req:method(Req),
    HasBody = cowboy_req:has_body(Req),
    maybe_process(Req, State, Method, Path, HasBody).

terminate(_Reason, _Req, _State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================

maybe_process(Req, State, <<"POST">>, Path, true) ->
  {Username, Password, Req} = credentials(Req),
    case {Username, Password} of
      {?USERNAME, ?PASSWORD} ->
        lager:info("Access granted"),
        process_post(Req, State, Path);
      _ ->
        unauthorized(Req, State)
      end;
maybe_process(Req, State, <<"POST">>, _, false) ->
    {ok, cowboy_req:reply(400, #{<<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, <<"{\"error\": \"Missing body\"}">>, Req), State};
maybe_process(Req, State, <<"OPTIONS">>, _, _) ->
    {ok, cowboy_req:reply(200, #{
        <<"content-type">> => <<"application/json">>,
        <<"access-control-allow-origin">> => <<"*">>,
        <<"access-control-allow-headers">> => <<"authorization">>,
        <<"access-control-allow-method">> => <<"POST">>
    } , <<>>, Req), State};
maybe_process(Req, State, _, _, _) ->
    %% Method not allowed.
    {ok, cowboy_req:reply(405, Req), State}.

%% Processing POST requests.
process_post(Req, State, Path) ->
  Date = get_date(Req),
  lager:info("~p POST req recvd, Date ~p: ~p", [self(), Date, Path]),
  {ok, TokenPayload, _Req2} = cowboy_req:read_body(Req),
  case jsx:is_json(TokenPayload) of
    true ->
      case jsx:decode(TokenPayload) of
        [{<<"refresh_token">>, RefreshToken}] ->
          lager:info("RefreshToken  ~p", [RefreshToken]),
          case cowboy_req:path(Req) of
            <<"/auth/tokens">> ->
              lager:info("PATH /auth/tokens"),
              case spreadbot_auth:refresh_access_token(RefreshToken) of
                {ok, Resp} ->
                  lager:info("RESP 200 - Token refreshed"),
                  {ok, cowboy_req:reply(200, #{<<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, jsx:encode([Resp]), Req), State};
                {error, Error} ->
                  lager:info("RESP Error - Token NOT refreshed ~p", [Error]),
                  {ok, cowboy_req:reply(400, #{<<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, <<"{\"error\": \"Invalid token\"}">>, Req), State}
                end;
            <<"/blacklists/tokens">> ->
              lager:info("PATH /blacklists/tokens"),
              ok = spreadbot_auth:revoke_refresh_token(RefreshToken),
              lager:info("RESP 200 - Token blacklisted"),
              {ok, cowboy_req:reply(200, Req), State}
            end;
        _ ->
          {ok, cowboy_req:reply(400, #{<<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, <<"{\"error\": \"Missing parameters\"}">>, Req), State}
        end;
    false ->
      {ok, cowboy_req:reply(400, #{<<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, <<"{\"error\": \"Malformed request\"}">>, Req), State}
    end.

credentials(Req) ->
  AuthorizationHeader = cowboy_req:header(<<"authorization">>, Req),
  case AuthorizationHeader of
    undefined ->
      {undefined, undefined, Req};
    _ ->
      {Username, Password} = credentials_from_header(AuthorizationHeader),
      {Username, Password, Req}
  end.

credentials_from_header(AuthorizationHeader) ->
  case binary:split(AuthorizationHeader, <<$ >>) of
    [<<"Basic">>, EncodedCredentials] ->
      decoded_credentials(EncodedCredentials);
    _ ->
      {undefined, undefined}
  end.

decoded_credentials(EncodedCredentials) ->
  DecodedCredentials = base64:decode(EncodedCredentials),
  case binary:split(DecodedCredentials, <<$:>>) of
    [Username, Password] ->
      {Username, Password};
    _ ->
      {undefined, undefined}
  end.

unauthorized(Req, State) ->
  lager:info("Access denied, refusing it"),
  {ok, cowboy_req:reply(401, #{<<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, <<"{\"error\": \"Unauthenticated requests cannot POST\"}">>, Req), State}.

get_date(Req) ->
  case cowboy_req:header(<<"etag">>, Req) of
    undefined ->
      erlang:system_time(microsecond);
    RawEtag ->
      [_, Etag, _] = binary:split(RawEtag, <<"\"">>, [global]),
      binary_to_integer(Etag)
    end.