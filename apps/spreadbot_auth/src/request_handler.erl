-module(request_handler).

%% Application callbacks
-export([init/2]).
-export([allowed_methods/2]).
-export([is_authorized/2]).
-export([content_types_provided/2]).
-export([content_types_accepted/2]).
-export([router/2]).

-define(USERNAME, <<"admin">>).
-define(PASSWORD, <<"password">>).

%%====================================================================
%% API functions
%%====================================================================

init(Req, Opts) ->
  {cowboy_rest, Req, Opts}.

allowed_methods(Req, State) ->
  {[<<"POST">>], Req, State}.

is_authorized(Req, State) ->
  {Username, Password, Req} = credentials(Req),
    case {Username, Password} of
      {?USERNAME, ?PASSWORD} ->
        authorized(Req, State);
      _ ->
        unauthorized(Req, State)
      end.

content_types_provided(Req, State) ->
	{[{<<"application/json">>, router}], Req, State}.

content_types_accepted(Req, State) ->
  {[{<<"application/json">>, router}], Req, State}.

router(Req, _Opts) ->
  lager:info("~p POST req recvd - Date ~p", [self(), get_date(Req)]),
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
                  % To Do
                  cowboy_req:reply(200, #{
                    <<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, 
                    <<"[\"a\",\"list\",\"of\",\"words\"]">>, Req);
                {error, Error} ->
                  lager:info("RESP Error - Token NOT refreshed ~p", [Error]),
                  cowboy_req:reply(400, #{<<"content-type">> => <<"application/json">>, 
                    <<"access-control-allow-origin">> => <<"*">>}, <<"[\"Invalid Token\"]">>, Req)
                end;
            <<"/blacklists/tokens">> ->
              lager:info("PATH /blacklists/tokens"),
              ok = spreadbot_auth:revoke_refresh_token(RefreshToken),
              lager:info("RESP 200 - Token blacklisted"),
              cowboy_req:reply(200, Req)
            end;
        _ ->
          cowboy_req:reply(400, #{
            <<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, 
            <<"[\"Missing parameters\"]">>, Req)
        end;
      false ->
        cowboy_req:reply(400, #{
          <<"content-type">> => <<"application/json">>, <<"access-control-allow-origin">> => <<"*">>}, 
          <<"[\"Malformed request\"]">>, Req)
    end.
    
%%====================================================================
%% Internal functions
%%====================================================================

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
  {{false, <<"Basic realm=\"cowboy\"">>}, Req, State}.

authorized(Req, State) ->
  lager:info("Access granted"),
  {true, Req, State}.

get_date(Req) ->
  case cowboy_req:header(<<"etag">>, Req) of
    undefined ->
      erlang:system_time(microsecond);
    RawEtag ->
      [_, Etag, _] = binary:split(RawEtag, <<"\"">>, [global]),
      binary_to_integer(Etag)
    end.