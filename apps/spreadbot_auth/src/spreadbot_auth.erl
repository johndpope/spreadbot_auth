-module(spreadbot_auth).

%% API
-export([refresh_access_token/1]).
-export([revoke_refresh_token/1]).

%% Macros
-define(TOKEN_TYPE, <<"bearer">>).
-define(TOKEN_EXPIRY_TIME, 3600). %% 1 hour

%% Records
-record(response, {	access_token             :: binary(),
					          expires_in               :: lifetime(),
          			    refresh_token            :: binary(),
          			    token_type = ?TOKEN_TYPE :: binary()
         		     }).

%% Types
-type lifetime() :: non_neg_integer().
-type response() :: #response{}.

-export_type([lifetime/0]).
-export_type([response/0]).

%%====================================================================
%% API functions
%%====================================================================

%% Validates a request for an access token from a refresh token, 
%%   issuing a new access token if valid.
-spec refresh_access_token(binary()) -> {ok, response()} | {error, atom()}.
refresh_access_token(RefreshToken) ->
  case spreadbot_auth_jwt:resolve_refresh_token(RefreshToken) of
    {error, _} -> 
      {error, invalid_token};
    {ok, Claims} ->
      {ok, ExpiryAbsolute} = get(Claims, <<"exp">>),
      case binary_to_integer(ExpiryAbsolute) > seconds_since_epoch(0) of
        true ->
			    {ok, AccessToken} = spreadbot_auth_jwt:issue_token(?TOKEN_EXPIRY_TIME, Claims),
    			Resp = #response{
            access_token = AccessToken, 
            expires_in = ?TOKEN_EXPIRY_TIME, 
            refresh_token = RefreshToken
          },
    			{ok, Resp};
        false ->
          lager:info("Token expired: ~p", [RefreshToken]),
          revoke_refresh_token(RefreshToken),
          {error, invalid_token}
        end
    end.

%% Revokes a refresh token, so that it cannot be used again.
-spec revoke_refresh_token(binary()) -> ok.
revoke_refresh_token(RefreshToken) ->
  spreadbot_auth_jwt:blacklist_refresh_token(RefreshToken).

%%====================================================================
%% Internal functions
%%====================================================================

%% Get a value from a key/value list.    
-spec get(map(), binary()) -> {ok, binary()} | {error, not_found}.
get(O, K) ->
  try maps:get(K, O) of
    X -> 
      {ok, X}
  catch
    _:_ ->
      {error, not_found}
  end.

%% Calculates the number of seconds since epoch (January 1, 1970).
-spec seconds_since_epoch(integer()) -> non_neg_integer().
seconds_since_epoch(Diff) ->
  {Mega, Secs, _} = os:timestamp(),
  Mega * 1000000 + Secs + Diff.