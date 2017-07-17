-module(spreadbot_auth_jwt).

%% API
-export([resolve_refresh_token/1]).
-export([issue_token/2]).
-export([blacklist_refresh_token/1]).

%% Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%====================================================================
%% API functions
%%====================================================================

%% Resolves a refresh token, returning the corresponding claims.
-spec resolve_refresh_token(binary()) -> {ok, map()} | {error, atom()}.
resolve_refresh_token(RefreshToken) ->
  case check_blacklist(RefreshToken) of
    ok ->
      case {application:get_env(spreadbot_auth, jwt_key), application:get_env(spreadbot_auth, jwt_iss)} of
				{undefined, undefined} ->
          lager:info("ERROR - JWT creds not set."),
        	{error, invalid_key};
        {{ok, IssuerKey}, {ok, Issuer}} ->
        	case decode_jwt(RefreshToken, IssuerKey, Issuer) of
        		{ok, Claims} ->
              lager:info("Claims ~p", [Claims]),
        			{ok, Claims};
        		{error, Error} ->
              lager:info("ERROR ~p", [Error]),
        		  {error, Error}
        		end
        end;
    {error, invalid_token} -> 
      lager:info("ERROR blacklisted token"),
      {error, invalid_token}
    end.

%% Generates a new JWT.
-spec issue_token(spreadbot_auth:lifetime(), map()) -> {ok, binary()}.
issue_token(ExpiresIn, Claims) ->
	{ok, IssuerKey} = application:get_env(spreadbot_auth, jwt_key),
	{ok, AccessToken} = jwt:encode(<<"HS256">>, Claims, ExpiresIn, IssuerKey),
  lager:info("New access token: ~p", [AccessToken]),
	{ok, AccessToken}.

%% Revokes a refresh token, so that it cannot be used again.
-spec blacklist_refresh_token(binary()) -> ok.
blacklist_refresh_token(RefreshToken) ->
  ets:insert(blacklisted_refresh_tokens, [{RefreshToken}]),
  lager:info("Token blacklisted: ~p", [RefreshToken]),
  ok.

%%====================================================================
%% Internal functions
%%====================================================================

%% Looks up the refresh token blacklist, returning an error 
%% if a match is found.
-spec check_blacklist(binary()) -> ok | {error, invalid_token}.
check_blacklist(Key) ->
  case ets:lookup(blacklisted_refresh_tokens, Key) of
	  [{_Key}] ->
      {error, invalid_token};
    [] ->
      ok
    end.

%% Decodes a JWT and returns the corresponding claims.
-spec decode_jwt(binary(), binary(), binary()) -> {ok, map()}  | {error, atom()}.
decode_jwt(RefreshToken, IssuerKey, Issuer) ->
	case jwt:decode(RefreshToken, IssuerKey) of
    {ok, Claims} ->    
      lager:info("Claims are ~p", [Claims]),
      case catch maps:get(<<"iss">>, Claims) of
        Issuer ->
          try maps:get(<<"uid">>, Claims) of
            _Uid -> 
              {ok, Claims}
          catch
            _:_ ->
              {error, no_uid}
          end;
        _ ->
          {error, bad_issuer}
        end;
    {error, Any} ->
      {error, Any}
    end.

%% ===================================================================
%% Tests
%% ===================================================================

-ifdef(TEST).

before_tests() ->
  % ets:new(blacklisted_refresh_tokens, [set, named_table, public]),
  application:start(crypto),
  ok.

after_tests() ->
  % ets:delete(blacklisted_refresh_tokens),
  ok.

setup_test_() ->
  {setup, 
    fun before_tests/0,
    fun after_tests/0
  }.

resolve_refresh_token_test() ->
  Iss = <<"test inc.">>,
  Key = <<"53F61451CAD6231FDCF6859C6D5B88C1EBD5DC38B9F7EBD990FADD4EB8EB9063">>,
  Uid = <<"tester@test.com">>,

  application:set_env(spreadbot_auth, jwt_key, Key),
  application:set_env(spreadbot_auth, jwt_iss, Iss),
  
  Claims = [{uid, Uid}],
  ExpiresIn = 86400,

  {ok, Token} = jwt:encode(<<"HS256">>, Claims, ExpiresIn, Key),
  ?assertEqual(resolve_refresh_token(Token), {error, bad_issuer}),

  ?assertEqual(resolve_refresh_token(Key), {error, invalid_token}),

  {ok, Token2} = jwt:encode(<<"HS256">>, [{iss, Iss} | Claims], ExpiresIn, Key),
  ets:insert(blacklisted_refresh_tokens, [{Token2}]),
	?assertEqual(resolve_refresh_token(Token2), {error, invalid_token}),

  {ok, Token3} = jwt:encode(<<"HS256">>, [{iss, Iss} | Claims], ExpiresIn, Key),
  % ?assertEqual(resolve_refresh_token(Token3), {ok,#{<<"exp">> => ExpiresIn,<<"iss">> => Iss, <<"uid">> => Uid}}),

  {ok, Token4} = jwt:encode(<<"HS256">>, [{iss, Iss}], ExpiresIn, Key),
  ?assertEqual(resolve_refresh_token(Token4), {error, no_uid}). 

% issue_token_test() ->
% 	Iss = <<"test inc.">>,
%   Key = <<"53F61451CAD6231FDCF6859C6D5B88C1EBD5DC38B9F7EBD990FADD4EB8EB9063">>,
%   Uid = <<"tester@test.com">>,

%   application:set_env(spreadbot_auth, jwt_key, Key),
%   application:set_env(spreadbot_auth, jwt_iss, Iss),

%   Claims = [{uid, Uid}],
%   ExpiresIn = 86400,

%   ?assertEqual(issue_token(ExpiresIn, Claims), {ok, "fix me"}).

blacklist_refresh_token_test() ->
	Iss = <<"test inc.">>,
  Key = <<"53F61451CAD6231FDCF6859C6D5B88C1EBD5DC38B9F7EBD990FADD4EB8EB9063">>,
  Uid = <<"tester@test.com">>,

  application:set_env(spreadbot_auth, jwt_key, Key),
  application:set_env(spreadbot_auth, jwt_iss, Iss),

  Claims = [{uid, Uid}],
  ExpiresIn = 86400,

  {ok, Token} = jwt:encode(<<"HS256">>, Claims, ExpiresIn, Key),

  ?assertEqual(blacklist_refresh_token(Token), ok),
  ?assertEqual(ets:lookup(blacklisted_refresh_tokens, Token), [{Token}]).

-endif.

