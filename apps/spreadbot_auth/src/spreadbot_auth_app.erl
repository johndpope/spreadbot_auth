-module(spreadbot_auth_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
  Dispatch = cowboy_router:compile([
    {'_', [
      {"/auth/tokens", request_handler, []},
      {"/blacklists/tokens", request_handler, []}
    ]}
	]),
  {ok, _} = cowboy:start_clear(spreadbot_auth_listener,
    [{port, 8080}],
    #{env => #{dispatch => Dispatch}}
  ),
  ets:new(blacklisted_refresh_tokens, [set, named_table, public]),
  spreadbot_auth_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
  ok.

%%===================================================================
%% Internal functions
%%====================================================================

%%====================================================================
%% Tests
%%====================================================================

-ifdef(TEST).

%% refresh_access_token tests
spreadbot_auth_app_test() ->
  application:start(base64url),
  application:start(cowboy),
  application:start(cowlib),
  application:start(goldrush),
  application:start(jsx),
  application:start(jwt),
  application:start(lager),
  application:start(ranch),
  application:start(spreadbot_auth_app),

  Iss = <<"test inc.">>,
  Key = <<"53F61451CAD6231FDCF6859C6D5B88C1EBD5DC38B9F7EBD990FADD4EB8EB9063">>,
  Uid = <<"tester@test.com">>,

  application:set_env(spreadbot_auth, jwt_key, Key),
  application:set_env(spreadbot_auth, jwt_iss, Iss),
  ets:new(blacklisted_refresh_tokens, [set, named_table, public]),

  Claims = [{uid, Uid}, {iss, Iss}],
  ExpiresIn = 86400,
  ExpiresIn2 = 1,

  {ok, ExpToken} = jwt:encode(<<"HS256">>, Claims, ExpiresIn2, Key),
  {ok, Token} = jwt:encode(<<"HS256">>, Claims, ExpiresIn, Key),
  {ok, BlacklistedToken} = jwt:encode(<<"HS256">>, Claims, ExpiresIn, Key),

  % bad request - refresh_access_token
  ?assertEqual("400", os:cmd("cd apps/spreadbot_auth/test && ./post_no_refresh_token.sh")),

  %% unauthorized - refresh_access_token
  ?assertEqual("401", os:cmd("cd apps/spreadbot_auth/test && ./post_refresh_token_no_auth.sh " 
    ++ binary_to_list(Token))),

  % blacklisted refresh token - refresh_access_token
  ets:insert(blacklisted_refresh_tokens, [{BlacklistedToken}]),
  % ?assertEqual("400", os:cmd("cd apps/spreadbot_auth/test && ./post_refresh_token.sh " 
  %   ++ binary_to_list(BlacklistedToken))),

  % %% expired refresh token - refresh_access_token
  timer:sleep(1500),
  ?assertEqual("400", os:cmd("cd apps/spreadbot_auth/test && ./post_refresh_token.sh " 
    ++ binary_to_list(ExpToken))),

  % success - refresh_access_token
  % ?assertEqual("200", os:cmd("cd apps/spreadbot_auth/test && ./post_refresh_token.sh " ++ binary_to_list(Token))),

  {ok, Token2} = jwt:encode(<<"HS256">>, Claims, ExpiresIn, Key),
  {ok, BlacklistedToken2} = jwt:encode(<<"HS256">>, Claims, ExpiresIn, Key),

  %% bad request - revoke_refresh_token
  ?assertEqual("400", os:cmd("cd apps/spreadbot_auth/test && ./post_no_revoke_token.sh")),

  %% unauthorized - revoke_refresh_token
  ?assertEqual("401", os:cmd("cd apps/spreadbot_auth/test && ./post_revoke_token_no_auth.sh "
    ++ binary_to_list(Token2))),

  %% blacklisted - revoke_refresh_token
  ets:insert(blacklisted_refresh_tokens, [{BlacklistedToken2}]),
  ?assertEqual("200", os:cmd("cd apps/spreadbot_auth/test && ./post_revoke_token.sh "
    ++ binary_to_list(BlacklistedToken2))),

  %% success - revoke_refresh_token
  ?assertEqual("200", os:cmd("cd apps/spreadbot_auth/test && ./post_revoke_token.sh "
    ++ binary_to_list(Token2))).

-endif.