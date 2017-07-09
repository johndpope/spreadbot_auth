spreadbot_auth
=====

Spreadbot auth is an OTP authentication application for refreshing JWT access tokens
and revoking refresh tokens.
Check the [documentation](http://docs.spreadbot.io) for details.

## Prerequisites

- erlang
- rebar3

## Installation

	$ mkdir spreadbot
	$ cd spreadbot
	$ git clone https://github.com/spreadbot/spreadbot_auth.git
	$ cd spreadbot_auth
	
## Build

    $ rebar3 compile
    
## Release

	$ rebar3 release

## Running locally

	$ ./_build/default/rel/spreadbot_auth/bin/spreadbot_auth foreground

## Tests

	$ rebar3 eunit

## Dialyzer

	$ rebar3 dialyzer