#!/bin/sh
curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -H "Authorization: Basic $baisc_auth" -d '{"refresh_token":"'$1'"}' http://localhost:8080/auth/tokens