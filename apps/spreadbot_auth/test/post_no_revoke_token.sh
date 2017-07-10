#!/bin/sh
baisc_auth="YWRtaW46cGFzc3dvcmQ="

curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -H "Authorization: Basic $baisc_auth" -X POST -d '{"message":"foobar"}' http://localhost:8080/blacklists/tokens