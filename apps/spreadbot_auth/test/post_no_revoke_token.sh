#!/bin/sh
echo "Running test on $OSTYPE"

baisc_auth="YWRtaW46cGFzc3dvcmQ="

curl http://localhost:8080/blacklists/tokens -H "Content-Type: application/json" -H "Authorization: Basic $baisc_auth" -X POST -d '{"message":"foobar"}'