#!/bin/sh
echo "Running test on $OSTYPE"

baisc_auth="YWRtaW46cGFzc3dvcmQ="

curl http://localhost:8080/auth/tokens -H "Content-Type: application/json" -H "Authorization: Basic $baisc_auth" -X POST  -d 'refresh_token=$1'