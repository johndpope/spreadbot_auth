#!/bin/sh
echo "Running test on $OSTYPE"

curl http://localhost:8080/blacklists/tokens -H "Content-Type: application/json" -X POST  -d 'refresh_token=$1'