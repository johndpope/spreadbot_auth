#!/bin/sh
curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d '{"refresh_token":"'$1'"}' http://localhost:8080/blacklists/tokens