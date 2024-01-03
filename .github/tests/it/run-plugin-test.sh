#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'
bad=0

ok(){
    echo -e "${GREEN}✔️ $1 succeeded ${RESET}"
}

fail(){
    echo -e "${RED}❌ $1 failed ${RESET}"
}

docker compose exec client su client -c "test -s /run/client/plugin_certs/svid.crt"
if [ $? -eq 0 ]; then 
  ok "Test plugin X.509 svid update"
else
  fail "Test plugin X.509 svid update"
  exit 1
fi

docker compose exec client su client -c "test -s /run/client/plugin_certs/jwt.json"
if [ $? -eq 0 ]; then 
  ok "Test plugin JWT svid update"
else
  fail "Test plugin JWT svid update"
  exit 1
fi
    
docker compose exec client su client -c "test -s /run/client/plugin_certs/jwk.json"
if [ $? -eq 0 ]; then 
  ok "Test plugin JWT bundle update"
else
  fail "Test plugin JWT bundle update"
  exit 1
fi

exit 0
