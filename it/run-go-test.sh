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

testWithParameter(){
    docker compose exec client /opt/go-client/client "$1"

    if [ "$?" -eq "$2" ] ; then
        ok "Test on go app with parameter $1"
    else
        fail "Test on go app with parameter $1"
        ((bad++))
    fi
}

# The first parameter is related to the user that will establish the connection
# while the second parameter is the expected exit value

testWithParameter "$1" "$2"

exit $bad
