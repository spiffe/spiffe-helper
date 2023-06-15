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
    var=$(docker compose exec client su client -c "/run/client/postgres-connect.sh \"$1\"")

    if echo "$var" | grep -q "test@user.com"; then
        if [ "$2" -eq 1 ]; then 
            fail "Test on PostgreSQL with parameter $1"
            ((bad++))
        else 
            ok "Test on PostgreSQL with parameter $1"
        fi
    else
        if [ "$2" -eq 1 ]; then 
            ok "Test on PostgreSQL with parameter $1"
        else
            fail "Test on PostgreSQL with parameter $1"
            ((bad++))
        fi
    fi
}

# The first parameter is related to the user that will establish the connection
# while the second parameter is the expected exit value 

testWithParameter "$1" "$2"

exit $bad
