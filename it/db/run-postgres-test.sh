#!/bin/bash

# Without parameters, two tests are performed:
# The first one attempts to connect with the user 'testuser' and it will succeed if a connection can be established.
# The second test attempts to connect with the user 'testuser1' and should fail, because connection can't be established.


RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'
bad=0
ok(){
    echo  -e "${GREEN}✔️ $1 succeeded ${RESET}"
}

fail(){
    echo -e "${RED}❌ $1 failed ${RESET}"
    ((bad++))
}

testWithParameter(){
    var=$(docker compose exec client su client -c "/run/client/postgres-connect.sh \"$1\"")

    if echo "$var" | grep -q "test@user.com"; then
        ok "Test on PostgreSQL with parameter $1"
    else
        fail "Test on PostgreSQL with parameter $1"
    fi
}

if [ -z "$1" ]; then
    testWithParameter client
else
    testWithParameter $1
fi



if [ -z "$1" ]; then
    exit $bad
elif [ "$1" == "fail" ] && [ $bad == 1 ]; then
    exit 0
fi

exit 1