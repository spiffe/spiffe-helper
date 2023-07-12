#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'
TEST_FAILED=0

# Testing to connect to postgres/mysql/server with valid svid
bash run-postgres-test.sh client 0
TEST_FAILED=$((TEST_FAILED + $?))

bash run-mysql-test.sh client 0
TEST_FAILED=$((TEST_FAILED + $?))

bash run-go-test.sh 0 0
TEST_FAILED=$((TEST_FAILED + $?))

# Testing to connect to postgres/mysql/server without svid
bash run-postgres-test.sh fail 1
TEST_FAILED=$((TEST_FAILED + $?))

bash run-mysql-test.sh fail 1
TEST_FAILED=$((TEST_FAILED + $?))

bash run-go-test.sh 1 1
TEST_FAILED=$((TEST_FAILED + $?))

# Testing to connect to postgres/mysql after updating client entry with invalid dns
bash change-entry-client-test.sh 1
TEST_FAILED=$((TEST_FAILED + $?))

# Testing to connect to postgres/mysql after restoring client entry with valid dns
bash change-entry-client-test.sh
TEST_FAILED=$((TEST_FAILED + $?))

echo
if  ((TEST_FAILED == 1)); then
    echo -e "${RED}❌ ${TEST_FAILED} test failed.${RESET}"
    exit 1
elif ((TEST_FAILED > 1)); then
    echo -e "${RED}❌ ${TEST_FAILED} tests failed.${RESET}"
    exit 1
else 
    echo -e "${GREEN}✔️ All tests succeded.${RESET}"
    exit 0
fi
