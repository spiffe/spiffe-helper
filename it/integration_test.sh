#!/bin/bash

TEST_FAILED=0

bash run-postgres-test.sh client 0
TEST_FAILED=$((TEST_FAILED + $?))

bash run-postgres-test.sh fail 1
TEST_FAILED=$((TEST_FAILED + $?))

bash run-mysql-test.sh client 0
TEST_FAILED=$((TEST_FAILED + $?))

bash run-mysql-test.sh fail 1
TEST_FAILED=$((TEST_FAILED + $?))

bash change-entry-client-test.sh 1
TEST_FAILED=$((TEST_FAILED + $?))

bash change-entry-client-test.sh
TEST_FAILED=$((TEST_FAILED + $?))

if  ((TEST_FAILED == 1)); then
    echo "${TEST_FAILED} test failed."
    exit 1
elif ((TEST_FAILED > 1)); then
    echo "${TEST_FAILED} tests failed."
    exit 1
else 
    echo "All tests succeded."
    exit 0
fi
