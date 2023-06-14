#!/bin/bash

MAX_RETRIES=100

restore-entry(){
    # This test restores the original values of the entry so the test should succeed
    docker compose exec spire-server ./bin/spire-server entry show -spiffeID spiffe://example.org/client > /tmp/entryFound
    ENTRYID=$( grep 'Entry ID         :' /tmp/entryFound | awk '{print $4}')
    PARENTID=$( grep 'Parent ID        :' /tmp/entryFound | awk '{print $4}')

    rows_count_client=$(docker compose logs client | grep -c "SVID updated")
    docker compose exec spire-server ./bin/spire-server entry update \
        -entryID $ENTRYID \
        -parentID $PARENTID \
        -spiffeID spiffe://example.org/client \
        -selector unix:uid:72 \
        -ttl 150 \
        -dns client

    echo "Entry restored"

    for((i=0; i<MAX_RETRIES; i++))
    do
        rows_count_client_now=$(docker compose logs client | grep -c "SVID updated") 
        if [ $rows_count_client -lt $rows_count_client_now ]; then
            bash run-postgres-test.sh client 0
            exit_code_postgres=$?
            bash run-mysql-test.sh client 0
            exit_code_mysql=$?
            if [ $exit_code_postgres == 0 ] && [ $exit_code_mysql == 0 ] ; then
                exit 0
            else
                exit 1
            fi
        else
            sleep 1
        fi
    done
    exit 1
}

bad-entry(){
    #This test changes the values of the entry so the 2 connection tests should fail
    docker compose exec spire-server ./bin/spire-server entry show -spiffeID spiffe://example.org/client > /tmp/entryFound
    ENTRYID=$( grep 'Entry ID         :' /tmp/entryFound | awk '{print $4}')
    PARENTID=$( grep 'Parent ID        :' /tmp/entryFound | awk '{print $4}')

    rows_count_client=$(docker compose logs client | grep -c "SVID updated")

    docker compose exec spire-server ./bin/spire-server entry update \
        -entryID $ENTRYID \
        -parentID $PARENTID \
        -spiffeID spiffe://example.org/client \
        -selector unix:uid:72 \
        -ttl 150 \
        -dns testuser1
    
    echo "Entry changed, now with dns=testuser1"
   
    for((i=0; i<MAX_RETRIES; i++))
    do
        rows_count_client_now=$(docker compose logs client | grep -c "SVID updated") 
        if [ $rows_count_client -lt $rows_count_client_now ]; then
            bash run-postgres-test.sh client 1
            exit_code_postgres=$?
            bash run-mysql-test.sh client 1
            exit_code_mysql=$?
            if [ $exit_code_postgres == 0 ] && [ $exit_code_mysql == 0 ] ; then
                exit 0
            else
                exit 1
            fi
        else
            sleep 1
        fi
    done
    exit 1
}

if [ "$1" == "1" ]; then
    bad-entry
else
    restore-entry
fi
