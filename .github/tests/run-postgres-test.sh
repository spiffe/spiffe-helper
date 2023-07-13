#!/bin/bash

# Define the target directory path
target_dir="./it"

# Check if the target directory exists
if [ ! -d "$target_dir" ]; then
  echo "Error: The target directory '$target_dir' does not exist."
  exit 1
fi

# Change to the target directory
cd "$target_dir" || exit

bash run-postgres-test.sh client 0
exit_code_postgres_client=$?
bash run-postgres-test.sh fail 1
exit_code_postgres_fail=$?

if [ $exit_code_postgres_client == 0 ] && [ $exit_code_postgres_fail == 0 ] ; then
    exit 0
else
    exit 1
fi