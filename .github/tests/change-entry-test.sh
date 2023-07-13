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

bash change-entry-client-test.sh 1