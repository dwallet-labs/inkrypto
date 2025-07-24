#!/bin/bash

# Predefined SHA-256 hash of the expected LICENSE file content
expected_hash="f7f28b8c7a1af76b9874ca6d040e8b1eb6768fd1043106c9d315090ea96754e7"

# Check if the LICENSE file exists in the current directory
if [ -f "./LICENSE" ]; then
    # Determine the correct command for SHA-256 hashing based on the available command
    if command -v sha256sum >/dev/null 2>&1; then
        hash_command="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        hash_command="shasum -a 256"
    else
        echo "Error: No suitable hashing command found (sha256sum or shasum)."
        exit 1
    fi

    # Compute the SHA-256 hash of the LICENSE file's content
    actual_hash=$($hash_command "./LICENSE" | awk '{ print $1 }')

    # Compare the computed hash with the expected hash
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "The LICENSE file's content does NOT match the expected content."
        exit 1
    fi
else
    echo "LICENSE file not found."
    exit 1
fi