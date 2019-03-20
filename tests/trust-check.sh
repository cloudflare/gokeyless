#!/bin/bash
# Verify that mutual certificate authentication with the Keyless server has
# proper certificate validation.
set -e

wait_for_port_pid() {
    local port=$1 pid=$2 timeout=10

    for ((i=0; i<10*timeout; i++)); do
        if nc -z localhost $port; then
            return
        fi
        # Stop checking if the process has died.
        kill -0 $pid 2>/dev/null || return 2
        sleep .1
    done

    echo "Port $port not responding after $timeout seconds!"
    return 1
}

date_to_unix() {
    case "$(uname -s)" in
    Darwin)
        date -j -f %Y-%m-%dT%H:%M:%SZ "$1" +%s
        ;;
    *)
        date -d "$1" +%s
        ;;
    esac
}

keyless_connect() {
    local current_time="$1" current_time_unix="$(date_to_unix "$1")"

    ./gokeyless \
        --auth_cert tests/testdata/server.pem \
        --auth_key tests/testdata/server-key.pem \
        --cloudflare_ca_cert tests/testdata/ca.pem \
        --current-time "$current_time" & keyless_pid=$!

    if ! wait_for_port_pid 2407 $keyless_pid; then
        kill $keyless_pid || :
        return 1
    fi

    # For less spam, add -brief, but that requires OpenSSL >= 1.1.0
    echo | openssl s_client \
        -connect localhost:2407 \
        -cert tests/testdata/client.pem \
        -key tests/testdata/client-key.pem \
        -CAfile tests/testdata/ca.pem \
        -verify 2 -verify_return_error \
        -attime $current_time_unix; rc=$?

    kill $keyless_pid || :
    return $rc
}

fail() {
    echo "FAIL: $1"
    exit 1
}

echo "Checking validation of a valid certificate"
keyless_connect 2019-01-01T00:00:00Z ||
    fail "Should pass on a valid certificate"

echo "Checking validation of an expired certificate"
keyless_connect 2119-01-01T00:00:00Z &&
    fail "Should fail connection on expired certificate"

echo PASSED
