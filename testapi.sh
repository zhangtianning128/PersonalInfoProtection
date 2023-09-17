#!/bin/bash

public_key_file="./second_party_public_key.pem"
signature_file="./second_party_signature.sig"

public_key=$(cat $public_key_file)
signature=$(cat $signature_file)

urlencode() {
    # urlencode <string>
    old_lc_collate=$LC_COLLATE
    LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done

    LC_COLLATE=$old_lc_collate
}

public_key=$(urlencode $public_key)
signature=$(urlencode $signature)

curl -X POST -d "public_key=$public_key&signature=$signature" http://127.0.0.1:8000/login
