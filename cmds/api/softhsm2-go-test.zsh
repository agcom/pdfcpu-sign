#!/usr/bin/zsh

set -eE

cd "$(dirname "$0")/"

source ./softhsm2/common.zsh

token_pin=1234
token_label="$(rnd_str 7)"
token_slot="$(init_token "$token_label" "$token_pin")"

trap 'rm_token "$token_label"' EXIT ERR

docker_compose run --rm \
	-e SIGN_SERVER_PKCS11_TOKEN_SLOT="$token_slot" -e SIGN_SERVER_PKCS11_TOKEN_PIN="$token_pin" \
	-w /src/ \
	softhsm2go \
	go test ./... -v \
	-gcflags '-N -l' # Disable optimizations; due to encountering a go compiler bug!
