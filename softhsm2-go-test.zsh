#!/usr/bin/zsh

set -e

source ./softhsm2-go-common.zsh

TOKEN_PIN=1234
token_label="$(rnd_str 7)"

token_slot="$(init_token "$token_label" "$TOKEN_PIN")"
trap 'rm_token "$token_label"' EXIT

docker_compose run \
	-e SIGN_SERVER_PKCS11_TOKEN_SLOT="$token_slot" -e SIGN_SERVER_PKCS11_TOKEN_PIN="$TOKEN_PIN" \
	-w /src/ \
	softhsm2go \
	go test ./... -v \
	-gcflags '-N -l' # Disable optimizations; due to encountering a go compiler bug!