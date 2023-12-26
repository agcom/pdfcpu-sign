#!/usr/bin/zsh

set -e

compose() {
	docker compose -f ./softhsm2/test-compose.yaml "$@"
}

init_slot() {
	compose run softhsm2go softhsm2-util --show-slots | grep -Po '^Slot \K\d+$' | tail -n 1
}

init_token() {
	label="$1"

	compose run softhsm2go softhsm2-util --init-token --slot "$(init_slot)" --label "$label" --pin "$TOKEN_PIN" --so-pin "$TOKEN_PIN" | \
		awk '{print $NF}'
}

rm_token() {
	label="$1"

	compose run softhsm2go softhsm2-util --delete-token --token "$label"
}

rnd_str() {
	len="$1"

	head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$len"
}

TOKEN_PIN=1234
token_label="$(rnd_str 7)"

trap 'rm_token "$token_label"' EXIT

token_slot="$(init_token "$token_label")"

compose run \
	-e SIGN_SERVER_PKCS11_TOKEN_SLOT="$token_slot" -e SIGN_SERVER_PKCS11_TOKEN_PIN="$TOKEN_PIN" \
	-w /src/ \
	softhsm2go \
	go test ./... -v \
	-gcflags '-N -l' # Disable optimizations; due to encountering a go compiler bug!