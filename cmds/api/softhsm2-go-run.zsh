#!/usr/bin/zsh

set -eE

cd "$(dirname "$0")/"

kert="${1-./test-kert.p12}"
kert_pass="${2-1234}"

source ./softhsm2/common.zsh

cleanup() {
	# TODO: remove the added kert from the SoftHSM (although it is removed as an effect of removing its token).
	rm_token "$token_label" || true
}
trap 'cleanup' EXIT ERR

token_pin=1234
token_label="$(rnd_str)"
token_slot="$(init_token "$token_label" "$token_pin")"

kert_id=$(import_kert "$token_slot" $token_pin "$kert" "$kert_pass")

docker_compose run --rm \
	-e SIGN_SERVER_PKCS11_TOKEN_SLOT="$token_slot" -e SIGN_SERVER_PKCS11_TOKEN_PIN="$token_pin" \
	-e SIGN_SERVER_PKCS11_KERT_ID_HEX="$kert_id" \
	-w /src/ \
	-p 4648:4648 \
	softhsm2go \
	go run .
