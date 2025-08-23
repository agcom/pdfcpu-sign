#!/usr/bin/zsh

# Expects `set -eE`, but does not apply it in here.
#set -eE

# This function expects to be called from the cmd's root directory. TODO: overcome this limitation.
docker_compose() {
	docker compose -f ./softhsm2/test-compose.yaml "$@"
}

# Finds the latest empty slot id.
find_empty_slot() {
	docker_compose run -q --quiet-build --quiet-pull --rm softhsm2 softhsm2-util --show-slots | grep -Po '^Slot \K\d+$' | tail -n 1
}

init_token() {
	label="${1-test}"
	pin="${2-1234}"

	docker_compose run -q --quiet-build --quiet-pull --rm softhsm2 \
		softhsm2-util --init-token --slot "$(find_empty_slot)" --label "$label" --pin "$pin" --so-pin "$pin" |
		awk '{print $NF}'
}

rm_token() {
	label="$1"
	docker_compose run -q --quiet-build --quiet-pull --rm softhsm2 softhsm2-util --delete-token --token "$label"
}

rnd_str() {
	len="${1-7}"

	head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$len"
}

rnd_num() {
	len="${1-7}"

	head /dev/urandom | tr -dc '0-9' | head -c "$len"
}

# Import a kert file (PKCS#12 bundle with a key pair and a certificate).
import_kert() {
	token_slot="$1"
	token_pin="${2-1234}"
	kert="${3-./test-kert.p12}"
	kert_pass="${4-1234}"
	kert_id="${5-$(rnd_num 4)}"

	docker_compose run -q --quiet-build --quiet-pull --rm -v "$(realpath "$kert"):/tmp/agcom-pdfcpu-sign-tests/kert.p12" -w /src/cmds/api/ softhsm2 \
		sh -c "source ./softhsm2/common.zsh && _import_kert '$token_slot' '$token_pin' '/tmp/agcom-pdfcpu-sign-tests/kert.p12' '$kert_pass' '$kert_id'"
}

# This function is expected to be run in a SoftHSMv2 enabled environment.
_import_kert() {
	token_slot="$1"
	token_pin="$2"
	kert="${3-/tmp/agcom-pdfcpu-sign-tests/kert.p12}"
	kert_pass="${4-1234}"
	kert_id="${5-$(rnd_num 4)}"

	tmp_dir="$(mktemp -d /tmp/agcom-pdfcpu-sign-tests-XXXXXXX)"
	cert_der_tmp="$(mktemp -p "$tmp_dir" cert.der-XXXXXXX)"
	key_der_tmp="$(mktemp -p "$tmp_dir" key.der-XXXXXXX)"

	openssl pkcs12 -in "$kert" -password "pass:$kert_pass" -out "$cert_der_tmp" -clcerts -nokeys 1>&2
	openssl pkcs12 -in "$kert" -password "pass:$kert_pass" -out "$key_der_tmp" -nocerts -noenc 1>&2

	pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so \
		--write-object "$key_der_tmp" --type privkey \
		--slot "$token_slot" -l --pin "$token_pin" --id "$kert_id" 1>&2

	pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so \
		--write-object "$cert_der_tmp" --type cert \
		--slot "$token_slot" -l --pin "$token_pin" --id "$kert_id" 1>&2

	echo "$kert_id"
}
