#!/usr/bin/zsh

# Generates a test kert (key + certificate) using the OpenSSL tool and outputs them in a PKCS#12 bundle.

set -e

kert_out="${1-./test-kert.p12}"
kert_pass="${2-1234}"

cleanup() {
	rm -f "$key_tmp" || true
	rm -f "$cert_tmp" || true
	rm -rf "$tmp_dir" || true
}

trap 'cleanup' EXIT

tmp_dir=$(mktemp -d /tmp/agcom-pdfcpu-sign-tests-XXXXXXX)
key_tmp=$(mktemp -p "$tmp_dir" key.pem.XXXXXXX)
cert_tmp=$(mktemp -p "$tmp_dir" cert.pem.XXXXXXX)

openssl req -newkey rsa:2048 -nodes -keyout "$key_tmp" -x509 -days 365 -out "$cert_tmp" -batch
openssl pkcs12 -export -inkey "$key_tmp" -in "$cert_tmp" -out "$kert_out" -password "pass:$kert_pass"