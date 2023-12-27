#!/usr/bin/zsh

# Generates a test kert (key + certificate) using the OpenSSL tool and outputs them in a PKCS#12 bundle.

set -e

p12_out="${1-./test-kert.p12}"
p12_pass="${2-1234}"

cleanup() {
	rm -f "$key_tmp" || true
	rm -f "$cert_tmp" || true
	rm -rf "$tmp_dir" || true
}

trap 'cleanup' EXIT

tmp_dir=$(mktemp -d /tmp/golang-signserver-tests-XXXXXXX)

key_tmp=$(mktemp -p "$tmp_dir" key-XXXXXXX.pem)
cert_tmp=$(mktemp -p "$tmp_dir" cert-XXXXXXX.pem)

openssl req -newkey rsa:2048 -nodes -keyout "$key_tmp" -x509 -days 365 -out "$cert_tmp" -batch
openssl pkcs12 -inkey "$key_tmp" -in "$cert_tmp" -export -out "$p12_out" -password "pass:$p12_pass"