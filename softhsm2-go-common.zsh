#!/usr/bin/zsh

docker_compose() {
	docker compose -f ./softhsm2/test-compose.yaml "$@"
}

init_slot() {
	docker_compose run --rm softhsm2go softhsm2-util --show-slots | grep -Po '^Slot \K\d+$' | tail -n 1
}

init_token() {
	label="$1"
	pin="$2"

	docker_compose run --rm softhsm2go softhsm2-util --init-token --slot "$(init_slot)" --label "$label" --pin "$pin" --so-pin "$pin" | \
		awk '{print $NF}'
}

rm_token() {
	label="$1"

	docker_compose run --rm softhsm2go softhsm2-util --delete-token --token "$label"
}

rnd_str() {
	len="${1-7}"

	head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$len"
}

rnd_num() {
	len="${1-7}"

	head /dev/urandom | tr -dc '0-9' | head -c "$len"
}