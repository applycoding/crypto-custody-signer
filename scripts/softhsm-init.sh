#!/usr/bin/env bash
# Creates a throwaway SoftHSM2 token "custody" (user PIN 1234) under ./.softhsm
set -euo pipefail
dir="$(pwd)/.softhsm"
rm -rf "$dir" && mkdir -p "$dir/tokens"
cat > "$dir/softhsm2.conf" <<CONF
directories.tokendir = $dir/tokens
objectstore.backend = file
log.level = ERROR
CONF
export SOFTHSM2_CONF="$dir/softhsm2.conf"
softhsm2-util --init-token --free --label custody --pin 1234 --so-pin 0000 >/dev/null
echo "export SOFTHSM2_CONF=$SOFTHSM2_CONF"
