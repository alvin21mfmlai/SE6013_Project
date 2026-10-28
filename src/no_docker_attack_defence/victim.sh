#!/usr/bin/env bash
# Victim node. Two modes:
#   bash victim.sh           -> VULNERABLE run (fires the reverse shell)
#   bash victim.sh defend    -> DEFENDED run  (safe_from_pretrained blocks the load)
set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
export HF_HOME="$REPO/.hfcache"
export HF_HUB_OFFLINE=1               # resolve model + kernel from the local cache only
export ATTACKER_HOST="${ATTACKER_HOST:-127.0.0.1}"

MODE="${1:-${DEFENCE:-attack}}"
case "$MODE" in
  defend|defended|1|safe)
    # Find the defence module. Prefer the repo's single source of truth
    # (../defence), fall back to a local copy, else fetch it.
    DEF=""
    for c in "$REPO/../defence" "$REPO"; do
      if [ -f "$c/defence_mechanisms.py" ]; then DEF="$(cd "$c" && pwd)"; break; fi
    done
    if [ -z "$DEF" ]; then
      echo "[*] defence_mechanisms.py not found locally — fetching ..."
      wget -q -O "$REPO/defence_mechanisms.py" \
        https://raw.githubusercontent.com/alvin21mfmlai/SE6013_Project/main/src/defence/defence_mechanisms.py
      DEF="$REPO"
    fi
    export PYTHONPATH="$DEF:${PYTHONPATH:-}"
    echo "[*] Victim (DEFENDED) — defence from: $DEF"
    exec python3 "$REPO/victim_safe.py"
    ;;
  *)
    echo "[*] Victim (VULNERABLE) — shell will call back to $ATTACKER_HOST:4444"
    exec python3 "$REPO/victim_test.py"
    ;;
esac
