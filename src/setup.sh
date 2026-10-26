#!/usr/bin/env bash
# One-time setup. Seeds the offline kernel cache FIRST (instant, no network),
# then installs Python deps. No Docker, no Hugging Face Hub at runtime.
set -uo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
export HF_HOME="$REPO/.hfcache"
HUB="$HF_HOME/hub"
REV="0000000000000000000000000000000000000001"

echo "[1/3] Seeding offline cache for the malicious kernel at $HUB"
d="$HUB/models--malatker--evil-kernel"; s="$d/snapshots/$REV"
rm -rf "$d"; mkdir -p "$s" "$d/refs"
cp -r "$REPO/payload/evil-kernel/." "$s/"
echo -n "$REV" > "$d/refs/main"
echo "    seeded malatker/evil-kernel"

echo "[2/3] Installing torch 2.5.1+cu121 (REQUIRED: its build variant matches the kernel)"
if ! pip install -q "torch==2.5.1" --index-url https://download.pytorch.org/whl/cu121; then
  echo "    !! torch install failed — fix networking and re-run. Cache is already seeded." ; exit 1
fi
pip install -q "transformers==5.2.0" "kernels==0.10.5" "huggingface_hub" || { echo "    !! deps install failed"; exit 1; }

echo "[3/3] Verifying environment"
python3 - <<'PY'
import torch
v = torch.version.cuda
want = "12.1"
print(f"    torch {torch.__version__}  cuda {v}")
assert v == want, f"torch.version.cuda is {v}, need {want} (install torch==2.5.1+cu121)"
from kernels.utils import build_variant
print(f"    kernel build variant: {build_variant()}  (must be torch25-cxx98-cu121-x86_64-linux)")
PY

echo
echo "[+] Setup complete. Now, in two terminals:"
echo "      Terminal 1:  bash attacker.sh"
echo "      Terminal 2:  bash victim.sh"
