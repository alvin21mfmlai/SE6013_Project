# CVE-2026-4372 — No-Docker Lab (single host)

Self-contained reproduction of the `transformers` + `kernels` supply-chain RCE,
runnable on one plain machine (e.g. a RunPod CPU pod). No Docker, no GPU, and no
Hugging Face Hub access: the tampered model and the malicious kernel are bundled
and loaded from a repo-local offline cache.

## How it works
The victim loads the model directly from the local `payload/model` folder. Its
`config.json` sets `"_attn_implementation_internal": "malatker/evil-kernel"`, so
during model construction `transformers` asks the `kernels` library for that repo,
imports it from the seeded offline cache, and the package's `__init__.py` opens a
reverse shell to the attacker on port 4444. Fires on construction — no inference,
no GPU, no network.

## Run it (3 steps)
```bash
bash setup.sh          # once: installs deps + seeds the offline cache
bash attacker.sh       # terminal 1: the listener
bash victim.sh         # terminal 2: triggers the exploit
```
The shell lands in terminal 1. Terminal 2 may then print a "weights not found"
error — expected; the zip ships no weights and the payload has already run.

## Notes
- `setup.sh` pins **torch 2.5.1+cu121** on purpose: `kernels` derives its build
  variant from `torch.version.cuda`, and that wheel matches the bundled
  `torch25-cxx98-cu121-x86_64-linux` variant. Other torch builds won't match.
- Everything stays on this host: the shell target defaults to `127.0.0.1`
  (override with `ATTACKER_HOST=... bash victim.sh` if attacker/victim are split).
- Nothing contacts the network at runtime (`HF_HUB_OFFLINE=1`).
