# Detection & Defence Toolkit — Usage

Runnable implementation of the **Detection** (README §5) and **mitigation**
(README §6.6) layers for CVE-2026-4372. Every script here is defensive: none loads
a model, constructs a trigger, or executes repo content. The exploit/replication
half remains the documented benign-marker methodology in the README and
`src/setup.md` — it is intentionally not scripted here.

## Layout

```
SE6013_Project/
├── detection/
│   ├── config_scanner.py       # static pre-load scan of model config JSON   (§5.1)
│   ├── audit_dependencies.py   # flag transformers < 5.3.0                    (§5.2)
│   └── generate_sbom.sh        # CycloneDX SBOM + optional SCA match          (§5.3)
├── defence/
│   └── safe_load.py            # hardened from_pretrained wrapper             (§6.6)
├── tests/
│   ├── fixtures/               # inert benign + flagged configs (never loaded)
│   └── test_detection.py       # pytest suite
├── .github/workflows/
│   └── security.yml            # CI gate: audit + scan + tests                (§5.4)
├── requirements-secure.txt     # patched dependency floor
└── run_checks.py               # one-shot orchestrator / demo runner
```

## Quick start

From the repo root, in the **patched** environment (`~/cve-env-patched`, see
`src/setup.md` §6):

```bash
pip install -r requirements-secure.txt    # or at least: pip install packaging pytest
python run_checks.py                       # audit + scan fixtures + defence dry-run
pytest -q                                  # unit tests
```

## 1. Detection

### 1.1 Config scanner (`detection/config_scanner.py`)

Reads model config JSON and flags fields that can steer loading toward code
execution (the CVE-2026-4372 field class, plus the documented custom-code fields).
It imports nothing from `transformers` and loads no model — safe to run against a
hostile repo.

```bash
python detection/config_scanner.py path/to/model_repo        # scan a repo dir
python detection/config_scanner.py --min-severity high .     # CI-style gate
python detection/config_scanner.py --json path/to/config.json
```

Exit `0` = clean, `1` = findings (review required), `2` = usage/IO error.
Confirm the implicated field name against the fix-commit diff (README §2) and
adjust `SUSPICIOUS_KEYS` if the advisory names a different key.

### 1.2 Dependency audit (`detection/audit_dependencies.py`)

```bash
python detection/audit_dependencies.py                                  # active env
python detection/audit_dependencies.py --requirements requirements.txt  # a pin file
python detection/audit_dependencies.py --pip-audit                      # + full cross-check
```

Flags any `transformers < 5.3.0`. Run it against the **vulnerable** env
(`~/cve-env`) to see it fire, and the **patched** env to see it pass — this is the
C/D rows of the README experiment matrix.

### 1.3 SBOM (`detection/generate_sbom.sh`)

```bash
./detection/generate_sbom.sh sbom.json
```

Emits a CycloneDX SBOM and, if `osv-scanner` or `grype` is present, matches it
against the advisory database.

## 2. Defence

### `defence/safe_load.py`

A drop-in hardened wrapper that applies four controls before any load:

1. **Version gate (the actual fix)** — refuses if `transformers < 5.3.0`, checked
   against both the installed distribution and the module actually imported.
2. **Kernels gate** — on a vulnerable version (lab only, `allow_vulnerable_env=True`),
   refuses if the `kernels` package is installed, since it enables the Hub-kernel
   code path.
3. **Pre-load scan** — resolves a Hub repo to one commit sha, downloads only its
   config files at that commit (never weights, never code), scans them, then loads
   that same commit, so the config that was scanned is the one that gets loaded.
   Flags any non-built-in `attn_implementation` / `_attn_implementation_internal`
   value (including per-sub-config dicts) as high. `config=` is rejected because it
   would bypass the scan.
4. **No remote code** — forces `trust_remote_code=False`. This is hygiene only:
   CVE-2026-4372 bypasses that flag, so it is not a mitigation for this CVE.

Controls 2–4 are best-effort defence-in-depth (a deny-list cannot prove a config
safe). Upgrading to `transformers>=5.3.0` is the only complete remediation.

```python
from defence.safe_load import safe_from_pretrained, UnsafeModelLoad

try:
    model = safe_from_pretrained("some-org/some-model", revision="<pinned-sha>")
except UnsafeModelLoad as exc:
    print("refused:", exc)
```

Dry-run the controls without loading a model:

```bash
python defence/safe_load.py tests/fixtures/flagged --local-files-only   # BLOCKED
python defence/safe_load.py tests/fixtures/benign  --local-files-only   # passes
# lab: exercise the scan on an unpatched version instead of stopping at the version gate
python defence/safe_load.py tests/fixtures/flagged --local-files-only --assume-version 5.2.0 --allow-vulnerable-env
```

## 3. CI gate

`.github/workflows/security.yml` runs three jobs on every push/PR: the dependency
audit, a high-severity config scan of the repo, and the unit tests. Any failure
blocks the build — the same pip-audit-gate pattern the upstream ecosystem used to
remediate this CVE.

## Mapping to the experiment matrix (README §6.3)

| Run | What this toolkit provides |
|---|---|
| C — scanner flags config pre-load | `config_scanner.py` / `safe_load.py` control 2 |
| D — audit fails on vulnerable pin | `audit_dependencies.py` |
| Mitigation: upgrade to 5.3.0+ | `requirements-secure.txt` + version gate |
| Mitigation: pre-load scanning | `config_scanner.py` |
| Mitigation: revision pinning | `safe_from_pretrained(..., revision=...)` |

Runs A and B (the vulnerable-vs-patched *load* demonstration with a benign marker)
stay in the isolated VM per `src/setup.md`; this toolkit supplies the detection and
defence that those runs are measured against.
