# SE6013_Project
CVE-2026-4372: Threat Model, Root-Cause Analysis, Replication &amp; Detection
# CVE-2026-4372: Threat Model, Root-Cause, Replication & Detection

> Defensive analysis of a critical RCE in Hugging Face `transformers`
---

## Contents

1. [Vulnerability at a glance](#1-vulnerability-at-a-glance)
2. [Confirm from primary sources first](#2-confirm-from-primary-sources-first)
3. [Threat modeling](#3-threat-modeling)
4. [Root-cause analysis](#4-root-cause-analysis)
5. [Detection](#5-detection)
6. [Defensive simulation](#6-defensive-simulation)
7. [References](#7-references)

---

## 1. Vulnerability at a glance

| Field | Value |
|---|---|
| Identifier | CVE-2026-4372 / GHSA-29pf-2h5f-8g72 |
| Component | Hugging Face `transformers` |
| Class | Remote Code Execution (CWE-94 code injection / CWE-502-adjacent untrusted deserialization-of-behavior) |
| Entry point | `AutoModelForCausalLM.from_pretrained()` (model-load time) |
| Public mechanism | A crafted `config.json` field (`_attn_implementation_internal`) drives download + execution of attacker-controlled code |
| Key property | **Bypasses `trust_remote_code`** — the control users rely on to prevent exactly this |
| Fixed in | `transformers 5.3.0` |
| Standard remediation | Pin `transformers>=5.3.0` (pulls `huggingface_hub>=1.3`) |

The defining characteristic — and what makes this worth a case study — is that the
vulnerable path runs **without** the user opting into remote code. A user who
deliberately set `trust_remote_code=False` to stay safe was still exposed.

---

## 2. Confirm from primary sources first ⚠️

Before treating any mechanism detail below as settled, reconcile it against:

- **GHSA-29pf-2h5f-8g72** (GitHub advisory) — affected range, summary.
- **NVD** entry for CVE-2026-4372 — CVSS vector, CWE mapping, references.
- **The fix commit / PR** linked from the advisory — the diff is authoritative
  for *which code path was closed* and *what field/trigger* was involved.

Two trigger descriptions circulate and must be reconciled:

1. `config.json` → `_attn_implementation_internal` path (bypasses `trust_remote_code`).
2. A `kernels`-package trigger, often pulled in via `transformers[all]`.

The fix diff resolves whether these are the same mechanism, related, or distinct.
**Treat the field name and call chain in this document as provisional until the
diff confirms them.**

---

## 3. Threat modeling

### 3.1 System under analysis

The model-loading pipeline for a Hugging Face model, from a user's perspective:

```
[ Model repo on Hub ]           (untrusted artifact source)
        │  model files: config.json, tokenizer, weights, (code)
        ▼
[ huggingface_hub download ]    (fetch to local cache)
        ▼
[ transformers config parse ]   (read config.json → model config object)
        ▼
[ Auto* class resolution ]      (pick architecture / attention impl)
        ▼
[ model instantiation ]         (load weights, build modules)
        ▼
[ in-process model object ]     (runs with the user's privileges)
```

### 3.2 Trust boundaries

| # | Boundary | Crosses from → to | Guard that *should* apply |
|---|---|---|---|
| TB-1 | Hub → local cache | Untrusted network artifact → local disk | Repo reputation, revision pinning, checksum |
| TB-2 | Config data → config object | Untrusted file content → parsed structure | Schema validation, allow-listing of fields |
| TB-3 | Config object → code execution | Parsed data → running code | **`trust_remote_code`** |
| TB-4 | Model object → host | In-process code → OS/user account | OS sandbox, least privilege |

The vulnerability is a failure at **TB-3**: a value carried across TB-2 reached a
code-execution path that TB-3 was supposed to gate, but didn't.

### 3.3 Attack surface

Everything an untrusted repo controls is attacker-controlled input:

- `config.json` and every field within it ← **the exploited surface**
- tokenizer/processor config files
- weight files and their format
- any auxiliary code files in the repo
- repo/revision metadata

The relevant surface here is **the set of `config.json` fields that influence
control flow rather than just data** — specifically fields that select an
implementation, module, or callable.

### 3.4 Threat actors & entry scenarios

- **Typosquatted / look-alike repo** — `bert-large-uncased` vs a near-identical name.
- **Compromised or malicious upstream** — a legitimate-looking org pushes a poisoned revision.
- **Supply-chain reference** — a tutorial, notebook, or dependency points at a malicious repo ID.
- **Unpinned revision** — a repo that was benign at pin time serves new malicious files later.

In every case the victim action is the ordinary, documented call:
`AutoModelForCausalLM.from_pretrained("<repo-id>")` — often believed safe because
`trust_remote_code` was left at its default.

### 3.5 Where `trust_remote_code` was supposed to sit

`trust_remote_code` is the gate at **TB-3**. Its intended contract: *no code from
a model repo executes unless the user explicitly opts in.* It normally guards the
"custom modeling file" path (repos shipping their own `modeling_*.py`).

The CVE exists because **a second path to code execution existed that did not
consult this gate** — the config-driven implementation-selection path reached
executable behavior while bypassing the TB-3 check entirely.

---

## 4. Root-cause analysis

### 4.1 The design gap (layer mismatch)

The failure is a **guard-placement / layer-mismatch** flaw:

- The **security guard** (`trust_remote_code`) lived at the *explicit custom-code*
  layer.
- The **vulnerable behavior** lived at the *config-driven implementation-selection*
  layer.
- Data flowed from an untrusted config field into the implementation-selection
  layer and from there into a code-loading action — **a path that never passed
  through the guard's layer.**

```
         untrusted config.json field
                    │
                    ▼
      implementation-selection logic   ← reached code-loading here
                    │                     WITHOUT consulting:
                    ✗ ────────────────▶  trust_remote_code  (guard sat on a
                                          different, parallel path)
                    ▼
            code download + execution
```

### 4.2 Contributing factors

1. **Two parallel routes to the same dangerous capability.** When a security
   decision guards one route but a second route to the same capability exists,
   the guard is incomplete. The config-selection route was the ungated one.
2. **Control-carrying data treated as benign configuration.** A field that
   *selects executable behavior* was processed with the trust level of plain
   configuration data, not with the trust level of code.
3. **Internal/undocumented field reachable from untrusted input.** A field named
   like an internal detail (`_` prefix) was nonetheless populated from an
   attacker-controlled file, so "internal" gave a false sense of safety.
4. **Implicit capability via `extras`.** If the `kernels`/`[all]` path is a
   genuine trigger condition, then installing a broad extras bundle silently
   widened the attack surface — a dependency-driven capability the user didn't
   knowingly enable.

### 4.3 Why the fix works (to validate, not assume)

`transformers 5.3.0` closes the path. Confirm from the diff **which** of these it did:

- Routed the config-selection path through the `trust_remote_code` gate, and/or
- Removed the ability for config data to designate an arbitrary code target, and/or
- Allow-listed permissible values for the implicated field.

The patched-vs-unpatched simulation (§6) empirically verifies the chosen fix holds.

### 4.4 Generalizable lesson

**Guard the *capability*, not one *route* to it.** Security gates belong at the
point where the dangerous capability is exercised (here: "about to load/execute
code"), not at one syntactic entry point among several. Any data path that can
reach the capability must converge on the same check.

---

## 5. Detection

Three complementary layers: artifact scanning, dependency auditing, and a CI gate.

### 5.1 Artifact scanner: flag dangerous `config.json` fields

Static check run against any model repo *before* it is loaded. Flags config fields
that can influence control flow. (Confirm the exact field name against the fix diff
per §2 and extend the list as the advisory clarifies.)

```python
#!/usr/bin/env python3
"""scan_model_config.py — flag control-flow-influencing fields in a model config.
Defensive pre-load check. Exits non-zero if a suspicious field is present."""
import json, sys, re
from pathlib import Path

# Fields that select an implementation / callable rather than carry plain data.
# Treat presence as "review required", not automatically malicious.
SUSPICIOUS_FIELDS = {
    "_attn_implementation_internal",   # implicated in CVE-2026-4372 (confirm vs diff)
    "auto_map",                        # maps to custom code objects
}
# Value patterns worth flagging (module paths, URLs, dotted callables).
SUSPICIOUS_VALUE = re.compile(r"(https?://|\.\.|[\w.]+:[\w.]+|/|\\)")

def scan(path: Path) -> list[str]:
    findings = []
    try:
        cfg = json.loads(path.read_text())
    except Exception as e:
        return [f"{path}: unparseable config.json ({e})"]
    def walk(obj, trail=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                here = f"{trail}.{k}" if trail else k
                if k in SUSPICIOUS_FIELDS:
                    findings.append(f"{path}: field '{here}' present → manual review")
                if isinstance(v, str) and SUSPICIOUS_VALUE.search(v):
                    findings.append(f"{path}: value at '{here}' looks like a path/URL: {v!r}")
                walk(v, here)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{trail}[{i}]")
    walk(cfg)
    return findings

if __name__ == "__main__":
    roots = [Path(a) for a in sys.argv[1:]] or [Path(".")]
    all_findings = []
    for root in roots:
        for cfg in root.rglob("config.json"):
            all_findings += scan(cfg)
    for f in all_findings:
        print(f)
    sys.exit(1 if all_findings else 0)
```

> This is a *triage* signal, not a verdict: `auto_map` and implementation fields
> have legitimate uses. The scanner surfaces configs that warrant a human look
> before loading from an untrusted source.

### 5.2 Dependency audit: catch the vulnerable version

```bash
# pip-audit: flags installed/declared transformers below the fixed version
pip install pip-audit
pip-audit                         # audits the active environment
pip-audit -r requirements.txt     # audits a lockfile

# safety (alternative)
pip install safety
safety check -r requirements.txt
```

A healthy environment reports no advisory for `transformers`; a vulnerable one
flags **GHSA-29pf-2h5f-8g72 / CVE-2026-4372** and names `5.3.0` as the fixed version.

### 5.3 SBOM angle

Generate an SBOM and match it against advisory feeds so the vulnerable pin is
visible in inventory, not just at install time:

```bash
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.json    # CycloneDX SBOM of the current env
# Feed sbom.json to an SCA/vuln-matching tool (e.g. osv-scanner, grype) in CI.
```

### 5.4 CI gate

Fail the build on any unresolved advisory — mirrors the `pip-audit` gate pattern
seen across the ecosystem's own remediations.

```yaml
# .github/workflows/security.yml
name: security
on: [push, pull_request]
jobs:
  deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install pip-audit
      - run: pip-audit -r requirements.txt --strict     # non-zero exit fails CI
  configs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: python scan_model_config.py .              # flag suspicious configs in repo
```

### 5.5 Runtime / behavioral indicators (for the lab)

When demonstrating in the sandbox (§6), the signals a monitor should catch:

- Child-process spawn (`execve`) during a model *load*, which should be pure data handling.
- Outbound network connection from the load path beyond the expected Hub fetch.
- File writes outside the model cache during load.

These are the ground-truth signals the benign-marker run is designed to produce.

---

## 6. Defensive simulation

Goal: **demonstrate the control-flow failure and measure mitigations — without a
working exploit.** The scientific claim is *"attacker-controlled behavior ran via
the config path despite `trust_remote_code` being off."* A benign marker proves
exactly that.

### 6.1 Principle: benign marker, not payload

The stand-in "attacker behavior" does nothing harmful; it only leaves evidence
that the untrusted path executed:

- write a sentinel file, e.g. `/tmp/poc_executed_at_<timestamp>`, **or**
- emit a single DNS lookup / HTTP request to the lab sinkhole.

Your monitoring captures this exactly as it would real code. Swapping in a real
payload is explicitly **out of scope** and is not required for any result below.

> **Constructing the trigger config:** derive its structure from the confirmed fix
> diff (§2). The diff shows which field and value shape the vulnerable path
> consumed; reproduce that shape with the benign marker as the designated behavior.
> This wiki intentionally does not ship a ready-made trigger file.

### 6.2 Lab topology

```
┌───────────────────────── Isolated host-only network ─────────────────────────┐
│                                                                               │
│   [ Victim VM ]  ── loads model ──▶  (benign marker fires)                     │
│     Ubuntu 22.04/24.04                                                         │
│     transformers = last-vulnerable 5.2.x   (Run A)                             │
│     transformers >= 5.3.0                   (Run B, control)                   │
│     strace / auditd + pcap                                                     │
│                                                                               │
│   [ Sinkhole ]  INetSim / local DNS+listener  ◀── captures any callback       │
│                                                                               │
│   [ Local model source ]  private/unlisted repo OR local path, benign marker  │
└───────────────────────────────────────────────────────────────────────────────┘
      No route to the internet. Snapshot before each run; revert after.
```

See the companion **lab-setup** doc for VM/container, pinning, and isolation details.

### 6.3 Experiment matrix

| Run | transformers | `trust_remote_code` | Expected marker | Demonstrates |
|---|---|---|---|---|
| **A** | last `5.2.x` | `False` (default) | **fires** | The bypass: code runs with the guard off |
| **B** | `>= 5.3.0` | `False` | does not fire | Fix closes the path |
| **C** | last `5.2.x` | `False` | scanner flags config pre-load | Detection (§5.1) catches it before load |
| **D** | last `5.2.x` | n/a | `pip-audit` fails | Detection (§5.2) catches the vulnerable pin |

Run A is the core finding; B is the control; C and D show the detections working.

### 6.4 Procedure

1. Snapshot the clean VM.
2. **Run A:** install the pinned vulnerable stack; start `strace`/`auditd` + pcap;
   load the model from the local benign-marker source with `trust_remote_code=False`;
   record whether the sentinel/sinkhole fires. Revert.
3. **Run B:** identical, with `transformers>=5.3.0`. Confirm the marker does **not**
   fire. Revert.
4. **Run C:** run `scan_model_config.py` against the source; confirm it flags the
   config *before* any load.
5. **Run D:** run `pip-audit` against both environments; confirm it flags A, passes B.
6. Archive artifacts per run: `pip freeze`, strace/auditd logs, pcap, scanner
   output, timestamps.

### 6.5 Evidence to capture

- **Syscall trace** showing (or not showing) process-spawn / file-write / network
  during load.
- **Sinkhole log** showing (or not) the callback.
- **Sentinel file** presence/absence and timestamp.
- **Scanner + audit output** for the detection runs.

The A-vs-B contrast in these artifacts *is* the result: identical inputs, guard
off in both, behavior fires only on the vulnerable version.

### 6.6 Mitigation measurement

Re-run A with each mitigation applied independently to show which neutralizes it:

- upgrade to `5.3.0+` (expected: full fix),
- pre-load config scanning (expected: blocks before load),
- revision pinning to a known-good commit (expected: prevents late-swapped files),
- least-privilege execution / OS sandbox at TB-4 (expected: contains impact even
  if code runs).

---

## 7. References

Pull and cite the primary sources directly (do not rely on secondhand summaries):

- GitHub Security Advisory **GHSA-29pf-2h5f-8g72**
- **NVD** — CVE-2026-4372
- `transformers` **5.3.0** release notes and the linked **fix commit / PR**
- Tooling: `pip-audit`, `safety`, `osv-scanner` / `grype`, `cyclonedx-py`, INetSim
