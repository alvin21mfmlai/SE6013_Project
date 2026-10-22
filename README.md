# CVE-2026-4372: Threat Model, Root Cause & Defence

> Defensive analysis of a critical remote code execution (RCE) bug in Hugging Face `transformers`.

---

## Contents

1. [Vulnerability at a glance](#1-vulnerability-at-a-glance)
2. [Confirm from primary sources first](#2-confirm-from-primary-sources-first)
3. [Threat model](#3-threat-model)
4. [Root cause](#4-root-cause)
5. [Defence](#5-defence)
6. [Detection](#6-detection)

---

## 1. Vulnerability at a glance

| Field | Value |
|---|---|
| Identifier | CVE-2026-4372 / GHSA-29pf-2h5f-8g72 |
| Component | Hugging Face `transformers` |
| Class | Remote code execution (CWE-94, code injection) |
| Entry point | `AutoModelForCausalLM.from_pretrained()`, when a model is loaded |
| Mechanism | An attention setting in the model's `config.json` (`attn_implementation` / `_attn_implementation_internal`) makes the library download and run attacker code |
| Key property | **Bypasses `trust_remote_code=False`**, the setting users rely on to stop exactly this |
| Fixed in | `transformers 5.3.0` |

A user who deliberately left `trust_remote_code=False` to stay safe was still exposed.

---

## 2. Confirm from primary sources first ⚠️

Check the details below against the official sources before treating them as final:

- **GHSA-29pf-2h5f-8g72** (GitHub advisory): affected versions and summary.
- **NVD** entry for CVE-2026-4372: severity score and weakness type.
- **The fix commit** linked from the advisory: shows exactly which code path was closed.

Two trigger descriptions are in circulation:

1. A `config.json` attention field (`_attn_implementation_internal`).
2. The `kernels` package, often installed through `transformers[all]`.

They are most likely the same path: the attention field names a Hub repository, and the
`kernels` package downloads and runs code from it. **Treat the field names here as
provisional until the fix commit confirms them.**

---

## 3. Threat model

### 3.1 How a model is loaded

```
[ Model repo on the Hub ]       untrusted source
        │  config.json, tokenizer, weights, (code)
        ▼
[ Download to local cache ]
        ▼
[ Read config.json ]            settings become a config object
        ▼
[ Pick model class + attention type ]
        ▼
[ Build model, load weights ]
        ▼
[ Model runs in the user's process, with the user's permissions ]
```

### 3.2 Trust boundaries

| # | Boundary | Guard that *should* apply |
|---|---|---|
| TB-1 | Hub → local disk | Trusted repos, pinning to a fixed commit |
| TB-2 | Config file → config object | Only allowing known, safe values |
| TB-3 | Config object → running code | **`trust_remote_code`** |
| TB-4 | Model → operating system | Sandbox, least privilege |

The bug is a failure at **TB-3**: a value from the config file reached code execution
without passing the `trust_remote_code` check.

### 3.3 How a victim gets an attacker's model

- **Look-alike repo name**, e.g. a near-copy of a popular model's name.
- **Malicious or compromised publisher** pushes a poisoned version.
- **A tutorial, notebook or dependency** points at a malicious repo.
- **Unpinned version**: a repo that was safe yesterday serves a malicious file today.

In every case the victim only runs the normal call,
`AutoModelForCausalLM.from_pretrained("<repo-id>")`.

---

## 4. Root cause

### 4.1 The guard was on the wrong path

`trust_remote_code` guards one way of running repo code: custom `modeling_*.py` files.
The attention setting was a **second way** that never went through that guard.

```
     untrusted config.json attention setting
                    │
                    ▼
        "pick attention type" logic
                    │                  never checks:
                    ✗ ─────────────▶   trust_remote_code
                    ▼
     download + run code from the Hub (via `kernels`)
```

### 4.2 Contributing factors

1. **Two routes to the same dangerous action**, only one of them guarded.
2. **A setting that selects code was treated as plain data**, with the trust level of a number.
3. **An "internal" field (`_` prefix) could still be set from an untrusted file.**
4. **An optional package (`kernels`) silently enabled the attack** when installed, for example via `transformers[all]`.

### 4.3 Lesson

**Guard the dangerous action, not one route to it.** Every path that can lead to
"run code" must go through the same check.

---

## 5. Defence

The defence is one self-contained script, [`defence/safe_load.py`](defence/safe_load.py).
Its function `safe_from_pretrained()` replaces `from_pretrained()` and runs four checks
before any model is loaded. If one fails, it raises `UnsafeModelLoad` and nothing is loaded.

| # | Check | What it does |
|---|---|---|
| 1 | **Version** | Refuses if `transformers` is older than 5.3.0. **This is the real fix.** |
| 2 | **Kernels** | On an old version, refuses if the `kernels` package is installed, since the attack needs it. |
| 3 | **Config** | Reads the model's config files and refuses if they contain a risky setting (see below). Hub models are checked and loaded at the same commit. |
| 4 | **Remote code** | Always sets `trust_remote_code=False`. Good practice only: this CVE bypasses it. |

An old version is refused at check 1. Checks 2 and 3 only run on an old version if the
lab-only option `allow_vulnerable_env=True` is set.

**What check 3 blocks:**

- An attention setting (`attn_implementation`, `_attn_implementation`,
  `_attn_implementation_internal`) that is not built in. Only `eager`, `sdpa`,
  `flash_attention_2`, `flash_attention_3` and `flex_attention` are allowed, so a value
  like `attacker-org/evil-kernel` is blocked, even inside a nested sub-config.
- The fields `_attn_implementation_internal`, `auto_map` and `custom_pipelines`.
- Config files that cannot be read.
- A config passed directly with `config=`, since it would skip the check.

For Hub models, only the config files are downloaded, never weights or code. They are
downloaded at one fixed commit, and the model is then loaded from that same commit,
so the files cannot be swapped between the check and the load. After reviewing the
warnings, a person can override check 3 with `accept_findings=True`.

| Situation | What stops the attack |
|---|---|
| `transformers` 5.3.0 or newer | Check 1 |
| Old version, `kernels` installed | Check 2 |
| Old version, risky setting in config | Check 3 |
| Repo changed after it was checked | Check 3 (same commit checked and loaded) |

**Limitation:** check 3 only knows the settings listed above, so it cannot catch a new
attack. Upgrading to `transformers>=5.3.0` is the only complete fix.

---

## 6. Detection

The detection component identifies potentially unsafe Hugging Face model configurations and vulnerable dependencies associated with CVE-2026-4372. It provides two independent detection mechanisms: **static configuration scanning** and **dependency analysis**.

Unlike the Defence component, these tools report potential security risks without loading models or executing untrusted code.

### 6.1 Static Configuration Detection

**File:** `src/detection/static_detector.py`

The static detector parses `config.json` files and recursively examines nested JSON objects and arrays for security-sensitive fields.

The following fields are monitored:

| Configuration Field | Detection Purpose |
|---|---|
| `_attn_implementation_internal` | Internal attention configuration field associated with CVE-2026-4372 |
| `_experts_implementation_internal` | Additional internal implementation field requiring review |
| `auto_map` | May reference custom model implementation code |
| `custom_pipelines` | May reference custom pipeline implementations |

**Usage:**

```bash
cd src/detection
python3 static_detector.py samples/suspicious_config.json
```

**Example output:**

```text
[WARNING] samples/suspicious_config.json: review field '_attn_implementation_internal'
```

**Exit codes:**

| Exit Code | Meaning |
|---|---|
| `0` | PASS — No monitored fields detected |
| `1` | WARNING — One or more monitored fields detected |
| `2` | ERROR — Invalid JSON, missing file, or processing error |

The presence of a monitored field does not necessarily indicate exploitation. Findings require further investigation.

### 6.2 Dependency Detection

**File:** `src/detection/dependency_detector.py`

The dependency detector examines the Python environment to identify:

- Installed Hugging Face Transformers version
- Installed `kernels` package version, if available
- Whether the optional `kernels` package is importable
- Whether the Transformers version falls within the documented affected range

**Usage:**

```bash
cd src/detection
python3 -m pip install packaging
python3 dependency_detector.py
```

**Example output for a simulated vulnerable environment:**

```text
=== CVE-2026-4372 Dependency Detection ===
Transformers version: 5.2.0
Kernels version: Not installed
Kernels import available: False
[WARNING] Vulnerable Transformers version detected.
[INFO] The optional kernels package is not available.
[ACTION] Upgrade Transformers to 5.3.0 or newer.
```

The detector performs read-only checks and does not install or execute vulnerable Transformers versions.

### 6.3 Dependency Vulnerability Auditing

The `pip-audit` tool was used to compare published security advisories for vulnerable and patched Transformers versions.

**Files:**

- `requirements-vulnerable.txt` — Transformers 5.2.0
- `requirements-patched.txt` — Transformers 5.3.0

**Commands:**

```bash
cd src/detection

pip-audit --no-deps --disable-pip -r requirements-vulnerable.txt

pip-audit --no-deps --disable-pip -r requirements-patched.txt
```

**Observed results using pip-audit 2.10.1:**

| Transformers Version | Reported Vulnerability Entries |
|---|---|
| 5.2.0 | 6 |
| 5.3.0 | 3 |

The patched version showed three fewer vulnerability entries. However, Transformers 5.3.0 still had other reported vulnerabilities. These audit results may change as advisory databases are updated.

The audit identifies published dependency vulnerabilities; it does not independently demonstrate exploitability.

### 6.4 Automated Testing

**File:** `src/detection/test_detection.py`

Eight unit tests were implemented using Python's built-in `unittest` framework.

**Test coverage:**

1. Benign configuration
2. Suspicious attention implementation field
3. Nested attention implementation field
4. Experts implementation field
5. `auto_map` field
6. `custom_pipelines` field
7. Invalid JSON
8. Missing configuration file

**Run tests:**

```bash
cd src/detection
python3 -m unittest -v test_detection.py
```

**Observed result:**

```text
Ran 8 tests

OK
```

All eight tests passed in an isolated Python 3.12 Docker environment.

### 6.5 Limitations and Integration

- Static detection identifies predefined configuration fields but does not confirm remote code execution.
- Legitimate configurations may contain monitored fields, resulting in warnings.
- The scanner does not currently validate every possible attention implementation value.
- Dependency version-classification tests were performed using simulated package metadata.
- The tests use synthetic configuration files rather than a reproduced exploit.
- Validation against the Attack component's actual configuration is pending.

**Integration with other components:**

1. **Attack:** Supplies a controlled malicious model configuration.
2. **Detection:** Scans the configuration and reports potential security risks.
3. **Defence:** Evaluates whether the security controls prevent unsafe model loading.

This enables comparison of attack behaviour, detection findings, and defensive effectiveness using the same test configuration.

