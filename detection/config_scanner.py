#!/usr/bin/env python3
"""
config_scanner.py -- static pre-load scanner for Hugging Face model configs.

Part of the SE6013 CVE-2026-4372 defensive toolkit (DETECTION layer, README section 5.1).

What it does
------------
Reads a model repo's JSON config files and flags fields that can steer model
loading toward code execution (the class of field implicated in CVE-2026-4372,
plus the documented custom-code fields). It is a *triage* signal for a human,
not a verdict: several flagged fields have legitimate uses.

What it does NOT do
-------------------
It never imports `transformers`, never calls `from_pretrained`, never loads a
model, and never imports, downloads, or executes anything a config references.
It only parses JSON and inspects keys and string values. Running it against a
hostile repo is therefore safe: nothing in the repo is executed.

Exit codes (CLI)
----------------
    0  no findings
    1  findings present (manual review required)
    2  usage / I/O error

Usage
-----
    python config_scanner.py <path> [<path> ...]      # dirs or single config files
    python config_scanner.py --json <path>            # machine-readable output
    python config_scanner.py --min-severity high .    # only fail on high-severity

The exact field name implicated by CVE-2026-4372 should be confirmed against the
fix-commit diff (README section 2) and adjusted in SUSPICIOUS_KEYS below.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #

# Config keys that select an implementation, module, or callable rather than
# carrying plain numeric / enum hyperparameters. Presence is a review signal.
# value: (severity, why)
SUSPICIOUS_KEYS: dict[str, tuple[str, str]] = {
    "_attn_implementation_internal": ("high", "field implicated in CVE-2026-4372 (confirm vs fix diff)"),
    "auto_map": ("high", "maps config entries to custom Python objects / code"),
    "custom_pipelines": ("high", "declares custom pipeline code"),
}
# NOTE on precision: the public ``attn_implementation`` key is NOT listed -- it
# appears on nearly every modern config, so flagging its mere presence would bury
# real signal in false positives. Its VALUE is policed instead (ATTN_KEYS below).

# Keys that select the attention implementation. ``attn_implementation`` in
# config.json is copied into ``_attn_implementation_internal`` at config init, so
# the public key reaches the same CVE-2026-4372 code path as the internal one. On
# vulnerable versions a value shaped like a Hub repo id ("org/repo[@rev][:fn]")
# makes transformers fetch and run a kernel via the `kernels` package. Any value
# outside the built-in set is therefore high severity. Values may also be a dict
# of per-sub-config choices ({"text_config": "..."}); every leaf is checked.
ATTN_KEYS = {"attn_implementation", "_attn_implementation", "_attn_implementation_internal"}
BUILTIN_ATTN_IMPLEMENTATIONS = {
    "eager", "sdpa", "flash_attention_2", "flash_attention_3", "flex_attention",
}

# A value that looks like a dotted import path, module:attr target, filesystem
# path, or URL is suspicious: benign hyperparameters are numbers or short enums,
# not code targets. Ordered most-specific first.
VALUE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("url",         "high",   re.compile(r"https?://", re.IGNORECASE)),
    ("parent_ref",  "high",   re.compile(r"\.\.[\\/]")),
    ("module_attr", "high",   re.compile(r"[A-Za-z_][\w.]*\s*:\s*[A-Za-z_][\w.]*")),
    ("path_sep",    "medium", re.compile(r"[\\/]")),
    ("dotted_call", "medium", re.compile(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){2,}\b")),
]

# Keys whose values are legitimately dotted/CamelCase class names; do not raise a
# value-pattern finding on these unless the key itself is also suspicious.
VALUE_ALLOWLIST_KEYS = {"architectures", "model_type", "torch_dtype", "transformers_version"}

CONFIG_FILENAMES = ("config.json", "configuration.json")
CONFIG_GLOBS = ("config.json", "*config.json", "configuration_*.json", "preprocessor_config.json")

_SEV_RANK = {"low": 1, "medium": 2, "high": 3}


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    file: str
    location: str      # JSON path, e.g. "auto_map.AutoModel"
    kind: str          # "key" | "value" | "attn_value" | "custom_code_file" | "parse_error"
    severity: str      # "low" | "medium" | "high"
    detail: str
    snippet: str = ""

    def human(self) -> str:
        loc = f" :: {self.location}" if self.location else ""
        snip = f"  ({self.snippet})" if self.snippet else ""
        return f"[{self.severity.upper():>6}] {self.kind:<17} {self.file}{loc} -- {self.detail}{snip}"


# --------------------------------------------------------------------------- #
# Core scanning (pure JSON inspection -- no imports, no loading)
# --------------------------------------------------------------------------- #

def _truncate(value: Any, limit: int = 120) -> str:
    s = value if isinstance(value, str) else json.dumps(value, default=str)
    return s if len(s) <= limit else s[:limit] + "..."


def scan_config_file(path: Path) -> list[Finding]:
    """Parse one JSON config file and return findings. Never executes anything."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [Finding(str(path), "", "parse_error", "high", f"cannot read file: {exc}")]
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [Finding(str(path), "", "parse_error", "medium", f"unparseable JSON: {exc}")]

    findings: list[Finding] = []

    def walk(obj: Any, trail: str, parent_key: str | None) -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                here = f"{trail}.{key}" if trail else key
                if key in SUSPICIOUS_KEYS:
                    sev, why = SUSPICIOUS_KEYS[key]
                    findings.append(
                        Finding(str(path), here, "key", sev, why, _truncate(val))
                    )
                if key in ATTN_KEYS:
                    check_attn(val, here)
                    continue  # values fully policed by check_attn
                walk(val, here, key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{trail}[{i}]", parent_key)
        elif isinstance(obj, str):
            if parent_key in VALUE_ALLOWLIST_KEYS:
                return
            for name, sev, pat in VALUE_PATTERNS:
                if pat.search(obj):
                    findings.append(
                        Finding(str(path), trail, "value", sev,
                                f"value matches {name} pattern (code-target-like)",
                                _truncate(obj))
                    )
                    break  # one value finding per string is enough

    def check_attn(val: Any, trail: str) -> None:
        if val is None or (isinstance(val, str) and val in BUILTIN_ATTN_IMPLEMENTATIONS):
            return
        if isinstance(val, dict):
            for sub, v in val.items():
                check_attn(v, f"{trail}.{sub}")
            return
        findings.append(
            Finding(str(path), trail, "attn_value", "high",
                    "non-built-in attention implementation (Hub kernel / code "
                    "target; CVE-2026-4372 path)", _truncate(val))
        )

    walk(cfg, "", None)
    return findings


def scan_repo(root: Path) -> list[Finding]:
    """Scan every config file under a directory and note custom-code files."""
    findings: list[Finding] = []
    seen: set[Path] = set()
    for pattern in CONFIG_GLOBS:
        for cfg_path in root.rglob(pattern):
            if cfg_path.is_file() and cfg_path not in seen:
                seen.add(cfg_path)
                findings.extend(scan_config_file(cfg_path))

    # Presence of custom modeling/config code in a model repo is part of the
    # attack surface -- surface it as informational, not as a hard failure.
    for py in root.rglob("*.py"):
        if py.is_file():
            findings.append(
                Finding(str(py), "", "custom_code_file", "medium",
                        "repo ships Python code (loads only with trust_remote_code=True)")
            )
    return findings


def scan_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for p in paths:
        if p.is_dir():
            findings.extend(scan_repo(p))
        elif p.is_file():
            findings.extend(scan_config_file(p))
        else:
            findings.append(Finding(str(p), "", "parse_error", "high", "path does not exist"))
    return findings


def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = _SEV_RANK[min_severity]
    return [f for f in findings if _SEV_RANK.get(f.severity, 0) >= threshold]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Static pre-load scanner for Hugging Face model configs (CVE-2026-4372)."
    )
    parser.add_argument("paths", nargs="*", default=["."],
                        help="config files or model-repo directories (default: .)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit findings as JSON")
    parser.add_argument("--min-severity", choices=("low", "medium", "high"),
                        default="low", help="only report/fail at or above this severity")
    args = parser.parse_args(argv)

    try:
        paths = [Path(p) for p in (args.paths or ["."])]
        findings = filter_by_severity(scan_paths(paths), args.min_severity)
    except Exception as exc:  # pragma: no cover - defensive catch-all for CLI
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print(f"OK: no findings at or above '{args.min_severity}' severity.")
        else:
            print(f"{len(findings)} finding(s) -- manual review required:\n")
            for f in sorted(findings, key=lambda x: -_SEV_RANK.get(x.severity, 0)):
                print(f.human())

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
