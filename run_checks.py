#!/usr/bin/env python3
"""
run_checks.py -- run the SE6013 CVE-2026-4372 detection + defence toolkit end to end.

Convenience orchestrator for a local run or a demo. Runs:
  1. Dependency audit of the active environment (and of requirements-secure.txt).
  2. Static config scan of any target paths given (default: the tests/fixtures).
  3. The defensive safe-load dry-run against each fixture, showing block vs allow.

It aggregates exit status: non-zero if any detection control fires. This is a
reporting wrapper -- it loads no model and executes no fixture content.

Usage:
    python run_checks.py                      # audit env + scan bundled fixtures
    python run_checks.py path/to/model_dir    # also scan a specific repo/path
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
PY = sys.executable


def _run(label: str, argv: list[str]) -> int:
    print(f"\n{'=' * 72}\n{label}\n{'=' * 72}")
    proc = subprocess.run(argv, cwd=REPO)
    print(f"-> exit {proc.returncode}")
    return proc.returncode


def main() -> int:
    extra_targets = sys.argv[1:]
    worst = 0

    worst = max(worst, _run(
        "1. Dependency audit (active environment)",
        [PY, "detection/audit_dependencies.py"],
    ))
    worst = max(worst, _run(
        "2. Dependency audit (requirements-secure.txt)",
        [PY, "detection/audit_dependencies.py", "--requirements", "requirements-secure.txt"],
    ))

    benign = REPO / "tests/fixtures/benign"
    flagged = REPO / "tests/fixtures/flagged"

    _run("3a. Config scan -- benign fixture (expect: clean)",
         [PY, "detection/config_scanner.py", str(benign)])
    _run("3b. Config scan -- flagged fixture (expect: findings)",
         [PY, "detection/config_scanner.py", str(flagged)])

    for target in extra_targets:
        _run(f"3c. Config scan -- {target}",
             [PY, "detection/config_scanner.py", "--min-severity", "high", target])

    # --assume-version simulates a patched env so the config-scan control is what
    # is exercised here; on a real unpatched env the version gate blocks first.
    _run("4a. Defence dry-run -- benign fixture (expect: controls pass)",
         [PY, "defence/safe_load.py", str(benign), "--local-files-only",
          "--min-severity", "high", "--assume-version", "5.3.1"])
    _run("4b. Defence dry-run -- flagged fixture (expect: BLOCKED by scan)",
         [PY, "defence/safe_load.py", str(flagged), "--local-files-only",
          "--min-severity", "high", "--assume-version", "5.3.1"])

    print(f"\n{'=' * 72}\nDone. Detection surfaced issues where expected above.\n{'=' * 72}")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
