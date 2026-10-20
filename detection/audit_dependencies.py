#!/usr/bin/env python3
"""
audit_dependencies.py -- flag a transformers pin vulnerable to CVE-2026-4372.

Part of the SE6013 CVE-2026-4372 defensive toolkit (DETECTION layer, README section 5.2).

Checks, in order of preference:
  1. The transformers version actually installed in the active environment
     (concrete version -> direct comparison against the fixed version).
  2. A requirements / constraints file passed with --requirements. Here the value
     is a *specifier* (e.g. ``<5.3.0``, ``>=5.3.0,<6``, ``==5.2.0``), so the audit
     asks the correct question: does this pin PERMIT any version below the fix?
     A ``<5.3.0`` ceiling or an unpinned ``transformers`` both permit vulnerable
     installs and are flagged; ``>=5.3.0`` does not and passes.
  3. Optionally shells out to `pip-audit` (--pip-audit) for a full advisory
     cross-check of the environment.

Pure version/metadata inspection -- imports nothing from transformers, loads no model.

Exit codes
----------
    0  no vulnerable transformers pin found
    1  vulnerable (or vulnerable-permitting) transformers pin found
    2  could not determine a version (nothing installed, transformers not named)
    3  usage / tooling error
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

PACKAGE = "transformers"
FIXED_VERSION = "5.3.0"          # first release carrying the CVE-2026-4372 fix
ADVISORY = "GHSA-29pf-2h5f-8g72 / CVE-2026-4372"

# Representative affected versions used to test whether a specifier permits a
# vulnerable install. Any version strictly below FIXED_VERSION is affected.
_REPRESENTATIVE_VULN = ["4.57.3", "5.0.0", "5.2.99"]

try:
    from packaging.version import Version, InvalidVersion
    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    _HAVE_PACKAGING = True

    def _lt_fixed(ver: str) -> bool:
        try:
            return Version(ver) < Version(FIXED_VERSION)
        except InvalidVersion:
            raise ValueError(f"uninterpretable version string: {ver!r}")
except ModuleNotFoundError:  # pragma: no cover - exercised only without packaging
    _HAVE_PACKAGING = False

    def _parse(v: str) -> tuple[int, ...]:
        nums = re.findall(r"\d+", v)
        return tuple(int(n) for n in nums[:3]) if nums else (0,)

    def _lt_fixed(ver: str) -> bool:
        return _parse(ver) < _parse(FIXED_VERSION)


# --------------------------------------------------------------------------- #
# Active environment (concrete version)
# --------------------------------------------------------------------------- #

def installed_version() -> str | None:
    """Return the installed transformers version, or None if not installed."""
    try:
        from importlib.metadata import version, PackageNotFoundError
    except ModuleNotFoundError:  # pragma: no cover
        return None
    try:
        return version(PACKAGE)
    except PackageNotFoundError:
        return None


# --------------------------------------------------------------------------- #
# Requirements file (specifier)
# --------------------------------------------------------------------------- #

def spec_from_requirements(req_path: Path) -> str | None:
    """Return the transformers specifier from a requirements file.

    Examples: ``<5.3.0`` -> "<5.3.0"; ``transformers[all]>=5.3.0,<6`` -> ">=5.3.0,<6";
    bare ``transformers`` -> "" (no constraint). Returns None if transformers is
    not named at all.
    """
    line_re = re.compile(r"^\s*transformers(?:\[[^\]]*\])?\s*(.*)$", re.IGNORECASE)
    for line in req_path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        m = line_re.match(line)
        if m:
            return m.group(1).strip()
    return None


def permits_vulnerable(spec: str) -> bool:
    """True if the specifier permits any transformers version below the fix.

    An empty specifier (unpinned) permits everything, so it permits vulnerable
    versions. Requires `packaging` for correct specifier-set reasoning.
    """
    if not _HAVE_PACKAGING:
        raise RuntimeError(
            "auditing a requirements specifier needs the 'packaging' package "
            "(pip install packaging)."
        )
    if spec.strip() == "":
        return True
    try:
        ss = SpecifierSet(spec)
    except InvalidSpecifier as exc:
        raise ValueError(f"uninterpretable specifier: {spec!r} ({exc})")
    # Test the broad representatives AND every version literal named in the
    # specifier itself, so an exact pin like "==5.2.0" is caught even though it
    # coincides with none of the representatives. A candidate counts only if it is
    # itself a vulnerable version (< fixed) and the specifier admits it.
    candidates = set(_REPRESENTATIVE_VULN) | set(re.findall(r"\d+(?:\.\d+)*", spec))
    for cand in candidates:
        try:
            if _lt_fixed(cand) and ss.contains(cand, prereleases=True):
                return True
        except (ValueError, InvalidVersion):
            continue
    return False


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def report_installed(ver: str) -> int:
    if _lt_fixed(ver):
        print(f"VULNERABLE: {PACKAGE} {ver} (installed) is affected by {ADVISORY}.")
        print(f"            Fixed in {PACKAGE} >= {FIXED_VERSION}. Upgrade to remediate.")
        return 1
    print(f"OK: {PACKAGE} {ver} (installed) is at or above the fixed version {FIXED_VERSION}.")
    return 0


def report_specifier(spec: str, source: str) -> int:
    shown = spec if spec else "(unpinned)"
    if permits_vulnerable(spec):
        reason = ("unpinned -- permits any version" if spec == ""
                  else f"specifier '{spec}' permits versions below {FIXED_VERSION}")
        print(f"VULNERABLE: {PACKAGE} {shown} ({source}): {reason}, affected by {ADVISORY}.")
        print(f"            Pin {PACKAGE} >= {FIXED_VERSION} to remediate.")
        return 1
    print(f"OK: {PACKAGE} {shown} ({source}) excludes all versions below {FIXED_VERSION}.")
    return 0


def run_pip_audit() -> int:
    exe = shutil.which("pip-audit")
    if not exe:
        print("pip-audit not installed; skipping (pip install pip-audit).", file=sys.stderr)
        return 0
    print("Running pip-audit against the active environment...\n")
    proc = subprocess.run([exe], text=True)
    return 1 if proc.returncode != 0 else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Flag a transformers pin vulnerable to CVE-2026-4372."
    )
    parser.add_argument("--requirements", type=Path,
                        help="requirements/constraints file to inspect instead of the live env")
    parser.add_argument("--pip-audit", action="store_true",
                        help="also run pip-audit if available (full advisory cross-check)")
    args = parser.parse_args(argv)

    rc = 0
    try:
        if args.requirements:
            if not args.requirements.is_file():
                print(f"error: no such file: {args.requirements}", file=sys.stderr)
                return 3
            spec = spec_from_requirements(args.requirements)
            if spec is None:
                print(f"UNKNOWN: transformers is not named in {args.requirements}.")
                return 2
            rc = report_specifier(spec, f"from {args.requirements}")
        else:
            ver = installed_version()
            if ver is None:
                print("UNKNOWN: transformers is not installed in the active environment.")
                return 2
            rc = report_installed(ver)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.pip_audit:
        rc = max(rc, run_pip_audit())

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
