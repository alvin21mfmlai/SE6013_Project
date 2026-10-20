#!/usr/bin/env bash
#
# generate_sbom.sh -- produce a CycloneDX SBOM of the active environment and
# (if an SCA scanner is present) match it against the advisory database.
#
# Part of the SE6013 CVE-2026-4372 defensive toolkit (DETECTION layer, README 5.3).
#
# Usage:
#   ./generate_sbom.sh [output_path]      # default: ./sbom.json
#
# Requires cyclonedx-bom (pip install cyclonedx-bom). If osv-scanner or grype is
# on PATH, the SBOM is additionally scanned so a vulnerable transformers pin is
# visible in inventory, not just at install time.

set -euo pipefail

OUT="${1:-sbom.json}"

if ! python -c "import cyclonedx_py" >/dev/null 2>&1 && ! command -v cyclonedx-py >/dev/null 2>&1; then
  echo "cyclonedx-bom not found. Install it with:  pip install cyclonedx-bom" >&2
  exit 3
fi

echo "[*] Generating CycloneDX SBOM for the active environment -> ${OUT}"
cyclonedx-py environment -o "${OUT}"
echo "[*] SBOM written to ${OUT}"

if command -v osv-scanner >/dev/null 2>&1; then
  echo "[*] Matching SBOM against OSV advisory database..."
  osv-scanner scan --sbom "${OUT}" || {
    echo "[!] osv-scanner reported findings (see above)." >&2
    exit 1
  }
elif command -v grype >/dev/null 2>&1; then
  echo "[*] Matching SBOM against Grype advisory database..."
  grype "sbom:${OUT}" || {
    echo "[!] grype reported findings (see above)." >&2
    exit 1
  }
else
  echo "[i] No SCA scanner (osv-scanner / grype) on PATH."
  echo "    SBOM generated; feed ${OUT} to your scanner of choice to match advisories."
fi
