#!/usr/bin/env python3
"""
safe_load.py -- a hardened wrapper around Hugging Face model loading.

Part of the SE6013 CVE-2026-4372 defensive toolkit (DEFENCE layer, README 6.6).

It layers the project's defensive controls in front of `from_pretrained`:

  1. VERSION GATE   -- refuse to load if transformers is below the fixed version
                       (5.3.0). Checked against both the installed distribution
                       metadata and the module that is actually imported.
                       THIS IS THE FIX. Everything below is defence-in-depth for
                       environments that cannot upgrade yet, and is best-effort.
  2. KERNELS GATE   -- in a vulnerable environment (only reachable with
                       allow_vulnerable_env=True), refuse if the `kernels` package
                       is importable: it is the precondition for the Hub-kernel
                       code-execution path.
  3. PRE-LOAD SCAN  -- pin the repo to one immutable commit, download ONLY its
                       config files (never weights, never code) at that commit,
                       and run the static config_scanner. The real load then uses
                       the same commit, so the scanned config is the loaded one.
                       Refuse on findings unless the caller explicitly accepts them.
  4. NO REMOTE CODE -- force trust_remote_code=False on the real call. This is
                       hygiene for the documented custom-code path; it does NOT
                       mitigate CVE-2026-4372, which bypasses that flag by design.

The scan is a deny-list over known fields and value shapes. It narrows the attack
surface on an unpatched install but cannot prove a config safe; upgrading is the
only complete remediation.

The real loader is injectable (`loader=`) so this module is unit-testable without
transformers installed; by default it lazily imports AutoModelForCausalLM.

Example
-------
    from defence.safe_load import safe_from_pretrained
    model = safe_from_pretrained("some-org/some-model")      # raises if unsafe
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
import tempfile
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Any, Callable

# Make the sibling detection package importable whether this is run as a module
# or as a script from anywhere in the repo.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detection import config_scanner  # noqa: E402
from detection.config_scanner import Finding  # noqa: E402
from detection.audit_dependencies import installed_version, _lt_fixed, FIXED_VERSION  # noqa: E402


class UnsafeModelLoad(Exception):
    """Raised when a defensive control blocks a model load."""


def _kernels_installed() -> bool:
    return importlib.util.find_spec("kernels") is not None


def _default_loader(allow_vulnerable_env: bool) -> Callable[..., Any]:
    """Lazily import the real loader, re-checking the version of the imported module.

    The distribution metadata checked by the version gate can disagree with the
    module that actually imports (several environments, a shadowing copy on
    sys.path, an editable install). Gate on what will really run.
    """
    transformers = importlib.import_module("transformers")
    imported = getattr(transformers, "__version__", None)
    if imported is None:
        raise UnsafeModelLoad("imported transformers has no __version__; cannot verify it.")
    if imported != installed_version():
        raise UnsafeModelLoad(
            f"imported transformers {imported} does not match the installed "
            f"distribution {installed_version()}; refusing to guess which is used."
        )
    if _lt_fixed(imported) and not allow_vulnerable_env:
        raise UnsafeModelLoad(f"imported transformers {imported} is below {FIXED_VERSION}.")
    return transformers.AutoModelForCausalLM.from_pretrained


def _check_environment(allow_vulnerable_env: bool) -> None:
    """Controls 1 and 2: version gate, then kernels gate if the env is vulnerable."""
    ver = installed_version()
    if ver is None:
        raise UnsafeModelLoad(
            "transformers is not installed; cannot verify it is patched for CVE-2026-4372."
        )
    if not _lt_fixed(ver):
        return

    msg = (
        f"installed transformers {ver} is below the CVE-2026-4372 fix ({FIXED_VERSION}). "
        f"Upgrade with: pip install 'transformers>={FIXED_VERSION}'."
    )
    if not allow_vulnerable_env:
        raise UnsafeModelLoad(msg)
    if _kernels_installed():
        raise UnsafeModelLoad(
            f"{msg}\nThe `kernels` package is also installed, which enables the Hub-kernel "
            "code-execution path. Uninstall it (pip uninstall kernels) or upgrade."
        )
    print(f"WARNING: {msg}\n         Proceeding only because allow_vulnerable_env=True.",
          file=sys.stderr)


def _fetch_hub_configs(model_id: str, revision: str | None, dest: Path) -> tuple[str, list[Finding]]:
    """Pin a Hub repo to a commit and download only its config files into `dest`.

    Returns (commit_sha, findings for files that were listed but not downloaded).
    Config files are JSON data, so downloading them executes nothing.
    """
    try:
        from huggingface_hub import HfApi, hf_hub_download
    except ModuleNotFoundError as exc:
        raise UnsafeModelLoad(
            "huggingface_hub is required to pre-fetch the config for a remote repo id."
        ) from exc

    info = HfApi().model_info(model_id, revision=revision)
    sha = info.sha
    if not sha:
        raise UnsafeModelLoad(f"could not resolve {model_id!r} to an immutable commit.")

    extra: list[Finding] = []
    for sibling in info.siblings or []:
        name = sibling.rfilename
        base = PurePosixPath(name).name
        if any(fnmatch(base, g) for g in config_scanner.CONFIG_GLOBS):
            # Fresh dest dir, so nothing stale from the shared cache is scanned.
            hf_hub_download(repo_id=model_id, filename=name, revision=sha, local_dir=dest)
        elif base.endswith(".py"):
            extra.append(Finding(name, "", "custom_code_file", "medium",
                                 "repo ships Python code (listed, not downloaded)"))
    return sha, extra


def _scan(model_id: str, local_files_only: bool, revision: str | None) -> tuple[list[Finding], str | None]:
    """Control 3: scan every config the load could read.

    Returns (findings, pinned_commit). pinned_commit is None for a local path.
    The whole repo is scanned, which also covers any `subfolder=` the caller uses.
    """
    p = Path(model_id)
    if p.exists():
        if not p.is_dir():
            raise UnsafeModelLoad(f"{model_id!r} is a file; pass the model directory.")
        return config_scanner.scan_repo(p), None

    if local_files_only:
        raise UnsafeModelLoad(f"local_files_only=True but {model_id!r} is not a local path.")

    with tempfile.TemporaryDirectory(prefix="safe_load_") as tmp:
        sha, extra = _fetch_hub_configs(model_id, revision, Path(tmp))
        return config_scanner.scan_repo(Path(tmp)) + extra, sha


def safe_from_pretrained(
    model_id: str,
    *,
    loader: Callable[..., Any] | None = None,
    revision: str | None = None,
    local_files_only: bool = False,
    min_severity: str = "high",
    accept_findings: bool = False,
    allow_vulnerable_env: bool = False,
    **kwargs: Any,
) -> Any:
    """Load a model only after every defensive control passes.

    Parameters
    ----------
    model_id            Hub repo id or local model directory.
    loader              The real loader to call once checks pass. Defaults to
                        transformers.AutoModelForCausalLM.from_pretrained.
    revision            Branch, tag or commit. For a Hub id it is resolved to a
                        commit sha once, and that sha is used for both scan and load.
    local_files_only    Require model_id to be a local path.
    min_severity        Scanner severity at/above which findings block the load.
    accept_findings     If True, log scanner findings but do not block (human has
                        reviewed them). Defaults to False (block).
    allow_vulnerable_env If True, warn instead of raising when transformers is
                        below the fixed version. For the controlled lab only.
    **kwargs            Passed through to the real loader. Any trust_remote_code
                        value is overridden to False. `config=` is rejected,
                        because a config supplied that way bypasses the scan.

    Raises
    ------
    UnsafeModelLoad     If a control blocks the load.
    """
    # Controls 1 + 2: version gate, kernels gate.
    _check_environment(allow_vulnerable_env)

    if "config" in kwargs:
        raise UnsafeModelLoad(
            "config= bypasses the pre-load scan; let the loader read the repo's config."
        )

    # Control 3: pre-load config scan at a pinned commit (config only; no code).
    all_findings, pinned = _scan(model_id, local_files_only, revision)
    findings = config_scanner.filter_by_severity(all_findings, min_severity)
    if findings:
        header = (
            f"config scan flagged {len(findings)} item(s) at/above '{min_severity}' "
            f"for {model_id!r}:"
        )
        body = "\n".join("  " + f.human() for f in findings)
        if not accept_findings:
            raise UnsafeModelLoad(f"{header}\n{body}\n"
                                  "Review the repo; pass accept_findings=True to override.")
        print(f"WARNING: {header}\n{body}\n         Proceeding (accept_findings=True).",
              file=sys.stderr)

    # Control 4: never opt into remote code, whatever the caller passed.
    if kwargs.get("trust_remote_code"):
        print("NOTE: trust_remote_code was requested; forcing it to False.", file=sys.stderr)
    kwargs["trust_remote_code"] = False
    if pinned is not None:
        kwargs["revision"] = pinned  # load exactly the commit that was scanned
    if local_files_only:
        kwargs.setdefault("local_files_only", True)

    real_loader = loader or _default_loader(allow_vulnerable_env)
    return real_loader(model_id, **kwargs)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Dry-run the safe-load defensive controls against a repo id or path "
                    "(runs checks only; does not load the model)."
    )
    ap.add_argument("model_id", help="Hub repo id or local model directory")
    ap.add_argument("--revision", default=None)
    ap.add_argument("--local-files-only", action="store_true")
    ap.add_argument("--min-severity", choices=("low", "medium", "high"), default="high")
    ap.add_argument("--assume-version", default=None, metavar="VER",
                    help="pretend this transformers version is installed, to demo the "
                         "scan control on a machine without transformers (e.g. 5.3.1)")
    ap.add_argument("--allow-vulnerable-env", action="store_true",
                    help="lab only: let the defence-in-depth controls run on a vulnerable "
                         "version instead of stopping at the version gate")
    args = ap.parse_args()

    # Demo aid: let the dry-run simulate a given installed version so the config
    # scan can be exercised even where transformers is not installed. The library
    # API (safe_from_pretrained) is unaffected and still gates on the real env.
    if args.assume_version:
        globals()["installed_version"] = lambda: args.assume_version

    # A no-op loader lets us exercise every control without loading a model.
    def _dry(mid: str, **kw: Any) -> str:
        return f"[dry-run] all controls passed for {mid!r}; real loader would run with {kw}"

    try:
        print(safe_from_pretrained(
            args.model_id, loader=_dry, revision=args.revision,
            local_files_only=args.local_files_only, min_severity=args.min_severity,
            allow_vulnerable_env=args.allow_vulnerable_env,
        ))
    except UnsafeModelLoad as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1)
