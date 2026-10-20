#!/usr/bin/env python3
"""
safe_load.py -- a safer replacement for Hugging Face `from_pretrained`.

SE6013 CVE-2026-4372 defence. Self-contained: needs only the standard library
(plus `huggingface_hub` when loading a model from the Hub).

Four checks run before any model is loaded. If one fails, UnsafeModelLoad is raised.

  1. Version check  -- transformers must be 5.3.0 or newer (the real fix).
  2. Kernels check  -- on an old version, the `kernels` package must not be
                       installed (the attack needs it to run Hub code).
  3. Config check   -- the model's config files must not point at outside code.
                       Hub models are checked and loaded at the same commit.
  4. Remote code    -- trust_remote_code is always forced to False (good practice
                       only; this CVE bypasses it).

Checks 2 and 3 only matter on an old version, which is refused unless
allow_vulnerable_env=True (lab use only).

Usage:
    from safe_load import safe_from_pretrained
    model = safe_from_pretrained("some-org/some-model")

Dry run (checks only, nothing is loaded):
    python safe_load.py <model-folder-or-hub-id>
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

FIXED_VERSION = "5.3.0"

# Attention settings that are built into transformers. Anything else (for
# example "attacker-org/evil-kernel") makes old versions download and run code.
SAFE_ATTN_VALUES = {"eager", "sdpa", "flash_attention_2", "flash_attention_3", "flex_attention"}
ATTN_KEYS = {"attn_implementation", "_attn_implementation", "_attn_implementation_internal"}

# Settings that should never come from an untrusted config: the internal field
# the CVE uses, and the fields that point at custom Python code.
RISKY_KEYS = {"_attn_implementation_internal", "auto_map", "custom_pipelines"}


class UnsafeModelLoad(Exception):
    """Raised when a check blocks a model load."""


# ---------------------------------------------------------------- check 1 + 2

def installed_version() -> str | None:
    try:
        return version("transformers")
    except PackageNotFoundError:
        return None


def is_old(ver: str) -> bool:
    """True if `ver` is older than FIXED_VERSION, e.g. "5.2.0" -> True."""
    def parts(v: str) -> tuple[int, ...]:
        return tuple(int(n) for n in re.findall(r"\d+", v)[:3])
    return parts(ver) < parts(FIXED_VERSION)


def kernels_installed() -> bool:
    return importlib.util.find_spec("kernels") is not None


def check_environment(allow_vulnerable_env: bool) -> None:
    ver = installed_version()
    if ver is None:
        raise UnsafeModelLoad("transformers is not installed.")
    if not is_old(ver):
        return
    if not allow_vulnerable_env:
        raise UnsafeModelLoad(
            f"transformers {ver} is vulnerable to CVE-2026-4372. "
            f"Upgrade: pip install 'transformers>={FIXED_VERSION}'")
    if kernels_installed():
        raise UnsafeModelLoad(
            f"transformers {ver} is vulnerable and the `kernels` package is installed. "
            "Uninstall it (pip uninstall kernels) or upgrade transformers.")
    print(f"WARNING: running on vulnerable transformers {ver} (lab mode).", file=sys.stderr)


# ---------------------------------------------------------------- check 3

def check_config(path: Path, name: str) -> list[str]:
    """Return a list of problems found in one JSON config file (shown as `name`)."""
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{name}: cannot read config ({exc})"]

    problems: list[str] = []

    def check_attn(value, where: str) -> None:
        if isinstance(value, dict):                 # per-sub-model settings
            for sub, v in value.items():
                check_attn(v, f"{where}.{sub}")
        elif value is not None and value not in SAFE_ATTN_VALUES:
            problems.append(f"{name}: {where} = {value!r} is not a built-in attention type")

    def walk(obj, where: str) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                here = f"{where}.{key}" if where else key
                if key in RISKY_KEYS:
                    problems.append(f"{name}: {here} is a risky setting")
                if key in ATTN_KEYS:
                    check_attn(value, here)
                else:
                    walk(value, here)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{where}[{i}]")

    walk(cfg, "")
    return problems


def check_folder(folder: Path) -> list[str]:
    problems: list[str] = []
    for path in sorted(folder.rglob("*config*.json")):
        problems += check_config(path, path.relative_to(folder).as_posix())
    return problems


def check_hub_model(model_id: str, revision: str | None) -> tuple[list[str], str]:
    """Download only the config files of a Hub model at one fixed commit and check them.

    Returns (problems, commit). Loading the same commit afterwards means the
    files that were checked are the files that get loaded.
    """
    from huggingface_hub import HfApi, hf_hub_download

    info = HfApi().model_info(model_id, revision=revision)
    with tempfile.TemporaryDirectory() as tmp:
        for f in info.siblings or []:
            if re.search(r"config.*\.json$", Path(f.rfilename).name):
                hf_hub_download(model_id, f.rfilename, revision=info.sha, local_dir=tmp)
        return check_folder(Path(tmp)), info.sha


# ---------------------------------------------------------------- main entry

def safe_from_pretrained(model_id: str, *, loader=None, revision: str | None = None,
                         accept_findings: bool = False, allow_vulnerable_env: bool = False,
                         **kwargs):
    """Run the four checks, then load the model with `loader` (default: transformers).

    accept_findings=True loads anyway after a person has reviewed check 3's warnings.
    """
    check_environment(allow_vulnerable_env)                          # checks 1 + 2

    if "config" in kwargs:
        raise UnsafeModelLoad("config= is not allowed: it would skip the config check.")

    folder = Path(model_id)                                          # check 3
    if folder.is_dir():
        problems = check_folder(folder)
    elif kwargs.get("local_files_only"):
        raise UnsafeModelLoad(f"{model_id!r} is not a local model folder.")
    else:
        problems, kwargs["revision"] = check_hub_model(model_id, revision)
    if problems:
        report = "\n  ".join(problems)
        if not accept_findings:
            raise UnsafeModelLoad(f"unsafe config in {model_id!r}:\n  {report}")
        print(f"WARNING (accepted): {report}", file=sys.stderr)

    kwargs["trust_remote_code"] = False                              # check 4

    if loader is None:
        from transformers import AutoModelForCausalLM
        loader = AutoModelForCausalLM.from_pretrained
    return loader(model_id, **kwargs)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Run the checks without loading the model.")
    ap.add_argument("model", help="local model folder or Hub id (org/name)")
    ap.add_argument("--assume-version", metavar="VER",
                    help="pretend this transformers version is installed (demo)")
    ap.add_argument("--allow-vulnerable-env", action="store_true",
                    help="lab only: run checks 2-4 on a vulnerable version")
    args = ap.parse_args()

    if args.assume_version:
        installed_version = lambda: args.assume_version  # noqa: E731

    try:
        safe_from_pretrained(args.model, loader=lambda *a, **k: None,
                             allow_vulnerable_env=args.allow_vulnerable_env)
        print(f"PASSED: all checks passed for {args.model!r}")
    except UnsafeModelLoad as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        sys.exit(1)
