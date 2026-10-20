from importlib.metadata import PackageNotFoundError, version
from importlib.util import find_spec


def get_package_version(package):
    try:
        return version(package)
    except PackageNotFoundError:
        return None


def main():
    transformers_version = get_package_version("transformers")
    kernels_version = get_package_version("kernels")
    kernels_available = find_spec("kernels") is not None

    print("=== CVE-2026-4372 Dependency Detection ===")
    print(f"Transformers version: {transformers_version or 'Not installed'}")
    print(f"Kernels version: {kernels_version or 'Not installed'}")
    print(f"Kernels import available: {kernels_available}")

    if transformers_version is None:
        print("[INFO] Transformers is not installed.")
        return

    # Compare versions numerically, not alphabetically.
    from packaging.version import Version

    installed = Version(transformers_version)

    if installed >= Version("5.3.0"):
        print("[PASS] CVE-2026-4372 is fixed in this Transformers version.")
    elif Version("4.56.0") <= installed < Version("5.3.0"):
        if kernels_available:
            print("[WARNING] Vulnerable Transformers version and kernels available.")
            print("[ACTION] Upgrade Transformers to 5.3.0 or newer.")
        else:
            print("[WARNING] Vulnerable Transformers version detected.")
            print("[INFO] The optional kernels package is not available.")
            print("[ACTION] Upgrade Transformers to 5.3.0 or newer.")
    else:
        print("[INFO] Version is outside the documented affected range.")
        print("[ACTION] Check other applicable security advisories.")


if __name__ == "__main__":
    main()
