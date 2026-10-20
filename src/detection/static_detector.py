import json
import sys
from pathlib import Path

REVIEW_FIELDS = {
    "_attn_implementation_internal",
    "_experts_implementation_internal",
    "auto_map",
    "custom_pipelines",
}


def scan_config(path):
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"[ERROR] {path}: {error}")
        return 2

    if not isinstance(config, dict):
        print(f"[ERROR] {path}: expected a JSON object")
        return 2

    findings = []

    def inspect(value, location=""):
        if isinstance(value, dict):
            for key, item in value.items():
                current = f"{location}.{key}" if location else key

                if key in REVIEW_FIELDS:
                    findings.append(current)

                inspect(item, current)

        elif isinstance(value, list):
            for index, item in enumerate(value):
                inspect(item, f"{location}[{index}]")

    inspect(config)

    if findings:
        for finding in findings:
            print(f"[WARNING] {path}: review field '{finding}'")
        return 1

    print(f"[PASS] {path}: no review fields found")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python static_detector.py <config.json>")
        sys.exit(2)

    sys.exit(scan_config(Path(sys.argv[1])))
