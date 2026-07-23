#!/usr/bin/env python3
"""Validate the CycloneDX 2.0 threat model files in threat-models/.

Downloads the bundled draft schema (pinned revision of the CycloneDX
`2.0-dev-threatmodeling` branch) into scripts/cache/ on first use, then
validates every *.cdx.json file against it.

Requires the `jsonschema` package, e.g.:

    nix-shell -p "python3.withPackages (ps: [ ps.jsonschema ])" \
        --run "python3 scripts/validate-threat-models.py"

Pass file paths as arguments to validate a subset instead of the whole
directory.
"""

import json
import pathlib
import sys
import urllib.request

import jsonschema

SCHEMA_REV = "cf0bc55711517c20c0ccb10f55d822eccb521e03"
SCHEMA_URL = (
    "https://raw.githubusercontent.com/CycloneDX/specification/"
    f"{SCHEMA_REV}/schema/2.0/cyclonedx-2.0-bundled.schema.json"
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_CACHE = ROOT / "scripts" / "cache" / "cyclonedx-2.0-bundled.schema.json"
MODEL_DIR = ROOT / "threat-models"


def load_schema():
    if not SCHEMA_CACHE.exists():
        SCHEMA_CACHE.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading schema revision {SCHEMA_REV[:12]}...")
        with urllib.request.urlopen(SCHEMA_URL) as response:
            SCHEMA_CACHE.write_bytes(response.read())
    return json.loads(SCHEMA_CACHE.read_text())


def main():
    if len(sys.argv) > 1:
        files = [pathlib.Path(arg) for arg in sys.argv[1:]]
    else:
        files = sorted(MODEL_DIR.glob("*.cdx.json"))
    if not files:
        print("No threat model files found.", file=sys.stderr)
        return 1

    validator = jsonschema.Draft202012Validator(load_schema())
    failures = 0
    for path in files:
        try:
            document = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            print(f"FAIL {path}: invalid JSON: {error}")
            failures += 1
            continue
        errors = sorted(validator.iter_errors(document), key=lambda e: e.json_path)
        if errors:
            failures += 1
            print(f"FAIL {path}")
            for error in errors[:10]:
                print(f"  {error.json_path}: {error.message[:200]}")
        else:
            print(f"ok   {path.name}")

    print(f"{len(files) - failures}/{len(files)} files valid")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
