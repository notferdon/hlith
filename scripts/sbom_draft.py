#!/usr/bin/env python3
"""LOCAL SBOM/provenance draft: a CycloneDX-style JSON from uv.lock. No network, nothing published.

Every locked third-party package must carry at least one well-formed sha256 artifact hash (sdist or wheel), otherwise the
script FAILS (exit 1) and names the packages. Only the project itself (source editable/virtual = ".") is exempt: it is the
BOM's metadata.component, built from this tree, and has no locked artifact. A missing/unparsable lock or a lock with no
packages hard fails (exit 2). This is a local draft, not a release SBOM: no licence data, no signature, no attestation.

usage: python scripts/sbom_draft.py [--lock uv.lock] [--out sbom.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

_HASH = re.compile(r"sha256:([0-9a-f]{64})")
_PROJECT_SOURCES = ({"editable": "."}, {"virtual": "."})


class LockError(Exception):
    """The lock cannot be read or is empty (exit 2)."""


def _artifact_hashes(pkg: dict) -> tuple[list[str], list[str]]:
    """(valid sha256 hex digests, problems) over the package's sdist and wheels."""
    entries = []
    if isinstance(pkg.get("sdist"), dict):
        entries.append(pkg["sdist"])
    entries += [w for w in pkg.get("wheels") or [] if isinstance(w, dict)]
    good, bad = [], []
    for e in entries:
        h = e.get("hash")
        m = _HASH.fullmatch(h) if isinstance(h, str) else None
        if m:
            good.append(m.group(1))
        else:
            bad.append(f"artifact {str(e.get('url') or e.get('path') or '?')[-80:]} has {'no' if h is None else 'a malformed'} hash")
    return sorted(set(good)), bad


def build(lock_path: Path) -> tuple[dict, list[str]]:
    """Return (bom, problems). problems non-empty = the draft must not be used."""
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise LockError(f"cannot read {lock_path}: {e}") from e
    pkgs = lock.get("package")
    if not isinstance(pkgs, list) or not pkgs:
        raise LockError(f"{lock_path} lists no [[package]] entries")
    root, components, problems = None, [], []
    for pkg in pkgs:
        name, version, source = pkg.get("name"), pkg.get("version"), pkg.get("source")
        if not isinstance(name, str) or not name:
            problems.append("a [[package]] entry has no name")
            continue
        if source in _PROJECT_SOURCES:
            if root is not None:
                problems.append(f"two project roots in the lock: {root['name']} and {name}")
            root = {"type": "application", "bom-ref": f"{name}@{version}", "name": name, "version": str(version),
                    "properties": [{"name": "hlith:source", "value": json.dumps(source, sort_keys=True)}]}
            continue
        if not isinstance(version, str) or not version:
            problems.append(f"{name}: no locked version")
        good, bad = _artifact_hashes(pkg)
        problems += [f"{name} {version}: {b}" for b in bad]
        if not good:
            problems.append(f"{name} {version}: no sha256 artifact hash in the lock (source {json.dumps(source, sort_keys=True)})")
        components.append({
            "type": "library",
            "bom-ref": f"pkg:pypi/{name}@{version}",
            "name": name,
            "version": str(version),
            "purl": f"pkg:pypi/{name}@{version}",
            "hashes": [{"alg": "SHA-256", "content": h} for h in good],
        })
    if root is None:
        problems.append("the lock has no project root (source editable/virtual '.')")
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": root,
            "properties": [{"name": "hlith:draft", "value": "LOCAL draft from uv.lock; not a release SBOM; no licence data, unsigned"},
                           {"name": "hlith:lock", "value": lock_path.name}],
        },
        "components": sorted(components, key=lambda c: (c["name"], c["version"])),
    }
    return bom, problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[1] / "uv.lock")
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args(argv)
    try:
        bom, problems = build(a.lock)
    except LockError as e:
        print(f"sbom_draft: FAIL: {e}", file=sys.stderr)
        return 2
    if problems:
        for p in problems:
            print(f"sbom_draft: FAIL: {p}", file=sys.stderr)
        return 1
    text = json.dumps(bom, indent=2, sort_keys=True) + "\n"
    if a.out is None:
        sys.stdout.write(text)
    else:
        a.out.write_text(text, encoding="utf-8")
    print(f"sbom_draft: OK: {len(bom['components'])} hashed components + project {bom['metadata']['component']['name']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
