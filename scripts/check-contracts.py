#!/usr/bin/env python3
"""Verify the immutable synthetic contract snapshot without network access."""
from pathlib import Path
import hashlib
import json
import sys

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "testdata/manifest.json").read_text())
seen = set()
for entry in manifest["files"]:
    rel = entry["path"]
    path = root / rel
    if rel in seen or not rel.startswith("testdata/") or path.resolve().parent == root or not path.resolve().is_relative_to(root / "testdata"):
        raise SystemExit(f"Unsafe or duplicate snapshot path: {rel}")
    seen.add(rel)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != entry["sha256"]:
        raise SystemExit(f"Contract snapshot changed: {rel}")
actual_paths = {p.relative_to(root).as_posix() for p in (root / "testdata").rglob("*") if p.is_file() and p.name != "manifest.json"}
if actual_paths != seen:
    raise SystemExit("Contract snapshot contains missing or unexpected files")
print(f"Verified {len(seen)} vendored contract/vector files; source checkout HEAD {manifest['source_checkout_head']}")
