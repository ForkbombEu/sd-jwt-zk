#!/usr/bin/env python3
"""Offline lock verifier; mutable URLs are intentionally never fetched."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
 "rfc9901": "RFC 9901",
 "swiss-profile": "Swiss Profile for Verifiable Credentials 1.0 (edited 2026-06-22)",
 "sd-jwt-vc": "SD-JWT VC Internet-Draft 15",
 "token-status-list": "Token Status List Internet-Draft 20",
}
lock = json.loads((ROOT / "spec/reference-lock.json").read_text())
if lock.get("retrieved") != "2026-08-28": raise SystemExit("reference retrieval date drift")
seen = {x["id"]: x for x in lock["sources"]}
if set(seen) != set(EXPECTED): raise SystemExit("reference IDs drift")
for ident, version in EXPECTED.items():
    item = seen[ident]
    if item.get("version") != version: raise SystemExit(f"version drift: {ident}")
    if not item.get("url", "").startswith("https://") or not item.get("anchors"):
        raise SystemExit(f"invalid pinned metadata: {ident}")
print("reference lock OK: 4 sources, offline")
