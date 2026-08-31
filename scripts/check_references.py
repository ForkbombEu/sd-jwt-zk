#!/usr/bin/env python3
# Copyright (C) 2026 by The Forkbomb Company
# designed, written and maintained by Denis Roio
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
