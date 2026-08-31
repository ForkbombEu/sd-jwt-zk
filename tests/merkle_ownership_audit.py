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

"""Fail closed when SD-JWT regains a Merkle primitive or bypasses its package."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re


SDJWT = Path(__file__).resolve().parents[1]
WORKSPACE = SDJWT.parent
MATRIX = SDJWT / "tests" / "merkle_ownership_matrix.json"

NATIVE_HEADERS = ("merkle_tree.h", "merkle_commitment.h")
REMOVED_PRODUCTION_FILES = (
    "include/sd_jwt_zk/issuer_registry_membership_relation.h",
    "include/sd_jwt_zk/issuer_registry.h",
    "include/sd_jwt_zk/issuer_registry_policy.h",
    "include/sd_jwt_zk/registry_bearer_proof.h",
    "src/issuer_registry.cc",
    "src/issuer_registry_policy.cc",
    "src/registry_bearer_proof.cc",
)


def source_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.suffix in {".cc", ".h", ".cpp"}]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def upstream_sources(longfellow_arg: Path | None,
                     google_arg: Path | None) -> tuple[Path, Path]:
    longfellow = longfellow_arg or Path(
        os.environ.get("SD_JWT_ZK_LONGFELLOW_SOURCE", WORKSPACE / "longfellow-zk"))
    google = google_arg or Path(
        os.environ.get("SD_JWT_ZK_GOOGLE_LONGFELLOW_SOURCE",
                       longfellow / "vendor" / "longfellow-zk"))
    return longfellow.resolve(), google.resolve()


def audit_matrix() -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    require(matrix["schemaVersion"] == 1, "unexpected ownership matrix schema")
    names = {entry["name"] for entry in matrix["primitives"]}
    require(names == {
        "native-tree-and-compressed-path", "fixed-depth-circuit-membership",
        "sha256-and-bit-packing", "path-adaptation-and-witness-generation",
        "canonical-native-circuit-vectors", "status-leaf-and-snapshot-policy",
    }, "ownership matrix is incomplete")
    require(matrix["precedent"]["packageTarget"] == "LongfellowZKECDSA::ecdsa",
            "ECDSA installed-target precedent disappeared")


def audit_upstream_ownership(longfellow: Path, google_source: Path) -> None:
    for header in NATIVE_HEADERS:
        european = longfellow / "src" / "merkle" / header
        google = google_source / "lib" / "merkle" / header
        require(european.is_file(), f"Longfellow source header is missing: {european}")
        require(google.is_file(), f"Google baseline header is missing: {google}")
        current = european.read_text(encoding="utf-8")
        baseline = google.read_text(encoding="utf-8")
        if header == "merkle_tree.h" and current != baseline:
            # Controlled Longfellow c295424 hardening: reject trailing nodes
            # after consuming a compressed proof.  Normalize only this exact
            # scope move plus guard; every other byte remains pinned.
            require("size_t sz = 0;\n    /*scope for TREE */" in current and
                    "if (sz != proof_len)" in current,
                    "approved trailing-proof hardening is incomplete")
            normalized = current.replace("    size_t sz = 0;\n    /*scope for TREE */ {",
                                         "    /*scope for TREE */ {")
            normalized = normalized.replace("      // read the proof\n      for",
                                            "      // read the proof\n      size_t sz = 0;\n      for")
            approved_guard = (
                "    }\n\n"
                "    // The compressed proof has a unique traversal encoding.  Consuming only a\n"
                "    // prefix would accept a second, trailing-node encoding of the same\n"
                "    // opening, which disagrees with the pinned Rust verifier.\n"
                "    if (sz != proof_len) {\n"
                "      return false;\n"
                "    }\n")
            baseline_guard = (
                "      // Ensure entire proof is consumed.\n"
                "      if (sz != proof_len) return false;\n"
                "    }\n")
            require(approved_guard in normalized,
                    "approved trailing-proof hardening changed unexpectedly")
            normalized = normalized.replace(approved_guard, baseline_guard, 1)
            current = normalized
        require(current == baseline, f"native Merkle header changed: {header}")
    required = (
        longfellow / "src/circuits/merkle/fixed_depth_sha256_merkle_membership.h",
        longfellow / "src/circuits/sha/flatsha256_circuit.h",
        longfellow / "src/circuits/logic/bit_plucker.h",
        longfellow / "test/merkle/canonical_merkle_membership_vectors.json",
    )
    require(all(path.is_file() for path in required), "Longfellow Merkle surface is incomplete")


def audit_sdjwt_sources() -> None:
    require(not [path for path in REMOVED_PRODUCTION_FILES if (SDJWT / path).exists()],
            "removed issuer-registry production files returned")
    production = source_files(SDJWT / "src") + source_files(SDJWT / "include")
    allowed = SDJWT / "include/sd_jwt_zk/status_membership.h"
    generic_tokens = ("class MerkleTree", "class MerkleTreeVerifier",
                      "FixedDepthSha256MerklePathAdapter",
                      "FixedDepthSha256MerkleMembership")
    offenders = [str(path.relative_to(SDJWT)) for path in production
                 if path != allowed and any(token in path.read_text(errors="ignore")
                                            for token in generic_tokens)]
    require(not offenders, "SD-JWT owns a generic Merkle primitive: " + ", ".join(offenders))
    all_text = "\n".join(path.read_text(errors="ignore") for path in production)
    require("google-longfellow-zk" not in all_text and "/lib/merkle/" not in all_text,
            "SD-JWT contains a Google source-tree dependency")
    vector_files = [path for path in SDJWT.rglob("*") if path.is_file() and
                    re.search(r"merkle.*vector|vector.*merkle", path.name, re.I)]
    require(not vector_files, "SD-JWT maintains a divergent Merkle vector corpus")


def audit_repository_wide_status_ownership() -> None:
    """Reject a status-specific reimplementation in every deliverable area.

    Generic SHA relations elsewhere in this small research repository are not
    status Merkle logic.  The conjunction below deliberately catches only the
    old, forbidden pattern: status code that both constructs a Merkle path and
    builds its per-level hash/witness advice itself.
    """
    ignored = {"build", ".git", ".longfellow-install", "__pycache__"}
    candidates = [path for path in SDJWT.rglob("*") if path.is_file() and
                  not any(part in ignored or part.startswith("build")
                          for part in path.relative_to(SDJWT).parts)]
    offenders = []
    for path in candidates:
        if path == Path(__file__):
            continue
        text = path.read_text(errors="ignore")
        status_related = "status" in path.name.lower() or "status-membership" in text
        # A status bridge may legitimately use the installed SHA gadget for a
        # non-Merkle proof-binding commitment.  Flag only the former local
        # Merkle-level hash construction, not that separate bridge relation.
        manual_merkle_witness = "Digest::hash2" in text
        manual_path = ("direction_bits" in text or "generate_compressed_proof" in text)
        if status_related and manual_merkle_witness and manual_path:
            offenders.append(str(path.relative_to(SDJWT)))
    require(not offenders,
            "status Merkle path/hash/witness work must use Longfellow's adapter: " +
            ", ".join(offenders))


def audit_cmake_and_install(prefix: Path) -> None:
    cmake = (SDJWT / "CMakeLists.txt").read_text(encoding="utf-8")
    require("find_package(LongfellowZK CONFIG REQUIRED)" in cmake,
            "SD-JWT no longer requires installed LongfellowZK")
    require("LongfellowZK::" in cmake and "google-longfellow-zk" not in cmake,
            "SD-JWT CMake provenance is not the installed Longfellow package")
    require("find_package(LongfellowZKECDSA CONFIG REQUIRED)" in cmake and
            "LongfellowZKECDSA::ecdsa" in cmake,
            "ECDSA installed-target precedent is not retained")
    include = prefix / "include" / "longfellow-zk"
    require((include / "circuits/merkle/fixed_depth_sha256_merkle_membership.h").is_file(),
            "installed Longfellow package omits the membership gadget")
    forbidden = [path for path in prefix.rglob("*") if path.is_file() and
                 re.search(r"issuer_registry|registry_bearer|membership_relation", path.name)]
    require(not forbidden, "controlled install contains obsolete registry API")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-prefix", type=Path,
                        default=WORKSPACE / ".longfellow-install")
    parser.add_argument("--longfellow-source", type=Path)
    parser.add_argument("--google-longfellow-source", type=Path)
    args = parser.parse_args()
    longfellow, google_source = upstream_sources(
        args.longfellow_source, args.google_longfellow_source)
    audit_matrix()
    audit_upstream_ownership(longfellow, google_source)
    audit_sdjwt_sources()
    audit_repository_wide_status_ownership()
    audit_cmake_and_install(args.install_prefix)
    print("Merkle ownership audit: single upstream primitive surface and installed-only SD-JWT dependency")


if __name__ == "__main__":
    main()
