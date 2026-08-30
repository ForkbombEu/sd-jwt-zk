#!/usr/bin/env python3
"""Fail closed when SD-JWT regains a Merkle primitive or bypasses its package."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


SDJWT = Path(__file__).resolve().parents[1]
WORKSPACE = SDJWT.parent
LONGFELLOW = WORKSPACE / "longfellow-zk"
GOOGLE = WORKSPACE / "google-longfellow-zk"
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


def audit_upstream_ownership() -> None:
    for header in NATIVE_HEADERS:
        european = LONGFELLOW / "src" / "merkle" / header
        google = GOOGLE / "lib" / "merkle" / header
        require(european.read_bytes() == google.read_bytes(),
                f"native Merkle header changed: {header}")
    required = (
        LONGFELLOW / "src/circuits/merkle/fixed_depth_sha256_merkle_membership.h",
        LONGFELLOW / "src/circuits/sha/flatsha256_circuit.h",
        LONGFELLOW / "src/circuits/logic/bit_plucker.h",
        LONGFELLOW / "test/merkle/canonical_merkle_membership_vectors.json",
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
    args = parser.parse_args()
    audit_matrix()
    audit_upstream_ownership()
    audit_sdjwt_sources()
    audit_cmake_and_install(args.install_prefix)
    print("Merkle ownership audit: single upstream primitive surface and installed-only SD-JWT dependency")


if __name__ == "__main__":
    main()
