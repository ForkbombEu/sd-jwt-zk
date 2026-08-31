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

"""Regression tests for Merkle ownership audit source discovery."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("merkle_ownership_audit.py")
SPEC = importlib.util.spec_from_file_location("merkle_ownership_audit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class MerkleOwnershipAuditTest(unittest.TestCase):
    @staticmethod
    def make_surface(longfellow: Path, google: Path,
                     tree_current: str = "pinned upstream header\n",
                     tree_baseline: str = "pinned upstream header\n") -> None:
        headers = {
            "merkle_tree.h": (tree_current, tree_baseline),
            "merkle_commitment.h": (
                "pinned commitment header\n", "pinned commitment header\n"),
        }
        for header, (current_text, baseline_text) in headers.items():
            current = longfellow / "src" / "merkle" / header
            baseline = google / "lib" / "merkle" / header
            current.parent.mkdir(parents=True, exist_ok=True)
            baseline.parent.mkdir(parents=True, exist_ok=True)
            current.write_text(current_text, encoding="utf-8")
            baseline.write_text(baseline_text, encoding="utf-8")

        for relative in (
            "src/circuits/merkle/fixed_depth_sha256_merkle_membership.h",
            "src/circuits/sha/flatsha256_circuit.h",
            "src/circuits/logic/bit_plucker.h",
            "test/merkle/canonical_merkle_membership_vectors.json",
        ):
            path = longfellow / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()

    def test_ci_source_environment_is_used_for_upstream_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            longfellow = root / ".deps" / "longfellow-zk"
            google = root / ".deps" / "google-longfellow-zk"
            self.make_surface(longfellow, google)

            environment = {
                "SD_JWT_ZK_LONGFELLOW_SOURCE": str(longfellow),
                "SD_JWT_ZK_GOOGLE_LONGFELLOW_SOURCE": str(google),
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                actual_longfellow, actual_google = AUDIT.upstream_sources(None, None)

            self.assertEqual(actual_longfellow, longfellow.resolve())
            self.assertEqual(actual_google, google.resolve())
            AUDIT.audit_upstream_ownership(actual_longfellow, actual_google)

    def test_approved_trailing_proof_hardening_is_normalized(self) -> None:
        baseline = """\
    /*scope for TREE */ {
      // read the proof
      size_t sz = 0;
      for (;;) {}
      // Ensure entire proof is consumed.
      if (sz != proof_len) return false;
    }
"""
        current = """\
    size_t sz = 0;
    /*scope for TREE */ {
      // read the proof
      for (;;) {}
    }

    // The compressed proof has a unique traversal encoding.  Consuming only a
    // prefix would accept a second, trailing-node encoding of the same
    // opening, which disagrees with the pinned Rust verifier.
    if (sz != proof_len) {
      return false;
    }
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            longfellow = root / "longfellow-zk"
            google = root / "google-longfellow-zk"
            self.make_surface(longfellow, google, current, baseline)

            AUDIT.audit_upstream_ownership(longfellow, google)

    def test_dependency_checkout_is_not_treated_as_sdjwt_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "src").mkdir()
            (project / "include").mkdir()
            dependency_vector = (
                project / ".deps" / "longfellow-zk" / "test" /
                "merkle_membership_vectors.json")
            dependency_vector.parent.mkdir(parents=True)
            dependency_vector.write_text("{}\n", encoding="utf-8")

            with mock.patch.object(AUDIT, "SDJWT", project):
                AUDIT.audit_sdjwt_sources()


if __name__ == "__main__":
    unittest.main()
