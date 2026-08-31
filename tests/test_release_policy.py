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

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReleasePolicyTests(unittest.TestCase):
    def test_supported_identity_and_vectors_are_present(self):
        api = (ROOT / "include/sd_jwt_zk/presentation.h").read_text()
        cmake = (ROOT / "CMakeLists.txt").read_text()
        vectors = json.loads((ROOT / "fixtures/compact-vectors.json").read_text())
        self.assertIn("BuildBearerPresentationRequestV1", api)
        self.assertIn("BuildHolderPresentationRequestV1", api)
        self.assertIn("fixtures/compact-vectors.json", cmake)
        self.assertTrue(vectors)

    def test_release_configuration_excludes_private_state(self):
        cmake = (ROOT / "CMakeLists.txt").read_text()
        for excluded in ("[.]gestalt", "node_modules", "build[^/]"):
            self.assertIn(excluded, cmake)
        workflow = (ROOT / ".github/workflows/reduced.yml").read_text()
        for forbidden in ("registry", "swiss", "swiyu", "recursive", "32-slot"):
            self.assertNotIn(forbidden, workflow.lower())
        self.assertNotIn("credential", workflow.lower())
        self.assertNotIn("witness", workflow.lower())
        self.assertIn("write-checksum.sh", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)

    def test_benchmarked_release_bootstraps_and_then_uses_conventional_commits(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        for required in (
            "v1.0.0", "ietf-tools/semver-action@v1", "--target benchmark",
            "sd-jwt-zk-benchmarks.csv", "sd-jwt-zk-benchmarks.json",
            "sd-jwt-zk-benchmarks.md", "benchmark_notes", "SHA256SUMS",
            "gh release create",
        ):
            self.assertIn(required, workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn('SD_JWT_ZK_VERSION "1.0.0"',
                      (ROOT / "CMakeLists.txt").read_text())


if __name__ == "__main__":
    unittest.main()
