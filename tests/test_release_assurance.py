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


class ReleaseAssuranceTests(unittest.TestCase):
    def test_binding_matrix_is_complete_and_links_current_negatives(self):
        matrix = json.loads((ROOT / "spec/reduced-binding-matrix.json").read_text())
        self.assertEqual(matrix["schema"], "sd-jwt-zk/reduced-binding-matrix/v1")
        required = {
            "issuer_compact_jws", "root_object_scalar_disclosure",
            "root_array_scalar_disclosure", "disclosure_count",
            "bounded_claim_policy_and_result", "holder_cnf_and_kb_jwt",
            "audience_and_purpose", "nonce_time_and_replay", "exact_issuer_key",
            "local_status_credential_binding", "trusted_snapshot_metadata_and_root",
            "envelope_component_order", "circuit_identity_and_proof_parameters",
        }
        bindings = matrix["bindings"]
        self.assertEqual({entry["field"] for entry in bindings}, required)
        for entry in bindings:
            for column in ("parsing", "constraint", "presentation_binding",
                           "verifier_policy"):
                self.assertTrue(entry[column], f"{entry['field']} lacks {column}")
            negative = entry["negative"]
            source = ROOT / negative["source"]
            self.assertTrue(source.is_file(), source)
            self.assertIn(negative["contains"], source.read_text())

    def test_matrix_marks_every_deferred_family_excluded(self):
        matrix = json.loads((ROOT / "spec/reduced-binding-matrix.json").read_text())
        excluded = " ".join(matrix["excluded"]).lower()
        for term in ("registry", "aggregate", "recursive", "swiss", "swiyu",
                     "32-slot", "other capacity"):
            self.assertIn(term, excluded)

    def test_audience_purpose_binding_remains_exact(self):
        implementation = (ROOT / "src/presentation.cc").read_text()
        self.assertIn('policy.audience + "\\x1f" + policy.purpose', implementation)
        self.assertIn("policy.audience.find('\\x1f')", implementation)
        self.assertIn("policy.purpose.find('\\x1f')", implementation)

    def test_resource_record_covers_only_shipped_entry_points_and_limits(self):
        record = json.loads((ROOT / "spec/reduced-release-resources.json").read_text())
        self.assertEqual(record["schema"], "sd-jwt-zk/reduced-release-resources/v1")
        self.assertEqual({item["name"] for item in record["entry_points"]}, {
            "bearer-exact-key", "holder-bound-exact-key", "local-valid-status"
        })
        limits = record["input_limits"]
        self.assertEqual(limits["disclosure_count"], 2)
        self.assertEqual(limits["status_snapshot_entries"], 4)
        self.assertEqual(limits["status_path_siblings"], 2)
        self.assertIn("not release promises", record["timing_policy"])
        serialized = json.dumps(record).lower()
        for forbidden in ("wall_seconds", "peak_rss", "milliseconds", "throughput"):
            self.assertNotIn(forbidden, serialized)

    def test_install_manifest_excludes_experimental_headers_and_specs(self):
        cmake = (ROOT / "CMakeLists.txt").read_text()
        public_block = cmake.split("set(SD_JWT_ZK_PUBLIC_HEADERS", 1)[1].split(")", 1)[0]
        for forbidden in ("full_disclosure", "swiss", "bounded_json",
                          "disclosure_processing", "active_presentation"):
            self.assertNotIn(forbidden, public_block)
        self.assertNotIn("install(DIRECTORY include/", cmake)
        installed_spec = cmake.split("install(FILES spec/compatibility.md", 1)[1]
        installed_spec = installed_spec.split(")", 1)[0]
        for forbidden in ("full-family", "swiss-bounded", "two-slot-support-evidence"):
            self.assertNotIn(forbidden, installed_spec)


if __name__ == "__main__":
    unittest.main()
