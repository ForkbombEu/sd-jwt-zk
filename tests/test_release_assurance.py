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
    def test_gpl_license_metadata_notices_and_source_headers(self):
        copyright_line = "Copyright (C) 2026 by The Forkbomb Company"
        required_notice = """## Free without warranty
This is free and open source software provided without warranty under the terms of the GNU GPL v3 license. Professional support, maintenance, integration services, and contractual warranty options are available separately. Please [contact us](mailto:info@forkbomb.eu) for further information."""

        license_text = (ROOT / "LICENSE").read_text()
        self.assertIn("GNU GENERAL PUBLIC LICENSE", license_text)
        self.assertIn("Version 3, 29 June 2007", license_text)
        self.assertIn("How to Apply These Terms to Your New Programs", license_text)

        package = json.loads((ROOT / "package.json").read_text())
        lock_package = json.loads((ROOT / "package-lock.json").read_text())
        self.assertEqual(package["license"], "GPL-3.0-or-later")
        self.assertEqual(lock_package["packages"][""]["license"],
                         "GPL-3.0-or-later")
        cmake = (ROOT / "CMakeLists.txt").read_text()
        self.assertIn('set(SD_JWT_ZK_LICENSE "GPL-3.0-or-later")', cmake)
        self.assertIn('set(CPACK_RESOURCE_FILE_LICENSE', cmake)
        self.assertIn('set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-or-later")',
                      cmake)
        self.assertIn("install(FILES README.md LICENSE", cmake)
        package_config = (ROOT / "cmake/SDJWTZKConfig.cmake.in").read_text()
        self.assertIn('set(SDJWTZK_LICENSE "GPL-3.0-or-later")',
                      package_config)
        for documentation in (ROOT / "README.md", ROOT / "docs/index.md"):
            self.assertIn(required_notice, documentation.read_text())

        source_suffixes = {
            ".h", ".hpp", ".cc", ".cpp", ".py", ".sh", ".js", ".mjs",
            ".ts", ".mts", ".cmake",
        }
        excluded_parts = {".git", "node_modules", "vendor"}
        sources = []
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT)
            if (not path.is_file() or
                    relative.parts[:3] in {
                        ("docs", ".vitepress", "cache"),
                        ("docs", ".vitepress", "dist"),
                    } or any(
                    part in excluded_parts or part.startswith("build")
                    for part in relative.parts)):
                continue
            if (path.suffix in source_suffixes or
                    path.name in {"CMakeLists.txt", "SDJWTZKConfig.cmake.in"}):
                sources.append(path)
        self.assertEqual(len(sources), 111)
        for source in sources:
            opening = "\n".join(source.read_text().splitlines()[:4])
            self.assertIn(copyright_line, opening, source)

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
