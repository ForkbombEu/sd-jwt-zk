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

import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class DocumentationTests(unittest.TestCase):
    def test_product_site_has_required_pages_and_no_positive_deferred_claims(self):
        required = {
            "index.md", "what-it-proves.md", "architecture.md", "protocol.md",
            "two-slot-relation.md", "getting-started.md", "workflows.md",
            "status-operations.md", "security-claims.md", "privacy.md",
            "unsupported.md", "glossary.md", "specification.md", "api.md",
        }
        self.assertTrue(required.issubset({path.name for path in (ROOT / "docs").glob("*.md")}))
        site = "\n".join(path.read_text() for path in (ROOT / "docs").glob("*.md"))
        for claim in ("Swiss-compatible", "supports issuer hiding",
                      "supports recursive", "aggregate-registry support",
                      "performance guarantee"):
            self.assertNotIn(claim, site)
        for token in ("BuildBearerPresentationRequestV1",
                      "BuildHolderPresentationRequestV1", "VerifyRelation",
                      "VerifyPresentation", "PresentationResultV1",
                      "fixtures/compact-vectors.json"):
            self.assertIn(token, site)

    def test_product_boundary_is_explicit(self):
        text = (ROOT / "README.md").read_text()
        for token in ("VerifyRelation", "VerifyPresentation", "status-forbidden",
                      "status-required", "exact-key bearer", "holder-bound",
                      "independent cryptographic"):
            self.assertIn(token, text)
        for forbidden in ("Swiss-compatible", "aggregate registry",
                          "recursive disclosure support", "performance guarantee"):
            self.assertNotIn(forbidden, text)
    def test_required_decisions_and_labels_once(self):
        text = (ROOT / "spec/compatibility.md").read_text()
        for token in ("MVP", "later", "external", "unsupported", "omission defaults to SHA-256", "not Swiss-profile conformant"):
            self.assertIn(token, text)
        self.assertNotIn("omitting `_sd_alg` disables", text)

    def test_reference_lock(self):
        self.assertEqual(subprocess.run([sys.executable, "scripts/check_references.py"], cwd=ROOT).returncode, 0)

    def test_version_change_fails(self):
        source = ROOT / "spec/reference-lock.json"
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "reference-lock.json"
            data = json.loads(source.read_text()); data["sources"][0]["version"] = "RFC 9999"
            copy.write_text(json.dumps(data))
            original = source.read_text()
            try:
                source.write_text(copy.read_text())
                self.assertNotEqual(subprocess.run([sys.executable, "scripts/check_references.py"], cwd=ROOT).returncode, 0)
            finally: source.write_text(original)

    def test_privacy_contract_has_four_families_and_classification(self):
        text = (ROOT / "spec/sd-jwt-zk-v1.md").read_text()
        for identity in ("bearer/exact-key", "holder-bound/exact-key", "bearer/registry", "holder-bound/registry"):
            self.assertIn(identity, text)
        for label in ("public", "private", "external", "Capacity buckets leak", "Status is deliberately staged"):
            self.assertIn(label, text)

    def test_local_status_governance_does_not_overclaim(self):
        text = (ROOT / "spec/local-status-v1.md").read_text()
        for claim in ("strictly monotonic", "rolled back", "unavailable",
                      "status cohort", "private index", "fixed-depth"):
            self.assertIn(claim, text)
        for forbidden in ("Swiss-compatible", "issuer-hiding", "aggregate status"):
            self.assertNotIn(forbidden, text)
