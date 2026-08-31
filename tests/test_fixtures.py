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

import importlib.util, json, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("oracle", ROOT / "scripts/generate_fixtures.py")
oracle = importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)
verify_spec = importlib.util.spec_from_file_location("verify_es256", ROOT / "scripts/verify_es256_fixtures.py")
verify_es256 = importlib.util.module_from_spec(verify_spec); verify_spec.loader.exec_module(verify_es256)

class FixtureTests(unittest.TestCase):
    def test_checked_in_vectors_match_independent_oracle(self):
        self.assertEqual(subprocess.run([sys.executable, "scripts/generate_fixtures.py", "--check"], cwd=ROOT).returncode, 0)
        doc = json.loads((ROOT / "fixtures/compact-vectors.json").read_text())
        self.assertTrue(oracle.validate(doc)); self.assertEqual(len(doc["positive"]), 2); self.assertEqual(len(doc["negative"]), 12)

    def test_openssl_verifies_issuer_and_kb_jwt_signatures(self):
        self.assertEqual(subprocess.run([sys.executable, "scripts/verify_es256_fixtures.py"], cwd=ROOT).returncode, 0)

    def test_openssl_rejects_signature_and_key_mutation(self):
        doc = json.loads((ROOT / "fixtures/compact-vectors.json").read_text()); vector = doc["positive"][0]
        mutated = vector["issuer_jws"][:-1] + ("A" if vector["issuer_jws"][-1] != "A" else "B")
        self.assertFalse(verify_es256.verify(mutated, verify_es256.PEM))
        self.assertFalse(verify_es256.verify(vector["issuer_jws"], verify_es256.OTHER_PEM))

    def test_mutation_corpus_includes_es256_signature_and_key_rejections(self):
        doc = json.loads((ROOT / "fixtures/compact-vectors.json").read_text())
        negatives = {x["field"]: x for x in doc["negative"]}
        self.assertFalse(verify_es256.verify(negatives["issuer-signature"]["presentation_ascii"].split("~")[0], verify_es256.PEM))
        self.assertFalse(verify_es256.verify(negatives["issuer-key"]["presentation_ascii"].split("~")[0], verify_es256.OTHER_PEM))

    def test_field_mutations_do_not_match_expected_commitments(self):
        doc = json.loads((ROOT / "fixtures/compact-vectors.json").read_text())
        for item in doc["negative"]:
            if item["field"] in ("issuer-signature", "issuer-key"):
                continue  # independently rejected by the OpenSSL tests below
            self.assertFalse(oracle.valid_presentation(item["presentation_ascii"], item.get("provided_sd_hash")), item["name"])

    def test_mermaid_structure(self):
        self.assertEqual(subprocess.run([sys.executable, "scripts/validate_mermaid.py"], cwd=ROOT).returncode, 0)
