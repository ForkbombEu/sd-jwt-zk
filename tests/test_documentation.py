import json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class DocumentationTests(unittest.TestCase):
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
