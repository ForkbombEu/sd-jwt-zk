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


if __name__ == "__main__":
    unittest.main()
