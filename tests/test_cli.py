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

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


CLI = Path(os.environ["SD_JWT_ZK_CLI"])
HOLDER_FIXTURE_GEN = os.environ.get("SD_JWT_ZK_HOLDER_FIXTURE_GEN")


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([CLI, *args], text=True, capture_output=True)

    def test_help_and_unsupported_commands_fail_closed(self):
        self.assertEqual(self.run_cli("--help").returncode, 0)
        self.assertEqual(self.run_cli("prove", "--credential", "secret").returncode, 2)
        self.assertEqual(self.run_cli("verify", "--registry", "root").returncode, 2)
        self.assertEqual(self.run_cli("status-snapshot", "build").returncode, 2)
        for command in ("prove", "verify"):
            rejected = self.run_cli(command, "--mode", "registry")
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("unsupported mode", rejected.stderr)

    def test_inspect_refuses_symlink_and_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link"
            link.symlink_to("/etc/passwd")
            self.assertEqual(self.run_cli("inspect", "--input", str(link)).returncode, 2)
            self.assertEqual(self.run_cli("inspect", "--input", str(Path(directory) / "missing")).returncode, 2)

    def test_local_snapshot_build_uses_bounded_binary_entries(self):
        # P-256 generator, encoded x||y as the documented public-key file.
        key = ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
               "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key_file, entries, output = root / "key", root / "entries", root / "status"
            key_file.write_text(key)
            entries.write_bytes(b"".join(bytes([index]) * 32 + b"\x01" for index in range(4)))
            key_file.chmod(0o600)
            entries.chmod(0o600)
            result = self.run_cli("status-snapshot", "build", "--issuer-key-file", str(key_file),
                                  "--entries-file", str(entries), "--epoch", "7",
                                  "--valid-from", "1", "--valid-until", "9", "--out", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertGreater(output.stat().st_size, 32)
            self.assertEqual(self.run_cli("status-snapshot", "build", "--issuer-key-file", str(key_file),
                                          "--entries-file", str(entries), "--epoch", "7",
                                          "--valid-from", "1", "--valid-until", "9", "--out", str(output)).returncode, 2)

    def test_status_and_proof_file_inputs_reject_malformed_or_trailing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            challenge, presentation, key, output = (root / name for name in
                                                      ("challenge", "presentation", "key", "out"))
            challenge.write_bytes(b"not-a-canonical-request\x00")
            presentation.write_bytes(b"not-a-presentation")
            key.write_text("00" * 64)
            witness = root / "status-witness"
            witness.write_bytes(b"SPW1\x00" + bytes(64) + b"trailing")
            for path in (challenge, presentation, key, witness):
                path.chmod(0o600)
            result = self.run_cli("prove", "--challenge", str(challenge),
                                  "--presentation-file", str(presentation),
                                  "--issuer-key-file", str(key),
                                  "--status-witness-file", str(witness), "--out", str(output))
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())

    def test_world_readable_protected_input_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "challenge"
            source.write_bytes(b"public")
            source.chmod(0o644)
            self.assertEqual(self.run_cli("inspect", "--input", str(source)).returncode, 2)

    def test_one_over_cli_file_limit_rejects_before_decode(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "oversized"
            with source.open("wb") as stream:
                stream.truncate(6 * 1024 * 1024 + 1)
            source.chmod(0o600)
            self.assertEqual(self.run_cli("inspect", "--input", str(source)).returncode, 2)

    @unittest.skipUnless(HOLDER_FIXTURE_GEN, "expensive holder CLI fixture unavailable")
    def test_holder_prove_and_verify_with_two_disclosures_and_kb_jwt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = subprocess.run([HOLDER_FIXTURE_GEN, root], text=True,
                                       capture_output=True)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            for name in ("issuer.hex", "presentation", "challenge"):
                (root / name).chmod(0o600)
            proof, nonce_store = root / "proof", root / "nonces"
            proved = self.run_cli(
                "prove", "--mode", "holder", "--challenge", str(root / "challenge"),
                "--presentation-file", str(root / "presentation"),
                "--issuer-key-file", str(root / "issuer.hex"), "--out", str(proof))
            self.assertEqual(proved.returncode, 0, proved.stderr)
            verified = self.run_cli(
                "verify", "--mode", "holder", "--challenge", str(root / "challenge"),
                "--proof-file", str(proof), "--nonce-store", str(nonce_store),
                "--now", "1777334400")
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(nonce_store.is_dir())
            self.assertEqual(len(list(nonce_store.iterdir())), 1)
            replayed = self.run_cli(
                "verify", "--mode", "holder", "--challenge", str(root / "challenge"),
                "--proof-file", str(proof), "--nonce-store", str(nonce_store),
                "--now", "1777334400")
            self.assertEqual(replayed.returncode, 2)

            second = root / "second"
            second.mkdir()
            generated = subprocess.run(
                [HOLDER_FIXTURE_GEN, second, "challenge-0002"], text=True,
                capture_output=True)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            for name in ("issuer.hex", "presentation", "challenge"):
                (second / name).chmod(0o600)
            second_proof = second / "proof"
            proved = self.run_cli(
                "prove", "--mode", "holder", "--challenge", str(second / "challenge"),
                "--presentation-file", str(second / "presentation"),
                "--issuer-key-file", str(second / "issuer.hex"), "--out", str(second_proof))
            self.assertEqual(proved.returncode, 0, proved.stderr)
            verified = self.run_cli(
                "verify", "--mode", "holder", "--challenge", str(second / "challenge"),
                "--proof-file", str(second_proof), "--nonce-store", str(nonce_store),
                "--now", "1777334400")
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(len(list(nonce_store.iterdir())), 2)


if __name__ == "__main__":
    unittest.main()
