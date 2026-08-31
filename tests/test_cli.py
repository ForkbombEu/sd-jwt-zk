import os
import subprocess
import tempfile
import unittest
from pathlib import Path


CLI = Path(os.environ["SD_JWT_ZK_CLI"])


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([CLI, *args], text=True, capture_output=True)

    def test_help_and_unsupported_commands_fail_closed(self):
        self.assertEqual(self.run_cli("--help").returncode, 0)
        self.assertEqual(self.run_cli("prove", "--credential", "secret").returncode, 2)
        self.assertEqual(self.run_cli("verify", "--registry", "root").returncode, 2)
        self.assertEqual(self.run_cli("status-snapshot", "build").returncode, 2)

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


if __name__ == "__main__":
    unittest.main()
