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

import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/run_benchmarks.py"


def executable(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body),
                    encoding="utf-8")
    path.chmod(0o755)
    return path


class BenchmarkRunnerTests(unittest.TestCase):
    def fixtures(self, directory: Path) -> tuple[Path, Path, Path]:
        flat = executable(directory / "flat", """
            from pathlib import Path
            iteration = int(Path.cwd().name)
            Path("sd-jwt-zk-flat-bearer-proof-result.txt").write_text(
                "prove-ms=10\\nrerandomize-ms=11\\nverify-ms=3\\n"
                f"proof-bytes={1000 + iteration}\\n"
                f"presentation-proof-bytes={700 + iteration}\\n"
                "status-proof-bytes=264\\npublic-inputs=20\\ntotal-inputs=200\\n")
        """)
        holder = executable(directory / "holder", """
            print("credential-proof-bytes=700 kb-proof-bytes=300 "
                  "status-proof-bytes=250 aggregate-proof-bytes=1250 "
                  "prove-ms=20 verify-ms=6 peak-rss-kb=1234")
        """)
        status = executable(directory / "status", """
            print("public-inputs=768 prove-ms=7 rerandomize-ms=8 verify-ms=2 "
                  "proof-bytes=250 bridge-commitment-bytes=32")
        """)
        return flat, holder, status

    def test_writes_stable_csv_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            flat, holder, status = self.fixtures(directory)
            output = directory / "results"
            completed = subprocess.run([
                sys.executable, str(RUNNER),
                "--flat-bearer", str(flat),
                "--holder-bound", str(holder),
                "--status-membership", str(status),
                "--output-dir", str(output),
                "--source-dir", str(ROOT),
                "--version", "1.2.3",
                "--iterations", "2",
            ], text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)

            csv_path = output / "sd-jwt-zk-benchmarks.csv"
            json_path = output / "sd-jwt-zk-benchmarks.json"
            markdown_path = output / "sd-jwt-zk-benchmarks.md"
            with csv_path.open(encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 16)
            self.assertEqual({row["family"] for row in rows}, {
                "bearer-exact-key-with-status",
                "holder-bound-exact-key",
                "local-valid-status",
            })
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["metadata"]["schema"],
                             "sd-jwt-zk/benchmarks/v1")
            self.assertEqual(report["metadata"]["version"], "1.2.3")
            self.assertEqual(len(report["measurements"]), 16)
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("Operation timings", markdown)
            self.assertIn("holder-bound-exact-key", markdown)
            self.assertIn("1001–1002", markdown)

    def test_rejects_incomplete_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            flat, holder, status = self.fixtures(directory)
            holder.write_text("#!/usr/bin/env python3\nprint('prove-ms=20')\n",
                              encoding="utf-8")
            completed = subprocess.run([
                sys.executable, str(RUNNER),
                "--flat-bearer", str(flat),
                "--holder-bound", str(holder),
                "--status-membership", str(status),
                "--output-dir", str(directory / "results"),
                "--source-dir", str(ROOT),
            ], text=True, capture_output=True, check=False)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("omitted metrics", completed.stderr)


if __name__ == "__main__":
    unittest.main()
