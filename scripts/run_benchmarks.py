#!/usr/bin/env python3
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

"""Run shipped real-proof operations and publish reusable benchmark reports."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
from typing import Iterable


SCHEMA = "sd-jwt-zk/benchmarks/v1"
REPORT_STEM = "sd-jwt-zk-benchmarks"
CSV_FIELDS = (
    "iteration",
    "family",
    "operation",
    "duration_ms",
    "proof_bytes",
    "presentation_proof_bytes",
    "credential_proof_bytes",
    "kb_proof_bytes",
    "status_proof_bytes",
    "public_inputs",
    "total_inputs",
    "quad_terms",
    "peak_rss_kib",
)
PAIR = re.compile(r"(?<!\S)([a-z0-9][a-z0-9-]*)=([0-9]+)(?=\s|$)")


def arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flat-bearer", type=Path, required=True)
    parser.add_argument("--holder-bound", type=Path, required=True)
    parser.add_argument("--status-membership", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--version", default="dev")
    parser.add_argument("--source-dir", type=Path, default=Path.cwd())
    result = parser.parse_args(argv)
    if result.iterations < 1:
        parser.error("--iterations must be at least 1")
    if result.timeout < 1:
        parser.error("--timeout must be at least 1 second")
    return result


def run(executable: Path, cwd: Path, timeout: int) -> str:
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError(f"benchmark executable is unavailable: {executable}")
    completed = subprocess.run(
        [str(executable.resolve())],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(
            f"{executable.name} failed with exit {completed.returncode}: {detail}"
        )
    return completed.stdout


def values(text: str, required: Iterable[str], source: str) -> dict[str, int]:
    parsed = {name: int(value) for name, value in PAIR.findall(text)}
    missing = sorted(set(required) - parsed.keys())
    if missing:
        raise RuntimeError(f"{source} omitted metrics: {', '.join(missing)}")
    return parsed


def row(
    iteration: int,
    family: str,
    operation: str,
    duration_ms: int,
    **metrics: int,
) -> dict[str, int | str]:
    result: dict[str, int | str] = {field: 0 for field in CSV_FIELDS}
    result.update(
        iteration=iteration,
        family=family,
        operation=operation,
        duration_ms=duration_ms,
    )
    result.update(metrics)
    return result


def bearer_rows(
    executable: Path, iteration: int, cwd: Path, timeout: int
) -> list[dict[str, int | str]]:
    run(executable, cwd, timeout)
    result_path = cwd / "sd-jwt-zk-flat-bearer-proof-result.txt"
    if not result_path.is_file():
        raise RuntimeError(f"{executable.name} did not write {result_path.name}")
    metric = values(
        result_path.read_text(encoding="utf-8"),
        ("prove-ms", "rerandomize-ms", "verify-ms", "proof-bytes",
         "presentation-proof-bytes", "status-proof-bytes", "public-inputs",
         "total-inputs"),
        executable.name,
    )
    common = {
        "proof_bytes": metric["proof-bytes"],
        "presentation_proof_bytes": metric["presentation-proof-bytes"],
        "status_proof_bytes": metric["status-proof-bytes"],
        "public_inputs": metric["public-inputs"],
        "total_inputs": metric["total-inputs"],
    }
    return [
        row(iteration, "bearer-exact-key-with-status", "prove",
            metric["prove-ms"], **common),
        row(iteration, "bearer-exact-key-with-status", "rerandomize",
            metric["rerandomize-ms"], **common),
        row(iteration, "bearer-exact-key-with-status", "verify",
            metric["verify-ms"], **common),
    ]


def holder_rows(
    executable: Path, iteration: int, cwd: Path, timeout: int
) -> list[dict[str, int | str]]:
    metric = values(
        run(executable, cwd, timeout),
        ("credential-proof-bytes", "kb-proof-bytes", "status-proof-bytes",
         "aggregate-proof-bytes", "prove-ms", "verify-ms", "peak-rss-kb"),
        executable.name,
    )
    common = {
        "proof_bytes": metric["aggregate-proof-bytes"],
        "credential_proof_bytes": metric["credential-proof-bytes"],
        "kb_proof_bytes": metric["kb-proof-bytes"],
        "status_proof_bytes": metric["status-proof-bytes"],
        "peak_rss_kib": metric["peak-rss-kb"],
    }
    return [
        row(iteration, "holder-bound-exact-key", "prove",
            metric["prove-ms"], **common),
        row(iteration, "holder-bound-exact-key", "verify",
            metric["verify-ms"], **common),
    ]


def status_rows(
    executable: Path, iteration: int, cwd: Path, timeout: int
) -> list[dict[str, int | str]]:
    metric = values(
        run(executable, cwd, timeout),
        ("public-inputs", "prove-ms", "rerandomize-ms", "verify-ms",
         "proof-bytes", "bridge-commitment-bytes"),
        executable.name,
    )
    common = {
        "proof_bytes": metric["proof-bytes"],
        "status_proof_bytes": metric["proof-bytes"],
        "public_inputs": metric["public-inputs"],
    }
    return [
        row(iteration, "local-valid-status", "prove", metric["prove-ms"],
            **common),
        row(iteration, "local-valid-status", "rerandomize",
            metric["rerandomize-ms"], **common),
        row(iteration, "local-valid-status", "verify", metric["verify-ms"],
            **common),
    ]


def command_output(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        command, cwd=cwd, text=True, capture_output=True, check=False
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def cpu_name() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def metadata(args: argparse.Namespace) -> dict[str, str | int]:
    source = args.source_dir.resolve()
    compiler = os.environ.get("CXX", "c++")
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "version": args.version,
        "commit": command_output(["git", "rev-parse", "HEAD"], source),
        "iterations": args.iterations,
        "system": platform.platform(),
        "machine": platform.machine(),
        "cpu": cpu_name(),
        "compiler": command_output([compiler, "--version"], source).splitlines()[0],
        "cmake": command_output(["cmake", "--version"], source).splitlines()[0],
        "timing_policy": (
            "Descriptive wall-clock observations; not performance thresholds "
            "or release promises."
        ),
    }


def write_csv(path: Path, rows: list[dict[str, int | str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(
    path: Path, meta: dict[str, str | int], rows: list[dict[str, int | str]]
) -> None:
    grouped: dict[tuple[str, str], list[dict[str, int | str]]] = {}
    for item in rows:
        key = (str(item["family"]), str(item["operation"]))
        grouped.setdefault(key, []).append(item)
    lines = [
        f"# SD-JWT ZK {meta['version']} benchmarks",
        "",
        str(meta["timing_policy"]),
        "",
        f"- Commit: `{meta['commit']}`",
        f"- Generated: `{meta['generated_at']}`",
        f"- System: `{meta['system']}` (`{meta['machine']}`)",
        f"- CPU: `{meta['cpu']}`",
        f"- Compiler: `{meta['compiler']}`",
        f"- Iterations: {meta['iterations']}",
        "",
        "## Operation timings",
        "",
        "| Family | Operation | Median ms | Min ms | Max ms | Median proof bytes | Min bytes | Max bytes |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for family, operation in sorted(grouped):
        samples = grouped[(family, operation)]
        durations = [int(item["duration_ms"]) for item in samples]
        proof_sizes = [int(item["proof_bytes"]) for item in samples]
        lines.append(
            f"| {family} | {operation} | {statistics.median(durations):g} | "
            f"{min(durations)} | {max(durations)} | "
            f"{statistics.median(proof_sizes):g} | {min(proof_sizes)} | "
            f"{max(proof_sizes)} |"
        )
    lines.extend([
        "",
        "## Proof components",
        "",
        "Values are median bytes with the observed range in parentheses.",
        "",
        "| Family | Aggregate | Presentation | Credential | KB | Status |",
        "|---|---:|---:|---:|---:|---:|",
    ])

    def size_summary(samples: list[int]) -> str:
        median = statistics.median(samples)
        if min(samples) == max(samples):
            return f"{median:g}"
        return f"{median:g} ({min(samples)}–{max(samples)})"

    families = sorted({str(item["family"]) for item in rows})
    for family in families:
        family_rows = [item for item in rows if item["family"] == family]
        lines.append(
            f"| {family} | "
            f"{size_summary([int(item['proof_bytes']) for item in family_rows])} | "
            f"{size_summary([int(item['presentation_proof_bytes']) for item in family_rows])} | "
            f"{size_summary([int(item['credential_proof_bytes']) for item in family_rows])} | "
            f"{size_summary([int(item['kb_proof_bytes']) for item in family_rows])} | "
            f"{size_summary([int(item['status_proof_bytes']) for item in family_rows])} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv)
    rows: list[dict[str, int | str]] = []
    try:
        with tempfile.TemporaryDirectory(prefix="sd-jwt-zk-benchmark-") as temp:
            root = Path(temp)
            for iteration in range(1, args.iterations + 1):
                iteration_dir = root / str(iteration)
                iteration_dir.mkdir()
                rows.extend(bearer_rows(
                    args.flat_bearer, iteration, iteration_dir, args.timeout))
                rows.extend(holder_rows(
                    args.holder_bound, iteration, iteration_dir, args.timeout))
                rows.extend(status_rows(
                    args.status_membership, iteration, iteration_dir,
                    args.timeout))
        args.output_dir.mkdir(parents=True, exist_ok=True)
        meta = metadata(args)
        csv_path = args.output_dir / f"{REPORT_STEM}.csv"
        json_path = args.output_dir / f"{REPORT_STEM}.json"
        markdown_path = args.output_dir / f"{REPORT_STEM}.md"
        write_csv(csv_path, rows)
        json_path.write_text(
            json.dumps({"metadata": meta, "measurements": rows}, indent=2) + "\n",
            encoding="utf-8",
        )
        write_markdown(markdown_path, meta, rows)
        for output in (csv_path, json_path, markdown_path):
            print(output)
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
