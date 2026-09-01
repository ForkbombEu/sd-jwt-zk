---
title: Proof benchmarks
description: Reproduce prove and verify timings, proof sizes, and release artifacts.
---

# Proof benchmarks

The benchmark target runs the real production APIs for the three shipped proof
families: exact-key bearer with revocation, exact-key holder-bound, and a private
proof of `VALID` revocation-list membership. It measures circuit construction where exposed,
first proof generation, randomized repeat generation where exposed, and
successful verification. Proof-component sizes and available circuit dimensions
are recorded alongside the timings.

Wall-clock values are descriptive observations from a particular machine. They
are not thresholds or release promises. Randomized proof encodings can vary in
length, so raw samples are retained and the Markdown report shows byte-size
ranges rather than treating one run as a fixed size.

## Reproduce locally

Configure the opt-in real-proof lane against an installed Longfellow package:

```sh
cmake -S . -B build-benchmark -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/path/to/installed/longfellow \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DSD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS=ON \
  -DSD_JWT_ZK_BENCHMARK_ITERATIONS=2
cmake --build build-benchmark --target benchmark --parallel 1
```

The target writes:

- `build-benchmark/benchmarks/sd-jwt-zk-benchmarks.csv` — one row per
  family, operation, and iteration;
- `build-benchmark/benchmarks/sd-jwt-zk-benchmarks.json` — the same raw
measurements plus commit, version, CPU, OS, compiler, and CMake metadata;
- `build-benchmark/benchmarks/sd-jwt-zk-benchmarks.md` — median/min/max timing
  and proof-component tables for people.

`SD_JWT_ZK_BENCHMARK_OUTPUT_DIR` changes the destination. The runner can also
be invoked directly with `python3 scripts/run_benchmarks.py --help` when the
three real-proof executables have already been built.

`proof_bytes` is the aggregate proof payload carried by the corresponding API
envelope. Component columns split presentation, credential, KB, and revocation
proof bytes where those components are independently framed.

## Published results

The `benchmarked-release` GitHub workflow attaches all three formats to every
semantic release, along with Linux x86-64 and source archives and
`SHA256SUMS`. The Markdown report is also copied into the workflow summary so
timings and sizes are visible without downloading an asset.

The first tag in a tagless repository is `v1.0.0`. Later versions are computed
from Conventional Commits by `ietf-tools/semver-action`: breaking changes bump
the major version, `feat` bumps minor, and `fix`, `perf`, `refactor`, and test
commits bump patch. Commits without a configured release prefix do not replace
an existing release.
