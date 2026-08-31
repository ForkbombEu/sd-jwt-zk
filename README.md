# SD-JWT ZK

This repository contains a bounded SD-JWT ZK library for two presentation
families: exact-key bearer and exact-key holder-bound. Both use the fixed
two-slot scalar disclosure relation; optional status proves `VALID` against a
verifier-selected local snapshot. Native parsing is deliberately not an
acceptance path.

## Free without warranty
This is free and open source software provided without warranty under the terms of the GNU GPL v3 license. Professional support, maintenance, integration services, and contractual warranty options are available separately. Please [contact us](mailto:info@forkbomb.eu) for further information.

The public application boundary is [`presentation.h`](include/sd_jwt_zk/presentation.h).
Build a typed bearer or holder request with an explicit exact issuer key,
audience, purpose, nonce, time window, and either status-forbidden or
status-required local snapshot policy. `VerifyRelation` checks only the
cryptographic relation; applications should use `VerifyPresentation`, which
also consumes the nonce through their replay store and returns a closed result
enum. Purpose is canonically bound into the request transcript; it is not an
advisory label.

## Supported boundary

Supported: compact bearer and holder-bound presentations, local exact issuer
keys, one root-object plus one root-array scalar disclosure, and an optional
private `VALID` local-status membership component. The CLI creates canonical
challenges from protected nonce/key files and inspects only public envelope
fields. It never accepts credentials, holder keys, private status indices, or
Merkle paths as command-line arguments.

Unsupported: issuer-hiding or aggregate registries, Swiss/swiyu
interoperability, recursive disclosure shapes, additional disclosure slots,
the retained 32-slot experiment, and performance or conformance guarantees.
Bearer evidence can be replayed by a thief until the verifier consumes its
fresh nonce. Holder binding proves possession for the bounded KB-JWT relation,
but disclosed values, circuit bucket, and public status root/epoch can still
link presentations. This project has not had an independent cryptographic
audit.

`spec/local-status-v1.md` defines local snapshot authority, rotation,
rollback, and availability policy. The root and epoch identify a status cohort;
they do not hide an issuer or supply aggregate anonymity.

## Build

An installed Longfellow package is required. Configure against its package prefix (normally `/usr/local`):

```sh
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/path/to/installed/longfellow -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
cmake --build build
ctest --test-dir build --output-on-failure
```

`SD_JWT_ZK_LONGFELLOW_TARGET` selects the installed target (default `LongfellowZK::static`). `SD_JWT_ZK_ENABLE_SANITIZERS=ON` enables ASan/UBSan. `SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS=ON` enables the bounded real-proof and factory experiments and is off by default; the monolithic holder experiment remains disabled even in that lane.

With the pinned installed Longfellow package, ASan/UBSan covers the default
native/API suite and the deterministic reduced parser harness. Supported
non-sanitized proof smokes are separate bounded release gates. Resource
observations are environment-specific diagnostics, not timing or memory
promises; see `docs/release-assurance.md`.

The installed CMake package is `SDJWTZK`; downstream users call `find_package(SDJWTZK CONFIG REQUIRED)` and link `SDJWTZK::sd-jwt-zk`.

## Benchmarks and releases

Configure with `SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS=ON`, then run:

```sh
cmake --build build --target benchmark --parallel 1
```

The target executes real prove, verify, and supported randomized-repeat
operations for the shipped bearer, holder-bound, and local-status proof
families. It writes
raw CSV, structured JSON, and a Markdown summary under `build/benchmarks`,
including proof-component sizes and machine/toolchain metadata. Timings are
environment-specific observations rather than promises. See
[`docs/performance.md`](docs/performance.md) for the schema and direct runner
usage.

GitHub releases attach those reports, a Linux x86-64 installed build, the source
archive, and checksums. A tagless repository starts at `v1.0.0`; later versions
are calculated from Conventional Commits with `ietf-tools/semver-action`.

## CLI

Public challenge material is explicit, while nonce material is read from an
owner-controlled file. Output creation fails if the destination already exists
and uses mode `0600`.

```sh
sd-jwt-zk challenge create --mode bearer --audience https://verifier.example \
  --purpose age-check --nonce-file ./nonce --issuer-key-file ./issuer-p256.hex \
  --time-min 1700000000 --time-max 1700000300 --out ./challenge.bin
sd-jwt-zk inspect --input ./presentation.bin
```

`status-snapshot build` takes exactly four fixed 33-byte entry records from a
protected file: a 32-byte credential binding followed by `01` (`VALID`) or
`02` (revoked). It emits canonical local status-policy bytes; private indices
and Merkle paths are never inspected or printed by the CLI.

For a status-required challenge, `prove` also requires `--status-witness-file`.
Its only accepted format is `SPW1`, one private index byte, and exactly two
32-byte compressed-path siblings. The credential binding is derived from the
credential witness and is never accepted as a CLI argument or witness-file
field. `verify` accepts the status component only when the verifier-selected
challenge carries the matching local policy.

`prove` and `verify` require an explicit `--mode bearer|holder`. The nonce
store is an owner-only directory containing at most 4096 active entries.
Verification removes entries whose encoded expiry is earlier than `--now` and
fails closed if malformed entries remain or the active capacity is exhausted.

The issuer key file is exactly 128 hexadecimal characters (`x || y`). Do not
put private credentials, holder keys, or status witnesses in shell arguments,
environment variables, logs, or challenge files.
