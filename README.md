# SD-JWT ZK

This repository contains a bounded SD-JWT ZK library for two presentation
families: exact-key bearer and exact-key holder-bound. Both use the fixed
two-slot scalar disclosure relation; optional status proves `VALID` against a
verifier-selected local snapshot. Native parsing is deliberately not an
acceptance path.

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

With the installed Longfellow prefix used by this project, ASan/UBSan passes the normal native/API, KB-JWT, fixture-bridge, and adapter-contract tests. The opt-in production-scale holder factory currently triggers an AddressSanitizer stack-buffer-overflow inside Longfellow's installed `Logic::eq_reduce` path while compiling the credential circuit; this dependency limitation is retained as sanitizer evidence and does not disable the normal sanitizer suite. The bounded non-sanitized holder-pair and public adapter proof round trips remain required and are run sequentially with a 180-second, 4-GiB-RSS budget.

The installed CMake package is `SDJWTZK`; downstream users call `find_package(SDJWTZK CONFIG REQUIRED)` and link `SDJWTZK::sd-jwt-zk`.

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

The issuer key file is exactly 128 hexadecimal characters (`x || y`). Do not
put private credentials, holder keys, or status witnesses in shell arguments,
environment variables, logs, or challenge files.
