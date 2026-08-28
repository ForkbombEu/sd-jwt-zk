# SD-JWT ZK

This repository contains the bounded native and envelope foundation for the SD-JWT ZK relation described in `spec/sd-jwt-zk-v1.md`. The holder-bound V1 family has an opt-in real two-proof round trip; native parsing is deliberately not an acceptance path.

## Build

An installed Longfellow package is required. Configure against its package prefix (normally `/usr/local`):

```sh
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/usr/local
cmake --build build
ctest --test-dir build --output-on-failure
```

`SD_JWT_ZK_LONGFELLOW_TARGET` selects the installed target (default `LongfellowZK::static`). `SD_JWT_ZK_ENABLE_SANITIZERS=ON` enables ASan/UBSan. `SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS=ON` enables the bounded real-proof and factory experiments and is off by default; the monolithic holder experiment remains disabled even in that lane.

With the installed Longfellow prefix used by this project, ASan/UBSan passes the normal native/API, KB-JWT, fixture-bridge, and adapter-contract tests. The opt-in production-scale holder factory currently triggers an AddressSanitizer stack-buffer-overflow inside Longfellow's installed `Logic::eq_reduce` path while compiling the credential circuit; this dependency limitation is retained as sanitizer evidence and does not disable the normal sanitizer suite. The bounded non-sanitized holder-pair and public adapter proof round trips remain required and are run sequentially with a 180-second, 4-GiB-RSS budget.

The installed CMake package is `SDJWTZK`; downstream users call `find_package(SDJWTZK CONFIG REQUIRED)` and link `SDJWTZK::sd-jwt-zk`.
