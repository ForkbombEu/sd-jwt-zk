# SD-JWT ZK

This repository contains the bounded native and envelope foundation for the SD-JWT ZK relation described in `spec/sd-jwt-zk-v1.md`. It does **not** yet create or verify a zero-knowledge proof; native parsing is deliberately not an acceptance path.

## Build

An installed Longfellow package is required. Configure against its package prefix (normally `/usr/local`):

```sh
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/usr/local
cmake --build build
ctest --test-dir build --output-on-failure
```

`SD_JWT_ZK_LONGFELLOW_TARGET` selects the installed target (default `LongfellowZK::static`). `SD_JWT_ZK_ENABLE_SANITIZERS=ON` enables ASan/UBSan. `SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS=ON` is reserved for future compiled-circuit tests and is off by default.

The installed CMake package is `SDJWTZK`; downstream users call `find_package(SDJWTZK CONFIG REQUIRED)` and link `SDJWTZK::sd-jwt-zk`.
