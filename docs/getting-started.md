# Getting started

Install Longfellow, then configure, build, test, and install this package:

```sh
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/opt/longfellow
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /opt/sd-jwt-zk
```

Downstream CMake projects use `find_package(SDJWTZK CONFIG REQUIRED)` and link
`SDJWTZK::sd-jwt-zk`. Use `BuildBearerPresentationRequestV1` or
`BuildHolderPresentationRequestV1`; normally finish with
`VerifyPresentation`, not the relation-only entry point.
