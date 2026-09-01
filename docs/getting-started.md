---
title: Getting started
description: Build, install, and integrate the bounded SD-JWT ZK V1 library.
---

# Getting started

SD-JWT ZK is a C++ library and CLI built on Longfellow. Start by installing the
pinned Longfellow package, then build and test this repository against its CMake
package prefix.

## Build and install

```sh
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/opt/longfellow
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix /opt/sd-jwt-zk
```

`SD_JWT_ZK_LONGFELLOW_TARGET` selects the installed Longfellow target and
defaults to `LongfellowZK::static`. Set
`SD_JWT_ZK_ENABLE_SANITIZERS=ON` for the ASan/UBSan lane. Real-proof experiments
are opt-in through `SD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS=ON` and are not part
of the default build.

## Link a downstream project

The installed package is named `SDJWTZK`. A downstream CMake project needs only
the exported target:

```cmake
find_package(SDJWTZK CONFIG REQUIRED)
target_link_libraries(your_relying_party PRIVATE SDJWTZK::sd-jwt-zk)
```

Include `sd_jwt_zk/presentation.h` for the product-facing V1 API. The source
tree also contains experimental and historical relations; the public header is
the supported integration boundary.

## Choose a presentation family

- Use `BuildBearerPresentationRequestV1` for exact-key bearer presentations.
  Anyone holding bearer evidence may answer an unconsumed challenge.
- Use `BuildHolderPresentationRequestV1` when the bounded KB-JWT holder
  possession relation is required.

Both builders take a `PresentationPolicyV1`. The application supplies the
exact issuer key, audience, purpose, nonce, time window, and either a
`status-forbidden` or `status-required` revocation policy. Audience and purpose are separate
fields and are canonically bound into the request transcript.

## Finish at the application boundary

`VerifyRelation` answers only whether the cryptographic relation verifies. Most
applications should call `VerifyPresentation`, which also applies local policy,
uses the application-owned replay store, and returns a closed
`PresentationResultV1` value.

::: warning Before integrating
Read [what V1 proves](./what-it-proves.md), [privacy and linkability](./privacy.md),
and [unsupported features](./unsupported.md). The project has not received an
independent cryptographic audit.
:::

<WarrantyNotice />

Continue with the [wallet and relying-party workflows](./workflows.md) or inspect the
[V1 API and identities](./api.md).
