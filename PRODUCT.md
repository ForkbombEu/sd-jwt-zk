# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

The documentation serves implementers integrating the bounded V1 C++ library
and CLI, and security reviewers evaluating its proof boundary, privacy limits,
release evidence, and unsupported cases. The homepage gives both audiences an
equal starting point.

## Product Purpose

SD-JWT ZK provides bounded presentation proofs for exact-key bearer and
exact-key holder-bound credentials. It supports exactly two scalar disclosures
and an optional private `VALID` membership proof against a relying-party-selected
revocation-list snapshot. Success means that an integrator can select and verify
the supported relation without mistaking cryptographic validity for application
authorization, and that a reviewer can identify every public, private, and
external responsibility.

## Positioning

The project deliberately exposes a small, fixed, fail-closed relation instead
of a general anonymous-credential system: exact issuer keys, fixed disclosure
shape, typed request builders, explicit transcript context, and optional
revocation checks are part of the product boundary.

## Operating Context

Implementers build against an installed Longfellow package with CMake, construct
typed V1 requests, and finish verification through `VerifyPresentation` with a
durable replay store. Relying parties create canonical challenges from public policy
and protected key/nonce files. Wallets keep credentials, holder keys,
revocation-list indices, and Merkle paths out of command-line arguments and environment
variables.

## Capabilities and Constraints

- Supported families are exact-key bearer and exact-key holder-bound.
- The disclosure relation accepts one root-object scalar and one root-array
  scalar disclosure.
- A revocation check, when required, proves private `VALID` membership under a
  relying-party-selected four-leaf snapshot.
- `VerifyRelation` establishes only the cryptographic relation;
  `VerifyPresentation` adds policy and replay handling.
- Issuer hiding, registries, recursive disclosure shapes, arbitrary disclosure
  counts, Swiss/swiyu interoperability, and the retained 32-slot experiment are
  unsupported.
- The code has not received an independent cryptographic audit. Benchmark
  results are environment-specific observations, not performance guarantees.

## Brand Commitments

The product name is SD-JWT ZK. The site inherits the Forkbomb Vite Theme design
system exactly: blue and navy technical fields, mint signals, square geometry,
Barlow Semi Condensed display type, Public Sans reading type, restrained
forkbomb-expression watermarks, and native VitePress behavior. Technical copy
must remain precise, candid, and free of unsupported security or performance
claims.

## Evidence on Hand

- Product and integration boundary: `README.md` and
  `include/sd_jwt_zk/presentation.h`.
- Normative protocol and revocation profiles: `spec/sd-jwt-zk-v1.md` and
  `spec/local-status-v1.md`.
- Protocol sequences, compatibility decisions, and locked references under
  `spec/`.
- Bounded vectors: `fixtures/compact-vectors.json`.
- Release-assurance matrices and automated test gates under `spec/`, `tests/`,
  `scripts/`, and `ci/`.
- Reproducible benchmark tooling and release reports. No testimonials,
  independent audit report, or universal performance claim exists and none may
  be fabricated.

## Product Principles

- Make the supported relation understandable before asking readers to integrate.
- Keep cryptographic proof, application policy, and operational trust visibly
  separate.
- Put limitations and linkability surfaces beside capabilities, not in fine
  print.
- Route implementers quickly to buildable examples and reviewers to inspectable
  evidence.
- Prefer narrow factual claims backed by repository artifacts.

## Accessibility & Inclusion

Preserve VitePress navigation, search, keyboard behavior, responsive reading,
color-mode support, reduced-motion preferences, forced-colors compatibility,
and visible focus states.
