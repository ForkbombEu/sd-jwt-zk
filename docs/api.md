---
title: V1 API and identities
description: Use the typed presentation builders and closed verification result boundary.
---

# V1 API and identities

The product-facing header is `sd_jwt_zk/presentation.h`. It exposes only the
accepted bounded exact-key families; it is not a generic circuit factory.

## Presentation policy

`PresentationPolicyV1` contains the fields the application must choose:

| Field | Meaning |
| --- | --- |
| `audience` | Expected relying-party audience |
| `purpose` | Application purpose, separately transcript-bound |
| `nonce` | Fresh replay challenge |
| `time_min`, `time_max` | Accepted request window |
| `issuer_key` | Exact accepted P-256 issuer key |
| `status` | `forbidden` or `required` |
| `trusted_snapshot` | Local snapshot policy when status is required |

The typed builders are `BuildBearerPresentationRequestV1` and
`BuildHolderPresentationRequestV1`. Arbitrary proof identities are not
constructible through this API.

## Verification boundary

`VerifyRelation` reports cryptographic validity only and never records a nonce.
`VerifyPresentation` applies local policy, consumes replay state through the
caller-supplied store, and returns exactly one closed result:

| Result | Meaning |
| --- | --- |
| `accepted` | Relation and local presentation policy passed |
| `malformed` | Canonical decoding failed |
| `unsupported` | Version, shape, mode, or identity is outside V1 |
| `expired` | The accepted time policy failed |
| `replayed` | The nonce was already consumed |
| `policy_denied` | Typed local policy rejected the presentation |
| `status_required` | A required status component was absent or unacceptable |
| `verification_failed` | The cryptographic verification failed |

Callers should handle every enum value. There is no success-like default.

## Accepted identities

V1 accepts the exact-key bearer identity and the ordered holder credential/KB
identity pair. Either may be paired with the canonical private local-status
identity when the request requires it. Mode downgrade, component reordering,
and proof-identity substitution reject.

The bounded vector index shipped in every source archive is
`fixtures/compact-vectors.json`. Installed-consumer examples under
`tests/downstream` compile against the exported `SDJWTZK::sd-jwt-zk` target.
