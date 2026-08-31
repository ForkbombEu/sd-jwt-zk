---
title: Architecture
description: Understand the parser, relation, policy, and CLI boundaries in SD-JWT ZK V1.
---

# Architecture

The implementation separates untrusted bytes, bounded witness construction,
cryptographic verification, and application policy. This separation is part of
the security boundary: native parsing is never an acceptance path by itself.

## Layers

| Layer | Responsibility | Does not decide |
| --- | --- | --- |
| Native parser and codec | Decode canonical, bounded request and envelope shapes; construct witnesses | Whether a presentation is accepted |
| Relation layer | Constrain issuer signature, disclosures, claim policy, holder binding, and optional status | Issuer governance or authorization |
| `VerifyRelation` | Verify the selected cryptographic relation and identity | Replay consumption or application policy |
| `VerifyPresentation` | Add typed local policy and an application-owned replay store | The caller's final authorization decision |
| CLI | Adapt protected files to the public V1 APIs | Authority from proof-supplied trust material |

## Fail-closed dispatch

Typed builders construct only the supported exact-key bearer and holder-bound
identities. Version, binding mode, trust mode, capacity, digest, field, rate,
and query parameters are part of the accepted circuit identity. Malformed,
reordered, substituted, or unsupported envelopes reject before proof dispatch.

## Trust flows inward

The verifier supplies the exact issuer key and, when required, the trusted
local status snapshot. Neither value is accepted from the presentation. The
request transcript binds this policy with audience, purpose, nonce, time, claim
policy, and the selected circuit identity.

## Source map

- `include/sd_jwt_zk/presentation.h` — supported product-facing API.
- `src/presentation.cc` — typed request and presentation verification.
- `src/bounded_json.cc` and `src/restricted_json.cc` — bounded native parsing.
- `src/flat_bearer_proof.cc` and `src/holder_bound_proof.cc` — shipped proof families.
- `src/status_membership.cc` — optional local-status component.

Continue with the [protocol journey](./protocol.md) or inspect the
[release-assurance boundary](./release-assurance.md).
