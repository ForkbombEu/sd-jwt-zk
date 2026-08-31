---
title: Fixed two-slot relation
description: Understand the exact disclosure shape accepted by the V1 product API.
---

# Fixed two-slot relation

V1 accepts one disclosure shape: exactly two scalar openings, ordered as one
root-object disclosure and one root-array disclosure. The fixed shape keeps
parsing, circuit identity, and release evidence bounded.

## Constraints

| Input | V1 contract |
| --- | --- |
| Disclosure count | Exactly two active slots |
| Object slot | One scalar disclosure from the root object |
| Array slot | One scalar disclosure from a root array |
| Hash algorithm | SHA-256 |
| `_sd_alg` | Omitted, or exactly `sha-256`; omission still means SHA-256 |
| Issuer trust | Exact verifier-selected P-256 key |
| Serialization | Supported compact presentation shape |

Both ordered disclosures enter the active presentation hash. The bounded parser
checks separators and count before allocating the disclosure vector, then the
relation constrains digest membership, authenticated source ranges, placement,
and scalar type.

## Rejected shapes

Zero, one, or additional disclosures reject. Nested or recursive disclosure
shapes, arbitrary counts, decoy digests, and the retained 32-slot experiment
are not constructible through the V1 product API.

Supporting a new shape requires a new circuit identity and corresponding
release evidence; it is not a permissive parser option. See [unsupported
features](./unsupported.md) for the full product boundary.
