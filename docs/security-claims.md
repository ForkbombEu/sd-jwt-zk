---
title: Security claim matrix
description: Map each V1 property to its proved statement, public surface, and external responsibility.
---

# Security claim matrix

The table separates the relation from the responsibilities that remain with the
integrating application or operator.

| Property | Established by V1 | Public or external boundary |
| --- | --- | --- |
| Issuer signature | ES256 verification under the exact configured P-256 key | Key selection, provenance, rotation, and governance are external |
| Disclosures | Exactly two bounded scalar openings match signed `_sd` digests and the claim relation | Disclosed values, their order, and circuit capacity bucket are public |
| Holder binding | Bounded compact KB-JWT signature, audience, nonce, `iat`, and `sd_hash` relation | Holder-key custody and wallet security are external |
| Audience and purpose | Exact bytes are bound into the request transcript | The application defines their semantics and authorization effect |
| Time | Request bounds and supported KB-JWT time relation are checked | Clock source and surrounding freshness policy are external |
| Local status | Private `VALID` membership under the selected root, bridged to the presentation | Root, issuer, epoch, interval, and cohort are public; authority and rotation are external |
| Replay | The transcript binds nonce and context; successful presentation verification consumes it | Durable, atomic replay storage is supplied by the application |
| Circuit identity | Versioned accepted proof parameters and component order are fixed | New shapes require a new supported identity and release evidence |

::: danger Audit status
This code has not received an independent cryptographic audit. The release gates
provide implementation evidence; they are not a substitute for an audit or a
guarantee of cryptographic security.
:::

Read [release assurance](./release-assurance.md) for the exact automated gates
and [privacy and linkability](./privacy.md) for information that remains public.
