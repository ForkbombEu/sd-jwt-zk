---
title: Privacy and linkability
description: Identify which presentation fields remain public and how they can correlate sessions.
---

# Privacy and linkability

Zero knowledge hides the bounded witness; it does not make the entire
presentation unlinkable. Integrators should evaluate the public statement and
their own disclosure policy together.

## Public surfaces

The relying party can observe:

- disclosed scalar values;
- bearer or holder-bound presentation family;
- circuit identity and capacity bucket;
- exact issuer selection;
- audience and purpose policy;
- challenge context and time policy; and
- revocation root and epoch when a revocation check is required.

Stable disclosed values can correlate sessions. A reused revocation root and epoch
places presentations in the same public cohort. Exact issuer selection and a
specialized audience or purpose can narrow that cohort further.

## Private revocation witness

The revocation credential binding, Merkle leaf, private index, siblings, and path
directions are not serialized. The proof exposes the selected root and a public
presentation-bound bridge commitment, not those private Merkle coordinates.

## Replay is not unlinkability

Fresh nonces prevent successful proof replay after the relying party atomically
consumes the challenge. They do not erase disclosed values or other stable
public statement fields. Bearer evidence is especially theft-sensitive until
the intended relying party consumes its nonce.

## Deployment questions

Before enabling a policy, decide:

- whether both disclosed values are necessary for the decision;
- how issuer, audience, purpose, and revocation cohorts combine;
- how often revocation-list snapshots rotate and whether that cadence creates a useful
  correlation handle; and
- whether holder-bound mode is required for the threat model.

SD-JWT ZK does not claim issuer hiding, aggregate anonymity, or general-purpose
unlinkability. See [unsupported features](./unsupported.md) and the [security
claim matrix](./security-claims.md).
