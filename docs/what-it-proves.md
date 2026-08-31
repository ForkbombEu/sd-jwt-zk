---
title: What V1 proves
description: Separate the bounded cryptographic statement from application policy and operational trust.
---

# What V1 proves

An accepted V1 presentation establishes a deliberately small cryptographic
statement. It does not make a general authorization decision and it does not
turn SD-JWT into an unrestricted anonymous-credential system.

## Common statement

Bearer and holder-bound presentations both prove that:

1. an exact verifier-selected P-256 issuer key signed the compact credential;
2. exactly two bounded scalar disclosures open signed `_sd` values; and
3. the configured claim relation is true.

The exact issuer key is local verifier input. Trust material carried by a proof
or envelope does not become authoritative simply because the relation verifies.

## Holder-bound addition

Holder-bound mode also proves the bounded KB-JWT relation and possession of the
holder key. The KB-JWT binds the expected audience, nonce, issued-at time, and
`sd_hash` under the supported compact relation. A holder-bound envelope cannot
downgrade to the bearer identity.

## Optional local status

When the verifier requires status, a separate private membership component
proves `VALID` under the verifier-selected local snapshot. The component is
bridged to the same credential and presentation context. The root, issuer,
epoch, and validity interval are public policy; the credential binding, leaf,
index, siblings, and direction bits remain private.

The proof cannot choose its own trust root. Snapshot authentication, rotation,
rollback protection, and availability remain verifier-operator duties.

## What remains external

The application still chooses and enforces:

- issuer-key governance and accepted circuit identities;
- audience, purpose, time, nonce, and claim policy;
- durable, atomic replay handling;
- authorization after a presentation is accepted; and
- status-snapshot authority and lifecycle, when status is required.

`VerifyRelation` checks only the cryptographic relation. `VerifyPresentation`
adds the typed local policy and replay decision, but the caller still owns the
resulting authorization decision.

Next, review the [security claim matrix](./security-claims.md) and the explicit
[unsupported feature list](./unsupported.md).
