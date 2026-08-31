---
title: Local status operations
description: Build, authenticate, rotate, and select the fixed four-entry local status snapshot.
---

# Local status operations

Local status is an optional, separate proof component. It establishes private
`VALID` membership in a verifier-selected four-entry snapshot; it is not a Token
Status List representation and it does not provide issuer hiding.

## Operator responsibility

The verifier operator authenticates the snapshot authority, stores accepted
snapshots, enforces monotonic epochs, rejects rollback, and defines behavior for
stale or unavailable data. A presentation cannot supply its own trusted root.

The public snapshot contains:

- the issuer identifier;
- the fixed-depth Merkle root;
- the epoch; and
- the `valid_from` and `valid_until` interval.

## Build a snapshot

`status-snapshot build` consumes exactly four fixed 33-byte records. Each record
contains a 32-byte credential binding followed by `01` for `VALID` or `02` for
revoked. The command publishes the canonical local policy containing the root,
issuer, epoch, and validity interval.

The credential binding is derived from the credential signing digest. A valid
entry equals that private binding; non-valid entries use a domain-separated
SHA-256 encoding.

## Supply the private witness

For a status-required challenge, `prove` also receives a status-witness file.
Its only accepted format is:

1. the four-byte marker `SPW1`;
2. one private index byte; and
3. exactly two 32-byte compressed-path siblings.

The credential binding is derived internally and is not accepted as a command
argument or witness-file field.

## Verification and privacy

Verification requires the status component only when the original challenge
carries the matching trusted policy. Wrong-issuer, wrong-epoch, expired,
rollback, malformed, or unavailable snapshots fail according to local policy.

The root and epoch identify a status cohort and may correlate presentations.
The credential binding, leaf, private index, siblings, and path directions are
not serialized. Read [privacy and linkability](./privacy.md) before enabling
status.
