---
title: Wallet and relying-party workflows
description: Operate challenge, proving, inspection, and verification without exposing private witness material.
---

# Wallet and relying-party workflows

The CLI is a protected-file adapter around the public V1 APIs. Public policy is
explicit; private credentials, keys, revocation-list indices, and Merkle paths
remain in owner-controlled files.

## Relying-party workflow

1. Generate fresh nonce material in a protected file.
2. Create a canonical challenge with the selected mode, exact issuer key,
   audience, purpose, time window, and revocation policy.
3. Deliver the challenge to the wallet without treating any proof-supplied key
   or snapshot as authoritative.
4. Verify the returned envelope against the original challenge and current
   time.
5. Consume the nonce atomically only after all checks pass.

```sh
sd-jwt-zk challenge create --mode bearer \
  --audience https://rp.example \
  --purpose age-check \
  --nonce-file ./nonce \
  --issuer-key-file ./issuer-p256.hex \
  --time-min 1700000000 \
  --time-max 1700000300 \
  --out ./challenge.bin
```

Challenge creation fails if the output already exists. Owner-controlled output
files use mode `0600`.

## Wallet workflow

Pass file paths to `prove`; do not place credential bytes, holder keys, private
revocation-list indices, or Merkle paths in arguments, environment variables,
logs, or challenge files. The wallet selects witness material that matches the
relying party's fixed request and writes a new presentation file without
overwriting an existing destination.

Bearer evidence is theft-sensitive: anyone holding it may answer an unconsumed
challenge. Holder-bound mode adds possession of the bounded holder key, but it
does not create a general-purpose anonymous credential.

## Safe inspection

`inspect` reads only public envelope fields. It reports the mode, audience,
nonce, and whether a revocation component is present; it does not accept or print
credential witnesses, holder keys, private indices, or Merkle paths.

## Replay store behavior

The CLI replay store is an owner-only directory with at most 4096 active
entries. Verification removes entries whose encoded expiry is earlier than
`--now`. It fails closed when malformed entries remain or the active capacity
is exhausted.

<!--
Experimental: restore this cross-link when revocation-list operations are ready
for public use.

For `status-required` requests, continue with [revocation-list
operations](./status-operations.md).
-->

<WarrantyNotice />
