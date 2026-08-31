# What it proves

An accepted presentation proves that an exact verifier-selected P-256 issuer
key signed the compact credential, that the fixed two scalar disclosures open
the signed `_sd` values, and that the configured claim relation is true.
Holder-bound mode additionally proves the bounded KB-JWT relation and holder
key possession. If local status is required, a separate private membership
proof establishes `VALID` under the verifier-selected root and is bridged to
the same credential and presentation context.

Authorization remains external: the application chooses the issuer key,
audience, purpose, time, nonce policy, accepted circuit identities, claim
policy, and status snapshot.
