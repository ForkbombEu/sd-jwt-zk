# Pinned normative references

This lock is deliberately checked in and is never refreshed during ordinary
tests. Retrieval date: **2026-08-28**. `reference-lock.json` is the machine
checked copy; its exact version strings and anchor lists are an input to the
relation version, not advisory text.

| ID | Pinned version and URL | Used anchors |
|---|---|---|
| RFC 9901 | [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) | §4, §4.1.1, §4.2, §4.2.2, §4.2.5, §4.2.6, §4.3, §8, §9.11 |
| Swiss profile | [Swiss Profile for Verifiable Credentials 1.0](https://swiyu-admin-ch.github.io/specifications/swiss-profile-vc/) (edited 2026-06-22) | Cryptography; RFC mapping §4.1.1, §4.1.2, §4.2.2, §4.2.5, §4.2.6, §4.3, §6.1, §6.3, §8; SD-JWT VC §3.2.1–§3.2.2.4 |
| SD-JWT VC | [draft-ietf-oauth-sd-jwt-vc-15](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-15) | §3.1, §3.2.1, §3.2.2 |
| Token Status List | [draft-ietf-oauth-status-list-20](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-20) | §5.1, §6, §7.1, §8 |

The historical SD-JWT VC Draft 13 link is context only and is not an input.
Network retrieval, type metadata, issuer keys, registry roots, and revocation
snapshots are external inputs to relying-party policy; their authenticity is not
established by this checked-in lock.
