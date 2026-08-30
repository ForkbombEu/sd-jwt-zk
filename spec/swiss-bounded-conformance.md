# Bounded Swiss claim conformance matrix

This matrix describes the native `validate_swiss_compact_claims` boundary used
by the bounded compact flat-and-array family. It is not a claim of full Swiss
Profile credential-format conformance: recursive disclosure support remains
deferred.

| Requirement | Bounded behavior | Evidence |
| --- | --- | --- |
| Protected header | Require `alg=ES256`, `typ=dc+sd-jwt`, and `profile_version=swiss-profile-vc:1.0.0`; reject nested header values | `sd-jwt-zk-swiss-claims` cases 1, 2 |
| Top-level credential type | Require string `vct` at the issuer-payload root | cases 1, 19 |
| Hash algorithm | Permit omitted `_sd_alg` or exact root `sha-256`; reject another value | cases 1, 14 |
| Registered claim placement | Reject permanently disclosed `sub`, `aud`, `jti`, `vct_version`, `vct_subtype`, `vct_subtype_version`, and `expiry_date` | cases 4, 8, 9 |
| Time policy | Integer, non-negative `exp`, `nbf`, and `iat`; enforce public now/required-time boundaries | cases 3, 7, 20–22 |
| Disclosure shape | Permit root `_sd` string arrays and root arrays containing scalars or exact `{ "...": digest }` placeholders | case 10 |
| Recursive shape | Reject root object claim values, nested arrays, malformed placeholders, and dotted policy paths | cases 11–13, 18 |
| Typed policies | Enforce reveal, equality, integer/date range, boolean, bounded set membership, and duplicate/type failures | cases 1, 5, 6, 15–17, 23–25 |

Metadata retrieval, rendering, schema fetching, issuer trust, and recursive
Swiss disclosure processing are external or deferred. A swiyu-compatible
verifier cross-check is performed only when one is available in the local
execution environment; it is not bundled with this repository.
