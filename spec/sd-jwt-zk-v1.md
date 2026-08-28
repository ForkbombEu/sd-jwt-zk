# SD-JWT-ZK V1 relation and privacy contract

This is a versioned specification for a future proving system, not an implementation or a conformance assertion. It supports compact `dc+sd-jwt` only, SHA-256 only, and a flat restricted grammar. All multibyte integers are unsigned big-endian. `u16(x)` and `u32(x)` are fixed-width; `lp(x)` is `u32(len(x)) || x`; literal tags are ASCII with no terminator. JSON values in an encoding are their exact UTF-8 source bytes, not reserialized JSON.

## Domains, statement, witness, and transcript

The domain tags are ASCII: `SDJWT-ZK-V1/statement`, `SDJWT-ZK-V1/witness`, `SDJWT-ZK-V1/circuit`, and `SDJWT-ZK-V1/transcript`. A circuit implementation must use each byte sequence below exactly, with no implicit separators.

```
statement = tag(statement) || lp(circuit_id) || lp(mode) || lp(audience) || lp(nonce) || u64(time_min) || u64(time_max) || lp(policy_bytes) || lp(policy_result_bytes) || lp(trust_public) || lp(status_public)
witness   = tag(witness) || lp(issuer_compact_jws) || lp(disclosures_ascii) || lp(issuer_signature) || lp(hidden_claims) || lp(cnf_jwk) || lp(kb_compact_jws) || lp(registry_key_and_path) || lp(status_ref)
circuit_id = tag(circuit) || lp(protocol_version) || lp(binding) || lp(trust) || lp(capacity_bucket) || lp(hash) || lp(grammar)
transcript = tag(transcript) || SHA-256(statement) || SHA-256(circuit_id) || lp(proof_system_id) || lp(proof_system_public_input_encoding)
```

`protocol_version` is ASCII `1`; `hash` is ASCII `sha-256`; `grammar` is ASCII `flat-restricted-json-1`. `mode`, `binding`, and `trust` are fixed ASCII tokens. The Fiat-Shamir challenge is the proof-system hash of `transcript`; a backend may not substitute raw JSON, a display string, or concatenation without `lp`. `statement` binds the verifier audience, fresh nonce, complete requested policy, its selected values/predicate results, time window, trust commitment, and status commitment. Thus a proof cannot be transplanted to another challenge or policy.

## Fixed circuit families

There are no inactive trust or binding flags. Each tuple is a distinct circuit identity and verification key namespace; `B<n>` is the maximum private byte capacity bucket and is visible.

| Identity template | Binding | Trust | Public `trust_public` |
|---|---|---|---|
| `v1/bearer/exact-key/B<n>` | bearer | exact-key | encoded P-256 issuer public key |
| `v1/holder-bound/exact-key/B<n>` | holder-bound | exact-key | encoded P-256 issuer public key |
| `v1/bearer/registry/B<n>` | bearer | registry | registry root, epoch, fixed depth |
| `v1/holder-bound/registry/B<n>` | holder-bound | registry | registry root, epoch, fixed depth |

Bearer proves possession of a credential witness only. Holder-bound additionally proves a valid private `cnf.jwk` P-256 key signed the private KB-JWT whose `aud`, `nonce`, `iat`, and `sd_hash` bind the exact presentation. Exact-key mode reveals the accepted issuer key but not `kid`; registry mode proves the same hidden issuer key and hidden type are authorized under the public root.

## Classification: every byte

| Byte category | Classification | Destination / rationale |
|---|---|---|
| protocol version, circuit identity, mode, bucket | public | statement and proof envelope; family and capacity leak |
| audience/domain, nonce, time bounds, requested policy, selected values/results | public | statement; intentional verifier authorization output |
| exact issuer public key | public in exact-key; private in registry | exact-key trust input; registry witness/path |
| registry root, epoch, depth | public | registry trust input |
| status snapshot/root/epoch when enabled | public later | status trust context; V1 uses `status=staged` only |
| issuer compact JWS bytes, protected/payload bytes, issuer signature | private | witness, authenticated but never envelope output |
| disclosures, salts, digest list, disclosure ordering | private | witness; only policy result can emerge |
| all undisclosed claims, `vct`, hidden registered claims | private | witness, except an explicitly requested policy result |
| `cnf.jwk` coordinates and holder private key | private | holder-bound witness |
| KB-JWT bytes/signature and private `sd_hash` | private | holder-bound witness |
| registry leaf, issuer key, type, index, siblings, direction bits | private | registry witness |
| status URI, index, status reference and path | external now; private later | V1 does not process status |
| issuer key resolution, root distribution, status download, replay-store state | external | verifier policy, authenticated outside the proof |

Public output is exactly the policy result plus fresh challenge context (`audience`, `nonce`, verifier time/policy bounds and family/trust context). It never includes JWS bytes, a disclosure, salt, signature, `cnf`, KB-JWT, registry path, issuer identity in registry mode, or status index.

## Disclosure and signature relation

Both accepted `_sd_alg` forms are hash-bearing: omitted means `sha-256`; the only explicit form is `_sd_alg:"sha-256"`. For each object disclosure the private ASCII base64url disclosure `D` is constrained as `digest = base64url(SHA-256(ASCII(D)))`; no branch omits this SHA-256 gadget. The hidden issuer ES256 signing input authenticates the payload containing that digest. The holder-bound `sd_hash` similarly commits to the exact ASCII compact presentation including tildes and disclosed order. The initial grammar rejects arrays, recursion, decoys, duplicate names/digests and unused disclosures.

## Verifier policy

Before expensive verification, the verifier obtains the accepted exact key or authenticated registry root from local trust policy, selects one family and bucket, validates audience and a fresh high-entropy nonce, and requires `time_min <= now <= time_max`. It atomically consumes the nonce only after a successful proof; expiration, reuse, unsupported identity, wrong mode, unknown root/key, or unsatisfied policy rejects. The verifier must not trust a root, time limit, status snapshot, or replay state supplied only by the proof.

Status is deliberately staged: V1 returns no assertion that a credential is valid, unrevoked, or status-checked. A later status identity must bind an authenticated snapshot and still keep its reference/index private.

## Issuer authorization registry V1

Registry roots are locally authenticated trust inputs, never values chosen by a
presentation.  A registry has an unsigned transport record containing `epoch`,
`valid_from`, `valid_until`, fixed `depth`, and a 32-byte root.  Deployments
authenticate that transport record (for example with their trust-list signing
key) before giving it to the verifier; root download, signature verification,
caching, and rollback protection are external policy.

The canonical authorization record used for sorting is
`x(32) || y(32) || u32(len(vct)) || vct || u64(not_before) || u64(not_after)`.
All integer fields are unsigned big-endian; `vct` is nonempty printable ASCII
without quote or backslash; and `not_before <= not_after`.  The P-256 point
must be valid and non-infinite.  Records sort lexicographically by these exact
bytes and duplicate canonical records are rejected.

The host builder uses SHA-256 over the following concatenations (the tags are
literal ASCII with no implicit delimiter):

```
leaf(record) = SHA-256("SDJWT-ZK/issuer-registry/v1/leaf" || x || y || SHA-256(vct) || u64(not_before) || u64(not_after))
empty(h)    = SHA-256("SDJWT-ZK/issuer-registry/v1/empty" || u8(h))
node(l, r)  = SHA-256("SDJWT-ZK/issuer-registry/v1/node" || l || r)
```

At level zero, sorted records occupy the lowest indices and every remaining
slot is `empty(0)`.  Parent nodes are `node(left,right)`; a path contains one
sibling and one direction bit per level, where the direction bit equals bit
`level` of the little-endian conceptual leaf index.  Tree depth is one through
20, so capacity is exactly `2^depth`; the fixed depth is part of the circuit
identity and public request.  An empty registry has a deterministic root but
has no valid membership path.

The leaf's issuer coordinates, `vct`, interval, index, and path are private in
registry proof families.  The circuit exposes only root, epoch, the root
validity window, depth/capacity, and requested policy.  It proves that the
complete public root window lies in the hidden authorization interval; the
verifier separately requires its current time to lie in that root window and
in the request window.  A public `vct` policy is permitted only when local
governance authenticates a registry as single-VCT scoped; mixed or unscoped
roots cannot satisfy that policy merely because the presentation names a VCT.

### Local root lifecycle policy

The safe verification entry points require an
`IssuerRegistryVerifierPolicyV1` assembled from authenticated local
configuration.  Each accepted entry fixes the complete canonical context
tuple `(root, epoch, valid_from, valid_until, depth)`, its governed
authorization count, revocation state, and optional public VCT scope.  The
`root_id` used in inspection is the lowercase SHA-256 hex digest of the
canonical encoded context; matching only the 32-byte Merkle root is
insufficient because it would let a proof choose epoch, window, or capacity.

Policy evaluation occurs before proof parsing and fails closed for an unknown
or revoked context, epoch rollback, future or expired window, wrong fixed
depth/capacity, zero/oversized/undersized authorization set, or VCT-scope
mismatch.  Proof metadata never adds an accepted root.  Exact-key evidence is
rejected by registry policy and registry evidence is rejected by exact-key
entry points; applications must select a mode explicitly.

Rotation publishes the replacement at a strictly newer epoch.  Operators may
configure both old and new complete contexts during a bounded overlap, then
raise `minimum_epoch` and revoke/remove the old entry.  A rollback to the old
root fails even if its original validity window has not elapsed.  Emergency
revocation takes precedence over overlap and validity.  Verification fails
closed when authenticated root configuration is unavailable.

Safe inspection reports only `root_id`, epoch, public root window, fixed depth,
capacity, and the locally configured authorization-count upper bound.  It
never accepts a witness/path object and therefore cannot print issuer
coordinates, leaf index, siblings, direction bits, private authorization
interval, or hidden VCT.  It prints a public VCT only when the verifier policy
both requires that authenticated scope and explicitly enables inspection
disclosure.  Small registries, scoped roots, and rare authorized types can
still make the issuer linkable; the configured authorization count is an upper
bound on anonymity, not a promise that all entries are equally plausible.

## Privacy limits and leakage

ZK hides witness bytes; it does not hide public policy. Claim by claim: a revealed selected value is disclosed; equality/range/set/predicate reveals its Boolean result; requested paths, their number, and policy shape reveal intent; absence/unsupported-shape rejection can reveal format facts. Audience/domain, nonce, timing, verifier identity, proof size, circuit family, capacity bucket, exact issuer key (in exact-key mode), registry root/epoch/depth (in registry mode), and later status cohort are linkable public metadata. Capacity buckets leak an upper bound on credential/disclosure size. A small registry or rare credential type can re-identify an issuer even though the key/path are private. Network, transport, IP address, verifier logging, root/status retrieval and a verifier reusing challenges can independently destroy unlinkability. Fresh proof randomness is required but cannot repair any of those disclosures.
