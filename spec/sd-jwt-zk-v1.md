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

## Privacy limits and leakage

ZK hides witness bytes; it does not hide public policy. Claim by claim: a revealed selected value is disclosed; equality/range/set/predicate reveals its Boolean result; requested paths, their number, and policy shape reveal intent; absence/unsupported-shape rejection can reveal format facts. Audience/domain, nonce, timing, verifier identity, proof size, circuit family, capacity bucket, exact issuer key (in exact-key mode), registry root/epoch/depth (in registry mode), and later status cohort are linkable public metadata. Capacity buckets leak an upper bound on credential/disclosure size. A small registry or rare credential type can re-identify an issuer even though the key/path are private. Network, transport, IP address, verifier logging, root/status retrieval and a verifier reusing challenges can independently destroy unlinkability. Fresh proof randomness is required but cannot repair any of those disclosures.
