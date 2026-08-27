# SD-JWT-ZK V1 sequence diagrams

All arrows are logical deployment messages. Witness material stays local to the
holder/prover; ZK envelopes contain only the V1 public statement and proof.

## Issuance input
```mermaid
sequenceDiagram
 participant I as Issuer
 participant H as Holder
 Note over I: ES256 Sign protected-header and payload fixed JOSE raw signature
 I->>H: compact issuer JWS and base64url disclosures
 Note over H: SHA-256 ASCII disclosure then compare hidden _sd digest
 alt hash/header/ES256 invalid
  H-->>I: reject credential
 else valid flat credential
  H-->>I: store private witness
 end
```

## Bearer exact-key presentation
```mermaid
sequenceDiagram
 participant H as Holder-Prover
 participant V as Verifier
 V->>H: audience nonce policy time-window exact-issuer-key
 Note over H: SHA-256 disclosures and ES256 issuer verification in witness
 H->>V: proof public-statement circuit-id
 Note over V: Fiat-Shamir transcript binds statement and circuit-id
 alt proof and replay policy valid
  V-->>H: policy result
 else reject
  V-->>H: abort
 end
```

## Holder-bound exact-key presentation
```mermaid
sequenceDiagram
 participant H as Holder-Prover
 participant V as Verifier
 V->>H: audience nonce policy time-window exact-issuer-key
 Note over H: SHA-256 compact presentation to sd_hash then ES256 KB-JWT under private cnf.jwk
 H->>V: holder-bound proof and public statement
 Note over V: verify distinct holder-bound exact-key circuit identity
 alt aud nonce iat sd_hash and proof valid
  V-->>H: policy result
 else binding invalid
  V-->>H: abort
 end
```

## Bearer registry-trust presentation
```mermaid
sequenceDiagram
 participant R as Registry Policy
 participant H as Holder-Prover
 participant V as Verifier
 R->>V: authenticated root epoch depth
 V->>H: audience nonce policy root epoch depth
 Note over H: private issuer key/type/path SHA-256 membership and ES256 issuer verification
 H->>V: bearer registry proof
 alt root policy and proof valid
  V-->>H: policy result
 else unknown root or invalid path
  V-->>H: abort
 end
```

## Holder-bound registry-trust presentation
```mermaid
sequenceDiagram
 participant R as Registry Policy
 participant H as Holder-Prover
 participant V as Verifier
 R->>V: authenticated root epoch depth
 V->>H: audience nonce policy root and challenge
 Note over H: private registry path plus SHA-256 sd_hash and ES256 KB-JWT
 H->>V: holder-bound registry proof
 alt membership holder binding and replay policy valid
  V-->>H: policy result
 else invalid
  V-->>H: abort
 end
```

## Staged status extension
```mermaid
sequenceDiagram
 participant S as Status Provider
 participant V as Verifier
 participant H as Holder-Prover
 S->>V: authenticated status snapshot root epoch
 V->>H: future status-enabled circuit challenge
 Note over H: future private status reference/index/path proves VALID
 H->>V: future status proof
 alt authenticated fresh snapshot and VALID proof
  V-->>H: policy result
 else V1 status staged or status invalid
  V-->>H: abort
 end
```

Protocol summary: six flows cover issuance input, both binding modes, both trust
modes, and the intentionally staged status extension. Primitives are ES256,
SHA-256, and a domain-separated Fiat-Shamir transcript. There is no forward
secrecy claim and all error branches reject without releasing witness bytes.
