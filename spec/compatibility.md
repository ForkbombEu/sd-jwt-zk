# Compatibility matrix: restricted V1

States: **MVP** is specified by `sd-jwt-zk-v1.md`; **later** needs a new circuit
identity; **external** is a verifier policy outside the circuit; **unsupported**
is rejected. The flat MVP is **not Swiss-profile conformant**: Swiss requires
arrays and recursive disclosures, which are later work, and status is staged.

| Wire feature and source anchor | State | Contract |
|---|---|---|
| Compact SD-JWT / RFC 9901 §4 | MVP | only `issuer-jws~disclosure...~`; exact ASCII is bound |
| `typ: dc+sd-jwt` / SD-JWT VC §3.1, Swiss §9.11 | MVP | protected issuer header equals `dc+sd-jwt` |
| ES256 / Swiss Cryptography, §3.2.1 | MVP | issuer signature relation is P-256 ES256 only |
| `profile_version` / Swiss SD-JWT VC §3.2.1 | MVP | exact `swiss-profile-vc:1.0.0` is required |
| `_sd_alg` / RFC 9901 §4.1.1, Swiss §4.1.1 | MVP | only omitted or exact `sha-256`; **omission defaults to SHA-256 and never disables hashing** |
| object disclosures / RFC 9901 §4.2 | MVP | three-element `[salt,name,value]`, restricted flat JSON |
| array disclosures / RFC 9901 §4.2.2 | later | full Swiss circuit family |
| recursive disclosures / RFC 9901 §4.2.6 | later | full Swiss circuit family |
| decoy digests / RFC 9901 §4.2.5 | unsupported | reject; Swiss forbids them |
| JWS JSON serialization / RFC 9901 §8 | unsupported | compact serialization only; Swiss forbids JSON serialization |
| `cnf.jwk` / RFC 9901 §4.1.2 | MVP | exactly one private P-256 JWK for holder-bound family; no key in bearer family |
| KB-JWT / RFC 9901 §4.3, Swiss §4.3 | MVP | `typ=kb+jwt`, `alg=ES256`, private `aud`,`nonce`,`iat`,`sd_hash` constraints |
| registered claims / SD-JWT VC §3.2.2.2, Swiss §3.2.2.4 | MVP | `exp`,`nbf`,`iat` signed, non-disclosed; other placement rules later |
| Swiss claim disclosure rules / Swiss §3.2.2.2–§3.2.2.4 | later | full parser and recursive claim placement enforcement |
| issuer exact key | MVP | public accepted P-256 issuer key, no `kid` |
| issuer registry membership | MVP | public root; key/type/path remain private |
| Token Status List / TSL §5.1–§8 | external | status is staged; V1 never asserts checked status |
| type metadata / SD-JWT VC §5 | external | authenticated retrieval and interpretation are local policy |

No compatibility state above is a claim that an MVP presentation is Swiss
conformant. A verifier must reject unsupported shapes before proving.
