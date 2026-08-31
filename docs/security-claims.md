# Security claim matrix

| Property | Proved | External or leaked |
| --- | --- | --- |
| Issuer signature | Exact configured P-256 key | Key governance is external |
| Disclosures | Two bounded scalar openings | Values and circuit bucket are public |
| Holder binding | Bounded compact KB-JWT possession | Wallet key custody is external |
| Status | Private `VALID` membership and bridge | Root, epoch, and cohort are public |
| Replay | Transcript binds nonce and context | Durable atomic nonce storage is external |

This code has not received an independent cryptographic audit.
