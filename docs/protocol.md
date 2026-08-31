# Protocol

1. The verifier creates a challenge with an exact issuer key, audience,
   purpose, nonce, time window, mode, claim policy, and optional local status
   snapshot.
2. The wallet reads credential and private witness material from protected
   files and proves the requested relation.
3. The verifier checks the canonical envelope against its original challenge
   and atomically consumes the nonce only after all checks pass.

Audience and purpose are transcript-bound as `audience || 0x1f || purpose`.
Changing either byte invalidates the proof.
