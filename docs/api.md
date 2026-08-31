# V1 API and identities

The product header is `sd_jwt_zk/presentation.h`. Request construction is
limited to `BuildBearerPresentationRequestV1` and
`BuildHolderPresentationRequestV1`. `VerifyRelation` reports cryptographic
validity only. `VerifyPresentation` applies local policy and returns exactly
one closed `PresentationResultV1` value: `accepted`, `malformed`,
`unsupported`, `expired`, `replayed`, `policy_denied`, `status_required`, or
`verification_failed`.

Supported proof identities are the V1 exact-key bearer identity and the V1
ordered holder credential/KB identity pair, each optionally paired with the
canonical private local-status identity. Callers select identities through
typed builders; arbitrary identities are not constructible through this API.

The bounded input/vector index shipped with every source archive is
`fixtures/compact-vectors.json`. Installed-consumer examples live in
`tests/downstream` and compile against the exported `SDJWTZK::sd-jwt-zk`
target.
