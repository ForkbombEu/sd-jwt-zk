# Architecture

The native parser constructs bounded witnesses. The relation layer proves
cryptographic constraints. `VerifyRelation` checks only that layer;
`VerifyPresentation` adds the typed local policy and replay decision. The CLI
is a protected-file adapter around those public V1 APIs. Trust material in an
envelope never becomes authoritative merely because it was proved.
