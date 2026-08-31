# Local status operations

The verifier operator authenticates, stores, and rotates local snapshots.
`status-snapshot build` consumes exactly four fixed records and publishes a
root, issuer, epoch, and validity interval. Challenge creation selects that
policy. Wallet status files contain only `SPW1`, a private index, and two
siblings; the credential binding is derived internally.

Reject rollback, stale, unavailable, or wrong-issuer snapshots. Root and epoch
identify a status cohort and can link presentations even though index, path,
leaf, and credential binding remain private.
