# Local status snapshot V1

Status is an optional, separate proof component for the fixed two-slot scalar
bearer and holder-bound relations.  It is not a status-list protocol.

## Authority and snapshot format

A verifier configures the exact local authority (the same locally configured
issuer-key trust domain), expected issuer identity, monotonic epoch, root and
validity window before it reads a status proof.  The authority produces a
fixed-depth-four-leaf snapshot.  Each leaf is the domain-separated encoding of
the issuer identity, epoch, credential digest binding, and either `VALID` or
`REVOKED`.  Duplicate credential bindings, other status values, a capacity or
depth mismatch, malformed windows, and roots that do not rebuild from the
authenticated leaves are rejected.

The snapshot builder deterministically rebuilds the root and one compressed
path using the installed Longfellow `MerkleTree`.  Longfellow's verifier checks
the path against that root before its fixed-depth membership adapter turns it
into a circuit witness.  SD-JWT owns only leaf encoding and local policy.

## Verification and operations

The verifier selects and authenticates a local snapshot out of band, checks
issuer, epoch, root, validity window and `VALID` requirement before proof
parsing, and fails closed if the snapshot is unknown, unavailable, stale,
future, rolled back, or from the wrong authority.  The status statement binds
that selected metadata, credential digest, and fresh presentation context.
The private index and compressed path are witness data and are never emitted by
inspection.

Operators keep epochs strictly monotonic, permit only an explicitly configured
overlap during rotation, cache only within the authenticated validity window,
and retain rollback protection across restarts.  Recovery from unavailable
status data is to deny a status-required presentation, not to downgrade it.

The public local root and epoch identify a status cohort, so they can link
presentations made against the same snapshot.  This design provides neither
issuer hiding nor aggregate anonymity.  Swiss Token Status List ingestion,
compressed-list interoperability, swiyu fixtures, and aggregate registries are
unsupported.
