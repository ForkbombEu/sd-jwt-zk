---
title: Specification and vectors
description: Locate the normative V1 protocol, revocation profile, reference lock, compatibility record, and bounded fixtures.
---

# Specification and vectors

The source archive carries the normative protocol and its release evidence.
Read product support from the V1 API and current support records; some files
under `spec/` retain historical or experimental families that are not shipped.

## Normative and operational sources

| Artifact | Role |
| --- | --- |
| `spec/sd-jwt-zk-v1.md` | Normative bounded protocol |
| `spec/local-status-v1.md` | Revocation-list snapshot authority, rotation, rollback, and availability policy |
| `spec/protocol-sequences.md` | Logical deployment-message sequences |
| `spec/compatibility.md` | Feature decisions and external/unsupported classifications |
| `spec/references.md` | Locked standards reference index |
| `spec/reference-lock.json` | Machine-checked reference versions and anchors |

## Fixtures and assurance records

`fixtures/compact-vectors.json` indexes the bounded input vectors shipped with
every source archive. `spec/reduced-binding-matrix.json` traces each supported
input from parsing through its constraint, presentation binding, relying-party
policy, and negative test. `spec/reduced-release-resources.json` records the
structural resource boundary for the release lane.

## Reading rule

The presence of registry, aggregate, recursive, 32-slot, or broader
compatibility material does not make it part of the V1 product. The supported
surface is the fixed two-slot scalar exact-key bearer and holder-bound entry
points, optionally paired with a private `VALID` revocation check.

Start with [what SD-JWT ZK proves](./what-it-proves.md), then use the normative sources
for protocol-level review.
