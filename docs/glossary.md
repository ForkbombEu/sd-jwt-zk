---
title: Glossary
description: Definitions for the bounded SD-JWT ZK V1 product boundary.
---

# Glossary

**Bearer presentation**
: Exact-key presentation without the holder KB-JWT possession relation. Anyone
  holding bearer evidence may answer an unconsumed challenge.

**Challenge**
: Canonical verifier request bound into the proof transcript. It includes the
  selected mode, exact issuer key, audience, purpose, nonce, time window, claim
  policy, circuit identity, and status policy.

**Circuit identity**
: Versioned set of proof parameters and roles accepted by the verifier. A new
  disclosure shape or trust mode requires a new identity.

**Exact key**
: P-256 issuer public key selected by the verifier from local policy. A proof
  cannot choose it.

**Holder-bound presentation**
: Exact-key credential relation plus the bounded compact KB-JWT relation and
  holder-key possession.

**Local snapshot**
: Verifier-selected four-entry status root and public metadata: issuer, epoch,
  and validity interval.

**Presentation verification**
: `VerifyPresentation`: relation verification plus typed local policy and replay
  handling through the application-owned store.

**Purpose**
: Application context separately supplied with audience and canonically bound
  into the request transcript. It is not an advisory label.

**Relation verification**
: `VerifyRelation`: cryptographic validity only, without nonce consumption or
  an application authorization decision.

**Replay store**
: Durable, atomic application-owned state that records successful nonce
  consumption.

**Status bridge**
: Public commitment that binds the separate private status proof to the same
  credential and presentation context.

**Witness**
: Private material used to construct the proof, including credential inputs,
  holder key material, and private status path data. It is not serialized in
  the public envelope.
