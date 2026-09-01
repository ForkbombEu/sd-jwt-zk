---
title: Unsupported features
description: Know which identities, disclosure shapes, interoperability profiles, and claims V1 rejects.
---

# Unsupported features

This first release of SD-JWT ZK (V1) is intentionally narrow and the
product API does not silently accept a broader shape when a supported
check fails.

## Outside the product boundary

| Area | Not supported in V1 |
| --- | --- |
| Issuer privacy | Issuer hiding, issuer registries, and aggregate registries |
| Disclosure shape | Recursive or nested disclosures, arbitrary counts, decoy digests, and additional slots |
| Interoperability | EUDI or Swiss-profile interoperability claims |
| Circuit families | The retained 32-slot experiment and recursive proof composition |
| Serialization | Unsupported identities or presentation-mode downgrade |
| Assurance | Unmeasured timing or resource guarantees, and external conformance guarantees |

Product support is defined by the typed builders and accepted circuit
identities, not by the presence of a source file or historical specification.
Adding a disclosure shape or trust mode requires a new identity, parser boundary,
negative tests, and release evidence.

## Fail-closed behavior

Unsupported version, component order, binding mode, trust mode, capacity,
digest, field, rate, or query parameters reject. Bearer evidence cannot be
submitted as a holder-bound envelope, and a revocation requirement cannot
downgrade to `status-forbidden` behavior.

## Claims the project does not make

The project has not received an independent cryptographic audit, only
the Longfellow-ZK circuit builder and solver has. V1 also makes no
issuer-hiding, aggregate anonymity, forward-secrecy, or general
unlinkability claim.

## Free without warranty

This is free and open source software provided without warranty under
the terms of the GNU GPL v3 license. Professional support,
maintenance, integration services, and contractual warranty options
are available separately. Please [contact us](mailto:info@forkbomb.eu)
for further information.
