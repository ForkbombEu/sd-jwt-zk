# Fixed two-slot bounded support evidence

This evidence applies only to the L6 fixed relation: exactly one root `_sd`
object-property Disclosure and exactly one root-array `{ "...": digest }`
element Disclosure. It does not measure or claim support for the retained
32-slot full-disclosure family, recursive disclosures, or Swiss-profile
credential-format conformance.

## Fixed public capacity

| Input | Bound |
| --- | ---: |
| Compact protected-header base64url bytes | 102 |
| Compact payload base64url bytes | 256 |
| Decoded payload bytes | 192 |
| SHA-256 blocks | 6 |
| Root object-property slots | 1 |
| Root array-element slots | 1 |
| Opened values | scalar string, boolean, integer, or null |

The evaluator allocates each compact bridge input once: authenticated compact
header/payload, SHA witness, public signed digest, decoded payload, and active
lengths. The input count is fixed by the capacities above; no witness selects a
larger capacity or an additional disclosure slot.

## Observed contained runs

All measurements use `setsid`, `prlimit --as=6442450944 --stack=268435456`,
and `timeout --kill-after=15s 180s`. They are reproducible observations, not a
wall-time performance guarantee.

| Case | Exit | Elapsed | Peak RSS |
| --- | ---: | ---: | ---: |
| root object plus root array positive | 0 | 49.64 s | 10,612 KiB |
| signed public-digest mutation rejection | 0 | 51.21 s | 10,776 KiB |

The positive table covers boolean/integer and string/null. Its fixed-slot
negative checks reject missing or extra slots, duplicate/unused/wrong digests,
an invalid placeholder, disclosed containers, and recursive values. The
authenticated signed-public-digest mutation rejects separately. These are
non-recursive rejection checks, not recursive positive support.
