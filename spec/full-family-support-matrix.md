# Historical and experimental full disclosure family V1 evidence

The measured bucket has a 16-byte/8-token/depth-3 bounded JSON subrelation and
32 disclosure graph slots. The reserved 4096-byte/256-token/depth-8 identity
namespace has not been compiled or proved and is not claimed here.

## Focused parser bucket (diagnostic only)

`FullDisclosureFocusedV1` is a distinct, opt-in two-disclosure circuit bucket:
128 issuer-payload bytes, 64 decoded-disclosure bytes, 13 tokens, depth 13,
and exactly two disclosure sources. Its source count is fixed in the circuit
identity and therefore leaks that bucket; it is not a witness-conditional
shortcut and does not change the full32 family. The two sources cover the
object `_sd` and array `{"...": digest}` shapes. This bucket is currently
diagnostic-only: the heterogenous EvaluationBackend valid witness exceeds the
documented 180-second bound, so no proof or conformance claim is made from it.

The measured medium alternative is 24 bytes, 12 tokens, depth 5, and 32
disclosure slots. A 32-byte/16-token/depth-5 candidate SIGSEGVed immediately
with the default 8-MiB stack; with a 64-MiB stack and 6-GiB address-space bound
it reached the 300-second timeout (exit 124) without completing. The 24/12/5
bucket is therefore the largest currently reproduced bounded alternative, not
evidence for the declared 4096/256/8 namespace.

| Medium binding | Trust | Circuit ID | Terms | Inputs | Construction | Peak RSS |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| bearer | exact-key | `e1eb8e68a1007d33eaa0afdb982f1c9adf8f469ca0ccb4fecf1d72cfcc59126d` | 15,291,823 | 72,481 | 179.46s | 2,765,196 KiB |
| holder-bound | exact-key | `1aa6ff6ab7f83bb5d6f10e07865698df8a97c0e99c6c43975cbc7b8a87181cff` | 15,293,103 | 72,481 | 181.94s | 2,766,220 KiB |
| bearer | registry | `f253c14356d85a1d95c38e37714d5ab209254c1d5c573675cd94056e2bfbf596` | 17,209,939 | 89,195 | 197.46s | 3,144,044 KiB |
| holder-bound | registry | `df6ee3788ff8d562ac40e8416a3212403b5f309ca5e84e97c97d68bed435fe86` | 17,211,219 | 89,195 | 201.61s | 3,146,416 KiB |

Each row is a distinct Longfellow circuit graph. Exact-key rows constrain the
hidden issuer key to the trust key. Registry rows constrain the authorization
record issuer and selected public registry commitment. Holder rows additionally
constrain holder/KB key, presentation-hash, and challenge equality.

The following proof rows predate experimental graph SHA/digest-link and
issuer-JWS composition. They are retained as historical capacity measurements,
not current full-family proof evidence; their circuit IDs are no longer the
factory IDs produced by the source tree.

| Historical binding | Trust | Superseded circuit ID | Terms | Real proof | End-to-end | Peak RSS |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| bearer | exact-key | `b4e0881f72e331a11eee9299337dc3240a0e0d3bd296a82c5f5616e71772a831` | 7,407,069 | 478,476 B | 102.36s | 1,404,024 KiB |
| holder-bound | exact-key | `60cc2228ffdad72b04524e63cc1c07e4fefdef2e1769917f473563529a1066ca` | 7,408,349 | 477,900 B | 109.30s | 1,403,080 KiB |
| bearer | registry | `ef51c2aa88094d2569c60b08ce73b87b3a4f4c3c8e60cdba282f8b2ca56df1d3` | 9,325,185 | 532,108 B | 127.78s | 1,898,168 KiB |
| holder-bound | registry | `ebceac019fe3985fcec6f58a9319609472a35493da31d66690be2643bbefcdb2` | 9,326,465 | 531,596 B | 127.99s | 1,899,400 KiB |

The historical executable constructed the chosen full32 circuit, encoded a valid bounded
JSON plus disclosure/Swiss-policy witness, runs the real randomized `ZkProver`,
and verifies with `ZkVerifier`. Exact-key measurements use a 2.2-GiB bound;
registry measurements use 3 GiB because those circuits now compose the
established depth-2 SHA-256 issuer-registry Merkle-membership relation.

| Real bearer/exact witness | Proof bytes | End-to-end | Peak RSS |
| --- | ---: | ---: | ---: |
| array `[null]` | 478,476 | 102.36s | 1,404,024 KiB |
| recursive graph plus nested JSON `[["x"]]` | 477,516 | 106.83s | 1,402,968 KiB |
| Unicode `["é"]` | 477,900 | 107.93s | 1,402,564 KiB |
| typed policy | 477,708 | 105.92s | 1,403,140 KiB |
| exact 16 bytes plus all 32 disclosure slots | 477,676 | 107.73s | 1,405,132 KiB |
| exact eight tokens | 477,868 | 106.30s | 1,406,052 KiB |

On that superseded graph, repeated proofs of the same witness differed (133.89s, 1,398,872 KiB). A real
bearer/exact proof is rejected when dispatched to the holder/exact circuit
(186.48s, 2,136,228 KiB). Registry full32 witness construction rejects wrong
roots and direction paths, and the compiled relation rejects an issuer changed
after authorization (all exit 0 in their expected-negative modes).

The four EvaluationBackend lanes accept matching witnesses and reject wrong
exact trust keys, registry commitments, holder keys, presentation hashes, and
challenges. Their real compiler IDs are pairwise distinct. Focused tests also
reject one-over byte/token/depth inputs before circuit allocation.

One-over byte, token, and depth inputs reject before circuit allocation in
0.00s at at most 6,224 KiB RSS.

Important boundary: these are historical proofs of the then-composed full32 relation,
not of the reserved 4096/256/8 family. That relation received
issuer, holder, presentation, and challenge values as constrained advice; it
does not yet compose the desired release issuer-JWS and KB-JWS signature circuits.
Therefore the evidence must not be described as complete authenticated Swiss
presentation proofs. The reserved larger bucket remains staged.

The inherited L4 holder real-pair SIGSEGV remains excluded from defaults and
is not evidence for these rows.

## Retained experimental graph status

The compiler and EvaluationBackend now share the complete 32-slot bounded
base64url/SHA-256 advice layout. Because this layout embeds packed FlatSHA
witnesses, the evaluator requires a documented 64-MiB stack: the default
8-MiB stack exits 139. With `ulimit -s 65536` and a 60-second timeout, the
bearer/exact valid witness, bad-ASCII expected-negative, bad-digest
expected-negative, and canonical inactive `MA` witness each exit 0.

The retained experimental bearer/exact harness serializes this same graph/SHA layout and
the issuer-JWS suffix, but it has not produced a proof. Under a 64-MiB stack,
6-GiB virtual-memory limit, and 300-second timeout it throws `std::bad_alloc`
and exits 134 after 225.82 seconds with 3,829,800 KiB peak RSS. Consequently no
retained experimental-graph bearer, holder, registry, repeat, cross-circuit, or
maximum-bound real-proof row is claimed. Parser-authenticated reference
placement and KB-JWS composition also remain pending.

After allocating parser-derived strings, grammar frames, and container IDs for
all 33 graph sources and composing reference-placement constraints, the former
64-MiB evaluator bound is no longer sufficient: the full32 evaluator exits 139
immediately. With a 256-MiB stack, the valid lane reaches both 60- and
180-second timeouts (exit 124) without terminal relation output. These are
bounded infeasibility datapoints only; placement mutation runs are not credited
as conformance evidence until a valid full32 baseline terminates.
