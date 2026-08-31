# Reduced release assurance

The machine-readable binding audit is
[`spec/reduced-binding-matrix.json`](../spec/reduced-binding-matrix.json). The
structural resource record is
[`spec/reduced-release-resources.json`](../spec/reduced-release-resources.json).
Both cover only the fixed two-slot scalar bearer and holder-bound exact-key
entry points and the optional separate locally trusted `VALID` status proof.

The release parser gate runs deterministic mutations over request, envelope and
proof pre-parsing, compact JWS, base64url, bounded JSON, the exact-two disclosure
shape, and local snapshot metadata. ASan/UBSan covers that gate and the default
reduced product suite. Clang-tidy covers the project-owned native parser/codec
translation units; cppcheck covers all project source translation units. The
cppcheck `normalCheckLevelMaxBranches` information message is suppressed because
it reports the analyzer's bounded path exploration, not a source finding. No
warning, performance, portability, or error diagnostic is suppressed.

Configured sizes are fail-closed bounds, not allocation targets or performance
claims. Wall-clock and peak-RSS observations vary by machine and are diagnostic
only. No release resource row exists for the retained 32-slot experiment,
registry or aggregate modes, recursive disclosures, full-family matrices, or
Swiss/swiyu interoperability.
