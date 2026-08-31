#pragma once

// Product-facing V1 entry points.  This header deliberately exposes only the
// accepted, bounded exact-key families; it is not a generic circuit factory.

#include <optional>

#include "sd_jwt_zk/flat_bearer_proof.h"
#include "sd_jwt_zk/holder_bound_proof.h"

namespace sd_jwt_zk {

enum class StatusRequirementV1 : std::uint8_t { forbidden = 1, required = 2 };

// The application supplies audience and purpose separately.  They are
// canonically composed into the signed/transcript-bound Request audience so a
// verifier cannot accidentally validate a proof for a different purpose.
struct PresentationPolicyV1 {
  std::string audience;
  std::string purpose;
  std::string nonce;
  std::uint64_t time_min{};
  std::uint64_t time_max{};
  P256Key issuer_key{};
  StatusRequirementV1 status{StatusRequirementV1::forbidden};
  std::optional<StatusPolicyV1> trusted_snapshot;
};

struct BearerPresentationRequestV1 { Request request; };
struct HolderPresentationRequestV1 { HolderBoundVerifierPolicyV1 policy; };

// A closed result makes a policy failure distinct from proof validity.  Callers
// must handle every value; no success-like default exists.
enum class PresentationResultV1 : std::uint8_t {
  accepted = 1,
  malformed = 2,
  unsupported = 3,
  expired = 4,
  replayed = 5,
  policy_denied = 6,
  status_required = 7,
  verification_failed = 8,
};

Result<BearerPresentationRequestV1> BuildBearerPresentationRequestV1(
    const PresentationPolicyV1& policy, const Limits& limits = {});
Result<HolderPresentationRequestV1> BuildHolderPresentationRequestV1(
    const PresentationPolicyV1& policy, const Limits& limits = {});

// Relation verification performs cryptographic verification only and never
// records a nonce.  Applications should normally call VerifyPresentation.
Result<bool> VerifyRelation(const BearerPresentationRequestV1& expected,
                            const Envelope& envelope, std::uint64_t now,
                            const Limits& limits = {});
Result<bool> VerifyRelation(const HolderPresentationRequestV1& expected,
                            const HolderBoundEnvelope& envelope,
                            std::uint64_t now, const Limits& limits = {});

PresentationResultV1 VerifyPresentation(
    const BearerPresentationRequestV1& expected, const Envelope& envelope,
    std::uint64_t now, FlatBearerReplayStoreV1& replay_store,
    const Limits& limits = {});
PresentationResultV1 VerifyPresentation(
    const HolderPresentationRequestV1& expected,
    const HolderBoundEnvelope& envelope, std::uint64_t now,
    HolderBoundReplayStoreV1& replay_store, const Limits& limits = {});

}  // namespace sd_jwt_zk
