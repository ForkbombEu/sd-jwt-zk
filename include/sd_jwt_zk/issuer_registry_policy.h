#pragma once

#include <optional>
#include <string>
#include <vector>

#include "sd_jwt_zk/holder_bound_proof.h"
#include "sd_jwt_zk/registry_bearer_proof.h"

namespace sd_jwt_zk {

enum class RegistryPolicyDecisionV1 {
  accepted,
  wrong_trust_mode,
  malformed_context,
  unknown_root,
  revoked_root,
  rollback_epoch,
  root_not_yet_valid,
  root_expired,
  wrong_capacity,
  undersized_anonymity_set,
  vct_scope_mismatch,
};

// Entries are authenticated local configuration.  Nothing in this type is
// learned from an untrusted presentation.  public_vct_scope is meaningful
// only for a registry whose governed construction guarantees every included
// authorization has that VCT.
struct AcceptedIssuerRegistryRootV1 {
  RegistryTrustContextV1 context;
  std::uint32_t authorization_count{};
  bool revoked{};
  std::optional<std::string> public_vct_scope;
};

struct IssuerRegistryVerifierPolicyV1 {
  std::vector<AcceptedIssuerRegistryRootV1> accepted_roots;
  std::uint64_t minimum_epoch{};
  std::uint8_t required_depth{kIssuerRegistryDepthV1};
  std::uint32_t minimum_anonymity_set{2};
  std::optional<std::string> required_public_vct;
  bool reveal_public_vct_in_inspection{};
};

struct RegistryPolicyEvaluationV1 {
  RegistryPolicyDecisionV1 decision{RegistryPolicyDecisionV1::unknown_root};
  std::optional<std::size_t> accepted_root_index;
};

struct RegistryPublicInspectionV1 {
  std::string root_id;
  std::uint64_t epoch{};
  std::uint64_t valid_from{};
  std::uint64_t valid_until{};
  std::uint8_t depth{};
  std::uint32_t capacity{};
  std::uint32_t anonymity_set_upper_bound{};
  std::optional<std::string> public_vct;
};

std::string issuer_registry_root_id_v1(const RegistryTrustContextV1& context);
RegistryPolicyEvaluationV1 evaluate_issuer_registry_policy_v1(
    const Request& request, std::uint64_t now,
    const IssuerRegistryVerifierPolicyV1& policy);
Result<RegistryPublicInspectionV1> inspect_issuer_registry_public_v1(
    const Request& request, std::uint64_t now,
    const IssuerRegistryVerifierPolicyV1& policy);
std::string format_issuer_registry_public_inspection_v1(
    const RegistryPublicInspectionV1& inspection);

// These are policy-enforcing entry points.  They reject an unauthenticated,
// stale, revoked, rolled-back, wrong-capacity, or undersized root before proof
// bytes are parsed by the low-level relation verifier.
Result<bool> verify_authorized_registry_bearer_v1(
    const Envelope& envelope, const Request& expected_request,
    std::uint64_t now, const IssuerRegistryVerifierPolicyV1& policy,
    FlatBearerReplayStoreV1& replay_store, const Limits& limits = {});
Result<bool> verify_authorized_holder_registry_v1(
    const HolderBoundEnvelope& envelope,
    const HolderBoundVerifierPolicyV1& expected, std::uint64_t now,
    const IssuerRegistryVerifierPolicyV1& policy,
    HolderBoundReplayStoreV1& replay_store, const Limits& limits = {});

}  // namespace sd_jwt_zk
