#include "sd_jwt_zk/issuer_registry_policy.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>

namespace sd_jwt_zk {
namespace {

bool same_context(const RegistryTrustContextV1& left,
                  const RegistryTrustContextV1& right) {
  return left.root == right.root && left.epoch == right.epoch &&
         left.valid_from == right.valid_from &&
         left.valid_until == right.valid_until && left.depth == right.depth;
}

Result<bool> policy_failure(RegistryPolicyDecisionV1 decision) {
  return Result<bool>::fail(
      ErrorCode::unsupported,
      "issuer registry rejected by local policy: " +
          std::to_string(static_cast<unsigned>(decision)));
}

}  // namespace

std::string issuer_registry_root_id_v1(
    const RegistryTrustContextV1& context) {
  const auto encoded = encode_registry_trust_context_v1(context);
  if (!encoded) return {};
  const auto digest = sha256_ascii(std::string_view(
      reinterpret_cast<const char*>(encoded.value->data()),
      encoded.value->size()));
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const auto byte : digest)
    output << std::setw(2) << static_cast<unsigned>(byte);
  return output.str();
}

RegistryPolicyEvaluationV1 evaluate_issuer_registry_policy_v1(
    const Request& request, std::uint64_t now,
    const IssuerRegistryVerifierPolicyV1& policy) {
  if (request.identity.trust != Trust::registry)
    return {RegistryPolicyDecisionV1::wrong_trust_mode, std::nullopt};
  const auto requested =
      decode_registry_trust_context_v1(request.trust_public);
  if (!requested)
    return {RegistryPolicyDecisionV1::malformed_context, std::nullopt};
  const auto match = std::find_if(
      policy.accepted_roots.begin(), policy.accepted_roots.end(),
      [&](const auto& entry) { return same_context(entry.context, *requested.value); });
  if (match == policy.accepted_roots.end())
    return {RegistryPolicyDecisionV1::unknown_root, std::nullopt};
  const auto index = static_cast<std::size_t>(
      std::distance(policy.accepted_roots.begin(), match));
  if (match->revoked)
    return {RegistryPolicyDecisionV1::revoked_root, index};
  if (match->context.epoch < policy.minimum_epoch)
    return {RegistryPolicyDecisionV1::rollback_epoch, index};
  if (now < match->context.valid_from)
    return {RegistryPolicyDecisionV1::root_not_yet_valid, index};
  if (now > match->context.valid_until)
    return {RegistryPolicyDecisionV1::root_expired, index};
  if (match->context.depth != policy.required_depth ||
      match->context.depth >= std::numeric_limits<std::uint32_t>::digits)
    return {RegistryPolicyDecisionV1::wrong_capacity, index};
  const auto capacity = std::uint32_t{1} << match->context.depth;
  if (match->authorization_count == 0 ||
      match->authorization_count > capacity ||
      match->authorization_count < policy.minimum_anonymity_set)
    return {RegistryPolicyDecisionV1::undersized_anonymity_set, index};
  if (policy.required_public_vct &&
      match->public_vct_scope != policy.required_public_vct)
    return {RegistryPolicyDecisionV1::vct_scope_mismatch, index};
  return {RegistryPolicyDecisionV1::accepted, index};
}

Result<RegistryPublicInspectionV1> inspect_issuer_registry_public_v1(
    const Request& request, std::uint64_t now,
    const IssuerRegistryVerifierPolicyV1& policy) {
  const auto evaluation =
      evaluate_issuer_registry_policy_v1(request, now, policy);
  if (evaluation.decision != RegistryPolicyDecisionV1::accepted ||
      !evaluation.accepted_root_index)
    return Result<RegistryPublicInspectionV1>::fail(
        ErrorCode::unsupported, "issuer registry is not locally accepted");
  const auto& accepted =
      policy.accepted_roots[*evaluation.accepted_root_index];
  RegistryPublicInspectionV1 inspection{
      issuer_registry_root_id_v1(accepted.context), accepted.context.epoch,
      accepted.context.valid_from, accepted.context.valid_until,
      accepted.context.depth,
      std::uint32_t{1} << accepted.context.depth,
      accepted.authorization_count, std::nullopt};
  if (policy.reveal_public_vct_in_inspection &&
      policy.required_public_vct)
    inspection.public_vct = policy.required_public_vct;
  return Result<RegistryPublicInspectionV1>::ok(std::move(inspection));
}

std::string format_issuer_registry_public_inspection_v1(
    const RegistryPublicInspectionV1& inspection) {
  std::ostringstream output;
  output << "trust=registry root_id=" << inspection.root_id
         << " epoch=" << inspection.epoch
         << " valid_from=" << inspection.valid_from
         << " valid_until=" << inspection.valid_until
         << " depth=" << static_cast<unsigned>(inspection.depth)
         << " capacity=" << inspection.capacity
         << " anonymity_set_upper_bound="
         << inspection.anonymity_set_upper_bound;
  if (inspection.public_vct)
    output << " public_vct=" << *inspection.public_vct;
  return output.str();
}

Result<bool> verify_authorized_registry_bearer_v1(
    const Envelope& envelope, const Request& expected_request,
    std::uint64_t now, const IssuerRegistryVerifierPolicyV1& policy,
    FlatBearerReplayStoreV1& replay_store, const Limits& limits) {
  const auto evaluation =
      evaluate_issuer_registry_policy_v1(expected_request, now, policy);
  if (evaluation.decision != RegistryPolicyDecisionV1::accepted)
    return policy_failure(evaluation.decision);
  return verify_registry_bearer_v1(envelope, expected_request, now,
                                   replay_store, limits);
}

Result<bool> verify_authorized_holder_registry_v1(
    const HolderBoundEnvelope& envelope,
    const HolderBoundVerifierPolicyV1& expected, std::uint64_t now,
    const IssuerRegistryVerifierPolicyV1& policy,
    HolderBoundReplayStoreV1& replay_store, const Limits& limits) {
  const auto evaluation = evaluate_issuer_registry_policy_v1(
      expected.request, now, policy);
  if (evaluation.decision != RegistryPolicyDecisionV1::accepted)
    return policy_failure(evaluation.decision);
  return verify_holder_registry_bound_v1(envelope, expected, now,
                                         replay_store, limits);
}

}  // namespace sd_jwt_zk
