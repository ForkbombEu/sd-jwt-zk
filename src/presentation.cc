#include "sd_jwt_zk/presentation.h"

#include <algorithm>

namespace sd_jwt_zk {
namespace {

constexpr std::size_t kMaxPurposeBytes = 256;

Result<Bytes> status_bytes(const PresentationPolicyV1& policy);

Result<std::string> bound_audience(const PresentationPolicyV1& policy) {
  if (policy.audience.empty() || policy.purpose.empty() ||
      policy.purpose.size() > kMaxPurposeBytes ||
      policy.audience.find('\x1f') != std::string::npos ||
      policy.purpose.find('\x1f') != std::string::npos)
    return Result<std::string>::fail(ErrorCode::malformed,
                                     "invalid audience or purpose");
  return Result<std::string>::ok(policy.audience + "\x1f" + policy.purpose);
}

Result<bool> validate_policy_shape(const PresentationPolicyV1& policy) {
  const auto audience = bound_audience(policy);
  if (!audience) return Result<bool>::fail(audience.error->code, audience.error->message);
  const auto status = status_bytes(policy);
  if (!status) return Result<bool>::fail(status.error->code, status.error->message);
  if (policy.nonce.empty() || policy.time_min > policy.time_max ||
      !p256_key_is_valid(policy.issuer_key))
    return Result<bool>::fail(ErrorCode::malformed, "invalid presentation policy");
  return Result<bool>::ok(true);
}

Result<Bytes> status_bytes(const PresentationPolicyV1& policy) {
  if (policy.status == StatusRequirementV1::forbidden) {
    if (policy.trusted_snapshot)
      return Result<Bytes>::fail(ErrorCode::malformed,
                                 "status-forbidden policy has snapshot");
    return Result<Bytes>::ok({});
  }
  if (policy.status != StatusRequirementV1::required || !policy.trusted_snapshot)
    return Result<Bytes>::fail(ErrorCode::malformed,
                               "status-required policy lacks trusted snapshot");
  if (policy.trusted_snapshot->snapshot.issuer != status_issuer_v1(policy.issuer_key))
    return Result<Bytes>::fail(ErrorCode::malformed,
                               "trusted snapshot issuer does not match exact key");
  return Result<Bytes>::ok(encode_status_policy_v1(*policy.trusted_snapshot));
}

Result<Request> make_request(const PresentationPolicyV1& policy,
                             const CircuitIdentity& identity,
                             const Bytes& claim_policy,
                             const Bytes& claim_result,
                             const Limits& limits) {
  const auto audience = bound_audience(policy);
  const auto status = status_bytes(policy);
  if (!audience) return Result<Request>::fail(audience.error->code, audience.error->message);
  if (!status) return Result<Request>::fail(status.error->code, status.error->message);
  if (policy.nonce.empty() || policy.time_min > policy.time_max ||
      !p256_key_is_valid(policy.issuer_key))
    return Result<Request>::fail(ErrorCode::malformed, "invalid presentation policy");
  Request request{identity, *audience.value, policy.nonce, policy.time_min,
                  policy.time_max, claim_policy, claim_result,
                  flat_bearer_exact_key_trust_v1(policy.issuer_key), *status.value};
  const auto encoded = encode_request(request, limits);
  if (!encoded) return Result<Request>::fail(encoded.error->code, encoded.error->message);
  return Result<Request>::ok(std::move(request));
}

class BearerRelationReplay final : public FlatBearerReplayStoreV1 {
 public:
  bool consume(std::string_view, std::string_view, std::uint64_t) override { return true; }
};
class HolderRelationReplay final : public HolderBoundReplayStoreV1 {
 public:
  bool consume(std::string_view, std::string_view, std::uint64_t) override { return true; }
};

PresentationResultV1 map_result(const Result<bool>& result) {
  if (result && *result.value) return PresentationResultV1::accepted;
  if (!result.error) return PresentationResultV1::verification_failed;
  if (result.error->message.find("nonce has already") != std::string::npos)
    return PresentationResultV1::replayed;
  if (result.error->message.find("validity window") != std::string::npos ||
      result.error->message.find("outside its validity") != std::string::npos)
    return PresentationResultV1::expired;
  if (result.error->message.find("status") != std::string::npos)
    return PresentationResultV1::status_required;
  if (result.error->code == ErrorCode::unsupported)
    return PresentationResultV1::unsupported;
  if (result.error->code == ErrorCode::malformed ||
      result.error->code == ErrorCode::noncanonical ||
      result.error->code == ErrorCode::limit)
    return PresentationResultV1::malformed;
  return PresentationResultV1::verification_failed;
}

}  // namespace

Result<BearerPresentationRequestV1> BuildBearerPresentationRequestV1(
    const PresentationPolicyV1& policy, const Limits& limits) {
  const auto shape = validate_policy_shape(policy);
  if (!shape) return Result<BearerPresentationRequestV1>::fail(shape.error->code,
                                                                  shape.error->message);
  const auto request = make_request(policy, flat_bearer_circuit_identity_v1(),
                                    flat_bearer_policy_v1(),
                                    flat_bearer_true_policy_result_v1(), limits);
  if (!request) return Result<BearerPresentationRequestV1>::fail(request.error->code,
                                                                    request.error->message);
  return Result<BearerPresentationRequestV1>::ok({std::move(*request.value)});
}

Result<HolderPresentationRequestV1> BuildHolderPresentationRequestV1(
    const PresentationPolicyV1& policy, const Limits& limits) {
  const auto shape = validate_policy_shape(policy);
  if (!shape) return Result<HolderPresentationRequestV1>::fail(shape.error->code,
                                                                  shape.error->message);
  const auto credential = holder_bound_credential_circuit_identity_v1();
  const auto request = make_request(policy, credential, holder_bound_policy_v1(),
                                    holder_bound_true_policy_result_v1(), limits);
  if (!request) return Result<HolderPresentationRequestV1>::fail(request.error->code,
                                                                    request.error->message);
  return Result<HolderPresentationRequestV1>::ok(
      {holder_bound_verifier_policy_v1(*request.value)});
}

Result<bool> VerifyRelation(const BearerPresentationRequestV1& expected,
                            const Envelope& envelope, std::uint64_t now,
                            const Limits& limits) {
  BearerRelationReplay replay;
  return verify_flat_bearer_v1(envelope, expected.request, now, replay, limits);
}

Result<bool> VerifyRelation(const HolderPresentationRequestV1& expected,
                            const HolderBoundEnvelope& envelope,
                            std::uint64_t now, const Limits& limits) {
  HolderRelationReplay replay;
  return verify_holder_bound_v1(envelope, expected.policy, now, replay, limits);
}

PresentationResultV1 VerifyPresentation(
    const BearerPresentationRequestV1& expected, const Envelope& envelope,
    std::uint64_t now, FlatBearerReplayStoreV1& replay_store,
    const Limits& limits) {
  return map_result(verify_flat_bearer_v1(envelope, expected.request, now,
                                           replay_store, limits));
}

PresentationResultV1 VerifyPresentation(
    const HolderPresentationRequestV1& expected,
    const HolderBoundEnvelope& envelope, std::uint64_t now,
    HolderBoundReplayStoreV1& replay_store, const Limits& limits) {
  return map_result(verify_holder_bound_v1(envelope, expected.policy, now,
                                            replay_store, limits));
}

}  // namespace sd_jwt_zk
