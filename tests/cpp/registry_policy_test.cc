#include <iostream>
#include <stdexcept>
#include <string>

#include "sd_jwt_zk/issuer_registry_policy.h"

namespace {
void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
class Replay final : public sd_jwt_zk::FlatBearerReplayStoreV1 {
 public:
  bool consume(std::string_view, std::string_view, std::uint64_t) override {
    return true;
  }
};
sd_jwt_zk::Request request_for(
    const sd_jwt_zk::RegistryTrustContextV1& context) {
  auto encoded = sd_jwt_zk::encode_registry_trust_context_v1(context);
  require(static_cast<bool>(encoded), "test context encoding failed");
  sd_jwt_zk::CircuitIdentity identity{
      sd_jwt_zk::Binding::bearer, sd_jwt_zk::Trust::registry, 140, {},
      "p256-base", 4, 32};
  return {identity, "aud", "nonce", 100, 200, {'p'}, {1},
          *encoded.value, {}};
}
}  // namespace

int main() {
  try {
    sd_jwt_zk::RegistryTrustContextV1 old{};
    old.root[0] = 1;
    old.epoch = 7;
    old.valid_from = 100;
    old.valid_until = 200;
    old.depth = 2;
    auto replacement = old;
    replacement.root[0] = 2;
    replacement.epoch = 8;
    replacement.valid_from = 150;
    replacement.valid_until = 250;
    sd_jwt_zk::IssuerRegistryVerifierPolicyV1 policy{
        {{old, 3, false, std::nullopt},
         {replacement, 4, false, std::string("example")}},
        7, 2, 2, std::nullopt, false};
    const auto old_request = request_for(old);
    const auto replacement_request = request_for(replacement);
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                old_request, 175, policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::accepted,
            "accepted overlap old root rejected");
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                replacement_request, 175, policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::accepted,
            "accepted overlap replacement root rejected");

    auto rollback = policy;
    rollback.minimum_epoch = 8;
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                old_request, 175, rollback).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::rollback_epoch,
            "rollback epoch accepted");
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                replacement_request, 175, rollback).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::accepted,
            "replacement epoch rejected");
    auto revoked = policy;
    revoked.accepted_roots[0].revoked = true;
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                old_request, 175, revoked).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::revoked_root,
            "revoked root accepted");
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                old_request, 99, policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::root_not_yet_valid,
            "future root accepted");
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                old_request, 201, policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::root_expired,
            "expired root accepted");
    auto undersized = policy;
    undersized.minimum_anonymity_set = 4;
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                old_request, 175, undersized).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::undersized_anonymity_set,
            "undersized registry accepted");
    auto wrong_capacity = policy;
    wrong_capacity.required_depth = 3;
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                old_request, 175, wrong_capacity).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::wrong_capacity,
            "wrong-capacity registry accepted");

    auto proof_selected = old;
    proof_selected.valid_until = 201;
    const auto proof_selected_request = request_for(proof_selected);
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                proof_selected_request, 175, policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::unknown_root,
            "proof-supplied root metadata overrode local policy");
    auto unknown = old;
    unknown.root[1] = 1;
    const auto unknown_request = request_for(unknown);
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                unknown_request, 175, policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::unknown_root,
            "unknown root accepted");
    auto exact = old_request;
    exact.identity.trust = sd_jwt_zk::Trust::exact_key;
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                exact, 175, policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::wrong_trust_mode,
            "exact-key mode entered registry policy");

    auto vct_policy = policy;
    vct_policy.required_public_vct = "example";
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                replacement_request, 175, vct_policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::accepted,
            "locally authenticated VCT-scoped root rejected");
    require(sd_jwt_zk::evaluate_issuer_registry_policy_v1(
                old_request, 175, vct_policy).decision ==
                sd_jwt_zk::RegistryPolicyDecisionV1::vct_scope_mismatch,
            "unscoped root satisfied public VCT policy");

    const auto hidden_inspection =
        sd_jwt_zk::inspect_issuer_registry_public_v1(old_request, 175, policy);
    require(static_cast<bool>(hidden_inspection), "safe inspection rejected");
    const auto hidden_text =
        sd_jwt_zk::format_issuer_registry_public_inspection_v1(
            *hidden_inspection.value);
    require(hidden_text.find("issuer") == std::string::npos &&
                hidden_text.find("path") == std::string::npos &&
                hidden_text.find("vct") == std::string::npos &&
                hidden_text.find("capacity=4") != std::string::npos &&
                hidden_text.find("anonymity_set_upper_bound=3") !=
                    std::string::npos,
            "hidden inspection leaked private registry fields");
    vct_policy.reveal_public_vct_in_inspection = true;
    const auto public_inspection = sd_jwt_zk::inspect_issuer_registry_public_v1(
        replacement_request, 175, vct_policy);
    require(public_inspection && public_inspection.value->public_vct ==
                                     std::optional<std::string>("example"),
            "explicit public VCT inspection omitted policy scope");

    sd_jwt_zk::Envelope malformed{unknown_request, {0}};
    Replay replay;
    const auto preproof = sd_jwt_zk::verify_authorized_registry_bearer_v1(
        malformed, unknown_request, 175, policy, replay);
    require(!preproof && preproof.error &&
                preproof.error->code == sd_jwt_zk::ErrorCode::unsupported,
            "unknown root was not rejected before malformed proof parsing");
    std::cout << "registry lifecycle and safe inspection policy passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
