#include <algorithm>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>

#include "sd_jwt_zk/holder_bound_proof.h"
#include "sd_jwt_zk/issuer_registry.h"
#include "sd_jwt_zk/issuer_registry_policy.h"
#include "sd_jwt_zk/registry_bearer_proof.h"
#include "util/log.h"

namespace {
constexpr char kIssuerX[] = "mghCtkDvYlhoIJv3V9ntUSzKasQTW2-ieOZCkmyat6Q";
constexpr char kIssuerY[] = "WZmOD4TDO1MqiMdF-bLKRzqFOsZ4l-lrOBo5vNcVTAQ";
constexpr char kIssuer[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ."
    "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJkR1dlTzhURGpONm9DdkhKQ3VRX2gxaWEtc2dvV3dZWXVjVGVzeHlTc2hnIiwieSI6IjdJdzZfQVJGVWF0aTFwemVWdzdYQUVIVkwxcVpMVldkNGkxMzJUNGVibm8ifX19."
    "zC41XCiPUiMI38m0IrKCHoC0XmOW6I0N0Sx5QEUKKmTXNbvW0DxK_4zXPqai0K1-vi0MwVzUl835id3-znLG0w";
constexpr char kDisclosure[] =
    "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
constexpr char kKbJwt[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9."
    "eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUiLCJub25jZSI6ImNoYWxsZW5nZS0wMDAxIiwiaWF0IjoxNzc3MzM0NDAwLCJzZF9oYXNoIjoiNERvQ0R1X21JR0xaUGJ3aGhqVGlzWFgteWp0eUZ5em50TjcwV0dvYncyZyJ9."
    "cFheyMPYhStqIfLtdZQS4yWByMqI-9YUGUakJafMh7gFVvMPy0lXS3l8QCDP_IBATxcl8lWylqzc9seGMvQTwA";

void require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
class Replay final : public sd_jwt_zk::HolderBoundReplayStoreV1 {
 public:
  bool consume(std::string_view, std::string_view, std::uint64_t) override {
    bool expected = false;
    return used_.compare_exchange_strong(expected, true);
  }
 private:
  std::atomic<bool> used_{false};
};
}  // namespace

int main() {
  try {
    proofs::set_log_level(proofs::ERROR);
    const auto issuer = sd_jwt_zk::decode_p256_jwk(kIssuerX, kIssuerY);
    require(static_cast<bool>(issuer), "issuer fixture rejected");
    const sd_jwt_zk::IssuerAuthorizationRecordV1 record{
        *issuer.value, "example", 1777334200, 1777334600};
    const sd_jwt_zk::IssuerAuthorizationRecordV1 other{
        *issuer.value, "example/other", 1777334200, 1777334600};
    const auto registry = sd_jwt_zk::build_issuer_registry_v1(
        {other, record}, sd_jwt_zk::kIssuerRegistryDepthV1, 9,
        1777334300, 1777334500);
    require(static_cast<bool>(registry), "holder registry rejected");
    const auto path = std::find_if(
        registry.value->paths.begin(), registry.value->paths.end(),
        [](const auto& item) { return item.record.vct == "example"; });
    require(path != registry.value->paths.end(), "holder path missing");
    const std::string presentation = std::string(kIssuer) + "~" +
                                     kDisclosure + "~";
    const auto credential =
        sd_jwt_zk::holder_registry_credential_witness_from_presentation_v1(
            presentation, *path);
    require(static_cast<bool>(credential), "holder registry witness rejected");
    const auto& holder =
        *credential.value->credential.credential.payload.holder_key;
    const auto holder_x = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(holder.x.begin(), holder.x.end()));
    const auto holder_y = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(holder.y.begin(), holder.y.end()));
    const auto kb = sd_jwt_zk::holder_kb_witness_from_compact_jwt_v1(
        kKbJwt, holder_x, holder_y);
    require(static_cast<bool>(kb), "holder KB witness rejected");
    const auto trust = sd_jwt_zk::encode_registry_trust_context_v1(
        sd_jwt_zk::registry_trust_context_v1(*registry.value));
    require(static_cast<bool>(trust), "holder trust context rejected");
    sd_jwt_zk::Request request{};
    request.audience = "https://verifier.example";
    request.nonce = "challenge-0001";
    request.time_min = 1777334300;
    request.time_max = 1777334500;
    request.policy = sd_jwt_zk::holder_bound_policy_v1();
    request.policy_result = sd_jwt_zk::holder_bound_true_policy_result_v1();
    request.trust_public = *trust.value;
    const auto policy = sd_jwt_zk::holder_registry_verifier_policy_v1(request);
    sd_jwt_zk::Limits limits;
    limits.max_proof = 8 * 1024 * 1024;
    const auto envelope = sd_jwt_zk::prove_holder_registry_bound_v1(
        policy, *credential.value, *kb.value, limits);
    if (!envelope && envelope.error)
      std::cerr << "holder registry prove error: "
                << envelope.error->message << '\n';
    require(static_cast<bool>(envelope), "holder registry proof failed");
    const auto trust_context =
        sd_jwt_zk::registry_trust_context_v1(*registry.value);
    sd_jwt_zk::IssuerRegistryVerifierPolicyV1 local_policy{
        {{trust_context, 2, false, std::nullopt}}, 9,
        sd_jwt_zk::kIssuerRegistryDepthV1, 2, std::nullopt, false};
    Replay replay;
    const auto accepted = sd_jwt_zk::verify_authorized_holder_registry_v1(
        *envelope.value, policy, 1777334400, local_policy, replay, limits);
    require(accepted && *accepted.value, "holder registry proof rejected");
    auto changed_bridge = *envelope.value;
    changed_bridge.bridge_public[0] ^= 1;
    Replay bridge_replay;
    require(!sd_jwt_zk::verify_holder_registry_bound_v1(
                changed_bridge, policy, 1777334400, bridge_replay, limits),
            "holder registry bridge substitution accepted");
    auto exact_policy = policy;
    exact_policy.credential_identity =
        sd_jwt_zk::holder_bound_credential_circuit_identity_v1();
    exact_policy.kb_identity = sd_jwt_zk::holder_bound_kb_circuit_identity_v1();
    exact_policy.request.identity = exact_policy.credential_identity;
    Replay exact_replay;
    require(!sd_jwt_zk::verify_holder_registry_bound_v1(
                *envelope.value, exact_policy, 1777334400, exact_replay,
                limits),
            "exact-key holder mode accepted registry evidence");
    auto changed_root_policy = policy;
    changed_root_policy.request.trust_public[1] ^= 1;
    auto changed_root_envelope = *envelope.value;
    changed_root_envelope.request = changed_root_policy.request;
    Replay root_replay;
    require(!sd_jwt_zk::verify_holder_registry_bound_v1(
                changed_root_envelope, changed_root_policy, 1777334400,
                root_replay, limits),
            "holder registry root substitution accepted");
    auto reject_context = [&](std::size_t byte, std::uint8_t mask,
                              const char* message) {
      auto changed_policy = policy;
      changed_policy.request.trust_public[byte] ^= mask;
      auto changed_envelope = *envelope.value;
      changed_envelope.request = changed_policy.request;
      Replay store;
      require(!sd_jwt_zk::verify_holder_registry_bound_v1(
                  changed_envelope, changed_policy, 1777334400, store, limits),
              message);
    };
    reject_context(33 + 7, 1, "holder registry epoch substitution accepted");
    reject_context(49 + 6, 1,
                   "holder registry validity-window substitution accepted");
    reject_context(57, 3, "holder registry depth substitution accepted");
    auto bad_path = *credential.value;
    bad_path.authorization.siblings[0][0] ^= 1;
    require(!sd_jwt_zk::prove_holder_registry_bound_v1(
                policy, bad_path, *kb.value, limits),
            "holder registry sibling substitution proved");
    auto bad_index = *credential.value;
    bad_index.authorization.index ^= 1;
    require(!sd_jwt_zk::prove_holder_registry_bound_v1(
                policy, bad_index, *kb.value, limits),
            "holder registry index/direction substitution proved");
    auto bad_epoch = *credential.value;
    ++bad_epoch.authorization.epoch;
    require(!sd_jwt_zk::prove_holder_registry_bound_v1(
                policy, bad_epoch, *kb.value, limits),
            "holder registry private epoch substitution proved");
    auto bad_vct = *credential.value;
    bad_vct.authorization.record.vct = "example/other";
    require(!sd_jwt_zk::prove_holder_registry_bound_v1(
                policy, bad_vct, *kb.value, limits),
            "holder registry VCT substitution proved");
    auto bad_key = *credential.value;
    bad_key.authorization.record.issuer_key.x[0] ^= 1;
    require(!sd_jwt_zk::prove_holder_registry_bound_v1(
                policy, bad_key, *kb.value, limits),
            "holder registry key substitution proved");
    auto expired = *credential.value;
    expired.authorization.record.not_after = 1777334399;
    require(!sd_jwt_zk::prove_holder_registry_bound_v1(
                policy, expired, *kb.value, limits),
            "holder registry expired authorization proved");
    require(!sd_jwt_zk::verify_holder_registry_bound_v1(
                *envelope.value, policy, 1777334400, replay, limits),
            "holder registry replay accepted");
    const auto metrics = sd_jwt_zk::holder_registry_circuit_metrics_v1();
    std::cout << "holder registry real pair passed; credential-bytes="
              << envelope.value->credential_proof.size()
              << " kb-bytes=" << envelope.value->kb_proof.size()
              << " credential-public=" << metrics.credential_public_inputs
              << " credential-private=" << metrics.credential_private_inputs
              << " credential-terms=" << metrics.credential_terms
              << " kb-public=" << metrics.kb_public_inputs
              << " kb-private=" << metrics.kb_private_inputs
              << " kb-terms=" << metrics.kb_terms << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
