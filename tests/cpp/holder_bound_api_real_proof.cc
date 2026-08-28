#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

#include "sd_jwt_zk/holder_bound_proof.h"

namespace {

constexpr char kIssuerX[] = "mghCtkDvYlhoIJv3V9ntUSzKasQTW2-ieOZCkmyat6Q";
constexpr char kIssuerY[] = "WZmOD4TDO1MqiMdF-bLKRzqFOsZ4l-lrOBo5vNcVTAQ";
constexpr char kIssuer[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ."
    "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJkR1dlTzhURGpONm9DdkhKQ3VRX2gxaWEtc2dvV3dZWXVjVGVzeHlTc2hnIiwieSI6IjdJdzZfQVJGVWF0aTFwemVWdzdYQUVIVkwxcVpMVldkNGkxMzJUNGVibm8ifX19."
    "zC41XCiPUiMI38m0IrKCHoC0XmOW6I0N0Sx5QEUKKmTXNbvW0DxK_4zXPqai0K1-vi0MwVzUl835id3-znLG0w";
constexpr char kDisclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
constexpr char kKbJwt[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9."
    "eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUiLCJub25jZSI6ImNoYWxsZW5nZS0wMDAxIiwiaWF0IjoxNzc3MzM0NDAwLCJzZF9oYXNoIjoiNERvQ0R1X21JR0xaUGJ3aGhqVGlzWFgteWp0eUZ5em50TjcwV0dvYncyZyJ9."
    "cFheyMPYhStqIfLtdZQS4yWByMqI-9YUGUakJafMh7gFVvMPy0lXS3l8QCDP_IBATxcl8lWylqzc9seGMvQTwA";

class OneShotReplayStore final : public sd_jwt_zk::HolderBoundReplayStoreV1 {
 public:
  bool consume(std::string_view, std::string_view, std::uint64_t) override {
    bool expected = false;
    return consumed_.compare_exchange_strong(expected, true);
  }

 private:
  std::atomic<bool> consumed_{false};
};

void require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}

}  // namespace

int main() {
  try {
    const auto issuer = sd_jwt_zk::decode_p256_jwk(kIssuerX, kIssuerY);
    require(static_cast<bool>(issuer), "issuer key fixture rejected");
    const std::string presentation = std::string(kIssuer) + "~" +
                                     kDisclosure + "~";
    const auto credential =
        sd_jwt_zk::holder_credential_witness_from_presentation_v1(
            presentation, *issuer.value);
    require(static_cast<bool>(credential), "credential witness rejected");
    const auto& holder = *credential.value->credential.payload.holder_key;
    const auto holder_x = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(holder.x.begin(), holder.x.end()));
    const auto holder_y = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(holder.y.begin(), holder.y.end()));
    const auto kb = sd_jwt_zk::holder_kb_witness_from_compact_jwt_v1(
        kKbJwt, holder_x, holder_y);
    require(static_cast<bool>(kb), "KB witness rejected");

    sd_jwt_zk::Request request{};
    request.audience = "https://verifier.example";
    request.nonce = "challenge-0001";
    request.time_min = 1777334300;
    request.time_max = 1777334500;
    request.policy = sd_jwt_zk::holder_bound_policy_v1();
    request.policy_result = sd_jwt_zk::holder_bound_true_policy_result_v1();
    request.trust_public.insert(request.trust_public.end(), issuer.value->x.begin(),
                                issuer.value->x.end());
    request.trust_public.insert(request.trust_public.end(), issuer.value->y.begin(),
                                issuer.value->y.end());
    const auto policy = sd_jwt_zk::holder_bound_verifier_policy_v1(request);

    const auto envelope = sd_jwt_zk::prove_holder_bound_v1(
        policy, *credential.value, *kb.value);
    require(static_cast<bool>(envelope),
            "production holder-bound prover rejected fixture");
    OneShotReplayStore replay;
    const auto accepted = sd_jwt_zk::verify_holder_bound_v1(
        *envelope.value, policy, 1777334400, replay);
    require(accepted && *accepted.value,
            "production holder-bound verifier rejected fixture");
    auto changed_bridge = *envelope.value;
    changed_bridge.bridge_public.front() ^= 1;
    OneShotReplayStore changed_bridge_store;
    require(!sd_jwt_zk::verify_holder_bound_v1(
                changed_bridge, policy, 1777334400, changed_bridge_store),
            "production holder-bound verifier accepted changed bridge tag");
    auto mixed_components = *envelope.value;
    std::swap(mixed_components.credential_proof, mixed_components.kb_proof);
    OneShotReplayStore mixed_store;
    require(!sd_jwt_zk::verify_holder_bound_v1(
                mixed_components, policy, 1777334400, mixed_store),
            "production holder-bound verifier accepted mixed components");
    auto changed_request = policy;
    changed_request.request.audience = "https://other.example";
    OneShotReplayStore changed_request_store;
    require(!sd_jwt_zk::verify_holder_bound_v1(
                *envelope.value, changed_request, 1777334400,
                changed_request_store),
            "production holder-bound verifier accepted audience substitution");
    auto bearer_policy = policy;
    bearer_policy.request.identity.binding = sd_jwt_zk::Binding::bearer;
    OneShotReplayStore bearer_store;
    require(!sd_jwt_zk::verify_holder_bound_v1(
                *envelope.value, bearer_policy, 1777334400, bearer_store),
            "bearer policy accepted holder-bound evidence");
    const auto replayed = sd_jwt_zk::verify_holder_bound_v1(
        *envelope.value, policy, 1777334400, replay);
    require(!replayed,
            "production holder-bound verifier accepted replay");
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
