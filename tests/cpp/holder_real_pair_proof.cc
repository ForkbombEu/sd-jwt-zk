#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/resource.h>

#include "sd_jwt_zk/holder_bound_proof.h"

namespace {

constexpr char kKbJwt[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9."
    "eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUiLCJub25jZSI6ImNoYWxsZW5nZS0wMDAxIiwiaWF0IjoxNzc3MzM0NDAwLCJzZF9oYXNoIjoiNERvQ0R1X21JR0xaUGJ3aGhqVGlzWFgteWp0eUZ5em50TjcwV0dvYncyZyJ9."
    "cFheyMPYhStqIfLtdZQS4yWByMqI-9YUGUakJafMh7gFVvMPy0lXS3l8QCDP_IBATxcl8lWylqzc9seGMvQTwA";
constexpr char kIssuerX[] =
    "mghCtkDvYlhoIJv3V9ntUSzKasQTW2-ieOZCkmyat6Q";
constexpr char kIssuerY[] =
    "WZmOD4TDO1MqiMdF-bLKRzqFOsZ4l-lrOBo5vNcVTAQ";
constexpr char kIssuer[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ."
    "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJkR1dlTzhURGpONm9DdkhKQ3VRX2gxaWEtc2dvV3dZWXVjVGVzeHlTc2hnIiwieSI6IjdJdzZfQVJGVWF0aTFwemVWdzdYQUVIVkwxcVpMVldkNGkxMzJUNGVibm8ifX19."
    "zC41XCiPUiMI38m0IrKCHoC0XmOW6I0N0Sx5QEUKKmTXNbvW0DxK_4zXPqai0K1-vi0MwVzUl835id3-znLG0w";
constexpr char kDisclosure[] =
    "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";

class ReplayStore final : public sd_jwt_zk::HolderBoundReplayStoreV1 {
 public:
  bool consume(std::string_view, std::string_view,
               std::uint64_t) override {
    if (used_) return false;
    used_ = true;
    return true;
  }

 private:
  bool used_{};
};

}  // namespace

int main() {
  try {
    const auto issuer_key = sd_jwt_zk::decode_p256_jwk(kIssuerX, kIssuerY);
    if (!issuer_key) throw std::runtime_error(issuer_key.error->message);
    const std::string presentation =
        std::string(kIssuer) + "~" + kDisclosure + "~";
    const auto credential =
        sd_jwt_zk::holder_credential_witness_from_presentation_v1(
            presentation, *issuer_key.value);
    if (!credential) throw std::runtime_error(credential.error->message);
    const auto& holder_key = *credential.value->credential.payload.holder_key;
    const auto holder_x = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(holder_key.x.begin(), holder_key.x.end()));
    const auto holder_y = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(holder_key.y.begin(), holder_key.y.end()));
    const auto kb = sd_jwt_zk::holder_kb_witness_from_compact_jwt_v1(
        kKbJwt, holder_x, holder_y);
    if (!kb) throw std::runtime_error(kb.error->message);

    const auto construction_start = std::chrono::steady_clock::now();
    sd_jwt_zk::Request request{
        {}, "https://verifier.example", "challenge-0001", 1777334300,
        1777334500, sd_jwt_zk::holder_bound_policy_v1(),
        sd_jwt_zk::holder_bound_true_policy_result_v1(),
        sd_jwt_zk::flat_bearer_exact_key_trust_v1(*issuer_key.value), {}};
    const auto policy =
        sd_jwt_zk::holder_bound_verifier_policy_v1(std::move(request));
    const auto metrics = sd_jwt_zk::holder_bound_circuit_metrics_v1();
    const auto constructed = std::chrono::steady_clock::now();

    const auto first = sd_jwt_zk::prove_holder_bound_v1(
        policy, *credential.value, *kb.value);
    if (!first) throw std::runtime_error(first.error->message);
    const auto first_proved = std::chrono::steady_clock::now();
    const auto second = sd_jwt_zk::prove_holder_bound_v1(
        policy, *credential.value, *kb.value);
    if (!second) throw std::runtime_error(second.error->message);
    const auto second_proved = std::chrono::steady_clock::now();
    if (first.value->credential_commitment ==
            second.value->credential_commitment ||
        first.value->kb_commitment == second.value->kb_commitment ||
        (first.value->credential_proof == second.value->credential_proof &&
         first.value->kb_proof == second.value->kb_proof))
      throw std::runtime_error("repeated holder evidence was not randomized");

    ReplayStore first_replay;
    const auto first_verified = sd_jwt_zk::verify_holder_bound_v1(
        *first.value, policy, 1777334400, first_replay);
    if (!first_verified || !*first_verified.value)
      throw std::runtime_error("first real holder pair did not verify");
    ReplayStore second_replay;
    const auto second_verified = sd_jwt_zk::verify_holder_bound_v1(
        *second.value, policy, 1777334400, second_replay);
    if (!second_verified || !*second_verified.value)
      throw std::runtime_error("second real holder pair did not verify");

    auto mixed = *first.value;
    mixed.kb_proof = second.value->kb_proof;
    ReplayStore mixed_replay;
    if (sd_jwt_zk::verify_holder_bound_v1(
            mixed, policy, 1777334400, mixed_replay))
      throw std::runtime_error("mixed real holder pair verified");
    auto changed_bridge = *first.value;
    changed_bridge.bridge_public.front() ^= 1;
    ReplayStore bridge_replay;
    if (sd_jwt_zk::verify_holder_bound_v1(
            changed_bridge, policy, 1777334400, bridge_replay))
      throw std::runtime_error("mutated real holder bridge verified");
    const auto verified = std::chrono::steady_clock::now();

    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    const auto aggregate = first.value->credential_proof.size() +
                           first.value->kb_proof.size();
    std::cout
        << "credential-public-inputs=" << metrics.credential_public_inputs
        << " credential-private-inputs=" << metrics.credential_private_inputs
        << " credential-terms=" << metrics.credential_terms
        << " credential-proof-bytes="
        << first.value->credential_proof.size()
        << " kb-public-inputs=" << metrics.kb_public_inputs
        << " kb-private-inputs=" << metrics.kb_private_inputs
        << " kb-terms=" << metrics.kb_terms
        << " kb-proof-bytes=" << first.value->kb_proof.size()
        << " aggregate-proof-bytes=" << aggregate
        << " construct-ms="
        << std::chrono::duration_cast<std::chrono::milliseconds>(
               constructed - construction_start)
               .count()
        << " prove-1-ms="
        << std::chrono::duration_cast<std::chrono::milliseconds>(
               first_proved - constructed)
               .count()
        << " prove-2-ms="
        << std::chrono::duration_cast<std::chrono::milliseconds>(
               second_proved - first_proved)
               .count()
        << " verify-and-negatives-ms="
        << std::chrono::duration_cast<std::chrono::milliseconds>(
               verified - second_proved)
               .count()
        << " peak-rss-kb=" << usage.ru_maxrss << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
