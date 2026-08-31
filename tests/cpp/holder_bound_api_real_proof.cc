#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "merkle/merkle_tree.h"
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
    auto credential =
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
    const auto credential_binding =
        sd_jwt_zk::status_credential_binding_v1(
            credential.value->credential.signing_digest);
    const auto status_issuer = sd_jwt_zk::status_issuer_v1(*issuer.value);
    const auto valid_leaf = sd_jwt_zk::status_leaf_v1(
        status_issuer, 5, credential_binding,
        sd_jwt_zk::CredentialStatusV1::valid);
    auto other_binding = credential_binding;
    other_binding[0] ^= 1;
    const auto other_valid_leaf = sd_jwt_zk::status_leaf_v1(
        status_issuer, 5, other_binding,
        sd_jwt_zk::CredentialStatusV1::valid);
    const auto revoked_leaf = sd_jwt_zk::status_leaf_v1(
        status_issuer, 5, credential_binding,
        sd_jwt_zk::CredentialStatusV1::revoked);
    proofs::MerkleTree status_tree(4);
    status_tree.set_leaf(0, other_valid_leaf);
    status_tree.set_leaf(1, revoked_leaf);
    status_tree.set_leaf(2, valid_leaf);
    status_tree.set_leaf(3, revoked_leaf);
    const auto status_root = status_tree.build_tree();
    const std::size_t status_index = 2;
    std::vector<proofs::Digest> status_path;
    status_tree.generate_compressed_proof(status_path, &status_index, 1);
    const std::size_t other_status_index = 0;
    std::vector<proofs::Digest> other_status_path;
    status_tree.generate_compressed_proof(other_status_path, &other_status_index,
                                          1);
    request.status_public = sd_jwt_zk::encode_status_policy_v1(
        {{status_issuer, status_root, 5, 1777334300, 1777334500}});
    const auto status_policy =
        sd_jwt_zk::decode_status_policy_v1(request.status_public);
    require(static_cast<bool>(status_policy), "status policy did not decode");
    const sd_jwt_zk::StatusMembershipWitnessV1 status_witness{status_index,
                                                               status_path};
    const auto policy = sd_jwt_zk::holder_bound_verifier_policy_v1(request);

    const auto envelope = sd_jwt_zk::prove_holder_bound_v1(
        policy, *credential.value, *kb.value, status_witness);
    if (!envelope)
      throw std::runtime_error("production holder-bound prover rejected fixture: " +
                               envelope.error->message);
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
    auto tampered_status = *envelope.value;
    tampered_status.status_proof.back() ^= 1;
    OneShotReplayStore tampered_status_store;
    require(!sd_jwt_zk::verify_holder_bound_v1(
                tampered_status, policy, 1777334400, tampered_status_store),
            "production holder-bound verifier accepted invalid status proof");
    // This is a separately valid VALID status proof under the *same* root and
    // request context, but for a different hidden credential binding.  Swapping
    // both framed fields must reach the presentation-circuit bridge constraint
    // and reject rather than relying on a policy or context mismatch.
    const auto same_context = sd_jwt_zk::transcript_seed(policy.request);
    const auto other_status = sd_jwt_zk::prove_status_membership_v1(
        status_policy.value->snapshot, other_binding, other_status_index,
        other_status_path, same_context);
    require(static_cast<bool>(other_status),
            "other credential status proof rejected");
    const auto other_verified = sd_jwt_zk::verify_status_membership_v1(
        *other_status.value, status_policy.value->snapshot, status_issuer, 5,
        1777334400, same_context);
    require(other_verified && *other_verified.value,
            "other credential status proof did not verify standalone");
    auto other_credential_splice = *envelope.value;
    other_credential_splice.status_bridge_commitment =
        other_status.value->bridge_commitment;
    other_credential_splice.status_proof = other_status.value->proof;
    OneShotReplayStore other_credential_store;
    require(!sd_jwt_zk::verify_holder_bound_v1(
                other_credential_splice, policy, 1777334400,
                other_credential_store),
            "holder verifier accepted a different credential status proof");
    auto alternate_bridge = sd_jwt_zk::transcript_seed(policy.request);
    alternate_bridge[0] ^= 1;
    auto alternate_status = sd_jwt_zk::prove_status_membership_v1(
        status_policy.value->snapshot, credential_binding, status_index,
        status_path, alternate_bridge);
    require(static_cast<bool>(alternate_status), "alternate status proof rejected");
    const auto alternate_verified = sd_jwt_zk::verify_status_membership_v1(
        *alternate_status.value, status_policy.value->snapshot, status_issuer,
        5, 1777334400, alternate_bridge);
    require(alternate_verified && *alternate_verified.value,
            "alternate status proof did not verify in its own bridge context");
    // A valid status component from a distinct presentation bridge is not
    // interchangeable with this holder envelope.
    auto spliced_status = *envelope.value;
    spliced_status.status_bridge_commitment =
        alternate_status.value->bridge_commitment;
    spliced_status.status_proof = alternate_status.value->proof;
    OneShotReplayStore splice_store;
    require(!sd_jwt_zk::verify_holder_bound_v1(
                spliced_status, policy, 1777334400, splice_store),
            "holder status component splice accepted");
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
