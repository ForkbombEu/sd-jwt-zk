/*
 * Copyright (C) 2026 by The Forkbomb Company
 * designed, written and maintained by Denis Roio
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "merkle/merkle_tree.h"
#include "sd_jwt_zk/holder_bound_proof.h"
#include "nested_es256_fixture.h"

namespace {

constexpr char kIssuerX[] = "mghCtkDvYlhoIJv3V9ntUSzKasQTW2-ieOZCkmyat6Q";
constexpr char kIssuerY[] = "WZmOD4TDO1MqiMdF-bLKRzqFOsZ4l-lrOBo5vNcVTAQ";
constexpr char kIssuer[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ."
    "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJkR1dlTzhURGpONm9DdkhKQ3VRX2gxaWEtc2dvV3dZWXVjVGVzeHlTc2hnIiwieSI6IjdJdzZfQVJGVWF0aTFwemVWdzdYQUVIVkwxcVpMVldkNGkxMzJUNGVibm8ifX19."
    "zC41XCiPUiMI38m0IrKCHoC0XmOW6I0N0Sx5QEUKKmTXNbvW0DxK_4zXPqai0K1-vi0MwVzUl835id3-znLG0w";
constexpr char kDisclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
constexpr char kArrayDisclosure[] = "WyJhcnJheTAwMSIsIml0ZW0iXQ";
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
    const auto digest_text = [](std::string_view disclosure) {
      const auto digest = sd_jwt_zk::sha256_ascii(disclosure);
      return sd_jwt_zk::base64url_encode(sd_jwt_zk::Bytes(digest.begin(), digest.end()));
    };
    constexpr char kHeader[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
    constexpr char kHolderScalar[] =
        "6f1d2c3b4a59687766554433221100ffeeddccbbaa9988776655443322110099";
    sd_jwt_zk::P256Key holder_public{};
    std::array<unsigned char, 64> scratch{};
    require(sd_jwt_zk::test::sign_nested_fixture_es256(
                "holder-key", scratch, &holder_public, kHolderScalar),
            "holder fixture key generation failed");
    const auto x = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(holder_public.x.begin(), holder_public.x.end()));
    const auto y = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(holder_public.y.begin(), holder_public.y.end()));
    const std::string payload_json = "{\"_sd\":[\"" + digest_text(kDisclosure) +
        "\"],\"items\":[{\"...\":\"" + digest_text(kArrayDisclosure) +
        "\"}],\"iss\":\"https://issuer.example\",\"vct\":\"example\",\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" +
        x + "\",\"y\":\"" + y + "\"}}}";
    const std::string payload = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(payload_json.begin(), payload_json.end()));
    const std::string issuer_signing = std::string(kHeader) + "." + payload;
    std::array<unsigned char, 64> issuer_raw{};
    sd_jwt_zk::P256Key issuer_public{};
    require(sd_jwt_zk::test::sign_nested_fixture_es256(
                issuer_signing, issuer_raw, &issuer_public),
            "issuer fixture signing failed");
    const std::string issuer_compact = issuer_signing + "." +
        sd_jwt_zk::base64url_encode(sd_jwt_zk::Bytes(issuer_raw.begin(), issuer_raw.end()));
    const auto issuer = sd_jwt_zk::Result<sd_jwt_zk::P256Key>::ok(issuer_public);
    const std::string credential_presentation = issuer_compact + "~" +
        kDisclosure + "~" + kArrayDisclosure + "~";
    const auto presentation_hash = sd_jwt_zk::sha256_ascii(credential_presentation);
    const std::string kb_payload_json =
        "{\"aud\":\"https://verifier.example\",\"nonce\":\"challenge-0001\",\"iat\":1777334400,\"sd_hash\":\"" +
        sd_jwt_zk::base64url_encode(sd_jwt_zk::Bytes(presentation_hash.begin(), presentation_hash.end())) + "\"}";
    constexpr char kKbHeader[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9";
    const std::string kb_signing = std::string(kKbHeader) + "." +
        sd_jwt_zk::base64url_encode(sd_jwt_zk::Bytes(kb_payload_json.begin(), kb_payload_json.end()));
    std::array<unsigned char, 64> kb_raw{};
    require(sd_jwt_zk::test::sign_nested_fixture_es256(
                kb_signing, kb_raw, nullptr, kHolderScalar),
            "KB fixture signing failed");
    const std::string kb_compact = kb_signing + "." +
        sd_jwt_zk::base64url_encode(sd_jwt_zk::Bytes(kb_raw.begin(), kb_raw.end()));
    const std::string presentation = credential_presentation + kb_compact;
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
        kb_compact, holder_x, holder_y);
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
