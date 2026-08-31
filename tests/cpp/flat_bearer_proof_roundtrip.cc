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

#include "sd_jwt_zk/flat_bearer_proof.h"
#include "merkle/merkle_tree.h"
#include "util/log.h"
#include "nested_es256_fixture.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>

namespace {
using Clock = std::chrono::steady_clock;
constexpr char kHeader[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
constexpr char kDisclosure[] =
    "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
constexpr char kArrayDisclosure[] = "WyJhcnJheTAwMSIsIml0ZW0iXQ";

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
std::uint64_t milliseconds(Clock::time_point start, Clock::time_point end) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
          .count());
}
class ReplayStore final : public sd_jwt_zk::FlatBearerReplayStoreV1 {
 public:
  bool consume(std::string_view audience, std::string_view nonce,
               std::uint64_t) override {
    return seen_.insert(std::string(audience) + "\0" + std::string(nonce))
        .second;
  }
 private:
  std::set<std::string> seen_;
};
bool accepted(const sd_jwt_zk::Result<bool>& result) {
  return result && result.value.value();
}
}  // namespace

int main() {
  std::ofstream result("sd-jwt-zk-flat-bearer-proof-result.txt");
  try {
    proofs::set_log_level(proofs::ERROR);
    const auto digest_text = [](std::string_view disclosure) {
      const auto digest = sd_jwt_zk::sha256_ascii(disclosure);
      return sd_jwt_zk::base64url_encode(
          sd_jwt_zk::Bytes(digest.begin(), digest.end()));
    };
    const std::string payload_json = "{\"_sd\":[\"" +
        digest_text(kDisclosure) + "\"],\"items\":[{\"...\":\"" +
        digest_text(kArrayDisclosure) +
        "\"}],\"iss\":\"https://issuer.example\",\"vct\":\"example\"}";
    const std::string payload = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(payload_json.begin(), payload_json.end()));
    const std::string signing = std::string(kHeader) + "." + payload;
    std::array<unsigned char, 64> raw_signature{};
    sd_jwt_zk::P256Key issuer_public{};
    require(sd_jwt_zk::test::sign_nested_fixture_es256(
                signing, raw_signature, &issuer_public),
            "fixture issuer signing failed");
    const std::string signature = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(raw_signature.begin(), raw_signature.end()));
    const std::string issuer = signing + "." + signature;
    const std::string presentation = issuer + "~" + kDisclosure + "~" +
                                     kArrayDisclosure + "~";
    const auto issuer_key = sd_jwt_zk::Result<sd_jwt_zk::P256Key>::ok(issuer_public);
    auto witness = sd_jwt_zk::flat_bearer_witness_from_presentation(
        presentation, *issuer_key.value);
    require(static_cast<bool>(witness), "flat bearer witness rejected");
    sd_jwt_zk::Request request{
        sd_jwt_zk::flat_bearer_circuit_identity_v1(),
        "https://verifier.example\x1f" "cli-status", "cli-status-nonce",
        100, 200, sd_jwt_zk::flat_bearer_policy_v1(),
        sd_jwt_zk::flat_bearer_true_policy_result_v1(),
        sd_jwt_zk::flat_bearer_exact_key_trust_v1(*issuer_key.value), {}};
    const auto credential_binding =
        sd_jwt_zk::status_credential_binding_v1(witness.value->signing_digest);
    const auto status_issuer = sd_jwt_zk::status_issuer_v1(*issuer_key.value);
    const auto valid_leaf = sd_jwt_zk::status_leaf_v1(
        status_issuer, 3, credential_binding,
        sd_jwt_zk::CredentialStatusV1::valid);
    auto other_binding = credential_binding;
    other_binding[0] ^= 1;
    const auto other_valid_leaf = sd_jwt_zk::status_leaf_v1(
        status_issuer, 3, other_binding,
        sd_jwt_zk::CredentialStatusV1::valid);
    const auto revoked_leaf = sd_jwt_zk::status_leaf_v1(
        status_issuer, 3, credential_binding,
        sd_jwt_zk::CredentialStatusV1::revoked);
    proofs::MerkleTree status_tree(4);
    status_tree.set_leaf(0, other_valid_leaf);
    status_tree.set_leaf(1, valid_leaf);
    status_tree.set_leaf(2, revoked_leaf);
    status_tree.set_leaf(3, revoked_leaf);
    const auto status_root = status_tree.build_tree();
    const std::size_t status_index = 1;
    std::vector<proofs::Digest> status_path;
    status_tree.generate_compressed_proof(status_path, &status_index, 1);
    const std::size_t other_status_index = 0;
    std::vector<proofs::Digest> other_status_path;
    status_tree.generate_compressed_proof(other_status_path, &other_status_index,
                                          1);
    request.status_public = sd_jwt_zk::encode_status_policy_v1(
        {{status_issuer, status_root, 3, 100, 200}});
    const sd_jwt_zk::StatusMembershipWitnessV1 status_witness{status_index,
                                                               status_path};

    const auto prove_start = Clock::now();
    const auto envelope =
        sd_jwt_zk::prove_flat_bearer_v1(request, *witness.value, status_witness);
    const auto prove_end = Clock::now();
    require(static_cast<bool>(envelope), "production prover failed");
    const auto rerandomize_start = Clock::now();
    const auto rerandomized =
        sd_jwt_zk::prove_flat_bearer_v1(request, *witness.value, status_witness);
    const auto rerandomize_end = Clock::now();
    require(static_cast<bool>(rerandomized), "rerandomized prover failed");
    require(envelope.value->proof != rerandomized.value->proof,
            "repeated proof reused deterministic bytes");

    ReplayStore replay_store;
    const auto verify_start = Clock::now();
    require(accepted(sd_jwt_zk::verify_flat_bearer_v1(
                *envelope.value, request, 150, replay_store)),
            "production verifier rejected proof");
    const auto verify_end = Clock::now();
    require(!accepted(sd_jwt_zk::verify_flat_bearer_v1(
                *envelope.value, request, 150, replay_store)),
            "reused nonce accepted");
    ReplayStore second_store;
    require(accepted(sd_jwt_zk::verify_flat_bearer_v1(
                *rerandomized.value, request, 150, second_store)),
            "rerandomized proof did not verify");

    auto changed_disclosure = *witness.value;
    constexpr char kChangedDisclosureJson[] =
        "[\"salt-0001\",\"age_over\",\"frue\"]";
    const sd_jwt_zk::Bytes changed_json(
        kChangedDisclosureJson,
        kChangedDisclosureJson + sizeof(kChangedDisclosureJson) - 1);
    changed_disclosure.disclosures[0] =
        sd_jwt_zk::base64url_encode(changed_json);
    changed_disclosure.disclosure_digests[0] =
        sd_jwt_zk::sha256_ascii(changed_disclosure.disclosures[0]);
    auto false_request = request;
    false_request.policy_result = {0};
    require(!sd_jwt_zk::prove_flat_bearer_v1(false_request,
                                             changed_disclosure),
            "issuer-unbound disclosure produced a proof");
    require(!sd_jwt_zk::prove_flat_bearer_v1(false_request,
                                             *witness.value),
            "false policy result produced a proof for true value");
    auto changed_array = *witness.value;
    changed_array.disclosures[1][0] = changed_array.disclosures[1][0] == 'A' ? 'B' : 'A';
    changed_array.disclosure_digests[1] =
        sd_jwt_zk::sha256_ascii(changed_array.disclosures[1]);
    require(!sd_jwt_zk::prove_flat_bearer_v1(request, changed_array),
            "issuer-unbound root-array disclosure produced a proof");

    auto expect_reject = [&](const sd_jwt_zk::Envelope& candidate,
                             const sd_jwt_zk::Request& expected,
                             std::uint64_t now) {
      ReplayStore store;
      return !accepted(sd_jwt_zk::verify_flat_bearer_v1(
          candidate, expected, now, store));
    };
    auto changed_audience = request;
    changed_audience.audience = "https://other-verifier.example";
    require(expect_reject(*envelope.value, changed_audience, 150),
            "altered audience accepted");
    auto changed_nonce = request;
    changed_nonce.nonce = "different-nonce";
    require(expect_reject(*envelope.value, changed_nonce, 150),
            "altered nonce accepted");
    auto changed_policy = request;
    changed_policy.policy.push_back('x');
    require(expect_reject(*envelope.value, changed_policy, 150),
            "altered policy accepted");
    auto changed_time = request;
    changed_time.time_max = 201;
    require(expect_reject(*envelope.value, changed_time, 150),
            "altered time bound accepted");
    require(expect_reject(*envelope.value, request, 99),
            "future request accepted");
    require(expect_reject(*envelope.value, request, 201),
            "expired request accepted");
    auto wrong_status = request;
    wrong_status.status_public.back() ^= 1;
    require(expect_reject(*envelope.value, wrong_status, 150),
            "wrong status credential binding accepted");
    auto tampered_status = *envelope.value;
    tampered_status.proof.back() ^= 1;
    require(expect_reject(tampered_status, request, 150),
            "invalid status proof accepted");
    auto tampered_bridge = *envelope.value;
    const std::size_t presentation_size =
        (static_cast<std::size_t>(tampered_bridge.proof[0]) << 24) |
        (static_cast<std::size_t>(tampered_bridge.proof[1]) << 16) |
        (static_cast<std::size_t>(tampered_bridge.proof[2]) << 8) |
        tampered_bridge.proof[3];
    tampered_bridge.proof[4 + presentation_size] ^= 1;
    require(expect_reject(tampered_bridge, request, 150),
            "substituted status bridge commitment accepted");
    const auto same_context = sd_jwt_zk::transcript_seed(request);
    const auto status_policy =
        sd_jwt_zk::decode_status_policy_v1(request.status_public);
    require(static_cast<bool>(status_policy), "status policy decode failed");
    const auto other_status = sd_jwt_zk::prove_status_membership_v1(
        status_policy.value->snapshot, other_binding, other_status_index,
        other_status_path, same_context);
    require(static_cast<bool>(other_status),
            "different credential status proof failed");
    const auto other_verified = sd_jwt_zk::verify_status_membership_v1(
        *other_status.value, status_policy.value->snapshot, status_issuer, 3,
        150, same_context);
    require(other_verified && *other_verified.value,
            "different credential status proof did not verify standalone");
    auto other_credential_splice = *envelope.value;
    other_credential_splice.proof.resize(4 + presentation_size);
    other_credential_splice.proof.insert(
        other_credential_splice.proof.end(),
        other_status.value->bridge_commitment.begin(),
        other_status.value->bridge_commitment.end());
    other_credential_splice.proof.insert(other_credential_splice.proof.end(),
                                         other_status.value->proof.begin(),
                                         other_status.value->proof.end());
    require(expect_reject(other_credential_splice, request, 150),
            "bearer verifier accepted a different credential status proof");
    auto unsupported = request;
    unsupported.identity.query_count += 1;
    require(expect_reject(*envelope.value, unsupported, 150),
            "unsupported circuit identity accepted");
    auto wrong_digest = request;
    wrong_digest.identity.circuit_digest[0] ^= 1;
    require(expect_reject(*envelope.value, wrong_digest, 150),
            "wrong circuit digest accepted");
    auto statement_mismatch = *envelope.value;
    statement_mismatch.request.audience = changed_audience.audience;
    require(expect_reject(statement_mismatch, changed_audience, 150),
            "request/statement mismatch accepted");
    auto trust_mismatch = *envelope.value;
    trust_mismatch.request.trust_public[0] ^= 1;
    auto changed_trust_request = request;
    changed_trust_request.trust_public[0] ^= 1;
    require(expect_reject(trust_mismatch, changed_trust_request, 150),
            "issuer trust mismatch accepted");

    auto truncated = *envelope.value;
    truncated.proof.pop_back();
    require(expect_reject(truncated, request, 150),
            "truncated proof accepted");
    auto trailing = *envelope.value;
    trailing.proof.push_back(0);
    require(expect_reject(trailing, request, 150),
            "trailing proof bytes accepted");

    require(envelope.value->proof.size() >= 4 + presentation_size + 32,
            "composite proof framing is truncated");
    const std::size_t status_proof_size =
        envelope.value->proof.size() - 4 - presentation_size - 32;

    result << "production-real-randomized-proof-accepted\n"
           << "repeated-proof-bytes-differ\n"
           << "authenticated-disclosure-mutation-rejected\n"
           << "false-policy-result-witness-rejected\n"
           << "audience-mismatch-rejected\n"
           << "nonce-mismatch-rejected\n"
           << "nonce-reuse-rejected\n"
           << "policy-mismatch-rejected\n"
           << "time-mismatch-rejected\n"
           << "expired-and-future-rejected\n"
           << "circuit-identity-mismatch-rejected\n"
           << "request-statement-mismatch-rejected\n"
           << "issuer-trust-mismatch-rejected\n"
           << "malformed-and-trailing-proof-rejected\n"
           << "prove-ms=" << milliseconds(prove_start, prove_end) << '\n'
           << "rerandomize-ms="
           << milliseconds(rerandomize_start, rerandomize_end) << '\n'
           << "verify-ms=" << milliseconds(verify_start, verify_end) << '\n'
           << "proof-bytes=" << envelope.value->proof.size() << '\n'
           << "presentation-proof-bytes=" << presentation_size << '\n'
           << "status-proof-bytes=" << status_proof_size << '\n'
           << "public-inputs=" << sd_jwt_zk::kFlatBearerPublicInputsV1
           << '\n'
           << "total-inputs=" << sd_jwt_zk::kFlatBearerDenseInputsV1
           << '\n';
    std::cout << "production flat bearer proof API round trip passed\n";
    return 0;
  } catch (const std::exception& error) {
    result << "failed=" << error.what() << '\n';
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
}
