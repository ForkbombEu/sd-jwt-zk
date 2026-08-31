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

#include "arrays/dense.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "sd_jwt_zk/flat_bearer_proof.h"
#include "sd_jwt_zk/presentation.h"

#include <cstddef>
#include <iostream>
#include <string>
#include <string_view>

using Field=sd_jwt_zk::FlatBearerField;
constexpr char kHeader[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
constexpr char kPayload[] =
    "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSJ9";
constexpr char kSignature[] =
    "FQp4GsBBvr3_xbX1UtKSc7mtcw1ygaZ7Z-suRyHET3oggdcr1KqoyH-LA8Yy8pHr3xGkKrrQCu-7fCAbYrTljg";
constexpr char kDisclosure[] =
    "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
constexpr char kX[] = "Jl-RmGfWH_k-UmeHbUnLL58NFLxBz6qOzZqP7z_qxY4";
constexpr char kY[] = "VBuaEu3T_57clPlJDLwm8xnw1PHFyR4kbXUHyGsK9TU";
struct DenseReplayBackend : proofs::EvaluationBackend<Field> {
  explicit DenseReplayBackend(proofs::Dense<Field>& inputs)
      : proofs::EvaluationBackend<Field>(proofs::p256_base, false),
        inputs(inputs) {}

  V input_wire() const { return this->konst(inputs.v_.at(next_input++)); }

  proofs::Dense<Field>& inputs;
  // QuadCircuit allocates input zero as the fixed field-one constant before
  // the relation requests its first wire.  Dense witnesses include that slot,
  // so replay begins with the first relation-owned input.
  mutable std::size_t next_input{1};
};

using Backend=DenseReplayBackend; using Logic=proofs::Logic<Field,Backend>;
struct Source {
  Logic& logic;

  Logic::EltW element() const { return logic.eltw_input(); }
  Logic::BitW bit() const { return logic.input(); }

  template <std::size_t N>
  Logic::bitvec<N> value() const { return logic.template vinput<N>(); }
};
int main(int argc, char** argv){
  const bool mutate_policy_result =
      argc == 2 && std::string_view(argv[1]) == "--mutate-policy-result";
  const bool cli_status =
      argc == 2 && std::string_view(argv[1]) == "--cli-status";
  const bool mutate_purpose =
      argc == 2 && std::string_view(argv[1]) == "--mutate-purpose";
  if (argc != 1 && !mutate_policy_result && !cli_status && !mutate_purpose)
    return 64;
  const auto key = sd_jwt_zk::decode_p256_jwk(kX, kY);
  if (!key) return 1;
  const std::string presentation = std::string(kHeader) + "." + kPayload +
      "." + kSignature + "~" + kDisclosure + "~";
  std::cerr << "dense-replay: witness-start\n";
  const auto witness = sd_jwt_zk::flat_bearer_witness_from_presentation(
      presentation, *key.value);
  std::cerr << "dense-replay: witness-done\n";
  if (!witness) return 1;
  sd_jwt_zk::Request request;
  bool status_required = cli_status || mutate_purpose;
  if (status_required) {
    std::vector<sd_jwt_zk::LocalStatusEntryV1> entries(4);
    const auto binding =
        sd_jwt_zk::status_credential_binding_v1(witness.value->signing_digest);
    for (std::size_t i = 0; i < entries.size(); ++i) {
      entries[i].credential_binding[0] = static_cast<std::uint8_t>(i + 1);
      entries[i].status = sd_jwt_zk::CredentialStatusV1::revoked;
    }
    entries[1].credential_binding = binding;
    entries[1].status = sd_jwt_zk::CredentialStatusV1::valid;
    const auto snapshot = sd_jwt_zk::build_local_status_snapshot_v1(
        sd_jwt_zk::status_issuer_v1(*key.value), 3, 100, 200, entries);
    if (!snapshot) return 1;
    sd_jwt_zk::PresentationPolicyV1 policy{
        "https://verifier.example", "cli-status", "cli-status-nonce", 100,
        200, *key.value, sd_jwt_zk::StatusRequirementV1::required,
        sd_jwt_zk::StatusPolicyV1{snapshot.value->public_part}};
    const auto built = sd_jwt_zk::BuildBearerPresentationRequestV1(policy);
    if (!built) return 1;
    request = built.value->request;
  } else {
    request = {sd_jwt_zk::flat_bearer_circuit_identity_v1(),
               "https://verifier.example", "dense-replay-v1", 100, 200,
               sd_jwt_zk::flat_bearer_policy_v1(),
               sd_jwt_zk::flat_bearer_true_policy_result_v1(),
               sd_jwt_zk::flat_bearer_exact_key_trust_v1(*key.value), {}};
  }
  const auto statement = sd_jwt_zk::transcript_seed(request);
  const auto status_binding = status_required
      ? sd_jwt_zk::status_credential_binding_v1(witness.value->signing_digest)
      : std::array<std::uint8_t, 32>{};
  const auto status_commitment =
      sd_jwt_zk::status_private_bridge_v1(status_binding, statement);
  proofs::Dense<Field> d(1, sd_jwt_zk::kFlatBearerDenseInputsV1);
  std::cerr << "dense-replay: fill-start\n";
  if (!sd_jwt_zk::FillFlatBearerDenseWitnessV1(
          d, statement, true, *witness.value, status_required, status_binding,
          statement, status_commitment))
    return 1;
  if (mutate_policy_result) {
    // Dense slot zero is the compiler's implicit one; the 32-byte public
    // statement follows it, then this public policy-result bit.
    d.v_.at(33) = proofs::p256_base.zero();
  }
  if (mutate_purpose) {
    auto changed = request;
    changed.audience.back() ^= 1;
    const auto changed_statement = sd_jwt_zk::transcript_seed(changed);
    for (std::size_t i = 0; i < changed_statement.size(); ++i)
      d.v_.at(1 + i) = proofs::p256_base.of_scalar(changed_statement[i]);
  }
  std::cerr << "dense-replay: fill-done\n";
  proofs::QuadCircuit<Field> q(proofs::p256_base);
  Backend backend(d); Logic logic(&backend, proofs::p256_base);
  Source source{logic};
  sd_jwt_zk::AllocateFlatBearerRelationV1WithSource(&q, logic, source);
  const bool assertions_failed = backend.assertion_failed();
  if (backend.next_input != sd_jwt_zk::kFlatBearerDenseInputsV1) {
    std::cerr << "dense-replay: input-count=" << backend.next_input
              << " expected=" << sd_jwt_zk::kFlatBearerDenseInputsV1 << '\n';
    return 2;
  }
  if (mutate_policy_result || mutate_purpose) {
    if (!assertions_failed) {
      std::cerr << "dense-replay: mutation-accepted\n";
      return 4;
    }
    std::cout << (mutate_purpose
        ? "flat-bearer-dense-purpose-mutation-rejected\n"
        : "flat-bearer-dense-policy-mutation-rejected\n");
    return 0;
  }
  if (assertions_failed) {
    std::cerr << "dense-replay: relation-assertion-failed\n";
    return 3;
  }
  std::cerr << "dense-replay: valid-done\n";
  std::cout << "flat-bearer-dense-fixture-fill-ok\n";
  return 0;
}
