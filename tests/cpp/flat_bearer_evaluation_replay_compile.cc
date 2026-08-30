#include "arrays/dense.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "sd_jwt_zk/flat_bearer_proof.h"

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
  if (argc != 1 && !mutate_policy_result) return 64;
  const auto key = sd_jwt_zk::decode_p256_jwk(kX, kY);
  if (!key) return 1;
  const std::string presentation = std::string(kHeader) + "." + kPayload +
      "." + kSignature + "~" + kDisclosure + "~";
  std::cerr << "dense-replay: witness-start\n";
  const auto witness = sd_jwt_zk::flat_bearer_witness_from_presentation(
      presentation, *key.value);
  std::cerr << "dense-replay: witness-done\n";
  if (!witness) return 1;
  sd_jwt_zk::Request request{
      sd_jwt_zk::flat_bearer_circuit_identity_v1(),
      "https://verifier.example", "dense-replay-v1", 100, 200,
      sd_jwt_zk::flat_bearer_policy_v1(),
      sd_jwt_zk::flat_bearer_true_policy_result_v1(),
      sd_jwt_zk::flat_bearer_exact_key_trust_v1(*key.value), {}};
  proofs::Dense<Field> d(1, sd_jwt_zk::kFlatBearerDenseInputsV1);
  std::cerr << "dense-replay: fill-start\n";
  if (!sd_jwt_zk::FillFlatBearerDenseWitnessV1(
          d, sd_jwt_zk::transcript_seed(request), true, *witness.value))
    return 1;
  if (mutate_policy_result) {
    // Dense slot zero is the compiler's implicit one; the 32-byte public
    // statement follows it, then this public policy-result bit.
    d.v_.at(33) = proofs::p256_base.zero();
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
  if (mutate_policy_result) {
    if (!assertions_failed) {
      std::cerr << "dense-replay: mutated-policy-accepted\n";
      return 4;
    }
    std::cout << "flat-bearer-dense-policy-mutation-rejected\n";
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
