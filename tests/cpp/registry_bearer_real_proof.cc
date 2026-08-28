#include <algorithm>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>

#include "sd_jwt_zk/registry_bearer_proof.h"
#include "sd_jwt_zk/issuer_registry_policy.h"
#include "sumcheck/prover_layers.h"
#include "util/log.h"

namespace {
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

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

class Replay final : public sd_jwt_zk::FlatBearerReplayStoreV1 {
 public:
  bool consume(std::string_view, std::string_view, std::uint64_t) override {
    bool expected = false;
    return used_.compare_exchange_strong(expected, true);
  }
 private:
  std::atomic<bool> used_{false};
};

bool accepts(const proofs::Circuit<sd_jwt_zk::FlatBearerField>& circuit,
             const proofs::Dense<sd_jwt_zk::FlatBearerField>& dense) {
  proofs::ProverLayers<sd_jwt_zk::FlatBearerField> evaluator(
      proofs::p256_base);
  proofs::ProverLayers<sd_jwt_zk::FlatBearerField>::inputs layers;
  auto output = evaluator.eval_circuit(&layers, &circuit, dense.clone(),
                                       proofs::p256_base);
  return output && std::all_of(output->v_.begin(), output->v_.end(),
                               [](const auto& value) {
                                 return value == proofs::p256_base.zero();
                               });
}

void toggle(proofs::Dense<sd_jwt_zk::FlatBearerField>& dense,
            std::size_t position) {
  dense.v_[position] =
      dense.v_[position] == proofs::p256_base.zero()
          ? proofs::p256_base.one()
          : proofs::p256_base.zero();
}
}  // namespace

int main() {
  try {
    proofs::set_log_level(proofs::ERROR);
    const auto key = sd_jwt_zk::decode_p256_jwk(kX, kY);
    require(static_cast<bool>(key), "issuer key fixture rejected");
    sd_jwt_zk::IssuerAuthorizationRecordV1 record{
        *key.value, "example", 50, 250};
    sd_jwt_zk::IssuerAuthorizationRecordV1 other{
        *key.value, "example/other", 50, 250};
    const auto registry = sd_jwt_zk::build_issuer_registry_v1(
        {other, record}, sd_jwt_zk::kIssuerRegistryDepthV1, 7, 100, 200);
    require(static_cast<bool>(registry), "registry fixture rejected");
    const auto path = std::find_if(
        registry.value->paths.begin(), registry.value->paths.end(),
        [](const auto& item) { return item.record.vct == "example"; });
    require(path != registry.value->paths.end(), "authorization path missing");
    const std::string presentation = std::string(kHeader) + "." + kPayload +
                                     "." + kSignature + "~" + kDisclosure +
                                     "~";
    const auto witness =
        sd_jwt_zk::registry_bearer_witness_from_presentation_v1(presentation,
                                                                 *path);
    require(static_cast<bool>(witness), "registry bearer witness rejected");
    const auto trust = sd_jwt_zk::registry_trust_context_v1(*registry.value);
    const auto trust_bytes = sd_jwt_zk::encode_registry_trust_context_v1(trust);
    require(static_cast<bool>(trust_bytes), "registry context rejected");
    sd_jwt_zk::Request request{
        sd_jwt_zk::registry_bearer_circuit_identity_v1(),
        "https://verifier.example", "registry-real-proof-v1", 100, 200,
        sd_jwt_zk::flat_bearer_policy_v1(),
        sd_jwt_zk::flat_bearer_true_policy_result_v1(), *trust_bytes.value,
        {}};

    proofs::QuadCircuit<sd_jwt_zk::FlatBearerField> quad(proofs::p256_base);
    sd_jwt_zk::RegistryBearerDenseLayoutV1 layout;
    const auto circuit =
        sd_jwt_zk::BuildRegistryBearerCircuitV1(&quad, &layout);
    proofs::Dense<sd_jwt_zk::FlatBearerField> dense(1, circuit->ninputs);
    const auto statement = sd_jwt_zk::transcript_seed(request);
    require(sd_jwt_zk::FillRegistryBearerDenseWitnessV1(
                dense, layout, statement, true, trust, *witness.value),
            "compiler-derived dense registry witness rejected");
    require(accepts(*circuit, dense), "valid dense witness fails circuit");

    auto reject_toggle = [&](std::size_t position, const char* message) {
      auto changed = dense.clone();
      toggle(*changed, position);
      require(!accepts(*circuit, *changed), message);
    };
    constexpr std::size_t kLeafTagBytes =
        sizeof("SDJWT-ZK/issuer-registry/v1/leaf") - 1;
    reject_toggle(layout.leaf_message_first + kLeafTagBytes * 8,
                  "leaf issuer-key substitution satisfied circuit");
    reject_toggle(layout.leaf_message_first + (kLeafTagBytes + 64) * 8,
                  "leaf vct substitution satisfied circuit");
    reject_toggle(layout.not_before_bits_first,
                  "authorization interval substitution satisfied circuit");
    reject_toggle(layout.private_epoch_first,
                  "private epoch substitution satisfied circuit");
    reject_toggle(layout.leaf_index_first,
                  "leaf index/direction substitution satisfied circuit");
    reject_toggle(layout.siblings_first,
                  "Merkle sibling substitution satisfied circuit");
    reject_toggle(layout.public_root_first,
                  "public root substitution satisfied circuit");
    reject_toggle(layout.public_valid_until_first + 8,
                  "public validity-window substitution satisfied circuit");
    reject_toggle(layout.public_depth_first,
                  "alternate public depth satisfied circuit");
    reject_toggle(layout.leaf_message_first,
                  "empty/changed leaf satisfied circuit");

    sd_jwt_zk::Limits proof_limits;
    proof_limits.max_proof = 8 * 1024 * 1024;
    const auto proof = sd_jwt_zk::prove_registry_bearer_v1(
        request, *witness.value, proof_limits);
    require(static_cast<bool>(proof), "registry real proof failed");
    const auto rerandomized = sd_jwt_zk::prove_registry_bearer_v1(
        request, *witness.value, proof_limits);
    require(static_cast<bool>(rerandomized), "second registry proof failed");
    require(proof.value->proof != rerandomized.value->proof,
            "registry proofs were deterministic");
    sd_jwt_zk::IssuerRegistryVerifierPolicyV1 local_policy{
        {{trust, 2, false, std::nullopt}}, 7,
        sd_jwt_zk::kIssuerRegistryDepthV1, 2, std::nullopt, false};
    Replay replay;
    const auto verified = sd_jwt_zk::verify_authorized_registry_bearer_v1(
        *proof.value, request, 150, local_policy, replay, proof_limits);
    require(verified && *verified.value, "registry proof did not verify");

    auto wrong_root = request;
    wrong_root.trust_public[1] ^= 1;
    auto changed = *proof.value;
    changed.request = wrong_root;
    Replay wrong_root_replay;
    require(!sd_jwt_zk::verify_registry_bearer_v1(
                changed, wrong_root, 150, wrong_root_replay, proof_limits),
            "root-mutated proof verified");
    auto wrong_epoch = request;
    wrong_epoch.trust_public[33 + 7] ^= 1;
    changed.request = wrong_epoch;
    Replay wrong_epoch_replay;
    require(!sd_jwt_zk::verify_registry_bearer_v1(
                changed, wrong_epoch, 150, wrong_epoch_replay, proof_limits),
            "epoch-mutated proof verified");
    auto wrong_window = request;
    wrong_window.trust_public[49 + 6] ^= 1;
    changed.request = wrong_window;
    Replay wrong_window_replay;
    require(!sd_jwt_zk::verify_registry_bearer_v1(
                changed, wrong_window, 150, wrong_window_replay,
                proof_limits),
            "window-mutated proof verified");
    auto wrong_depth = request;
    wrong_depth.trust_public.back() = 1;
    changed.request = wrong_depth;
    Replay wrong_depth_replay;
    require(!sd_jwt_zk::verify_registry_bearer_v1(
                changed, wrong_depth, 150, wrong_depth_replay, proof_limits),
            "depth-mutated proof verified");
    auto exact_swap = request;
    exact_swap.identity = sd_jwt_zk::flat_bearer_circuit_identity_v1();
    changed.request = exact_swap;
    Replay exact_replay;
    require(!sd_jwt_zk::verify_registry_bearer_v1(
                changed, exact_swap, 150, exact_replay, proof_limits),
            "exact-key circuit identity accepted registry proof");
    std::cout << "registry bearer real proof passed; bytes="
              << proof.value->proof.size() << " public=" << circuit->npub_in
              << " total=" << circuit->ninputs << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
