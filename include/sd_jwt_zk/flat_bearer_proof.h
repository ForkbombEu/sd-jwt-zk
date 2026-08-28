#pragma once

#include <array>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/issuer_jws_relation.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"

namespace sd_jwt_zk {

// Native, secret-bearing source material for the compiler witness encoder.
// This type deliberately is not a proof and has no verification API: callers
// must pass it to the compiler-backed bearer prover once its wire encoder is
// selected by the circuit identity.
struct FlatBearerWitness {
  CompactJws issuer;
  P256Key issuer_key;
  P256Signature issuer_signature;
  Bytes signing_input;
  std::array<std::uint8_t, 32> signing_digest{};
  std::vector<std::string> disclosures;
  std::vector<std::array<std::uint8_t, 32>> disclosure_digests;
  RestrictedIssuerPayload payload;
};

// Parses only the bounded flat bearer form, verifies the issuer ES256 JWS
// independently, and derives every byte that the later circuit witness
// encoder needs.  It never treats this host validation as proof verification.
Result<FlatBearerWitness> flat_bearer_witness_from_presentation(
    std::string_view presentation, const P256Key& issuer_key,
    const Limits& limits = {});

// This factory fixes the V1 bounded family.  The first 32 input wires are the
// public statement digest; each is equality-bound to a private witness wire
// so transcript/circuit identity substitutions cannot be optimized away.
// The next public wire is the Boolean policy result, followed by the exact
// issuer P-256 coordinates. Remaining wires are private issuer/disclosure
// relation advice in the exact order declared below.
using FlatBearerField = proofs::Fp256Base;
using FlatBearerBackend = proofs::CompilerBackend<FlatBearerField>;
using FlatBearerLogic = proofs::Logic<FlatBearerField, FlatBearerBackend>;
inline constexpr std::size_t kFlatBearerPublicInputsV1 = 36;
inline constexpr std::size_t kFlatBearerDenseInputsV1 = 19704;

// Fills the exact wire order declared by BuildFlatBearerCircuitV1.  The full
// witness begins with the compiler's constant-one input, the public statement,
// the public Boolean policy result, and the equality-bound private statement
// copy. The verifier receives only the public prefix through
// FillFlatBearerPublicInputsV1.
bool FillFlatBearerDenseWitnessV1(
    proofs::Dense<FlatBearerField>& inputs,
    const std::array<std::uint8_t, 32>& public_statement,
    bool policy_result,
    const FlatBearerWitness& witness);
bool FillFlatBearerPublicInputsV1(
    proofs::Dense<FlatBearerField>& inputs,
    const std::array<std::uint8_t, 32>& public_statement,
    bool policy_result,
    const P256Key& issuer_key);

class FlatBearerReplayStoreV1 {
 public:
  virtual ~FlatBearerReplayStoreV1() = default;
  virtual bool consume(std::string_view audience, std::string_view nonce,
                       std::uint64_t expires_at) = 0;
};

// The low-level V1 API accepts only this exact circuit identity and policy.
// The canonical Request hash is both the 32-byte circuit statement and the
// Fiat-Shamir transcript seed. Verification consumes the audience/nonce pair
// atomically only after a successful proof.
CircuitIdentity flat_bearer_circuit_identity_v1();
Bytes flat_bearer_policy_v1();
Bytes flat_bearer_true_policy_result_v1();
Bytes flat_bearer_exact_key_trust_v1(const P256Key& issuer_key);
Result<Envelope> prove_flat_bearer_v1(const Request& request,
                                     const FlatBearerWitness& witness,
                                     const Limits& limits = {});
Result<bool> verify_flat_bearer_v1(const Envelope& envelope,
                                  const Request& expected_request,
                                  std::uint64_t now,
                                  FlatBearerReplayStoreV1& replay_store,
                                  const Limits& limits = {});

inline std::unique_ptr<proofs::Circuit<FlatBearerField>> BuildFlatBearerCircuitV1(
    proofs::QuadCircuit<FlatBearerField>* q) {
  constexpr std::size_t kSigningBlocks = 5, kHeaderChars = 102, kPayloadChars = 140;
  FlatBearerBackend backend(q); FlatBearerLogic logic(&backend, proofs::p256_base);
  std::array<FlatBearerLogic::EltW, 32> public_statement{};
  for (auto& wire : public_statement) wire = logic.eltw_input();
  const auto public_policy_result = logic.input();
  const auto public_x = logic.eltw_input();
  const auto public_y = logic.eltw_input();
  q->private_input();
  for (const auto& wire : public_statement) logic.assert_eq(wire, logic.eltw_input());
  using Relation = IssuerJwsRelation<FlatBearerLogic, kSigningBlocks, kHeaderChars, kPayloadChars>;
  using Sha = proofs::FlatSHA256Circuit<FlatBearerLogic, proofs::BitPlucker<FlatBearerLogic, 4>>;
  using Ecdsa = proofs::VerifyCircuit<FlatBearerLogic, FlatBearerField, proofs::P256>;
  std::array<FlatBearerLogic::v8, 64 * kSigningBlocks> signing{};
  for (auto& byte : signing) byte = logic.template vinput<8>();
  std::array<typename Sha::BlockWitness, kSigningBlocks> sha_witness{};
  for (auto& block : sha_witness) block.input(logic);
  FlatBearerLogic::v256 digest_bits{}; for (auto& bit : digest_bits) bit = logic.input();
  std::array<FlatBearerLogic::v8, kHeaderChars> header{}; for (auto& byte : header) byte = logic.template vinput<8>();
  std::array<FlatBearerLogic::v8, (kHeaderChars * 6) / 8> header_decoded{}; for (auto& byte : header_decoded) byte = logic.template vinput<8>();
  std::array<FlatBearerLogic::v8, kPayloadChars> payload{}; for (auto& byte : payload) byte = logic.template vinput<8>();
  std::array<FlatBearerLogic::v8, (kPayloadChars * 6) / 8> payload_decoded{}; for (auto& byte : payload_decoded) byte = logic.template vinput<8>();
  std::array<FlatBearerLogic::v8, 256> padded{}; for (auto& byte : padded) byte = logic.template vinput<8>();
  Relation::Index issuer_len{}, vct_len{}, payload_len{};
  for (auto* index : {&issuer_len, &vct_len, &payload_len}) for (auto& bit : *index) bit = logic.input();
  const auto explicit_sha = logic.input();
  const auto digest = logic.eltw_input();
  typename Ecdsa::Witness ecdsa{}; ecdsa.input(logic);
  typename Relation::Input issuer{signing, sha_witness, digest_bits, header, header_decoded, payload, payload_decoded,
      logic.template vinput<8>(), logic.template vinput<8>(), padded,
      issuer_len, vct_len, payload_len, explicit_sha, public_x, public_y, digest, ecdsa, 4};
  constexpr std::size_t kDisclosureChars = 42;
  using Disclosure = FlatDisclosureRelation<FlatBearerLogic, 1, kDisclosureChars>;
  using DisclosureSha = proofs::FlatSHA256Circuit<
      FlatBearerLogic, proofs::BitPlucker<FlatBearerLogic, 4>>;
  std::array<FlatBearerLogic::v8, kDisclosureChars> disclosure_ascii{};
  for (auto& byte : disclosure_ascii) byte = logic.template vinput<8>();
  std::array<FlatBearerLogic::v8, 64> disclosure_sha_input{};
  for (auto& byte : disclosure_sha_input) byte = logic.template vinput<8>();
  std::array<typename DisclosureSha::BlockWitness, 1> disclosure_sha_witness{};
  disclosure_sha_witness[0].input(logic);
  FlatBearerLogic::v256 disclosure_digest{};
  for (auto& bit : disclosure_digest) bit = logic.input();
  std::array<FlatBearerLogic::v8, 43> signed_digest{};
  for (auto& byte : signed_digest) byte = logic.template vinput<8>();
  typename Disclosure::Input disclosure_input{
      disclosure_ascii, disclosure_sha_input, disclosure_sha_witness,
      disclosure_digest, signed_digest, 1};
  FlatBearerLogic::bitvec<8> salt_len{}, name_len{}, value_len{},
      disclosure_len{};
  for (auto* index : {&salt_len, &name_len, &value_len, &disclosure_len})
    for (auto& bit : *index) bit = logic.input();

  Relation relation(logic);
  relation.assert_valid(issuer);
  relation.template assert_disclosure_binding<1, kDisclosureChars>(
      issuer, disclosure_input);
  Disclosure disclosure(logic);
  std::array<FlatBearerLogic::v8, (kDisclosureChars * 6) / 8>
      disclosure_json{};
  RestrictedBase64UrlRelation<FlatBearerLogic>(logic).decode(
      disclosure_ascii, disclosure_json);
  disclosure.assert_three_string_active_grammar(
      disclosure_json, salt_len, name_len, value_len, disclosure_len, 9, 8,
      4);
  constexpr std::array<std::uint8_t, 8> kPolicyName{
      'a', 'g', 'e', '_', 'o', 'v', 'e', 'r'};
  constexpr std::array<std::uint8_t, 4> kPolicyValue{'t', 'r', 'u', 'e'};
  disclosure.assert_named_string_policy(
      disclosure_json, salt_len, name_len, value_len, kPolicyName,
      kPolicyValue, public_policy_result, 9);
  return q->mkcircuit(1);
}

}  // namespace sd_jwt_zk
