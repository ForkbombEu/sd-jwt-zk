#pragma once

#include <array>
#include <memory>

#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "sd_jwt_zk/flat_bearer_proof.h"
#include "sd_jwt_zk/issuer_registry.h"
#include "sd_jwt_zk/issuer_registry_membership_relation.h"

namespace sd_jwt_zk {

inline constexpr std::size_t kIssuerRegistryDepthV1 = 2;

struct RegistryBearerWitnessV1 {
  FlatBearerWitness credential;
  IssuerRegistryPathV1 authorization;
};

// Captured from the compiler allocation itself.  Registry witness encoders do
// not duplicate a magic total-input constant and fail closed if any future
// factory edit changes a boundary without a matching encoder update.
struct RegistryBearerDenseLayoutV1 {
  std::size_t public_inputs{};
  std::size_t public_root_first{};
  std::size_t public_epoch_first{};
  std::size_t public_valid_from_first{};
  std::size_t public_valid_until_first{};
  std::size_t public_depth_first{};
  std::size_t issuer_key_first{};
  std::size_t membership_first{};
  std::size_t not_before_bits_first{};
  std::size_t not_after_bits_first{};
  std::size_t private_epoch_first{};
  std::size_t leaf_index_first{};
  std::size_t interval_bytes_first{};
  std::size_t leaf_message_first{};
  std::size_t siblings_first{};
  std::array<std::size_t, kIssuerRegistryDepthV1> node_message_first{};
  std::size_t total_inputs{};
};

Result<RegistryBearerWitnessV1> registry_bearer_witness_from_presentation_v1(
    std::string_view presentation, const IssuerRegistryPathV1& authorization,
    const Limits& limits = {});

bool FillRegistryBearerDenseWitnessV1(
    proofs::Dense<FlatBearerField>& inputs,
    const RegistryBearerDenseLayoutV1& layout,
    const std::array<std::uint8_t, 32>& public_statement, bool policy_result,
    const RegistryTrustContextV1& trust,
    const RegistryBearerWitnessV1& witness);
bool FillRegistryBearerPublicInputsV1(
    proofs::Dense<FlatBearerField>& inputs,
    const std::array<std::uint8_t, 32>& public_statement, bool policy_result,
    const RegistryTrustContextV1& trust);
bool AppendIssuerRegistryMembershipAdviceV1(
    proofs::DenseFiller<FlatBearerField>& filler,
    const RegistryTrustContextV1& trust,
    const IssuerRegistryPathV1& authorization);

CircuitIdentity registry_bearer_circuit_identity_v1();
Result<Envelope> prove_registry_bearer_v1(
    const Request& request, const RegistryBearerWitnessV1& witness,
    const Limits& limits = {});
Result<bool> verify_registry_bearer_v1(
    const Envelope& envelope, const Request& expected_request,
    std::uint64_t now, FlatBearerReplayStoreV1& replay_store,
    const Limits& limits = {});

inline std::unique_ptr<proofs::Circuit<FlatBearerField>>
BuildRegistryBearerCircuitV1(proofs::QuadCircuit<FlatBearerField>* q,
                             RegistryBearerDenseLayoutV1* layout = nullptr) {
  constexpr std::size_t B = 5, H = 102, P = 140;
  constexpr std::size_t DisclosureChars = 42;
  using L = FlatBearerLogic;
  using Relation = IssuerJwsRelation<L, B, H, P>;
  using Sha = proofs::FlatSHA256Circuit<L, proofs::BitPlucker<L, 4>>;
  using Ecdsa = proofs::VerifyCircuit<L, FlatBearerField, proofs::P256>;
  using Disclosure = FlatDisclosureRelation<L, 1, DisclosureChars>;
  using Membership =
      IssuerRegistryMembershipRelation<L, kIssuerRegistryDepthV1>;

  FlatBearerBackend backend(q);
  L logic(&backend, proofs::p256_base);
  std::array<L::EltW, 32> statement{};
  for (auto& wire : statement) wire = logic.eltw_input();
  const auto policy = logic.input();
  std::array<L::v8, 32> root{};
  if (layout) layout->public_root_first = q->ninput_;
  for (auto& byte : root) byte = logic.template vinput<8>();
  if (layout) layout->public_epoch_first = q->ninput_;
  const auto epoch = logic.template vinput<64>();
  if (layout) layout->public_valid_from_first = q->ninput_;
  const auto valid_from = logic.template vinput<64>();
  if (layout) layout->public_valid_until_first = q->ninput_;
  const auto valid_until = logic.template vinput<64>();
  if (layout) layout->public_depth_first = q->ninput_;
  const auto depth = logic.template vinput<8>();
  if (layout) layout->public_inputs = q->ninput_;
  q->private_input();

  if (layout) layout->issuer_key_first = q->ninput_;
  const auto issuer_x = logic.eltw_input();
  const auto issuer_y = logic.eltw_input();
  L::bitvec<256> issuer_x_bits{}, issuer_y_bits{};
  for (auto* coordinate : {&issuer_x_bits, &issuer_y_bits})
    for (auto& bit : *coordinate) bit = logic.input();
  CanonicalP256CoordinateRelation<L>(logic).assert_bound(issuer_x,
                                                          issuer_x_bits);
  CanonicalP256CoordinateRelation<L>(logic).assert_bound(issuer_y,
                                                          issuer_y_bits);
  std::array<L::v8, 32> issuer_x_bytes{}, issuer_y_bytes{};
  for (std::size_t byte = 0; byte < 32; ++byte)
    for (std::size_t bit = 0; bit < 8; ++bit) {
      issuer_x_bytes[31 - byte][bit] = issuer_x_bits[byte * 8 + bit];
      issuer_y_bytes[31 - byte][bit] = issuer_y_bits[byte * 8 + bit];
    }
  for (const auto& wire : statement)
    logic.assert_eq(wire, logic.eltw_input());

  std::array<L::v8, 64 * B> signing{};
  for (auto& byte : signing) byte = logic.template vinput<8>();
  std::array<typename Sha::BlockWitness, B> signing_witness{};
  for (auto& block : signing_witness) block.input(logic);
  L::v256 signing_digest_bits{};
  for (auto& bit : signing_digest_bits) bit = logic.input();
  std::array<L::v8, H> header{};
  for (auto& byte : header) byte = logic.template vinput<8>();
  std::array<L::v8, (H * 6) / 8> header_decoded{};
  for (auto& byte : header_decoded) byte = logic.template vinput<8>();
  std::array<L::v8, P> payload{};
  for (auto& byte : payload) byte = logic.template vinput<8>();
  std::array<L::v8, (P * 6) / 8> payload_decoded{};
  for (auto& byte : payload_decoded) byte = logic.template vinput<8>();
  std::array<L::v8, 256> payload_padded{};
  for (auto& byte : payload_padded) byte = logic.template vinput<8>();
  typename Relation::Index issuer_len{}, vct_len{}, payload_len{};
  for (auto* index : {&issuer_len, &vct_len, &payload_len})
    for (auto& bit : *index) bit = logic.input();
  const auto explicit_sha = logic.input();
  const auto signing_digest = logic.eltw_input();
  typename Ecdsa::Witness ecdsa{};
  ecdsa.input(logic);
  typename Relation::Input issuer{
      signing, signing_witness, signing_digest_bits, header, header_decoded,
      payload, payload_decoded, logic.template vinput<8>(),
      logic.template vinput<8>(), payload_padded, issuer_len, vct_len,
      payload_len, explicit_sha, issuer_x, issuer_y, signing_digest, ecdsa, 4};

  std::array<L::v8, DisclosureChars> disclosure_ascii{};
  for (auto& byte : disclosure_ascii) byte = logic.template vinput<8>();
  std::array<L::v8, 64> disclosure_sha_input{};
  for (auto& byte : disclosure_sha_input) byte = logic.template vinput<8>();
  std::array<typename Sha::BlockWitness, 1> disclosure_sha_witness{};
  disclosure_sha_witness[0].input(logic);
  L::v256 disclosure_digest{};
  for (auto& bit : disclosure_digest) bit = logic.input();
  std::array<L::v8, 43> signed_digest{};
  for (auto& byte : signed_digest) byte = logic.template vinput<8>();
  typename Disclosure::Input disclosure_input{
      disclosure_ascii, disclosure_sha_input, disclosure_sha_witness,
      disclosure_digest, signed_digest, 1};
  L::bitvec<8> salt_len{}, name_len{}, value_len{}, disclosure_len{};
  for (auto* index : {&salt_len, &name_len, &value_len, &disclosure_len})
    for (auto& bit : *index) bit = logic.input();

  std::array<L::v8, 64> vct_sha_input{};
  for (auto& byte : vct_sha_input) byte = logic.template vinput<8>();
  typename Sha::BlockWitness vct_sha_witness{};
  vct_sha_witness.input(logic);
  L::v256 vct_digest{};
  for (auto& bit : vct_digest) bit = logic.input();

  if (layout) layout->membership_first = q->ninput_;
  if (layout) layout->not_before_bits_first = q->ninput_;
  const auto not_before_bits = logic.template vinput<64>();
  if (layout) layout->not_after_bits_first = q->ninput_;
  const auto not_after_bits = logic.template vinput<64>();
  if (layout) layout->private_epoch_first = q->ninput_;
  const auto private_epoch = logic.template vinput<64>();
  if (layout) layout->leaf_index_first = q->ninput_;
  const auto leaf_index = logic.template vinput<kIssuerRegistryDepthV1>();
  std::array<L::v8, 8> not_before{}, not_after{};
  if (layout) layout->interval_bytes_first = q->ninput_;
  for (auto* value : {&not_before, &not_after})
    for (auto& byte : *value) byte = logic.template vinput<8>();
  std::array<L::v8, 192> leaf_message{};
  if (layout) layout->leaf_message_first = q->ninput_;
  for (auto& byte : leaf_message) byte = logic.template vinput<8>();
  std::array<typename Sha::BlockWitness, 3> leaf_witness{};
  for (auto& block : leaf_witness) block.input(logic);
  L::v256 leaf_digest{};
  for (auto& bit : leaf_digest) bit = logic.input();
  std::array<std::array<L::v8, 32>, kIssuerRegistryDepthV1> siblings{};
  if (layout) layout->siblings_first = q->ninput_;
  for (auto& sibling : siblings)
    for (auto& byte : sibling) byte = logic.template vinput<8>();
  std::array<L::BitW, kIssuerRegistryDepthV1> directions{};
  for (std::size_t i = 0; i < directions.size(); ++i)
    directions[i] = leaf_index[i];
  std::array<std::array<L::v8, 128>, kIssuerRegistryDepthV1> node_messages{};
  std::array<std::array<typename Sha::BlockWitness, 2>,
             kIssuerRegistryDepthV1>
      node_witnesses{};
  std::array<L::v256, kIssuerRegistryDepthV1> node_digests{};
  for (std::size_t level = 0; level < kIssuerRegistryDepthV1; ++level) {
    if (layout) layout->node_message_first[level] = q->ninput_;
    for (auto& byte : node_messages[level])
      byte = logic.template vinput<8>();
    for (auto& block : node_witnesses[level]) block.input(logic);
    for (auto& bit : node_digests[level]) bit = logic.input();
  }

  Relation relation(logic);
  relation.assert_valid(issuer);
  relation.assert_registry_vct_hash(
      issuer, typename Relation::RegistryVctHashInput{
                  vct_sha_input, vct_sha_witness, vct_digest});
  relation.template assert_disclosure_binding<1, DisclosureChars>(
      issuer, disclosure_input);
  Disclosure disclosure(logic);
  std::array<L::v8, (DisclosureChars * 6) / 8> disclosure_json{};
  RestrictedBase64UrlRelation<L>(logic).decode(disclosure_ascii,
                                                   disclosure_json);
  disclosure.assert_three_string_active_grammar(
      disclosure_json, salt_len, name_len, value_len, disclosure_len, 9, 8,
      4);
  constexpr std::array<std::uint8_t, 8> kPolicyName{
      'a', 'g', 'e', '_', 'o', 'v', 'e', 'r'};
  constexpr std::array<std::uint8_t, 4> kPolicyValue{'t', 'r', 'u', 'e'};
  disclosure.assert_named_string_policy(disclosure_json, salt_len, name_len,
                                        value_len, kPolicyName, kPolicyValue,
                                        policy, 9);

  typename Membership::Hash3 leaf{leaf_message, leaf_witness, leaf_digest};
  std::array<typename Membership::Hash2, kIssuerRegistryDepthV1> nodes{
      typename Membership::Hash2{node_messages[0], node_witnesses[0],
                                 node_digests[0]},
      typename Membership::Hash2{node_messages[1], node_witnesses[1],
                                 node_digests[1]}};
  Membership(logic).assert_valid(typename Membership::Input{
      issuer_x_bytes, issuer_y_bytes,
      vct_digest, not_before, not_after, not_before_bits, not_after_bits,
      private_epoch, leaf_index, leaf, siblings, directions, nodes, root,
      epoch, valid_from, valid_until, depth});

  auto circuit = q->mkcircuit(1);
  if (layout) layout->total_inputs = circuit->ninputs;
  return circuit;
}

}  // namespace sd_jwt_zk
