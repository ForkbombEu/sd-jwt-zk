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

#pragma once

#include <array>
#include <string>
#include <vector>

#include "arrays/dense.h"
#include "circuits/sha/flatsha256_witness.h"
#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/issuer_jws_relation.h"
#include "sd_jwt_zk/p256_coordinate_relation.h"
#include "sd_jwt_zk/status_membership.h"
#include "sd_jwt_zk/status_private_bridge.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"

namespace sd_jwt_zk {

// Produces the padded compact-JWS signing input and SHA advice in the exact
// order consumed by IssuerJwsRelation.  Kept header-only because generic
// full-disclosure witness encoders need the same bounded representation.
template <std::size_t Blocks>
inline bool make_compact_sha_advice(
    std::string_view message, std::array<std::uint8_t, 64 * Blocks>& padded,
    std::array<proofs::FlatSHA256Witness::BlockWitness, Blocks>& advice,
    std::uint8_t& block_count) {
  proofs::FlatSHA256Witness::transform_and_witness_message(
      message.size(), reinterpret_cast<const std::uint8_t*>(message.data()),
      Blocks, block_count, padded.data(), advice.data());
  return block_count != 0;
}

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
// Status credential bindings moved behind the private-input boundary.  A
// status-capable proof has the same public bearer prefix as a statusless one.
inline constexpr std::size_t kFlatBearerPublicInputsV1 = 549;
inline constexpr std::size_t kFlatBearerDenseInputsV1 = 33113;

// Fills the exact wire order declared by BuildFlatBearerCircuitV1.  The full
// witness begins with the compiler's constant-one input, the public statement,
// the public Boolean policy result, and the equality-bound private statement
// copy. The verifier receives only the public prefix through
// FillFlatBearerPublicInputsV1.
bool FillFlatBearerDenseWitnessV1(
    proofs::Dense<FlatBearerField>& inputs,
    const std::array<std::uint8_t, 32>& public_statement,
    bool policy_result,
    const FlatBearerWitness& witness, bool status_required = false,
    const std::array<std::uint8_t, 32>& status_credential_binding = {},
    const std::array<std::uint8_t, 32>& status_context = {},
    const std::array<std::uint8_t, 32>& status_commitment = {});
bool FillFlatBearerPublicInputsV1(
    proofs::Dense<FlatBearerField>& inputs,
    const std::array<std::uint8_t, 32>& public_statement,
    bool policy_result,
    const P256Key& issuer_key, bool status_required = false,
    const std::array<std::uint8_t, 32>& status_context = {},
    const std::array<std::uint8_t, 32>& status_commitment = {});

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
Result<Envelope> prove_flat_bearer_v1(
    const Request& request, const FlatBearerWitness& witness,
    const StatusMembershipWitnessV1& status_witness,
    const Limits& limits = {});
Result<bool> verify_flat_bearer_v1(const Envelope& envelope,
                                  const Request& expected_request,
                                  std::uint64_t now,
                                  FlatBearerReplayStoreV1& replay_store,
                                  const Limits& limits = {});

// Exact wire bundle allocated by the issuer relation.  It is an optional
// composition handoff, not witness advice: every member is populated from the
// same canonical compact/JWS wires consumed by IssuerJwsRelation.
template <class LogicT> struct FlatBearerCompactOpeningWireBundleV1 {
  using Sha = proofs::FlatSHA256Circuit<LogicT, proofs::BitPlucker<LogicT, 4>>;
  std::array<typename LogicT::v8, 102> header{};
  typename LogicT::template bitvec<8> header_length{};
  std::array<typename LogicT::v8, 228> payload{};
  typename LogicT::template bitvec<8> payload_length{};
  std::array<typename LogicT::v8, 171> decoded_payload{};
  std::array<typename LogicT::v8, 384> sha_input{};
  std::array<typename Sha::BlockWitness, 6> sha_witness{};
  typename LogicT::v256 digest_bits{};
  typename LogicT::v8 sha_block_count{};
};

// Allocation seam for future Dense-backed evaluation replay.  The compiler
// implementation is intentionally a transparent forwarding source, so moving
// call sites to it does not alter the established flat-bearer wire order.
struct FlatBearerCompilerAllocationSourceV1 {
  FlatBearerLogic& logic;
  FlatBearerLogic::EltW element() const { return logic.eltw_input(); }
  FlatBearerLogic::BitW bit() const { return logic.input(); }
  template <std::size_t Bits>
  typename FlatBearerLogic::template bitvec<Bits> value() const {
    return logic.template vinput<Bits>();
  }
};

template <class LogicT, class AllocationSource>
inline void AllocateFlatBearerRelationV1WithSource(
    proofs::QuadCircuit<FlatBearerField>* q, LogicT& logic,
    AllocationSource& allocation_source,
    const std::array<typename LogicT::v8, 8>* issuer_prefix = nullptr,
    const std::array<typename LogicT::v8, 43>* signed_digest_binding = nullptr,
    std::array<typename LogicT::v8, 128>* payload_json_binding = nullptr,
    typename LogicT::template bitvec<8>* payload_length_binding = nullptr,
    std::array<typename LogicT::EltW, 32>* signing_digest_public_binding = nullptr,
    FlatBearerCompactOpeningWireBundleV1<LogicT>* compact_opening_binding = nullptr,
    bool enforce_flat_payload = true) {
  constexpr std::size_t kSigningBlocks = 6, kHeaderChars = 102, kPayloadChars = 228;
  auto& allocation = allocation_source;
  std::array<typename LogicT::EltW, 32> public_statement{};
  for (auto& wire : public_statement) wire = allocation.element();
  const auto public_policy_result = allocation.bit();
  const auto public_x = allocation.element();
  const auto public_y = allocation.element();
  const auto public_status_required = allocation.bit();
  // Reserved public bridge statement: request-fresh context and a SHA-256
  // commitment to the private signing digest.  The private binding below is
  // constrained to the issuer SHA digest before it is used by status.
  std::array<typename LogicT::v8, 32> public_status_context{};
  std::array<typename LogicT::v8, 32> public_status_commitment{};
  for (auto& byte : public_status_context) byte = allocation.template value<8>();
  for (auto& byte : public_status_commitment) byte = allocation.template value<8>();
  q->private_input();
  std::array<typename LogicT::v8, 32> private_status_binding{};
  for (auto& byte : private_status_binding) byte = allocation.template value<8>();
  using StatusBridge = StatusPrivateBridgeRelationV1<LogicT>;
  std::array<typename LogicT::v8, StatusBridge::kPaddedBytes> status_bridge_padded{};
  for (auto& byte : status_bridge_padded) byte = allocation.template value<8>();
  std::array<typename StatusBridge::Sha::BlockWitness, StatusBridge::kBlocks>
      status_bridge_witness{};
  for (auto& witness : status_bridge_witness) witness.input(logic);
  typename LogicT::v256 status_bridge_digest{};
  for (auto& bit : status_bridge_digest) bit = allocation.bit();
  // The bridge SHA relation is allocated with its witness advice in the
  // private partition after the credential-bound signing digest.
  typename LogicT::template bitvec<256> registry_x_bits{}, registry_y_bits{};
  for (auto* coordinate : {&registry_x_bits, &registry_y_bits})
    for (auto& bit : *coordinate) bit = allocation.bit();
  CanonicalP256CoordinateRelation<LogicT>(logic).assert_bound(
      public_x, registry_x_bits);
  CanonicalP256CoordinateRelation<LogicT>(logic).assert_bound(
      public_y, registry_y_bits);
  if (issuer_prefix != nullptr)
    for (std::size_t byte = 0; byte < issuer_prefix->size(); ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        logic.assert_eq((*issuer_prefix)[byte][bit],
                        registry_x_bits[(31 - byte) * 8 + bit]);
  for (const auto& wire : public_statement)
    logic.assert_eq(wire, allocation.element());
  using Relation = IssuerJwsRelation<LogicT, kSigningBlocks, kHeaderChars, kPayloadChars>;
  using Sha = proofs::FlatSHA256Circuit<LogicT, proofs::BitPlucker<LogicT, 4>>;
  using Ecdsa = proofs::VerifyCircuit<LogicT, FlatBearerField, proofs::P256>;
  std::array<typename LogicT::v8, 64 * kSigningBlocks> signing{};
  for (auto& byte : signing) byte = allocation.template value<8>();
  std::array<typename Sha::BlockWitness, kSigningBlocks> sha_witness{};
  for (auto& block : sha_witness) block.input(logic);
  typename LogicT::v256 digest_bits{}; for (auto& bit : digest_bits) bit = allocation.bit();
  std::array<typename LogicT::v8, kHeaderChars> header{}; for (auto& byte : header) byte = allocation.template value<8>();
  std::array<typename LogicT::v8, (kHeaderChars * 6) / 8> header_decoded{}; for (auto& byte : header_decoded) byte = allocation.template value<8>();
  std::array<typename LogicT::v8, kPayloadChars> payload{}; for (auto& byte : payload) byte = allocation.template value<8>();
  std::array<typename LogicT::v8, (kPayloadChars * 6) / 8> payload_decoded{}; for (auto& byte : payload_decoded) byte = allocation.template value<8>();
  std::array<typename LogicT::v8, 256> padded{}; for (auto& byte : padded) byte = allocation.template value<8>();
  typename Relation::Index issuer_len{}, vct_len{}, payload_len{};
  typename Relation::Index header_b64_len{}, payload_b64_len{};
  for (auto* index : {&header_b64_len, &payload_b64_len})
    for (auto& bit : *index) bit = allocation.bit();
  for (auto* index : {&issuer_len, &vct_len, &payload_len}) for (auto& bit : *index) bit = allocation.bit();
  if (compact_opening_binding != nullptr) {
    compact_opening_binding->header = header;
    compact_opening_binding->header_length = header_b64_len;
    compact_opening_binding->payload = payload;
    compact_opening_binding->payload_length = payload_len;
    compact_opening_binding->decoded_payload = payload_decoded;
    compact_opening_binding->sha_input = signing;
    compact_opening_binding->sha_witness = sha_witness;
    compact_opening_binding->digest_bits = digest_bits;
    compact_opening_binding->sha_block_count = logic.template vbit<8>(4);
  }
  if (payload_json_binding != nullptr) {
    for (std::size_t byte = 0; byte < payload_json_binding->size(); ++byte)
      (*payload_json_binding)[byte] =
          byte < payload_decoded.size()
              ? payload_decoded[byte]
              : logic.template vbit<8>(0);
  }
  if (payload_length_binding != nullptr) *payload_length_binding = payload_len;
  const auto explicit_sha = allocation.bit();
  const auto digest = allocation.element();
  for (std::size_t byte = 0; byte < private_status_binding.size(); ++byte) {
    typename LogicT::template bitvec<8> digest_byte{};
    for (std::size_t bit = 0; bit < 8; ++bit)
      digest_byte[bit] = digest_bits[(31 - byte) * 8 + bit];
    logic.assert_implies(public_status_required,
                         logic.veq(private_status_binding[byte], digest_byte));
  }
  StatusBridge(logic).assert_valid({private_status_binding, public_status_context,
                                    public_status_commitment, status_bridge_padded,
                                    status_bridge_witness, status_bridge_digest});
  // The issuer-side bridge exports the exact signing-input SHA-256 bytes only
  // through the existing public statement.  A disclosure circuit may bind an
  // opening to these values, but cannot substitute an arbitrary private
  // digest. SHA's field-bit vector is little-endian while compact digest bytes
  // are conventional big-endian.
  if (signing_digest_public_binding != nullptr) {
    for (std::size_t byte = 0; byte < signing_digest_public_binding->size();
         ++byte) {
      typename LogicT::template bitvec<8> digest_byte{};
      for (std::size_t bit = 0; bit < 8; ++bit)
        digest_byte[bit] = digest_bits[(31 - byte) * 8 + bit];
      (*signing_digest_public_binding)[byte] = logic.as_scalar(digest_byte);
      logic.assert_eq(public_statement[byte],
                      (*signing_digest_public_binding)[byte]);
    }
  }
  typename Ecdsa::Witness ecdsa{}; ecdsa.input(logic);
  typename Relation::Input issuer{signing, sha_witness, digest_bits, header, header_decoded, payload, payload_decoded,
      header_b64_len, payload_b64_len, padded,
      issuer_len, vct_len, payload_len, explicit_sha, public_x, public_y, digest, ecdsa, 6};
  constexpr std::size_t kDisclosureChars = 42;
  using Disclosure = FlatDisclosureRelation<LogicT, 1, kDisclosureChars>;
  using DisclosureSha = proofs::FlatSHA256Circuit<
      LogicT, proofs::BitPlucker<LogicT, 4>>;
  std::array<typename LogicT::v8, kDisclosureChars> disclosure_ascii{};
  for (auto& byte : disclosure_ascii) byte = allocation.template value<8>();
  std::array<typename LogicT::v8, 64> disclosure_sha_input{};
  for (auto& byte : disclosure_sha_input) byte = allocation.template value<8>();
  std::array<typename DisclosureSha::BlockWitness, 1> disclosure_sha_witness{};
  disclosure_sha_witness[0].input(logic);
  typename LogicT::v256 disclosure_digest{};
  for (auto& bit : disclosure_digest) bit = allocation.bit();
  std::array<typename LogicT::v8, 43> signed_digest{};
  for (auto& byte : signed_digest) byte = allocation.template value<8>();
  if (signed_digest_binding != nullptr)
    for (std::size_t i = 0; i < signed_digest.size(); ++i)
      logic.vassert_eq(signed_digest[i], (*signed_digest_binding)[i]);
  typename Disclosure::Input disclosure_input{
      disclosure_ascii, disclosure_sha_input, disclosure_sha_witness,
      disclosure_digest, signed_digest, 1};
  constexpr std::size_t kArrayDisclosureChars = 26;
  using ArrayDisclosure = FlatDisclosureRelation<LogicT, 1, kArrayDisclosureChars>;
  std::array<typename LogicT::v8, kArrayDisclosureChars> array_disclosure_ascii{};
  for (auto& byte : array_disclosure_ascii) byte = allocation.template value<8>();
  std::array<typename LogicT::v8, 64> array_disclosure_sha_input{};
  for (auto& byte : array_disclosure_sha_input) byte = allocation.template value<8>();
  std::array<typename DisclosureSha::BlockWitness, 1> array_disclosure_sha_witness{};
  array_disclosure_sha_witness[0].input(logic);
  typename LogicT::v256 array_disclosure_digest{};
  for (auto& bit : array_disclosure_digest) bit = allocation.bit();
  std::array<typename LogicT::v8, 43> array_signed_digest{};
  for (std::size_t i = 0; i < array_signed_digest.size(); ++i)
    array_signed_digest[i] = payload_decoded[72 + i];
  typename ArrayDisclosure::Input array_disclosure_input{
      array_disclosure_ascii, array_disclosure_sha_input,
      array_disclosure_sha_witness, array_disclosure_digest,
      array_signed_digest, 1};
  typename LogicT::template bitvec<8> salt_len{}, name_len{}, value_len{},
      disclosure_len{};
  for (auto* index : {&salt_len, &name_len, &value_len, &disclosure_len})
    for (auto& bit : *index) bit = allocation.bit();
  std::array<typename LogicT::v8, 64> registry_vct_sha_input{};
  for (auto& byte : registry_vct_sha_input) byte = allocation.template value<8>();
  typename Sha::BlockWitness registry_vct_sha_witness{};
  registry_vct_sha_witness.input(logic);
  typename LogicT::v256 registry_vct_digest{};
  for (auto& bit : registry_vct_digest) bit = allocation.bit();

  Relation relation(logic);
  if (enforce_flat_payload)
    relation.assert_valid(issuer);
  else
    relation.assert_compact_authenticated(issuer);
  if (!enforce_flat_payload) return;
  relation.assert_registry_vct_hash(
      issuer, typename Relation::RegistryVctHashInput{
          registry_vct_sha_input, registry_vct_sha_witness, registry_vct_digest});
  relation.template assert_disclosure_binding<1, kDisclosureChars>(
      issuer, disclosure_input);
  Disclosure disclosure(logic);
  std::array<typename LogicT::v8, (kDisclosureChars * 6) / 8>
      disclosure_json{};
  RestrictedBase64UrlRelation<LogicT>(logic).decode(
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
  ArrayDisclosure array_disclosure(logic);
  array_disclosure.assert_digest_match(array_disclosure_input);
  std::array<typename LogicT::v8, (kArrayDisclosureChars * 6) / 8>
      array_disclosure_json{};
  RestrictedBase64UrlRelation<LogicT>(logic).decode(
      array_disclosure_ascii, array_disclosure_json);
  array_disclosure.template assert_two_string_array<8, 4>(
      array_disclosure_json);
}

inline void AllocateFlatBearerRelationV1(
    proofs::QuadCircuit<FlatBearerField>* q, FlatBearerLogic& logic,
    const std::array<FlatBearerLogic::v8, 8>* issuer_prefix = nullptr,
    const std::array<FlatBearerLogic::v8, 43>* signed_digest_binding = nullptr,
    std::array<FlatBearerLogic::v8, 128>* payload_json_binding = nullptr,
    FlatBearerLogic::bitvec<8>* payload_length_binding = nullptr,
    std::array<FlatBearerLogic::EltW, 32>* signing_digest_public_binding = nullptr,
    FlatBearerCompactOpeningWireBundleV1<FlatBearerLogic>* compact_opening_binding = nullptr,
    bool enforce_flat_payload = true) {
  FlatBearerCompilerAllocationSourceV1 allocation{logic};
  AllocateFlatBearerRelationV1WithSource(
      q, logic, allocation, issuer_prefix, signed_digest_binding,
      payload_json_binding, payload_length_binding, signing_digest_public_binding,
      compact_opening_binding, enforce_flat_payload);
}

inline std::unique_ptr<proofs::Circuit<FlatBearerField>> BuildFlatBearerCircuitV1(
    proofs::QuadCircuit<FlatBearerField>* q) {
  FlatBearerBackend backend(q);
  FlatBearerLogic logic(&backend, proofs::p256_base);
  AllocateFlatBearerRelationV1(q, logic);
  return q->mkcircuit(1);
}

}  // namespace sd_jwt_zk
