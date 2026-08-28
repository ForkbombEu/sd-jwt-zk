#pragma once

#include <array>
#include <memory>

#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "ec/p256.h"
#include "sd_jwt_zk/active_presentation_message_relation.h"
#include "sd_jwt_zk/flat_disclosure_relation.h"
#include "sd_jwt_zk/holder_issuer_jws_relation.h"
#include "sd_jwt_zk/kb_jwt_relation.h"

namespace sd_jwt_zk {

using HolderPresentationField = proofs::Fp256Base;
using HolderPresentationBackend = proofs::CompilerBackend<HolderPresentationField>;
using HolderPresentationLogic = proofs::Logic<HolderPresentationField,
                                               HolderPresentationBackend>;

// The public prefix is statement (32 field elements), Boolean policy result,
// issuer trust key (two field elements), and the KB verifier challenge bytes:
// audience(24+8), nonce(14+8), and inclusive time bounds (10+10 bytes).
inline constexpr std::size_t kHolderPresentationPublicInputsV1 = 515;

namespace holder_presentation_detail {
template <class Logic, std::size_t N>
std::array<typename Logic::v8, N> private_bytes(const Logic& logic) {
  std::array<typename Logic::v8, N> values{};
  for (auto& value : values) value = logic.template vinput<8>();
  return values;
}

template <class Logic, std::size_t N>
typename Logic::template bitvec<N> private_bits(const Logic& logic) {
  typename Logic::template bitvec<N> values{};
  for (auto& value : values) value = logic.input();
  return values;
}
}  // namespace holder_presentation_detail

namespace D = holder_presentation_detail;

// Compile-only V1 holder-bound presentation family.  It intentionally has no
// Dense encoder or proving API yet.  Each semantic value is allocated once:
// issuer compact bytes feed the active presentation SHA, `sd_hash` feeds both
// that SHA encoding and KB payload grammar, issuer signature feeds issuer
// authentication and compact construction, and holder coordinates feed both
// cnf and KB ES256 verification.
inline std::unique_ptr<proofs::Circuit<HolderPresentationField>>
BuildHolderPresentationCircuitV1(proofs::QuadCircuit<HolderPresentationField>* q) {
  constexpr std::size_t kIssuerBlocks = 10, kIssuerHeader = 102;
  constexpr std::size_t kIssuerPayload = 472, kIssuerPadded = 384;
  constexpr std::size_t kIssuerCompact = 662, kDisclosure = 42;
  constexpr std::size_t kPresentationBlocks = 12;
  constexpr std::size_t kKbBlocks = 4, kKbHeader = 40, kKbPayload = 176;
  constexpr std::size_t kAudience = 24, kNonce = 14;
  using Logic = HolderPresentationLogic;
  using Holder = HolderIssuerJwsRelation<Logic, kIssuerBlocks, kIssuerHeader,
      kIssuerPayload, kIssuerPadded>;
  using Issuer = IssuerJwsRelation<Logic, kIssuerBlocks, kIssuerHeader,
      kIssuerPayload, kIssuerPadded, 9>;
  using IssuerSha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;
  using Ecdsa = proofs::VerifyCircuit<Logic, HolderPresentationField, proofs::P256>;
  using Disclosure = FlatDisclosureRelation<Logic, 1, kDisclosure>;
  using Presentation = ActivePresentationHashRelation<Logic, kIssuerCompact,
      kDisclosure, kPresentationBlocks>;
  using Kb = KbJwsRelation<Logic, kKbBlocks, kKbHeader, kKbPayload, kAudience, kNonce>;
  using KbSha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;

  HolderPresentationBackend backend(q);
  Logic logic(&backend, proofs::p256_base);
  std::array<Logic::EltW, 32> statement{};
  for (auto& wire : statement) wire = logic.eltw_input();
  const auto policy_result = logic.input();
  const auto issuer_x = logic.eltw_input();
  const auto issuer_y = logic.eltw_input();
  auto audience = D::private_bytes<Logic, kAudience>(logic);
  auto audience_length = D::private_bits<Logic, 8>(logic);
  auto nonce = D::private_bytes<Logic, kNonce>(logic);
  auto nonce_length = D::private_bits<Logic, 8>(logic);
  auto time_min = D::private_bytes<Logic, 10>(logic);
  auto time_max = D::private_bytes<Logic, 10>(logic);

  q->private_input();
  for (const auto& wire : statement) logic.assert_eq(wire, logic.eltw_input());
  auto issuer_sha_input = D::private_bytes<Logic, 64 * kIssuerBlocks>(logic);
  std::array<IssuerSha::BlockWitness, kIssuerBlocks> issuer_sha_witness{};
  for (auto& block : issuer_sha_witness) block.input(logic);
  auto issuer_digest_bits = D::private_bits<Logic, 256>(logic);
  auto issuer_header = D::private_bytes<Logic, kIssuerHeader>(logic);
  auto issuer_header_decoded = D::private_bytes<Logic, (kIssuerHeader * 6) / 8>(logic);
  auto issuer_payload = D::private_bytes<Logic, kIssuerPayload>(logic);
  auto issuer_payload_decoded = D::private_bytes<Logic, (kIssuerPayload * 6) / 8>(logic);
  auto issuer_payload_padded = D::private_bytes<Logic, kIssuerPadded>(logic);
  auto issuer_header_length = D::private_bits<Logic, 9>(logic);
  auto issuer_payload_length = D::private_bits<Logic, 9>(logic);
  auto issuer_name_length = D::private_bits<Logic, 9>(logic);
  auto issuer_vct_length = D::private_bits<Logic, 9>(logic);
  auto issuer_decoded_length = D::private_bits<Logic, 9>(logic);
  const auto explicit_sha256 = logic.input();
  const auto issuer_digest = logic.eltw_input();
  Ecdsa::Witness issuer_ecdsa{}; issuer_ecdsa.input(logic);
  std::array<Logic::v8, 86> issuer_signature{};
  for (auto& byte : issuer_signature) byte = logic.template vinput<8>();
  const auto issuer_signature_r = logic.eltw_input();
  const auto issuer_signature_s = logic.eltw_input();
  const auto holder_x = logic.eltw_input();
  const auto holder_y = logic.eltw_input();
  auto issuer_compact = D::private_bytes<Logic, kIssuerCompact>(logic);
  auto issuer_compact_length = D::private_bits<Logic, 9>(logic);
  typename Issuer::Input issuer{issuer_sha_input, issuer_sha_witness,
      issuer_digest_bits, issuer_header, issuer_header_decoded, issuer_payload,
      issuer_payload_decoded, issuer_header_length, issuer_payload_length,
      issuer_payload_padded, issuer_name_length, issuer_vct_length,
      issuer_decoded_length, explicit_sha256, issuer_x, issuer_y, issuer_digest,
      issuer_ecdsa, kIssuerBlocks};

  auto disclosure = D::private_bytes<Logic, kDisclosure>(logic);
  auto disclosure_sha_input = D::private_bytes<Logic, 64>(logic);
  std::array<IssuerSha::BlockWitness, 1> disclosure_sha_witness{};
  disclosure_sha_witness[0].input(logic);
  auto disclosure_digest_bits = D::private_bits<Logic, 256>(logic);
  auto signed_disclosure_digest = D::private_bytes<Logic, 43>(logic);
  typename Disclosure::Input disclosure_input{disclosure, disclosure_sha_input,
      disclosure_sha_witness, disclosure_digest_bits, signed_disclosure_digest, 1};
  auto salt_length = D::private_bits<Logic, 8>(logic);
  auto disclosure_name_length = D::private_bits<Logic, 8>(logic);
  auto disclosure_value_length = D::private_bits<Logic, 8>(logic);
  auto disclosure_length8 = D::private_bits<Logic, 8>(logic);
  Logic::bitvec<1> disclosure_high{};
  disclosure_high[0] = logic.bit(0);
  const auto disclosure_length9 = logic.vappend(disclosure_length8, disclosure_high);

  auto presentation_padded = D::private_bytes<Logic, 64 * kPresentationBlocks>(logic);
  std::array<IssuerSha::BlockWitness, kPresentationBlocks> presentation_witness{};
  for (auto& block : presentation_witness) block.input(logic);
  auto presentation_digest_bits = D::private_bits<Logic, 256>(logic);
  auto presentation_block_count = D::private_bits<Logic, 9>(logic);
  auto sd_hash = D::private_bytes<Logic, 43>(logic);

  auto kb_sha_input = D::private_bytes<Logic, 64 * kKbBlocks>(logic);
  std::array<KbSha::BlockWitness, kKbBlocks> kb_sha_witness{};
  for (auto& block : kb_sha_witness) block.input(logic);
  auto kb_digest_bits = D::private_bits<Logic, 256>(logic);
  auto kb_header = D::private_bytes<Logic, kKbHeader>(logic);
  auto kb_header_decoded = D::private_bytes<Logic, (kKbHeader * 6) / 8>(logic);
  auto kb_payload = D::private_bytes<Logic, kKbPayload>(logic);
  auto kb_signature = D::private_bytes<Logic, 86>(logic);
  auto kb_payload_decoded = D::private_bytes<Logic, (kKbPayload * 6) / 8>(logic);
  auto kb_header_length = D::private_bits<Logic, 8>(logic);
  auto kb_payload_length = D::private_bits<Logic, 8>(logic);
  const auto kb_signature_r = logic.eltw_input();
  const auto kb_signature_s = logic.eltw_input();
  const auto kb_digest = logic.eltw_input();
  Ecdsa::Witness kb_ecdsa{}; kb_ecdsa.input(logic);
  typename Kb::Input kb{kb_sha_input, kb_sha_witness, kb_digest_bits, kb_header,
      kb_header_decoded, kb_payload, kb_signature, kb_payload_decoded,
      kb_header_length, kb_payload_length, audience, audience_length, nonce,
      nonce_length, time_min, time_max, sd_hash, holder_x, holder_y,
      kb_signature_r, kb_signature_s, kb_digest, kb_ecdsa, kKbBlocks};

  Holder holder(logic);
  holder.assert_valid(issuer, holder_x, holder_y, issuer_signature,
                      issuer_signature_r, issuer_signature_s);
  holder.assert_full_compact_binding(issuer, issuer_signature, issuer_compact,
                                     issuer_compact_length);
  Issuer(logic).template assert_disclosure_binding<1, kDisclosure>(
      issuer, disclosure_input);
  Disclosure disclosure_relation(logic);
  std::array<Logic::v8, (kDisclosure * 6) / 8> disclosure_json{};
  RestrictedBase64UrlRelation<Logic>(logic).decode(disclosure, disclosure_json);
  disclosure_relation.assert_three_string_active_grammar(
      disclosure_json, salt_length, disclosure_name_length,
      disclosure_value_length, disclosure_length8, 9, 8, 4);
  constexpr std::array<std::uint8_t, 8> kPolicyName{
      'a', 'g', 'e', '_', 'o', 'v', 'e', 'r'};
  constexpr std::array<std::uint8_t, 4> kPolicyValue{'t', 'r', 'u', 'e'};
  disclosure_relation.assert_named_string_policy(
      disclosure_json, salt_length, disclosure_name_length,
      disclosure_value_length, kPolicyName, kPolicyValue, policy_result, 9);
  typename Presentation::Input presentation{issuer_compact, issuer_compact_length,
      disclosure, disclosure_length9, presentation_padded,
      presentation_block_count, presentation_witness, presentation_digest_bits,
      sd_hash};
  Kb(logic).assert_valid(kb);
  Kb(logic).template assert_active_presentation_binding<kPresentationBlocks,
      kIssuerCompact, kDisclosure>(kb, presentation);
  return q->mkcircuit(1);
}

}  // namespace sd_jwt_zk
