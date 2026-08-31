#pragma once

#include <algorithm>
#include <array>
#include <memory>
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
#include <chrono>
#include <iostream>
#endif

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "ec/p256.h"
#include "sd_jwt_zk/active_presentation_message_relation.h"
#include "sd_jwt_zk/flat_disclosure_relation.h"
#include "sd_jwt_zk/holder_bridge_mac_relation.h"
#include "sd_jwt_zk/holder_dense_layout.h"
#include "sd_jwt_zk/holder_issuer_jws_relation.h"
#include "sd_jwt_zk/presentation_hash_relation.h"
#include "sd_jwt_zk/p256_coordinate_relation.h"
#include "sd_jwt_zk/status_private_bridge.h"

namespace sd_jwt_zk {
using HolderCredentialField = proofs::Fp256Base;
using HolderCredentialBackend = proofs::CompilerBackend<HolderCredentialField>;
using HolderCredentialLogic = proofs::Logic<HolderCredentialField, HolderCredentialBackend>;

namespace holder_credential_detail {
template <class Logic, std::size_t N>
std::array<typename Logic::v8, N> bytes(const Logic& logic) {
  std::array<typename Logic::v8, N> out{};
  for (auto& byte : out) byte = logic.template vinput<8>();
  return out;
}
template <class Logic, std::size_t N>
typename Logic::template bitvec<N> bits(const Logic& logic) {
  typename Logic::template bitvec<N> out{};
  for (auto& bit : out) bit = logic.input();
  return out;
}
}  // namespace holder_credential_detail

// Bounded credential component of the holder pair.  It deliberately contains
// no KB wires: its only cross-component interface is the MAC on cnf x/y and
// the exact active-presentation SHA-256 digest.
inline std::unique_ptr<proofs::Circuit<HolderCredentialField>>
BuildHolderCredentialCircuitV1(
    proofs::QuadCircuit<HolderCredentialField>* q,
    HolderDenseLayoutV1* layout = nullptr, bool include_bridge = true) {
  // The first real-proof V1 bucket fixes the authenticated compact length at
  // 514 bytes (seven signing blocks) while retaining zero-padded parser
  // capacity.  Larger active compact lengths require a distinct circuit ID.
  constexpr std::size_t B = 10, H = 102, P = 472, Pad = 384, Compact = 662;
  constexpr std::size_t DisclosureChars = 42, ActiveCompact = 514;
  constexpr std::size_t PresentationBlocks = 9;
  using L = HolderCredentialLogic;
  using Issuer = IssuerJwsRelation<L, B, H, P, Pad, 9>;
  using Holder = HolderIssuerJwsRelation<L, B, H, P, Pad>;
  using Sha = proofs::FlatSHA256Circuit<L, proofs::BitPlucker<L, 4>>;
  using Ecdsa = proofs::VerifyCircuit<L, HolderCredentialField, proofs::P256>;
  using Disclosure = FlatDisclosureRelation<L, 1, DisclosureChars>;
  using Presentation = PresentationHashRelation<
      L, PresentationBlocks, ActiveCompact, DisclosureChars>;
  using Bridge = HolderBridgeMacRelation<L>;
  HolderCredentialBackend backend(q);
  L logic(&backend, proofs::p256_base);
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
  const auto started = std::chrono::steady_clock::now();
  auto stage = [&](const char* name) {
    const auto now = std::chrono::steady_clock::now();
    std::cerr << "holder-credential stage=" << name
              << " ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(now-started).count()
              << " inputs=" << q->ninput_ << '\n';
  };
#endif
  std::array<L::v128, Bridge::kTags> tags{};
  for (auto& tag : tags) tag = logic.vinput<128>();
  const auto av = logic.vinput<128>();
  const auto policy = logic.input();
  const auto status_required = logic.input();
  L::EltW issuer_x{}, issuer_y{};
  issuer_x = logic.eltw_input();
  issuer_y = logic.eltw_input();
  std::array<L::v8, 32> status_context{}, status_commitment{};
  for (auto& byte : status_context) byte = logic.template vinput<8>();
  for (auto& byte : status_commitment) byte = logic.template vinput<8>();
  if (layout) layout->begin(q->ninput_);
  q->private_input();
  const auto status_start = q->ninput_;
  std::array<L::v8, 32> status_binding{};
  for (auto& byte : status_binding) byte = logic.template vinput<8>();
  if (layout) layout->add("status-private-binding", status_start, q->ninput_);
  const auto status_bridge_start = q->ninput_;
  using StatusBridge = StatusPrivateBridgeRelationV1<L>;
  std::array<L::v8, StatusBridge::kPaddedBytes> status_bridge_padded{};
  for (auto& byte : status_bridge_padded) byte = logic.template vinput<8>();
  std::array<typename StatusBridge::Sha::BlockWitness, StatusBridge::kBlocks> status_bridge_witness{};
  for (auto& witness : status_bridge_witness) witness.input(logic);
  L::v256 status_bridge_digest{};
  for (auto& bit : status_bridge_digest) bit = logic.input();
  if (layout) layout->add("status-private-bridge", status_bridge_start, q->ninput_);
  const auto issuer_start = q->ninput_;
  auto sha_in = holder_credential_detail::bytes<L, 64 * B>(logic);
  std::array<Sha::BlockWitness, B> sha_w{}; for (auto& w : sha_w) w.input(logic);
  auto digest_bits = holder_credential_detail::bits<L, 256>(logic);
  auto header = holder_credential_detail::bytes<L, H>(logic);
  auto header_json = holder_credential_detail::bytes<L, (H * 6) / 8>(logic);
  auto payload = holder_credential_detail::bytes<L, P>(logic);
  auto payload_json = holder_credential_detail::bytes<L, (P * 6) / 8>(logic);
  auto padded = holder_credential_detail::bytes<L, Pad>(logic);
  auto header_len = holder_credential_detail::bits<L, 9>(logic);
  auto payload_len = holder_credential_detail::bits<L, 9>(logic);
  auto issuer_len = holder_credential_detail::bits<L, 9>(logic);
  auto vct_len = holder_credential_detail::bits<L, 9>(logic);
  auto decoded_len = holder_credential_detail::bits<L, 9>(logic);
  const auto explicit_sha = logic.input();
  const auto issuer_digest = logic.eltw_input();
  Ecdsa::Witness issuer_ecdsa{}; issuer_ecdsa.input(logic);
  auto signature = holder_credential_detail::bytes<L, 86>(logic);
  const auto signature_r = logic.eltw_input();
  const auto signature_s = logic.eltw_input();
  const auto holder_x = logic.eltw_input();
  const auto holder_y = logic.eltw_input();
  if (layout) layout->add("issuer-cnf-and-signature", issuer_start, q->ninput_);
  const auto presentation_start = q->ninput_;
  auto compact = holder_credential_detail::bytes<L, Compact>(logic);
  auto compact_len = holder_credential_detail::bits<L, 10>(logic);
  typename Issuer::Input issuer{sha_in, sha_w, digest_bits, header, header_json,
      payload, payload_json, header_len, payload_len, padded, issuer_len, vct_len,
      decoded_len, explicit_sha, issuer_x, issuer_y, issuer_digest, issuer_ecdsa, 7};
  auto disclosure = holder_credential_detail::bytes<L, DisclosureChars>(logic);
  auto disclosure_sha = holder_credential_detail::bytes<L, 64>(logic);
  std::array<Sha::BlockWitness, 1> disclosure_w{}; disclosure_w[0].input(logic);
  auto disclosure_digest = holder_credential_detail::bits<L, 256>(logic);
  auto signed_digest = holder_credential_detail::bytes<L, 43>(logic);
  typename Disclosure::Input disclosure_input{disclosure, disclosure_sha, disclosure_w,
      disclosure_digest, signed_digest, 1};
  auto salt_len = holder_credential_detail::bits<L, 8>(logic);
  auto name_len = holder_credential_detail::bits<L, 8>(logic);
  auto value_len = holder_credential_detail::bits<L, 8>(logic);
  auto disclosure_len8 = holder_credential_detail::bits<L, 8>(logic);
  auto presentation_padded = holder_credential_detail::bytes<L, 64 * PresentationBlocks>(logic);
  std::array<Sha::BlockWitness, PresentationBlocks> presentation_w{};
  for (auto& w : presentation_w) w.input(logic);
  auto presentation_digest = holder_credential_detail::bits<L, 256>(logic);
  auto sd_hash = holder_credential_detail::bytes<L, 43>(logic);
  if (layout) layout->add("active-presentation", presentation_start, q->ninput_);
  const auto bridge_start = q->ninput_;
  Holder(logic).assert_valid(issuer, holder_x, holder_y, signature,
                             signature_r, signature_s);
  Holder(logic).assert_full_compact_binding(issuer, signature, compact,
                                            compact_len);
  logic.assert1(logic.veq(compact_len, ActiveCompact));
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
  stage("issuer-cnf-ecdsa");
#endif
  Disclosure disclosure_relation(logic);
  std::array<L::v8, (DisclosureChars * 6) / 8> disclosure_json{};
  Issuer(logic).template assert_disclosure_binding<1, DisclosureChars>(
      issuer, disclosure_input);
  RestrictedBase64UrlRelation<L>(logic).decode(disclosure, disclosure_json);
  disclosure_relation.assert_three_string_active_grammar(
      disclosure_json, salt_len, name_len, value_len, disclosure_len8, 9, 8,
      4);
  constexpr std::array<std::uint8_t, 8> name{'a','g','e','_','o','v','e','r'};
  constexpr std::array<std::uint8_t, 4> value{'t','r','u','e'};
  disclosure_relation.assert_named_string_policy(
      disclosure_json, salt_len, name_len, value_len, name, value, policy, 9);
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
  stage("disclosure-policy");
#endif
  std::array<L::v8, ActiveCompact> active_compact{};
  std::copy_n(compact.begin(), ActiveCompact, active_compact.begin());
  typename Presentation::Input presentation{
      active_compact, disclosure, presentation_padded, presentation_w,
      presentation_digest, sd_hash};
  Presentation(logic).assert_valid(presentation);
  for (std::size_t byte = 0; byte < status_binding.size(); ++byte) {
    L::v8 digest_byte{};
    for (std::size_t bit = 0; bit < 8; ++bit)
      digest_byte[bit] = digest_bits[(31 - byte) * 8 + bit];
    logic.assert_implies(status_required,
                         logic.veq(status_binding[byte], digest_byte));
  }
  StatusBridge(logic).assert_valid({status_binding, status_context,
                                    status_commitment, status_bridge_padded,
                                    status_bridge_witness, status_bridge_digest});
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
  stage("active-presentation-sha");
#endif
  Bridge bridge(logic);
  if (include_bridge) {
    const auto presentation_hash = bridge.bind_digest(presentation_digest);
    Bridge::Witness bridge_witness{}; bridge_witness.input(logic);
    bridge.assert_valid(tags, av, holder_x, holder_y, presentation_hash,
                        bridge_witness);
    if (layout) layout->add("bridge-mac", bridge_start, q->ninput_);
  }
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
  stage("bridge-mac");
#endif
  auto circuit = q->mkcircuit(1);
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
  stage("mkcircuit");
#endif
  if (layout) layout->finish(circuit->ninputs);
  return circuit;
}

}  // namespace sd_jwt_zk
