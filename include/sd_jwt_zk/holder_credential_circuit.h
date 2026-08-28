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
#include "sd_jwt_zk/issuer_registry_membership_relation.h"

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
template <bool Registry>
inline std::unique_ptr<proofs::Circuit<HolderCredentialField>>
BuildHolderCredentialCircuitImplV1(
    proofs::QuadCircuit<HolderCredentialField>* q,
    HolderDenseLayoutV1* layout = nullptr, bool include_bridge = true) {
  // The first real-proof V1 bucket fixes the authenticated compact length at
  // 514 bytes (seven signing blocks) while retaining zero-padded parser
  // capacity.  Larger active compact lengths require a distinct circuit ID.
  constexpr std::size_t B = 7, H = 102, P = 472, Pad = 384, Compact = 662;
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
  using Membership = IssuerRegistryMembershipRelation<L, 2>;
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
  L::EltW issuer_x{}, issuer_y{};
  std::array<L::v8, 32> registry_root{};
  L::bitvec<64> registry_epoch{}, registry_valid_from{},
      registry_valid_until{};
  L::bitvec<8> registry_depth{};
  if constexpr (Registry) {
    for (auto& byte : registry_root) byte = logic.template vinput<8>();
    registry_epoch = logic.template vinput<64>();
    registry_valid_from = logic.template vinput<64>();
    registry_valid_until = logic.template vinput<64>();
    registry_depth = logic.template vinput<8>();
    if (layout) layout->begin(q->ninput_);
    q->private_input();
    issuer_x = logic.eltw_input();
    issuer_y = logic.eltw_input();
  } else {
    issuer_x = logic.eltw_input();
    issuer_y = logic.eltw_input();
    if (layout) layout->begin(q->ninput_);
    q->private_input();
  }
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
  L::bitvec<256> registry_issuer_x_bits{}, registry_issuer_y_bits{};
  for (auto* coordinate : {&registry_issuer_x_bits, &registry_issuer_y_bits})
    for (auto& bit : *coordinate) bit = logic.input();
  CanonicalP256CoordinateRelation<L>(logic).assert_bound(issuer_x,
                                                          registry_issuer_x_bits);
  CanonicalP256CoordinateRelation<L>(logic).assert_bound(issuer_y,
                                                          registry_issuer_y_bits);
  std::array<L::v8, 64> registry_vct_sha_input{};
  for (auto& byte : registry_vct_sha_input) byte = logic.template vinput<8>();
  Sha::BlockWitness registry_vct_sha_witness{};
  registry_vct_sha_witness.input(logic);
  L::v256 registry_vct_digest{};
  for (auto& bit : registry_vct_digest) bit = logic.input();
  if constexpr (Registry) {
    std::array<L::v8, 32> issuer_x_bytes{}, issuer_y_bytes{};
    for (std::size_t byte = 0; byte < 32; ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit) {
        issuer_x_bytes[31 - byte][bit] =
            registry_issuer_x_bits[byte * 8 + bit];
        issuer_y_bytes[31 - byte][bit] =
            registry_issuer_y_bits[byte * 8 + bit];
      }
    const auto not_before_bits = logic.template vinput<64>();
    const auto not_after_bits = logic.template vinput<64>();
    const auto private_epoch = logic.template vinput<64>();
    const auto leaf_index = logic.template vinput<2>();
    std::array<L::v8, 8> not_before{}, not_after{};
    for (auto* value : {&not_before, &not_after})
      for (auto& byte : *value) byte = logic.template vinput<8>();
    std::array<L::v8, 192> leaf_message{};
    for (auto& byte : leaf_message) byte = logic.template vinput<8>();
    std::array<typename Sha::BlockWitness, 3> leaf_witness{};
    for (auto& block : leaf_witness) block.input(logic);
    L::v256 leaf_digest{};
    for (auto& bit : leaf_digest) bit = logic.input();
    std::array<std::array<L::v8, 32>, 2> siblings{};
    for (auto& sibling : siblings)
      for (auto& byte : sibling) byte = logic.template vinput<8>();
    std::array<L::BitW, 2> directions{leaf_index[0], leaf_index[1]};
    std::array<std::array<L::v8, 128>, 2> node_messages{};
    std::array<std::array<typename Sha::BlockWitness, 2>, 2>
        node_witnesses{};
    std::array<L::v256, 2> node_digests{};
    for (std::size_t level = 0; level < 2; ++level) {
      for (auto& byte : node_messages[level])
        byte = logic.template vinput<8>();
      for (auto& block : node_witnesses[level]) block.input(logic);
      for (auto& bit : node_digests[level]) bit = logic.input();
    }
    typename Membership::Hash3 leaf{leaf_message, leaf_witness, leaf_digest};
    std::array<typename Membership::Hash2, 2> nodes{
        typename Membership::Hash2{node_messages[0], node_witnesses[0],
                                   node_digests[0]},
        typename Membership::Hash2{node_messages[1], node_witnesses[1],
                                   node_digests[1]}};
    Membership(logic).assert_valid(typename Membership::Input{
        issuer_x_bytes, issuer_y_bytes, registry_vct_digest, not_before,
        not_after, not_before_bits, not_after_bits, private_epoch, leaf_index,
        leaf, siblings, directions, nodes, registry_root, registry_epoch,
        registry_valid_from, registry_valid_until, registry_depth});
  }
  if (layout) layout->add("issuer-cnf-and-signature", issuer_start, q->ninput_);
  const auto presentation_start = q->ninput_;
  auto compact = holder_credential_detail::bytes<L, Compact>(logic);
  auto compact_len = holder_credential_detail::bits<L, 10>(logic);
  typename Issuer::Input issuer{sha_in, sha_w, digest_bits, header, header_json,
      payload, payload_json, header_len, payload_len, padded, issuer_len, vct_len,
      decoded_len, explicit_sha, issuer_x, issuer_y, issuer_digest, issuer_ecdsa, B};
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
  Issuer(logic).assert_registry_vct_hash(
      issuer, typename Issuer::RegistryVctHashInput{
          registry_vct_sha_input, registry_vct_sha_witness, registry_vct_digest});
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

inline std::unique_ptr<proofs::Circuit<HolderCredentialField>>
BuildHolderCredentialCircuitV1(proofs::QuadCircuit<HolderCredentialField>* q,
                               HolderDenseLayoutV1* layout = nullptr,
                               bool include_bridge = true) {
  return BuildHolderCredentialCircuitImplV1<false>(q, layout, include_bridge);
}

inline std::unique_ptr<proofs::Circuit<HolderCredentialField>>
BuildHolderRegistryCredentialCircuitV1(
    proofs::QuadCircuit<HolderCredentialField>* q,
    HolderDenseLayoutV1* layout = nullptr, bool include_bridge = true) {
  return BuildHolderCredentialCircuitImplV1<true>(q, layout, include_bridge);
}
}  // namespace sd_jwt_zk
