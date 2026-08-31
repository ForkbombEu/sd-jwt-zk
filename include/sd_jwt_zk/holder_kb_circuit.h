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
#include <memory>
#include <stdexcept>
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
#include <chrono>
#include <iostream>
#endif

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "ec/p256.h"
#include "sd_jwt_zk/holder_bridge_mac_relation.h"
#include "sd_jwt_zk/holder_credential_circuit.h"
#include "sd_jwt_zk/kb_jwt_relation.h"

namespace sd_jwt_zk {
// Bounded KB component. It owns only the complete KB-JWT relation and the
// bridge interface; issuer/disclosure wires cannot enter this circuit.
inline std::unique_ptr<proofs::Circuit<HolderCredentialField>>
BuildHolderKbCircuitV1(proofs::QuadCircuit<HolderCredentialField>* q,
                       HolderDenseLayoutV1* layout = nullptr,
                       bool include_bridge = true,
                       std::size_t bridge_values = 3,
                       bool allocate_bridge_witness = true) {
  constexpr std::size_t B = 4, H = 40, P = 176, Audience = 24, Nonce = 14;
  using L = HolderCredentialLogic;
  using Kb = KbJwsRelation<L, B, H, P, Audience, Nonce>;
  using Sha = proofs::FlatSHA256Circuit<L, proofs::BitPlucker<L, 4>>;
  using Ecdsa = proofs::VerifyCircuit<L, HolderCredentialField, proofs::P256>;
  using Bridge = HolderBridgeMacRelation<L>;
  HolderCredentialBackend backend(q);
  L logic(&backend, proofs::p256_base);
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
  const auto started = std::chrono::steady_clock::now();
  auto stage = [&](const char* name) {
    std::cerr << "holder-kb stage=" << name << " ms="
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - started).count()
              << " inputs=" << q->ninput_ << '\n';
  };
#endif
  std::array<L::v128, Bridge::kTags> tags{};
  for (auto& tag : tags) tag = logic.vinput<128>();
  const auto av = logic.vinput<128>();
  auto audience = holder_credential_detail::bytes<L, Audience>(logic);
  auto audience_len = holder_credential_detail::bits<L, 8>(logic);
  auto nonce = holder_credential_detail::bytes<L, Nonce>(logic);
  auto nonce_len = holder_credential_detail::bits<L, 8>(logic);
  auto time_min = holder_credential_detail::bytes<L, 10>(logic);
  auto time_max = holder_credential_detail::bytes<L, 10>(logic);
  if (layout) layout->begin(q->ninput_);
  q->private_input();
  const auto kb_start = q->ninput_;
  auto sha_in = holder_credential_detail::bytes<L, 64 * B>(logic);
  std::array<Sha::BlockWitness, B> sha_w{}; for (auto& w : sha_w) w.input(logic);
  auto digest_bits = holder_credential_detail::bits<L, 256>(logic);
  auto header = holder_credential_detail::bytes<L, H>(logic);
  auto header_json = holder_credential_detail::bytes<L, (H * 6) / 8>(logic);
  auto payload = holder_credential_detail::bytes<L, P>(logic);
  auto signature = holder_credential_detail::bytes<L, 86>(logic);
  auto payload_json = holder_credential_detail::bytes<L, (P * 6) / 8>(logic);
  auto header_len = holder_credential_detail::bits<L, 8>(logic);
  auto payload_len = holder_credential_detail::bits<L, 8>(logic);
  const auto holder_x = logic.eltw_input();
  const auto holder_y = logic.eltw_input();
  const auto signature_r = logic.eltw_input();
  const auto signature_s = logic.eltw_input();
  const auto digest = logic.eltw_input();
  Ecdsa::Witness ecdsa{}; ecdsa.input(logic);
  auto sd_hash = holder_credential_detail::bytes<L, 43>(logic);
  if (layout) layout->add("kb-jwt", kb_start, q->ninput_);
  const auto bridge_start = q->ninput_;
  typename Kb::Input kb{sha_in, sha_w, digest_bits, header, header_json, payload,
      signature, payload_json, header_len, payload_len, audience, audience_len,
      nonce, nonce_len, time_min, time_max, sd_hash, holder_x, holder_y,
      signature_r, signature_s, digest, ecdsa, B};
  Kb(logic).assert_valid(kb);
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
  stage("kb-jws");
#endif
  std::array<L::v8, 32> hash_bytes{};
  // Relations are allocation-free once their explicit witness bundle is
  // supplied.  Preserve that ABI invariant: bridge Dense advice starts
  // immediately after the named KB-JWT range, not after hidden late inputs.
  if (q->ninput_ != bridge_start)
    throw std::logic_error("KB relation allocated bridge-adjacent advice");
  RestrictedBase64UrlRelation<L>(logic).decode(sd_hash, hash_bytes);
  L::v256 presentation_digest{};
  for (std::size_t byte = 0; byte < hash_bytes.size(); ++byte)
    for (std::size_t bit = 0; bit < 8; ++bit)
      presentation_digest[(31 - byte) * 8 + bit] = hash_bytes[byte][bit];
  Bridge bridge(logic);
  if (include_bridge) {
    const auto presentation_hash = bridge.bind_digest(presentation_digest);
    if (layout) layout->add("bridge-digest", bridge_start, q->ninput_);
    Bridge::Witness bridge_witness{};
    if (allocate_bridge_witness) bridge_witness.input(logic);
    if (bridge_values != 0 && !allocate_bridge_witness)
      throw std::logic_error("bridge MAC constraints require witness advice");
    bridge.assert_valid(tags, av, holder_x, holder_y, presentation_hash,
                        bridge_witness, bridge_values);
    if (layout) layout->add("bridge-mac-advice", bridge_start + 1, q->ninput_);
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
