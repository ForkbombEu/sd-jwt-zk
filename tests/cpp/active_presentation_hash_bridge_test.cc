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

#include "sd_jwt_zk/active_presentation_message_relation.h"
#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/holder_issuer_jws_relation.h"
#include "sd_jwt_zk/kb_jwt_relation.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"

namespace {

using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Holder = sd_jwt_zk::HolderIssuerJwsRelation<Logic, 1, 1, 1, 1>;
using HolderBase = sd_jwt_zk::IssuerJwsRelation<Logic, 1, 1, 1, 1, 9>;
using Kb = sd_jwt_zk::KbJwsRelation<Logic, 1, 40, 176, 1, 1>;
using Sha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;
using Ecdsa = proofs::VerifyCircuit<Logic, Field, proofs::P256>;
using Active = sd_jwt_zk::ActivePresentationHashRelation<Logic, 91, 2, 2>;

enum class Mutation { kNone, kIssuer, kDisclosure, kTilde, kTail };

const char* name(Mutation mutation) {
  switch (mutation) {
    case Mutation::kNone: return "active-presentation-hash-bridge-valid";
    case Mutation::kIssuer: return "active-presentation-hash-bridge-issuer-rejected";
    case Mutation::kDisclosure: return "active-presentation-hash-bridge-disclosure-rejected";
    case Mutation::kTilde: return "active-presentation-hash-bridge-tilde-rejected";
    case Mutation::kTail: return "active-presentation-hash-bridge-tail-rejected";
  }
  return "unknown";
}

proofs::Fp256Nat nat(const std::array<std::uint8_t, 32>& bytes) {
  std::array<std::uint8_t, 32> little{};
  for (std::size_t i = 0; i < little.size(); ++i)
    little[i] = bytes[little.size() - 1 - i];
  return proofs::Fp256Nat::of_bytes(little.data());
}

bool accepts(Mutation mutation) {
  constexpr std::size_t kCompactLength = 90;
  constexpr std::size_t kMessageLength = kCompactLength + 1 + 1 + 1;
  static_assert(kMessageLength == 93);
  const std::string compact = std::string("h.p.") + std::string(86, 'A');
  const std::string presentation = compact + "~d~";
  const auto hash = sd_jwt_zk::sha256_ascii(presentation);
  const auto hash_b64 = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(hash.begin(), hash.end()));
  if (hash_b64.size() != 43) return false;

  std::array<std::uint8_t, 128> padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 2> advice{};
  std::uint8_t block_count = 0;
  proofs::FlatSHA256Witness::transform_and_witness_message(
      presentation.size(), reinterpret_cast<const std::uint8_t*>(presentation.data()),
      2, block_count, padded.data(), advice.data());
  if (block_count != 2) return false;
  if (mutation == Mutation::kTilde) padded[kCompactLength] = '.';

  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  std::array<Logic::v8, 64> issuer_sha{};
  std::array<Sha::BlockWitness, 1> issuer_witness{};
  Logic::v256 issuer_digest_bits{};
  std::array<Logic::v8, 1> header{}, payload{}, padded_payload{};
  std::array<Logic::v8, 0> header_decoded{}, payload_decoded{};
  Logic::bitvec<9> header_length{}, payload_length{}, issuer_length{}, vct_length{},
      decoded_payload_length{}, compact_length{};
  logic.bits(9, header_length.data(), 1);
  logic.bits(9, payload_length.data(), 1);
  logic.bits(9, issuer_length.data(), 1);
  logic.bits(9, vct_length.data(), 1);
  logic.bits(9, decoded_payload_length.data(), 0);
  logic.bits(9, compact_length.data(), kCompactLength);
  header[0] = logic.template vbit<8>('h');
  payload[0] = logic.template vbit<8>('p');
  padded_payload[0] = logic.template vbit<8>(0);
  for (auto& byte : issuer_sha) byte = logic.template vbit<8>(0);
  for (auto& bit : issuer_digest_bits) bit = logic.bit(0);
  const auto zero = logic.konst(field.zero());
  const auto explicit_sha = logic.bit(0);
  Ecdsa::Witness issuer_ecdsa{};
  HolderBase::Input issuer_input{issuer_sha, issuer_witness, issuer_digest_bits,
      header, header_decoded, payload, payload_decoded, header_length,
      payload_length, padded_payload, issuer_length, vct_length,
      decoded_payload_length, explicit_sha, zero, zero, zero, issuer_ecdsa, 1};
  std::array<Logic::v8, 86> signature{};
  for (auto& byte : signature) byte = logic.template vbit<8>('A');
  std::array<Logic::v8, 91> issuer_compact{};
  for (std::size_t i = 0; i < issuer_compact.size(); ++i) {
    char byte = i == 0 ? 'h' : i == 1 || i == 3 ? '.' :
        (i == 2 ? 'p' : (i < kCompactLength ? 'A' : 0));
    if (mutation == Mutation::kIssuer && i == 0) byte = 'x';
    if (mutation == Mutation::kTail && i == kCompactLength) byte = 'A';
    issuer_compact[i] = logic.template vbit<8>(byte);
  }
  Holder(logic).assert_full_compact_binding(issuer_input, signature,
                                            issuer_compact, compact_length);

  std::array<Logic::v8, 2> disclosure{};
  disclosure[0] = logic.template vbit<8>(mutation == Mutation::kDisclosure ? 'e' : 'd');
  disclosure[1] = logic.template vbit<8>(0);
  std::array<Logic::v8, 128> padded_wire{};
  for (std::size_t i = 0; i < padded_wire.size(); ++i)
    padded_wire[i] = logic.template vbit<8>(padded[i]);
  Logic::bitvec<9> disclosure_length{}, presentation_blocks{};
  logic.bits(9, disclosure_length.data(), 1);
  logic.bits(9, presentation_blocks.data(), block_count);
  const auto digest_nat = nat(hash);
  Logic::v256 digest_bits{};
  for (std::size_t i = 0; i < digest_bits.size(); ++i)
    digest_bits[i] = logic.bit(digest_nat.bit(i));
  proofs::BitPluckerEncoder<Field, 4> encoder(proofs::p256_base);
  std::array<Sha::BlockWitness, 2> sha_witness{};
  for (std::size_t block = 0; block < sha_witness.size(); ++block) {
    for (std::size_t word = 0; word < 48; ++word)
      sha_witness[block].outw[word] = logic.konst(encoder.mkpacked_v32(advice[block].outw[word]));
    for (std::size_t word = 0; word < 64; ++word) {
      sha_witness[block].oute[word] = logic.konst(encoder.mkpacked_v32(advice[block].oute[word]));
      sha_witness[block].outa[word] = logic.konst(encoder.mkpacked_v32(advice[block].outa[word]));
    }
    for (std::size_t word = 0; word < 8; ++word)
      sha_witness[block].h1[word] = logic.konst(encoder.mkpacked_v32(advice[block].h1[word]));
  }
  std::array<Logic::v8, 43> sd_hash{};
  for (std::size_t i = 0; i < sd_hash.size(); ++i)
    sd_hash[i] = logic.template vbit<8>(static_cast<unsigned char>(hash_b64[i]));
  Active::Input active{issuer_compact, compact_length, disclosure,
      disclosure_length, padded_wire, presentation_blocks, sha_witness,
      digest_bits, sd_hash};

  std::array<Logic::v8, 64> kb_sha{};
  std::array<Sha::BlockWitness, 1> kb_witness{};
  Logic::v256 kb_digest_bits{};
  std::array<Logic::v8, 40> kb_header{};
  std::array<Logic::v8, 30> kb_header_decoded{};
  std::array<Logic::v8, 176> kb_payload{};
  std::array<Logic::v8, 86> kb_signature{};
  std::array<Logic::v8, 132> kb_payload_decoded{};
  std::array<Logic::v8, 1> audience{}, nonce{};
  std::array<Logic::v8, 10> time_min{}, time_max{};
  Logic::bitvec<8> kb_header_length{}, kb_payload_length{}, audience_length{}, nonce_length{};
  for (auto& byte : kb_sha) byte = logic.template vbit<8>(0);
  for (auto& bit : kb_digest_bits) bit = logic.bit(0);
  for (auto& byte : kb_header) byte = logic.template vbit<8>(0);
  for (auto& byte : kb_header_decoded) byte = logic.template vbit<8>(0);
  for (auto& byte : kb_payload) byte = logic.template vbit<8>(0);
  for (auto& byte : kb_signature) byte = logic.template vbit<8>(0);
  for (auto& byte : kb_payload_decoded) byte = logic.template vbit<8>(0);
  for (auto& byte : audience) byte = logic.template vbit<8>(0);
  for (auto& byte : nonce) byte = logic.template vbit<8>(0);
  for (auto& byte : time_min) byte = logic.template vbit<8>(0);
  for (auto& byte : time_max) byte = logic.template vbit<8>(0);
  logic.bits(8, kb_header_length.data(), 0);
  logic.bits(8, kb_payload_length.data(), 0);
  logic.bits(8, audience_length.data(), 0);
  logic.bits(8, nonce_length.data(), 0);
  Ecdsa::Witness kb_ecdsa{};
  Kb::Input kb{kb_sha, kb_witness, kb_digest_bits, kb_header, kb_header_decoded,
      kb_payload, kb_signature, kb_payload_decoded, kb_header_length,
      kb_payload_length, audience, audience_length, nonce, nonce_length,
      time_min, time_max, sd_hash, zero, zero, zero, zero, zero, kb_ecdsa, 1};
  Kb(logic).template assert_active_presentation_binding<2, 91, 2>(kb, active);
  return !backend.assertion_failed();
}

}  // namespace

int main() {
  bool passed = true;
  for (const auto mutation : {Mutation::kNone, Mutation::kIssuer,
                              Mutation::kDisclosure, Mutation::kTilde,
                              Mutation::kTail}) {
    const bool actual = accepts(mutation);
    std::cout << name(mutation) << '=' << (actual ? "accepted" : "rejected") << '\n';
    passed = passed && actual == (mutation == Mutation::kNone);
  }
  return passed ? 0 : 1;
}
