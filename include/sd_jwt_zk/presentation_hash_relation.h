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
#include <cstddef>
#include <cstdint>

#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "sd_jwt_zk/restricted_base64url_relation.h"

namespace sd_jwt_zk {

// Hashes exactly `issuer-jws~disclosure-1~...~disclosure-N~`.  Fixed circuit
// families select concrete compact/disclosure capacities; no host length or
// delimiter decision participates in the statement.
template <class LogicCircuit, std::size_t ShaBlocks, std::size_t IssuerChars,
          std::size_t DisclosureChars>
class PresentationHashRelation {
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using Plucker = proofs::BitPlucker<LogicCircuit, 4>;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit, Plucker>;
  static constexpr std::size_t kMessageChars = IssuerChars + 1 + DisclosureChars + 1;
  static constexpr std::size_t kPaddedChars = ShaBlocks * 64;

 public:
  static_assert(kMessageChars + 9 <= kPaddedChars,
                "presentation SHA bucket is too small for SHA-256 padding");

  struct Input {
    const std::array<v8, IssuerChars>& issuer_compact;
    const std::array<v8, DisclosureChars>& disclosure;
    const std::array<v8, kPaddedChars>& sha_input;
    const std::array<typename Sha::BlockWitness, ShaBlocks>& sha_witness;
    const v256& digest_bits;
    const std::array<v8, 43>& sd_hash_b64url;
  };

  explicit PresentationHashRelation(const LogicCircuit& logic) : logic_(logic) {}

  void assert_valid(const Input& in) const {
    for (std::size_t i = 0; i < IssuerChars; ++i)
      logic_.vassert_eq(in.sha_input[i], in.issuer_compact[i]);
    logic_.vassert_eq(in.sha_input[IssuerChars], '~');
    for (std::size_t i = 0; i < DisclosureChars; ++i)
      logic_.vassert_eq(in.sha_input[IssuerChars + 1 + i], in.disclosure[i]);
    logic_.vassert_eq(in.sha_input[kMessageChars - 1], '~');
    assert_exact_sha256_padding(in.sha_input);

    Sha(logic_).assert_message_hash(ShaBlocks,
        logic_.template vbit<8>(ShaBlocks), in.sha_input.data(),
        in.digest_bits, in.sha_witness.data());
    std::array<v8, 32> digest_bytes{};
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(
        in.sd_hash_b64url, digest_bytes);
    for (std::size_t byte = 0; byte < digest_bytes.size(); ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        logic_.assert_eq(digest_bytes[byte][bit],
                         in.digest_bits[(31 - byte) * 8 + bit]);
  }

 private:
  void assert_exact_sha256_padding(const std::array<v8, kPaddedChars>& input) const {
    logic_.vassert_eq(input[kMessageChars], 0x80);
    for (std::size_t i = kMessageChars + 1; i < kPaddedChars - 8; ++i)
      logic_.vassert_eq(input[i], 0);
    const std::uint64_t bits = static_cast<std::uint64_t>(kMessageChars) * 8;
    for (std::size_t i = 0; i < 8; ++i)
      logic_.vassert_eq(input[kPaddedChars - 8 + i],
                         static_cast<std::uint8_t>(bits >> ((7 - i) * 8)));
  }

  const LogicCircuit& logic_;
};

template <class LogicCircuit, std::size_t ShaBlocks, std::size_t IssuerChars,
          std::size_t ObjectChars, std::size_t ArrayChars>
class TwoDisclosurePresentationHashRelation {
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit,
      proofs::BitPlucker<LogicCircuit, 4>>;
  static constexpr std::size_t kMessageChars =
      IssuerChars + ObjectChars + ArrayChars + 3;
 public:
  struct Input {
    const std::array<v8, IssuerChars>& issuer_compact;
    const std::array<v8, ObjectChars>& object_disclosure;
    const std::array<v8, ArrayChars>& array_disclosure;
    const std::array<v8, 64 * ShaBlocks>& sha_input;
    const std::array<typename Sha::BlockWitness, ShaBlocks>& sha_witness;
    const v256& digest_bits;
    const std::array<v8, 43>& sd_hash_b64url;
  };
  explicit TwoDisclosurePresentationHashRelation(const LogicCircuit& logic)
      : logic_(logic) {}
  void assert_valid(const Input& in) const {
    std::size_t at = 0;
    for (const auto& byte : in.issuer_compact) logic_.vassert_eq(in.sha_input[at++], byte);
    logic_.vassert_eq(in.sha_input[at++], '~');
    for (const auto& byte : in.object_disclosure) logic_.vassert_eq(in.sha_input[at++], byte);
    logic_.vassert_eq(in.sha_input[at++], '~');
    for (const auto& byte : in.array_disclosure) logic_.vassert_eq(in.sha_input[at++], byte);
    logic_.vassert_eq(in.sha_input[at++], '~');
    logic_.vassert_eq(in.sha_input[kMessageChars], 0x80);
    for (std::size_t i = kMessageChars + 1; i < 64 * ShaBlocks - 8; ++i)
      logic_.vassert_eq(in.sha_input[i], 0);
    const std::uint64_t bits = kMessageChars * 8;
    for (std::size_t i = 0; i < 8; ++i)
      logic_.vassert_eq(in.sha_input[64 * ShaBlocks - 8 + i],
                        static_cast<std::uint8_t>(bits >> ((7 - i) * 8)));
    Sha(logic_).assert_message_hash(ShaBlocks,
        logic_.template vbit<8>(ShaBlocks), in.sha_input.data(),
        in.digest_bits, in.sha_witness.data());
    std::array<v8, 32> digest_bytes{};
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(in.sd_hash_b64url,
                                                              digest_bytes);
    for (std::size_t byte = 0; byte < 32; ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        logic_.assert_eq(digest_bytes[byte][bit],
                         in.digest_bits[(31 - byte) * 8 + bit]);
  }
 private:
  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
