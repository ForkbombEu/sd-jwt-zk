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
#include <string>

#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "sd_jwt_zk/api.h"

namespace sd_jwt_zk {

// A verifier-visible, request-fresh commitment to a private status binding.
// It is intentionally not the binding itself: the only public value is this
// SHA-256 digest, while the preimage remains in each proof's witness.
inline std::array<std::uint8_t, 32> status_private_bridge_v1(
    const std::array<std::uint8_t, 32>& binding,
    const std::array<std::uint8_t, 32>& context) {
  static constexpr char kDomain[] = "sd-jwt-zk/status-private-bridge/v2";
  std::string material(kDomain, sizeof(kDomain) - 1);
  material.append(reinterpret_cast<const char*>(binding.data()), binding.size());
  material.append(reinterpret_cast<const char*>(context.data()), context.size());
  return sha256_ascii(material);
}

template <class LogicCircuit>
class StatusPrivateBridgeRelationV1 {
 public:
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using Sha = proofs::FlatSHA256Circuit<
      LogicCircuit, proofs::BitPlucker<LogicCircuit, 4>>;
  static constexpr std::size_t kBlocks = 2;
  static constexpr std::size_t kPaddedBytes = kBlocks * 64;
  struct Input {
    const std::array<v8, 32>& private_binding;
    const std::array<v8, 32>& public_context;
    const std::array<v8, 32>& public_commitment;
    const std::array<v8, kPaddedBytes>& padded;
    const std::array<typename Sha::BlockWitness, kBlocks>& witness;
    const v256& digest_bits;
  };

  explicit StatusPrivateBridgeRelationV1(const LogicCircuit& logic) : logic_(logic) {}

  void assert_valid(const Input& input) const {
    static constexpr char kDomain[] = "sd-jwt-zk/status-private-bridge/v2";
    constexpr std::size_t kDomainBytes = sizeof(kDomain) - 1;
    static_assert(kDomainBytes + 64 + 9 <= kPaddedBytes);
    for (std::size_t i = 0; i < kDomainBytes; ++i)
      logic_.vassert_eq(input.padded[i], static_cast<std::uint8_t>(kDomain[i]));
    for (std::size_t i = 0; i < 32; ++i) {
      logic_.vassert_eq(input.padded[kDomainBytes + i], input.private_binding[i]);
      logic_.vassert_eq(input.padded[kDomainBytes + 32 + i], input.public_context[i]);
    }
    constexpr std::size_t message_bytes = kDomainBytes + 64;
    logic_.vassert_eq(input.padded[message_bytes], 0x80);
    for (std::size_t i = message_bytes + 1; i < kPaddedBytes - 8; ++i)
      logic_.vassert_eq(input.padded[i], 0);
    constexpr std::uint64_t bits = message_bytes * 8;
    for (std::size_t i = 0; i < 8; ++i)
      logic_.vassert_eq(input.padded[kPaddedBytes - 8 + i],
                         static_cast<std::uint8_t>(bits >> ((7 - i) * 8)));
    Sha(logic_).assert_message_hash(kBlocks, logic_.template vbit<8>(kBlocks),
                                    input.padded.data(), input.digest_bits,
                                    input.witness.data());
    for (std::size_t byte = 0; byte < 32; ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        logic_.assert_eq(input.public_commitment[byte][bit],
                         input.digest_bits[(31 - byte) * 8 + bit]);
  }

 private:
  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
