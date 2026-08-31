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

// Exact padded SHA-256 message for `issuer~disclosure~` with bounded active
// lengths.  This deliberately constrains padding in the same relation that
// routes active bytes, so zero bucket tails never become presentation bytes.
template <class LogicCircuit, std::size_t IssuerCapacity,
          std::size_t DisclosureCapacity, std::size_t Blocks,
          std::size_t IndexBits = 9>
class ActivePresentationMessageRelation {
  using v8 = typename LogicCircuit::v8;
  using Index = typename LogicCircuit::template bitvec<IndexBits>;

 public:
  static constexpr std::size_t kPaddedBytes = Blocks * 64;
  explicit ActivePresentationMessageRelation(const LogicCircuit& logic)
      : logic_(logic) {}

  void assert_valid(const std::array<v8, IssuerCapacity>& issuer,
                    const Index& issuer_length,
                    const std::array<v8, DisclosureCapacity>& disclosure,
                    const Index& disclosure_length,
                    const std::array<v8, kPaddedBytes>& padded,
                    const Index& block_count) const {
    typename LogicCircuit::BitW selected = logic_.bit(0);
    for (std::size_t il = 1; il <= IssuerCapacity; ++il) {
      const auto ib = logic_.veq(issuer_length, il);
      for (std::size_t dl = 1; dl <= DisclosureCapacity; ++dl) {
        const auto branch = logic_.land(ib, logic_.veq(disclosure_length, dl));
        const std::size_t message = il + 1 + dl + 1;
        const std::size_t bytes = ((message + 9 + 63) / 64) * 64;
        if (bytes > kPaddedBytes) continue;
        selected = logic_.lor_exclusive(selected, branch);
        logic_.assert_implies(branch, logic_.veq(block_count, bytes / 64));
        for (std::size_t i = 0; i < il; ++i)
          logic_.assert_implies(branch, logic_.veq(padded[i], issuer[i]));
        for (std::size_t i = il; i < IssuerCapacity; ++i)
          logic_.assert_implies(branch, logic_.veq(issuer[i], 0));
        logic_.assert_implies(branch, logic_.veq(padded[il], '~'));
        for (std::size_t i = 0; i < dl; ++i)
          logic_.assert_implies(branch, logic_.veq(padded[il + 1 + i], disclosure[i]));
        for (std::size_t i = dl; i < DisclosureCapacity; ++i)
          logic_.assert_implies(branch, logic_.veq(disclosure[i], 0));
        logic_.assert_implies(branch, logic_.veq(padded[message - 1], '~'));
        logic_.assert_implies(branch, logic_.veq(padded[message], 0x80));
        for (std::size_t i = message + 1; i < bytes - 8; ++i)
          logic_.assert_implies(branch, logic_.veq(padded[i], 0));
        const std::uint64_t bits = static_cast<std::uint64_t>(message) * 8;
        for (std::size_t i = 0; i < 8; ++i)
          logic_.assert_implies(branch, logic_.veq(padded[bytes - 8 + i],
              static_cast<std::uint8_t>(bits >> ((7 - i) * 8))));
        for (std::size_t i = bytes; i < kPaddedBytes; ++i)
          logic_.assert_implies(branch, logic_.veq(padded[i], 0));
      }
    }
    logic_.assert1(selected);
  }
 private:
  const LogicCircuit& logic_;
};

// Extends the active presentation router with the actual SHA-256 relation and
// canonical base64url rendering of its digest.  Unlike PresentationHashRelation
// this accepts bounded buckets and proves the selected active length determines
// both the padded message and the number of SHA blocks.
template <class LogicCircuit, std::size_t IssuerCapacity,
          std::size_t DisclosureCapacity, std::size_t Blocks,
          std::size_t IndexBits = 9>
class ActivePresentationHashRelation {
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using Index = typename LogicCircuit::template bitvec<IndexBits>;
  using Plucker = proofs::BitPlucker<LogicCircuit, 4>;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit, Plucker>;

 public:
  static_assert(IndexBits >= 8, "SHA block count needs an eight-bit view");
  static constexpr std::size_t kPaddedBytes = Blocks * 64;

  struct Input {
    const std::array<v8, IssuerCapacity>& issuer;
    const Index& issuer_length;
    const std::array<v8, DisclosureCapacity>& disclosure;
    const Index& disclosure_length;
    const std::array<v8, kPaddedBytes>& padded;
    const Index& block_count;
    const std::array<typename Sha::BlockWitness, Blocks>& sha_witness;
    const v256& digest_bits;
    const std::array<v8, 43>& sd_hash_b64url;
  };

  explicit ActivePresentationHashRelation(const LogicCircuit& logic)
      : logic_(logic) {}

  void assert_valid(const Input& in) const {
    ActivePresentationMessageRelation<LogicCircuit, IssuerCapacity,
        DisclosureCapacity, Blocks, IndexBits>(logic_).assert_valid(
            in.issuer, in.issuer_length, in.disclosure, in.disclosure_length,
            in.padded, in.block_count);
    Sha(logic_).assert_message_hash(Blocks, logic_.template slice<0, 8>(in.block_count),
        in.padded.data(), in.digest_bits, in.sha_witness.data());
    std::array<v8, 32> digest_bytes{};
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(
        in.sd_hash_b64url, digest_bytes);
    for (std::size_t byte = 0; byte < digest_bytes.size(); ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        logic_.assert_eq(digest_bytes[byte][bit],
                         in.digest_bits[(31 - byte) * 8 + bit]);
  }

 private:
  const LogicCircuit& logic_;
};
}  // namespace sd_jwt_zk
