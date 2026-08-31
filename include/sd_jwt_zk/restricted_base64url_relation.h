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

// This is deliberately project-owned.  The Longfellow tree has a test-only
// decoder which accepts padded input; SD-JWT's compact segments must not use
// it.  Every input byte is constrained to exactly one RFC 4648 URL alphabet
// character, and the resulting six bits are constrained to its sextet.
namespace sd_jwt_zk {

template <class LogicCircuit>
class RestrictedBase64UrlRelation {
  using BitW = typename LogicCircuit::BitW;
  using v6 = typename LogicCircuit::template bitvec<6>;
  using v8 = typename LogicCircuit::v8;

 public:
  explicit RestrictedBase64UrlRelation(const LogicCircuit& logic) : logic_(logic) {}

  void decode_char(const v8& input, v6& output) const {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::array<BitW, 64> hit{};
    auto total = logic_.konst(0);
    for (std::size_t value = 0; value < hit.size(); ++value) {
      const auto expected = logic_.template vbit<8>(static_cast<unsigned char>(alphabet[value]));
      hit[value] = logic_.eq(8, input.data(), expected.data());
      total = logic_.add(total, logic_.eval(hit[value]));
    }
    // Equality to one both rejects '=' and prevents an unconstrained
    // alternative sextet from satisfying the relation.
    logic_.assert_eq(total, logic_.konst(1));
    for (std::size_t bit = 0; bit < 6; ++bit) {
      auto selected = logic_.konst(0);
      for (std::size_t value = 0; value < hit.size(); ++value) {
        if ((value & (std::size_t{1} << bit)) != 0) {
          selected = logic_.add(selected, logic_.eval(hit[value]));
        }
      }
      output[bit] = BitW(selected, logic_.f_);
    }
  }

  template <std::size_t EncodedBytes>
  void decode(const std::array<v8, EncodedBytes>& input,
              std::array<v8, (EncodedBytes * 6) / 8>& output) const {
    static_assert(EncodedBytes % 4 != 1,
                  "base64url lengths congruent to one modulo four are invalid");
    std::array<v6, EncodedBytes> sextets{};
    for (std::size_t index = 0; index < EncodedBytes; ++index) {
      decode_char(input[index], sextets[index]);
    }
    if constexpr (EncodedBytes % 4 == 2) {
      for (std::size_t bit = 0; bit < 4; ++bit)
        logic_.assert0(sextets[EncodedBytes - 1][bit]);
    }
    if constexpr (EncodedBytes % 4 == 3) {
      for (std::size_t bit = 0; bit < 2; ++bit)
        logic_.assert0(sextets[EncodedBytes - 1][bit]);
    }
    for (std::size_t byte = 0; byte < output.size(); ++byte) {
      for (std::size_t bit = 0; bit < 8; ++bit) {
        const std::size_t stream_bit = byte * 8 + bit;
        const std::size_t sextet = stream_bit / 6;
        const std::size_t sextet_bit = stream_bit % 6;
        // Longfellow bit vectors are least-significant-bit first.  RFC 4648
        // transmits each sextet most-significant-bit first.
        output[byte][7 - bit] = sextets[sextet][5 - sextet_bit];
      }
    }
  }

  // Decode an unpadded compact segment stored in a zero-padded bucket.  Unlike
  // ordinary base64 padding, inactive cells are not alphabet characters and
  // never participate in the sextet stream.  The selected active length has a
  // legal RFC 4648 residue and the unused tail bits are required to be zero.
  template <std::size_t EncodedBytes, class Index>
  void decode_active(const std::array<v8, EncodedBytes>& input,
                     std::array<v8, (EncodedBytes * 6) / 8>& output,
                     const Index& active_length) const {
    static_assert(EncodedBytes > 1);
    std::array<v6, EncodedBytes> sextets{};
    for (std::size_t index = 0; index < EncodedBytes; ++index) {
      const auto active = logic_.vlt(index, active_length);
      decode_char_if(active, input[index], sextets[index]);
    }
    BitW selected = logic_.bit(0);
    for (std::size_t length = 2; length <= EncodedBytes; ++length) {
      if (length % 4 == 1) continue;
      const auto branch = logic_.veq(active_length, length);
      selected = logic_.lor_exclusive(selected, branch);
      if (length % 4 == 2)
        for (std::size_t bit = 0; bit < 4; ++bit)
          logic_.assert_implies(branch, logic_.lnot(sextets[length - 1][bit]));
      if (length % 4 == 3)
        for (std::size_t bit = 0; bit < 2; ++bit)
          logic_.assert_implies(branch, logic_.lnot(sextets[length - 1][bit]));
    }
    logic_.assert1(selected);
    for (std::size_t byte = 0; byte < output.size(); ++byte) {
      for (std::size_t bit = 0; bit < 8; ++bit) {
        const std::size_t stream_bit = byte * 8 + bit;
        const std::size_t sextet = stream_bit / 6;
        const std::size_t sextet_bit = stream_bit % 6;
        const auto present = logic_.vlt(sextet, active_length);
        const auto source = sextets[sextet][5 - sextet_bit];
        logic_.assert_implies(present, logic_.eq(1, &output[byte][7 - bit], &source));
        logic_.assert_implies(logic_.lnot(present), logic_.lnot(output[byte][7 - bit]));
      }
    }
  }

 private:
  void decode_char_if(const BitW& active, const v8& input, v6& output) const {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::array<BitW, 64> hit{};
    auto total = logic_.konst(0);
    for (std::size_t value = 0; value < hit.size(); ++value) {
      const auto expected = logic_.template vbit<8>(static_cast<unsigned char>(alphabet[value]));
      hit[value] = logic_.eq(8, input.data(), expected.data());
      total = logic_.add(total, logic_.eval(hit[value]));
    }
    // active * (alphabet-hit-count - 1) == 0.
    logic_.assert_eq(logic_.mul(logic_.eval(active), total), logic_.eval(active));
    logic_.assert_implies(logic_.lnot(active), logic_.veq(input, 0));
    for (std::size_t bit = 0; bit < 6; ++bit) {
      auto selected = logic_.konst(0);
      for (std::size_t value = 0; value < hit.size(); ++value)
        if ((value & (std::size_t{1} << bit)) != 0) selected = logic_.add(selected, logic_.eval(hit[value]));
      output[bit] = BitW(selected, logic_.f_);
    }
  }
  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
