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

namespace sd_jwt_zk {

// Binds a byte-oriented SHA-256 preimage to the same field-coordinate wire
// consumed by the installed ECDSA relation.  Merely accepting a private
// 32-byte witness here would permit issuer-key substitution, so the binary
// expansion is recomposed in the P-256 base field and range-checked below p.
template <class LogicCircuit>
class CanonicalP256CoordinateRelation {
  using BitW = typename LogicCircuit::BitW;
  using EltW = typename LogicCircuit::EltW;
  using Bits = typename LogicCircuit::template bitvec<256>;
  using v8 = typename LogicCircuit::v8;

 public:
  explicit CanonicalP256CoordinateRelation(const LogicCircuit& logic)
      : logic_(logic) {}

  void assert_bound(const EltW& coordinate, const Bits& little_endian_bits) const {
    EltW value = logic_.konst(0);
    EltW weight = logic_.konst(1);
    for (std::size_t bit = 0; bit < little_endian_bits.size(); ++bit) {
      logic_.assert_is_bit(little_endian_bits[bit]);
      value = logic_.add(value,
                         logic_.mul(logic_.eval(little_endian_bits[bit]), weight));
      weight = logic_.add(weight, weight);
    }
    logic_.assert_eq(coordinate, value);
    assert_less_than_p(little_endian_bits);
  }

  std::array<v8, 32> canonical_big_endian_bytes(const Bits& bits) const {
    std::array<v8, 32> out{};
    for (std::size_t byte = 0; byte < out.size(); ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        out[byte][bit] = bits[(31 - byte) * 8 + bit];
    return out;
  }

 private:
  void assert_less_than_p(const Bits& value) const {
    // A bitwise subtraction value - p has a final borrow precisely when
    // value < p.  This removes the field-modulus alias otherwise possible
    // when a 256-bit expansion is only recomposed modulo p.
    static constexpr std::array<std::uint8_t, 32> kP = {
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    BitW borrow = logic_.bit(0);
    for (std::size_t bit = 0; bit < 256; ++bit) {
      const auto p_bit = logic_.bit((kP[31 - bit / 8] >> (bit % 8)) & 1U);
      // borrow_out = (!a & (p | borrow)) | (p & borrow)
      const auto need = logic_.land(logic_.lnot(value[bit]),
                                    logic_.lor(p_bit, borrow));
      borrow = logic_.lor(need, logic_.land(p_bit, borrow));
    }
    logic_.assert1(borrow);
  }

  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
