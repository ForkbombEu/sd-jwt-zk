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
#include <utility>

#include "circuits/logic/routing.h"

namespace sd_jwt_zk {

// A bounded, active-length relation for the canonical flat issuer payload.
// The caller supplies a zero-padded decoded payload and private active lengths;
// delimiters are routed from their computed offsets rather than searched for.
template <class LogicCircuit, std::size_t Capacity, std::size_t IndexBits>
class RestrictedJsonRelation {
  static_assert(Capacity >= 221, "flat issuer grammar requires the 64/64 explicit capacity");
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using Index = typename LogicCircuit::template bitvec<IndexBits>;

 public:
  explicit RestrictedJsonRelation(const LogicCircuit& logic) : logic_(logic), routing_(logic) {}

  void assert_ascii_slot(const std::array<v8, Capacity>& text, const Index& start,
                         const Index& length, std::size_t maximum) const {
    std::array<v8, Capacity> shifted{};
    routing_.shift(start, shifted.size(), shifted.data(), text.size(), text.data(),
                   logic_.template vbit<8>(0), 3);
    logic_.assert1(logic_.vleq(length, maximum));
    for (std::size_t i = 0; i < maximum; ++i) {
      const BitW active = logic_.vlt(i, length);
      // Active bytes are printable ASCII and exclude JSON quote/backslash;
      // inactive bytes are forced to zero by the caller's padded buffer.
      const BitW low = logic_.vlt(0x20, shifted[i]);
      const BitW high = logic_.vlt(shifted[i], 0x7f);
      logic_.assert_implies(active, logic_.land(low, high));
      logic_.assert_implies(active, logic_.lnot(logic_.veq(shifted[i], '"')));
      logic_.assert_implies(active, logic_.lnot(logic_.veq(shifted[i], '\\')));
    }
  }

  void assert_literal_at(const std::array<v8, Capacity>& text, const Index& start,
                         const char* literal, std::size_t literal_length) const {
    // Route each bounded delimiter byte independently.  This avoids relying
    // on aggregate vector packing while keeping every byte and offset inside
    // the arithmetic relation.
    for (std::size_t i = 0; i < literal_length; ++i) {
      const auto offset = logic_.vadd(start, i);
      const auto got = routed_first(text, offset);
      logic_.vassert_eq(got, static_cast<unsigned char>(literal[i]));
    }
  }

  v8 routed_first(const std::array<v8, Capacity>& text, const Index& start) const {
    std::array<v8, 1> shifted{};
    routing_.shift(start, shifted.size(), shifted.data(), text.size(), text.data(),
                   logic_.template vbit<8>(0), 3);
    return std::move(shifted[0]);
  }

  // Finite-length alternative to dynamic routing.  Exactly one permitted
  // issuer-length branch is selected in-circuit and that branch fixes every
  // delimiter byte at its compile-time offset.
  void assert_literal_after_length(const std::array<v8, Capacity>& text,
                                   const Index& length, std::size_t base,
                                   std::size_t minimum, std::size_t maximum,
                                   const char* literal,
                                   std::size_t literal_length) const {
    BitW selected = logic_.bit(0);
    for (std::size_t candidate = minimum; candidate <= maximum; ++candidate) {
      const BitW branch = logic_.veq(length, candidate);
      selected = logic_.lor_exclusive(selected, branch);
      for (std::size_t i = 0; i < literal_length; ++i) {
        const BitW same = logic_.veq(text[base + candidate + i],
                                     static_cast<unsigned char>(literal[i]));
        logic_.assert_implies(branch, same);
      }
    }
    logic_.assert1(selected);
  }

  void assert_literal_after_lengths(const std::array<v8, Capacity>& text,
                                    const Index& first, const Index& second,
                                    std::size_t base, std::size_t first_min,
                                    std::size_t first_max, std::size_t second_min,
                                    std::size_t second_max, const char* literal,
                                    std::size_t literal_length) const {
    BitW selected = logic_.bit(0);
    for (std::size_t a = first_min; a <= first_max; ++a) for (std::size_t b = second_min; b <= second_max; ++b) {
      const BitW branch = logic_.land(logic_.veq(first, a), logic_.veq(second, b));
      selected = logic_.lor_exclusive(selected, branch);
      for (std::size_t i = 0; i < literal_length; ++i)
        logic_.assert_implies(branch, logic_.veq(text[base + a + b + i], static_cast<unsigned char>(literal[i])));
    }
    logic_.assert1(selected);
  }

  void assert_algorithm_ending(const std::array<v8, Capacity>& text,
                               const Index& issuer_length, const Index& vct_length,
                               const BitW& explicit_sha256,
                               std::size_t issuer_maximum = 64,
                               std::size_t vct_maximum = 64) const {
    logic_.assert_is_bit(explicit_sha256);
    for (std::size_t issuer = 1; issuer <= issuer_maximum; ++issuer) for (std::size_t vct = 1; vct <= vct_maximum; ++vct) {
      const BitW shape = logic_.land(logic_.veq(issuer_length, issuer), logic_.veq(vct_length, vct));
      // The explicit spelling starts with the closing quote of `vct`; the
      // omitted spelling has that quote before its final closing brace.
      const std::size_t explicit_at = 135 + issuer + vct;
      const std::size_t omitted_at = explicit_at + 1;
      const char explicit_text[] = "\",\"_sd_alg\":\"sha-256\"}";
      for (std::size_t i = 0; i < 22; ++i)
        logic_.assert_implies(logic_.land(shape, explicit_sha256), logic_.veq(text[explicit_at + i], static_cast<unsigned char>(explicit_text[i])));
      logic_.assert_implies(logic_.land(shape, logic_.lnot(explicit_sha256)), logic_.veq(text[omitted_at], '}'));
    }
  }

  // Bind the variable slots and the end of the active JSON value.  In
  // particular, this forbids quote/backslash escapes in either string slot
  // and makes any bytes after the chosen canonical ending padding, not an
  // unconstrained suffix.
  void assert_flat_payload(const std::array<v8, Capacity>& text,
                           const Index& issuer_length, const Index& vct_length,
                           const BitW& explicit_sha256,
                           const Index& active_length,
                           std::size_t issuer_maximum = 64,
                           std::size_t vct_maximum = 64) const {
    static constexpr char digest_to_array[] = "\"],\"items\":[{\"...\":\"";
    static constexpr char array_to_issuer[] = "\"}],\"iss\":\"";
    for (std::size_t i = 0; i < 20; ++i)
      logic_.vassert_eq(text[52 + i], static_cast<unsigned char>(digest_to_array[i]));
    for (std::size_t i = 0; i < 43; ++i) {
      typename LogicCircuit::template bitvec<6> sextet{};
      RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode_char(text[72 + i], sextet);
    }
    for (std::size_t i = 0; i < 11; ++i)
      logic_.vassert_eq(text[115 + i], static_cast<unsigned char>(array_to_issuer[i]));
    assert_literal_after_length(text, issuer_length, 126, 1, issuer_maximum, "\",\"vct\":\"", 9);
    BitW selected = logic_.bit(0);
    for (std::size_t issuer = 1; issuer <= issuer_maximum; ++issuer) {
      for (std::size_t vct = 1; vct <= vct_maximum; ++vct) {
        const BitW shape = logic_.land(logic_.veq(issuer_length, issuer),
                                       logic_.veq(vct_length, vct));
        selected = logic_.lor_exclusive(selected, shape);
        for (std::size_t i = 0; i < issuer; ++i) assert_safe_byte(shape, text[126 + i]);
        for (std::size_t i = 0; i < vct; ++i) assert_safe_byte(shape, text[135 + issuer + i]);
        const std::size_t explicit_size = 157 + issuer + vct;
        const std::size_t omitted_size = 137 + issuer + vct;
        const BitW explicit_branch = logic_.land(shape, explicit_sha256);
        const BitW omitted_branch = logic_.land(shape, logic_.lnot(explicit_sha256));
        logic_.assert_implies(explicit_branch, logic_.veq(active_length, explicit_size));
        logic_.assert_implies(omitted_branch, logic_.veq(active_length, omitted_size));
        for (std::size_t i = explicit_size; i < Capacity; ++i)
          logic_.assert_implies(explicit_branch, logic_.veq(text[i], 0));
        for (std::size_t i = omitted_size; i < Capacity; ++i)
          logic_.assert_implies(omitted_branch, logic_.veq(text[i], 0));
      }
    }
    logic_.assert1(selected);
    assert_algorithm_ending(text, issuer_length, vct_length, explicit_sha256,
                            issuer_maximum, vct_maximum);
  }

 private:
  void assert_safe_byte(const BitW& active, const v8& byte) const {
    const BitW printable = logic_.land(logic_.vlt(0x20, byte), logic_.vlt(byte, 0x7f));
    logic_.assert_implies(active, printable);
    logic_.assert_implies(active, logic_.lnot(logic_.veq(byte, '"')));
    logic_.assert_implies(active, logic_.lnot(logic_.veq(byte, '\\')));
  }

  const LogicCircuit& logic_;
  proofs::Routing<LogicCircuit> routing_;
};

}  // namespace sd_jwt_zk
