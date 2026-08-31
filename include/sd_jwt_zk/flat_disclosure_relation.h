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
#include <string_view>

#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "sd_jwt_zk/restricted_base64url_relation.h"

namespace sd_jwt_zk {

// The hash-bearing core shared by every bounded flat disclosure slot.  The
// disclosure ASCII is hashed in-circuit; the issuer `_sd` text is decoded in
// circuit before byte-for-byte comparison, so a native digest is only advice.
template <class LogicCircuit, std::size_t ShaBlocks, std::size_t DisclosureChars>
class FlatDisclosureRelation {
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using Plucker = proofs::BitPlucker<LogicCircuit, 4>;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit, Plucker>;

 public:
  struct Input {
    const std::array<v8, DisclosureChars>& disclosure_ascii;
    const std::array<v8, 64 * ShaBlocks>& sha_input;
    const std::array<typename Sha::BlockWitness, ShaBlocks>& sha_witness;
    const v256& digest_bits;
    const std::array<v8, 43>& signed_digest_b64url;
    std::uint8_t sha_block_count;
  };

  explicit FlatDisclosureRelation(const LogicCircuit& logic) : logic_(logic) {}

  // Fixed-capacity flat disclosure grammar: `["salt","name","value"]`.
  // Callers select a family with concrete slot lengths; each byte is checked
  // in the circuit and string bytes exclude the two unsupported JSON escapes.
  template <std::size_t SaltChars, std::size_t NameChars, std::size_t ValueChars>
  void assert_three_string_array(const std::array<v8, 10 + SaltChars + NameChars + ValueChars>& json) const {
    constexpr std::size_t name_at = 5 + SaltChars;
    constexpr std::size_t value_at = 8 + SaltChars + NameChars;
    logic_.vassert_eq(json[0], '['); logic_.vassert_eq(json[1], '"');
    logic_.vassert_eq(json[2 + SaltChars], '"'); logic_.vassert_eq(json[3 + SaltChars], ',');
    logic_.vassert_eq(json[4 + SaltChars], '"'); logic_.vassert_eq(json[name_at + NameChars], '"');
    logic_.vassert_eq(json[name_at + NameChars + 1], ',');
    logic_.vassert_eq(json[name_at + NameChars + 2], '"');
    logic_.vassert_eq(json[value_at + ValueChars], '"'); logic_.vassert_eq(json[value_at + ValueChars + 1], ']');
    for (std::size_t i = 0; i < SaltChars; ++i) assert_string_byte(json[2 + i]);
    for (std::size_t i = 0; i < NameChars; ++i) assert_string_byte(json[name_at + i]);
    for (std::size_t i = 0; i < ValueChars; ++i) assert_string_byte(json[value_at + i]);
  }

  // RFC 9901 array-element disclosures use two items.  This separate relation
  // prevents an object-property disclosure from being reused at an array
  // placeholder merely because both carry a SHA-256 digest.
  template <std::size_t SaltChars, std::size_t ValueChars>
  void assert_two_string_array(const std::array<v8, 7 + SaltChars + ValueChars>& json) const {
    constexpr std::size_t value_at = 5 + SaltChars;
    logic_.vassert_eq(json[0], '['); logic_.vassert_eq(json[1], '"');
    logic_.vassert_eq(json[2 + SaltChars], '"'); logic_.vassert_eq(json[3 + SaltChars], ',');
    logic_.vassert_eq(json[4 + SaltChars], '"');
    logic_.vassert_eq(json[value_at + ValueChars], '"');
    logic_.vassert_eq(json[value_at + ValueChars + 1], ']');
    for (std::size_t i = 0; i < SaltChars; ++i) assert_string_byte(json[2 + i]);
    for (std::size_t i = 0; i < ValueChars; ++i) assert_string_byte(json[value_at + i]);
  }

  // Active length selector for a configured disclosure family.  A selected
  // slot must be within capacity and all bytes above it are zero padding.
  template <std::size_t Capacity, class Index>
  void assert_active_string(const std::array<v8, Capacity>& slot, const Index& active_length) const {
    logic_.assert1(logic_.vleq(active_length, Capacity));
    for (std::size_t i = 0; i < Capacity; ++i)
      logic_.assert_implies(logic_.lnot(logic_.vlt(i, active_length)), logic_.veq(slot[i], 0));
  }

  // Finite branch selector for the two delimiters following a variable salt
  // and name.  This is the bounded alternative to host-computed offsets.
  template <std::size_t Capacity, class Index>
  void assert_salt_name_delimiters(const std::array<v8, Capacity>& json,
                                   const Index& salt_length, const Index& name_length,
                                   std::size_t salt_max, std::size_t name_max) const {
    typename LogicCircuit::BitW selected = logic_.bit(0);
    for (std::size_t salt = 1; salt <= salt_max; ++salt) for (std::size_t name = 1; name <= name_max; ++name) {
      const auto shape = logic_.land(logic_.veq(salt_length, salt), logic_.veq(name_length, name));
      selected = logic_.lor_exclusive(selected, shape);
      constexpr char after_salt[] = "\",\"";
      for (std::size_t i = 0; i < 3; ++i)
        logic_.assert_implies(shape, logic_.veq(json[2 + salt + i], static_cast<unsigned char>(after_salt[i])));
      constexpr char after_name[] = "\",\"";
      for (std::size_t i = 0; i < 3; ++i)
        logic_.assert_implies(shape, logic_.veq(json[5 + salt + name + i], static_cast<unsigned char>(after_name[i])));
    }
    logic_.assert1(selected);
  }

  template <std::size_t Capacity, class Index>
  void assert_value_ending(const std::array<v8, Capacity>& json, const Index& salt_length,
                           const Index& name_length, const Index& value_length,
                           const Index& active_length, std::size_t salt_max,
                           std::size_t name_max, std::size_t value_max) const {
    typename LogicCircuit::BitW selected = logic_.bit(0);
    for (std::size_t salt = 1; salt <= salt_max; ++salt) for (std::size_t name = 1; name <= name_max; ++name) for (std::size_t value = 1; value <= value_max; ++value) {
      const auto shape = logic_.land(logic_.land(logic_.veq(salt_length, salt), logic_.veq(name_length, name)), logic_.veq(value_length, value));
      selected = logic_.lor_exclusive(selected, shape);
      const std::size_t end = 8 + salt + name + value;
      logic_.assert_implies(shape, logic_.veq(json[end], '"'));
      logic_.assert_implies(shape, logic_.veq(json[end + 1], ']'));
      logic_.assert_implies(shape, logic_.veq(active_length, end + 2));
      for (std::size_t i = end + 2; i < Capacity; ++i)
        logic_.assert_implies(shape, logic_.veq(json[i], 0));
    }
    logic_.assert1(selected);
  }

  template <std::size_t Capacity, class Index>
  void assert_three_string_active_grammar(const std::array<v8, Capacity>& json,
                                          const Index& salt_length, const Index& name_length,
                                          const Index& value_length, const Index& active_length,
                                          std::size_t salt_max, std::size_t name_max,
                                          std::size_t value_max) const {
    logic_.vassert_eq(json[0], '['); logic_.vassert_eq(json[1], '"');
    assert_salt_name_delimiters(json, salt_length, name_length, salt_max, name_max);
    assert_value_ending(json, salt_length, name_length, value_length, active_length,
                        salt_max, name_max, value_max);
    assert_variable_string_bytes(json, salt_length, name_length, value_length,
                                 salt_max, name_max, value_max);
    assert_name_is_not_reserved(json, salt_length, name_length, salt_max, name_max);
  }

  template <class Index>
  void assert_decoded_three_string_grammar(const std::array<v8, DisclosureChars>& disclosure,
                                           const Index& salt, const Index& name, const Index& value,
                                           const Index& total, std::size_t salt_max,
                                           std::size_t name_max, std::size_t value_max) const {
    std::array<v8, (DisclosureChars * 6) / 8> json{};
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(disclosure, json);
    assert_three_string_active_grammar(json, salt, name, value, total, salt_max, name_max, value_max);
  }

  void assert_digest_match(const Input& in) const {
    for (std::size_t i = 0; i < DisclosureChars; ++i)
      logic_.vassert_eq(in.sha_input[i], in.disclosure_ascii[i]);
    Sha sha(logic_);
    sha.assert_message_hash(ShaBlocks, logic_.template vbit<8>(in.sha_block_count),
                            in.sha_input.data(), in.digest_bits, in.sha_witness.data());
    RestrictedBase64UrlRelation<LogicCircuit> base64(logic_);
    std::array<v8, 32> signed_digest{};
    base64.decode(in.signed_digest_b64url, signed_digest);
    for (std::size_t byte = 0; byte < signed_digest.size(); ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        // FlatSHA advice is represented as a little-endian field natural,
        // while base64url emits conventional big-endian digest bytes.
        logic_.assert_eq(signed_digest[byte][bit],
                         in.digest_bits[(31 - byte) * 8 + bit]);
  }

  // Every active supplied disclosure has exactly one active `_sd` match.
  // The exclusive sum is deliberately asserted as one: zero matches and
  // duplicate matches both fail in the arithmetic relation.
  template <std::size_t SignedSlots, std::size_t PresentedSlots, class Index>
  void assert_unique_signed_matches(
      const std::array<std::array<v8, 43>, SignedSlots>& signed_digests,
      const std::array<std::array<v8, 43>, PresentedSlots>& presented_digests,
      const Index& signed_active, const Index& presented_active) const {
    for (std::size_t p = 0; p < PresentedSlots; ++p) {
      const auto present = logic_.vlt(p, presented_active);
      typename LogicCircuit::BitW matches = logic_.bit(0);
      for (std::size_t s = 0; s < SignedSlots; ++s) {
        typename LogicCircuit::BitW same = logic_.bit(1);
        for (std::size_t i = 0; i < 43; ++i)
          same = logic_.land(same, logic_.veq(presented_digests[p][i], signed_digests[s][i]));
        matches = logic_.lor_exclusive(matches, logic_.land(logic_.vlt(s, signed_active), same));
      }
      logic_.assert_implies(present, matches);
    }
    for (std::size_t a = 0; a < PresentedSlots; ++a) for (std::size_t b = a + 1; b < PresentedSlots; ++b) {
      typename LogicCircuit::BitW same = logic_.bit(1);
      for (std::size_t i = 0; i < 43; ++i)
        same = logic_.land(same, logic_.veq(presented_digests[a][i], presented_digests[b][i]));
      const auto both_active = logic_.land(logic_.vlt(a, presented_active), logic_.vlt(b, presented_active));
      logic_.assert_implies(both_active, logic_.lnot(same));
    }
    for (std::size_t a = 0; a < SignedSlots; ++a) for (std::size_t b = a + 1; b < SignedSlots; ++b) {
      typename LogicCircuit::BitW same = logic_.bit(1);
      for (std::size_t i = 0; i < 43; ++i)
        same = logic_.land(same, logic_.veq(signed_digests[a][i], signed_digests[b][i]));
      const auto both_active = logic_.land(logic_.vlt(a, signed_active), logic_.vlt(b, signed_active));
      logic_.assert_implies(both_active, logic_.lnot(same));
    }
  }

  template <std::size_t Slots, std::size_t NameChars, class Index>
  void assert_unique_presented_names(const std::array<std::array<v8, NameChars>, Slots>& names,
                                     const Index& active) const {
    for (std::size_t a = 0; a < Slots; ++a) for (std::size_t b = a + 1; b < Slots; ++b) {
      typename LogicCircuit::BitW same = logic_.bit(1);
      for (std::size_t i = 0; i < NameChars; ++i)
        same = logic_.land(same, logic_.veq(names[a][i], names[b][i]));
      logic_.assert_implies(logic_.land(logic_.vlt(a, active), logic_.vlt(b, active)), logic_.lnot(same));
    }
  }

  // Public policy results are constrained directly to the private parsed
  // value slot.  `equal` is a public Boolean result, not host control flow.
  template <std::size_t ValueChars>
  void assert_string_policy(const std::array<v8, ValueChars>& private_value,
                            const std::array<v8, ValueChars>& public_value,
                            const typename LogicCircuit::BitW& equal) const {
    logic_.assert_is_bit(equal);
    typename LogicCircuit::BitW all_equal = logic_.bit(1);
    for (std::size_t i = 0; i < ValueChars; ++i)
      all_equal = logic_.land(all_equal, logic_.veq(private_value[i], public_value[i]));
    logic_.assert_eq(equal, all_equal);
  }

  // Compare a named string claim against a circuit-family policy without
  // exposing either the claim name or value.  Only `equal` is public; the
  // selected salt offset and all disclosure bytes remain private.
  template <std::size_t Capacity, std::size_t NameChars,
            std::size_t ValueChars, class Index>
  void assert_named_string_policy(
      const std::array<v8, Capacity>& json, const Index& salt_length,
      const Index& name_length, const Index& value_length,
      const std::array<std::uint8_t, NameChars>& expected_name,
      const std::array<std::uint8_t, ValueChars>& expected_value,
      const typename LogicCircuit::BitW& equal,
      std::size_t salt_max) const {
    logic_.assert_is_bit(equal);
    logic_.vassert_eq(name_length, NameChars);
    typename LogicCircuit::BitW selected_equal = logic_.bit(0);
    for (std::size_t salt = 1; salt <= salt_max; ++salt) {
      const auto selected_salt = logic_.veq(salt_length, salt);
      for (std::size_t i = 0; i < NameChars; ++i)
        logic_.assert_implies(
            selected_salt,
            logic_.veq(json[5 + salt + i], expected_name[i]));
      auto same = logic_.land(selected_salt,
                              logic_.veq(value_length, ValueChars));
      for (std::size_t i = 0; i < ValueChars; ++i)
        same = logic_.land(
            same,
            logic_.veq(json[8 + salt + NameChars + i], expected_value[i]));
      selected_equal = logic_.lor_exclusive(selected_equal, same);
    }
    logic_.assert_eq(equal, selected_equal);
  }

  template <std::size_t ValueChars>
  void assert_reveal_policy(const std::array<v8, ValueChars>& private_value,
                            const std::array<v8, ValueChars>& revealed_value) const {
    for (std::size_t i = 0; i < ValueChars; ++i) logic_.vassert_eq(private_value[i], revealed_value[i]);
  }

 private:
  template <std::size_t Capacity, class Index>
  void assert_variable_string_bytes(const std::array<v8, Capacity>& json,
                                    const Index& salt_length, const Index& name_length,
                                    const Index& value_length, std::size_t salt_max,
                                    std::size_t name_max, std::size_t value_max) const {
    for (std::size_t salt = 1; salt <= salt_max; ++salt) for (std::size_t name = 1; name <= name_max; ++name) for (std::size_t value = 1; value <= value_max; ++value) {
      const auto shape = logic_.land(logic_.land(logic_.veq(salt_length, salt), logic_.veq(name_length, name)), logic_.veq(value_length, value));
      for (std::size_t i = 0; i < salt; ++i) assert_string_byte(shape, json[2 + i]);
      for (std::size_t i = 0; i < name; ++i) assert_string_byte(shape, json[5 + salt + i]);
      for (std::size_t i = 0; i < value; ++i) assert_string_byte(shape, json[8 + salt + name + i]);
    }
  }

  template <std::size_t Capacity, class Index>
  void assert_name_is_not_reserved(const std::array<v8, Capacity>& json,
                                   const Index& salt_length, const Index& name_length,
                                   std::size_t salt_max, std::size_t name_max) const {
    constexpr std::array<std::string_view, 3> reserved{"_sd", "_sd_alg", "..."};
    for (std::size_t salt = 1; salt <= salt_max; ++salt) {
      const auto salt_shape = logic_.veq(salt_length, salt);
      for (const auto literal : reserved) {
        if (literal.size() > name_max) continue;
        typename LogicCircuit::BitW same = logic_.veq(name_length, literal.size());
        for (std::size_t i = 0; i < literal.size(); ++i)
          same = logic_.land(same, logic_.veq(json[5 + salt + i], static_cast<unsigned char>(literal[i])));
        logic_.assert_implies(salt_shape, logic_.lnot(same));
      }
    }
  }

  void assert_string_byte(const typename LogicCircuit::BitW& active, const v8& byte) const {
    logic_.assert_implies(active, logic_.land(logic_.vlt(0x20, byte), logic_.vlt(byte, 0x7f)));
    logic_.assert_implies(active, logic_.lnot(logic_.veq(byte, '"')));
    logic_.assert_implies(active, logic_.lnot(logic_.veq(byte, '\\')));
  }

  void assert_string_byte(const v8& byte) const {
    logic_.assert1(logic_.land(logic_.vlt(0x20, byte), logic_.vlt(byte, 0x7f)));
    logic_.assert0(logic_.veq(byte, '"'));
    logic_.assert0(logic_.veq(byte, '\\'));
  }

  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
