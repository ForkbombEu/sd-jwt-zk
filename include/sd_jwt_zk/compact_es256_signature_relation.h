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

#include "sd_jwt_zk/restricted_base64url_relation.h"

namespace sd_jwt_zk {

// Decodes the fixed unpadded 86-character ES256 compact-signature segment
// into the two conventional 32-byte big-endian scalars.  Callers bind the
// returned field elements to the ECDSA verifier's r/s scalar wires; keeping
// that binding explicit prevents a presentation hash from carrying a
// signature spelling unrelated to the verified signature witness.
template <class LogicCircuit>
class CompactEs256SignatureRelation {
  using v8 = typename LogicCircuit::v8;
  using EltW = typename LogicCircuit::EltW;

 public:
  static constexpr std::size_t kEncodedChars = 86;
  static constexpr std::size_t kRawBytes = 64;

  explicit CompactEs256SignatureRelation(const LogicCircuit& logic)
      : logic_(logic) {}

  void assert_decode(const std::array<v8, kEncodedChars>& encoded,
                     const EltW& r, const EltW& s) const {
    std::array<v8, kRawBytes> raw{};
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(encoded, raw);
    std::array<v8, 32> r_bytes{}, s_bytes{};
    for (std::size_t i = 0; i < 32; ++i) {
      r_bytes[i] = raw[i];
      s_bytes[i] = raw[32 + i];
    }
    logic_.assert_eq(repack(r_bytes), r);
    logic_.assert_eq(repack(s_bytes), s);
  }

 private:
  EltW repack(const std::array<v8, 32>& bytes) const {
    auto out = logic_.konst(0);
    const auto two = logic_.konst(2);
    for (const auto& byte : bytes)
      for (std::size_t bit = 8; bit-- > 0;)
        out = logic_.add(logic_.mul(out, two), logic_.eval(byte[bit]));
    return out;
  }

  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
