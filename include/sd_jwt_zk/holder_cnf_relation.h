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

#include "ec/p256.h"
#include "sd_jwt_zk/restricted_base64url_relation.h"

namespace sd_jwt_zk {

// The holder-bound family uses exactly this canonical JWK member ordering.
// `jwk` is the authenticated substring from the issuer payload, while x/y
// are private field elements which will be supplied to the KB-JWT verifier.
// Keeping this relation separate prevents a bearer circuit from acquiring an
// optional holder-binding branch.
template <class LogicCircuit>
class HolderCnfRelation {
  using EltW = typename LogicCircuit::EltW;
  using v8 = typename LogicCircuit::v8;

 public:
  static constexpr std::size_t kJwkChars = 126;

  explicit HolderCnfRelation(const LogicCircuit& logic) : logic_(logic) {}

  void assert_canonical_jwk(const std::array<v8, kJwkChars>& jwk,
                            const EltW& holder_x, const EltW& holder_y) const {
    constexpr char prefix[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"";
    constexpr char middle[] = "\",\"y\":\"";
    constexpr char suffix[] = "\"}";
    static_assert(sizeof(prefix) - 1 + 43 + sizeof(middle) - 1 + 43 +
                      sizeof(suffix) - 1 ==
                  kJwkChars);
    for (std::size_t i = 0; i < sizeof(prefix) - 1; ++i)
      logic_.vassert_eq(jwk[i], static_cast<unsigned char>(prefix[i]));
    constexpr std::size_t x_at = sizeof(prefix) - 1;
    constexpr std::size_t middle_at = x_at + 43;
    constexpr std::size_t y_at = middle_at + sizeof(middle) - 1;
    constexpr std::size_t suffix_at = y_at + 43;
    for (std::size_t i = 0; i < sizeof(middle) - 1; ++i)
      logic_.vassert_eq(jwk[middle_at + i], static_cast<unsigned char>(middle[i]));
    for (std::size_t i = 0; i < sizeof(suffix) - 1; ++i)
      logic_.vassert_eq(jwk[suffix_at + i], static_cast<unsigned char>(suffix[i]));

    std::array<v8, 43> x64{}, y64{};
    for (std::size_t i = 0; i < 43; ++i) {
      x64[i] = jwk[x_at + i];
      y64[i] = jwk[y_at + i];
    }
    std::array<v8, 32> x_bytes{}, y_bytes{};
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(x64, x_bytes);
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(y64, y_bytes);
    logic_.assert_eq(repack(x_bytes), holder_x);
    logic_.assert_eq(repack(y_bytes), holder_y);
    assert_on_p256(holder_x, holder_y);
  }

 private:
  EltW repack(const std::array<v8, 32>& bytes) const {
    auto out = logic_.konst(0);
    const auto two = logic_.konst(2);
    for (const auto& byte : bytes) {
      for (std::size_t bit = 8; bit-- > 0;) {
        out = logic_.add(logic_.mul(out, two), logic_.eval(byte[bit]));
      }
    }
    return out;
  }

  void assert_on_p256(const EltW& x, const EltW& y) const {
    const auto yy = logic_.mul(y, y);
    const auto xx = logic_.mul(x, x);
    const auto xxx = logic_.mul(x, xx);
    const auto ax = logic_.mul(logic_.konst(proofs::p256.a_), x);
    const auto rhs = logic_.add(logic_.add(xxx, ax),
                                logic_.konst(proofs::p256.b_));
    logic_.assert_eq(yy, rhs);
  }

  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
