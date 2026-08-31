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
#include <memory>
#include <string_view>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include "sd_jwt_zk/api.h"

namespace sd_jwt_zk::test {

// Test-only fixed scalar.  It is intentionally not a production signing API.
inline constexpr char kNestedFixturePrivateScalar[] =
    "519b423d715f8b5d5494d2b7f2b7f0d3e71d7c2a3e5f6a7b8c9d0e1f10293847";

inline bool sign_nested_fixture_es256(std::string_view signing_input,
                                      std::array<unsigned char, 64>& raw,
                                      P256Key* public_key = nullptr,
                                      const char* private_scalar =
                                          kNestedFixturePrivateScalar) {
  using Key = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
  using Number = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
  using Point = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
  using Signature = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;
  Key key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
  BIGNUM* scalar_raw = nullptr;
  if (!key || BN_hex2bn(&scalar_raw, private_scalar) == 0)
    return false;
  Number scalar(scalar_raw, BN_free);
  if (EC_KEY_set_private_key(key.get(), scalar.get()) != 1)
    return false;
  const EC_GROUP* group = EC_KEY_get0_group(key.get());
  Point public_point(EC_POINT_new(group), EC_POINT_free);
  if (!public_point ||
      EC_POINT_mul(group, public_point.get(), scalar.get(), nullptr, nullptr,
                   nullptr) != 1 ||
      EC_KEY_set_public_key(key.get(), public_point.get()) != 1)
    return false;
  if (public_key != nullptr) {
    Number x(BN_new(), BN_free), y(BN_new(), BN_free);
    if (!x || !y ||
        EC_POINT_get_affine_coordinates(group, public_point.get(), x.get(),
                                        y.get(), nullptr) != 1 ||
        BN_bn2binpad(x.get(), public_key->x.data(), public_key->x.size()) !=
            static_cast<int>(public_key->x.size()) ||
        BN_bn2binpad(y.get(), public_key->y.data(), public_key->y.size()) !=
            static_cast<int>(public_key->y.size()))
      return false;
  }
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_size{};
  if (EVP_Digest(signing_input.data(), signing_input.size(), digest.data(),
                 &digest_size, EVP_sha256(), nullptr) != 1)
    return false;
  Signature signature(ECDSA_do_sign(digest.data(), digest_size, key.get()),
                      ECDSA_SIG_free);
  const BIGNUM *r = nullptr, *s = nullptr;
  if (!signature || (ECDSA_SIG_get0(signature.get(), &r, &s), !r || !s) ||
      BN_bn2binpad(r, raw.data(), 32) != 32 ||
      BN_bn2binpad(s, raw.data() + 32, 32) != 32)
    return false;
  if (ECDSA_do_verify(digest.data(), digest_size, signature.get(), key.get()) !=
      1)
    return false;
  // The circuit follows the canonical ES256 convention.  Normalize s without
  // changing validity so every test fixture has the same accepted form.
  Number order(BN_new(), BN_free), half_order(BN_new(), BN_free), canonical_s(
      BN_dup(s), BN_free);
  if (!order || !half_order || !canonical_s ||
      EC_GROUP_get_order(group, order.get(), nullptr) != 1 ||
      BN_rshift1(half_order.get(), order.get()) != 1)
    return false;
  if (BN_cmp(canonical_s.get(), half_order.get()) > 0 &&
      BN_sub(canonical_s.get(), order.get(), canonical_s.get()) != 1)
    return false;
  if (BN_bn2binpad(canonical_s.get(), raw.data() + 32, 32) != 32)
    return false;
  return true;
}

}  // namespace sd_jwt_zk::test
