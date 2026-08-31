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

#include "sd_jwt_zk/holder_cnf_relation.h"
#include "sd_jwt_zk/issuer_jws_relation.h"
#include "sd_jwt_zk/compact_es256_signature_relation.h"
#include "circuits/logic/routing.h"

namespace sd_jwt_zk {

// Holder-only issuer relation.  This deliberately does not change the bearer
// grammar: it authenticates the canonical cnf.jwk suffix and binds its hidden
// coordinates to the KB-JWT verifier's key wires.
template <class LogicCircuit, std::size_t SigningBlocks, std::size_t HeaderChars,
          std::size_t PayloadChars, std::size_t PaddedPayloadChars,
          std::size_t IssuerMax = 24, std::size_t VctMax = 14>
class HolderIssuerJwsRelation {
  using v8 = typename LogicCircuit::v8;
  using Base = IssuerJwsRelation<LogicCircuit, SigningBlocks, HeaderChars,
                                 PayloadChars, PaddedPayloadChars, 9>;

 public:
  using Input = typename Base::Input;
  using EltW = typename LogicCircuit::EltW;

  explicit HolderIssuerJwsRelation(const LogicCircuit& logic) : logic_(logic) {}

  void assert_valid(
      const Input& in, const EltW& holder_x, const EltW& holder_y,
      const std::array<v8,
          CompactEs256SignatureRelation<LogicCircuit>::kEncodedChars>&
          signature_b64, const EltW& signature_r,
      const EltW& signature_s) const {
    Base base(logic_);
    base.assert_sha(in);
    base.assert_compact_binding(in);
    base.decode_payload_bucket(in.payload_b64, in.payload_b64_length,
                               in.payload_decoded);
    base.assert_padded_payload(in.payload_decoded, in.payload_padded);
    base.assert_header(in, in.header_decoded);
    assert_cnf_binding(in, holder_x, holder_y);
    CompactEs256SignatureRelation<LogicCircuit>(logic_).assert_decode(
        signature_b64, signature_r, signature_s);
    base.assert_ecdsa_bound(in, signature_r, signature_s);
  }

  // Kept separately callable so capacity benchmarks can distinguish the cnf
  // bridge from shared issuer authentication machinery.
  void assert_cnf_binding(const Input& in, const EltW& holder_x,
                          const EltW& holder_y) const {
    assert_holder_json(in, holder_x, holder_y);
  }

  // Builds the sole presentation-facing issuer compact bucket from the same
  // header/payload/signature wires authenticated above.  Slots after the
  // active compact JWS are forced to zero; callers must pass this exact array
  // to PresentationHashRelation rather than allocate a second issuer string.
  template <std::size_t CompactChars, std::size_t LengthBits>
  void assert_full_compact_binding(
      const Input& in,
      const std::array<v8,
          CompactEs256SignatureRelation<LogicCircuit>::kEncodedChars>& signature,
      std::array<v8, CompactChars>& compact,
      const typename LogicCircuit::template bitvec<LengthBits>& compact_length) const {
    static_assert(CompactChars >= HeaderChars + 1 + PayloadChars + 1 + 86);
    for (std::size_t i = 0; i < HeaderChars; ++i)
      logic_.vassert_eq(compact[i], in.header_b64[i]);
    logic_.vassert_eq(compact[HeaderChars], '.');
    for (std::size_t i = 0; i < PayloadChars; ++i) {
      const auto active = logic_.vlt(i, in.payload_b64_length);
      logic_.assert_implies(active,
          logic_.veq(compact[HeaderChars + 1 + i], in.payload_b64[i]));
    }
    auto bind_suffix = [&](const auto& signature_at) {
      std::array<v8, 87> suffix{};
      routing_.shift(signature_at, suffix.size(), suffix.data(), compact.size(),
                     compact.data(), logic_.template vbit<8>(0), 3);
      logic_.vassert_eq(suffix[0], '.');
      for (std::size_t i = 0; i < signature.size(); ++i)
        logic_.vassert_eq(suffix[i + 1], signature[i]);
      const auto expected_length = logic_.vadd(signature_at, 87);
      logic_.vassert_eq(compact_length, expected_length);
    };
    if constexpr (LengthBits == 9) {
      auto signature_at9 =
          logic_.vadd(in.payload_b64_length, HeaderChars + 1);
      bind_suffix(signature_at9);
    } else {
      static_assert(LengthBits == 10,
                    "holder compact length supports 9- or 10-bit buckets");
      typename LogicCircuit::template bitvec<1> high{};
      high[0] = logic_.bit(0);
      const auto payload_length10 = logic_.vappend(in.payload_b64_length, high);
      bind_suffix(logic_.vadd(payload_length10, HeaderChars + 1));
    }
    for (std::size_t i = 0; i < CompactChars; ++i)
      logic_.assert_implies(logic_.lnot(logic_.vlt(i, compact_length)),
                            logic_.veq(compact[i], 0));
  }

 private:
  static constexpr std::size_t kJwkChars = HolderCnfRelation<LogicCircuit>::kJwkChars;

  void assert_holder_json(const Input& in, const EltW& holder_x,
                          const EltW& holder_y) const {
    constexpr char prefix[] = "{\"_sd\":[\"";
    constexpr char digest_to_array[] = "\"],\"items\":[{\"...\":\"";
    constexpr char array_to_issuer[] = "\"}],\"iss\":\"";
    constexpr char issuer_to_vct[] = "\",\"vct\":\"";
    constexpr char cnf_prefix[] = "\",\"cnf\":{\"jwk\":";
    constexpr char algorithm[] = ",\"_sd_alg\":\"sha-256\"}";
    static_assert(sizeof(prefix) - 1 == 9);
    static_assert(sizeof(digest_to_array) - 1 == 20);
    static_assert(sizeof(array_to_issuer) - 1 == 11);
    static_assert(sizeof(issuer_to_vct) - 1 == 9);
    static_assert(sizeof(cnf_prefix) - 1 == 15);

    for (std::size_t i = 0; i < sizeof(prefix) - 1; ++i)
      logic_.vassert_eq(in.payload_padded[i], static_cast<unsigned char>(prefix[i]));
    for (std::size_t i = 0; i < 43; ++i) {
      typename LogicCircuit::template bitvec<6> sextet{};
      RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode_char(
          in.payload_padded[9 + i], sextet);
    }
    for (std::size_t i = 0; i < sizeof(digest_to_array) - 1; ++i)
      logic_.vassert_eq(in.payload_padded[52 + i],
                         static_cast<unsigned char>(digest_to_array[i]));
    for (std::size_t i = 0; i < 43; ++i) {
      typename LogicCircuit::template bitvec<6> sextet{};
      RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode_char(
          in.payload_padded[72 + i], sextet);
    }
    for (std::size_t i = 0; i < sizeof(array_to_issuer) - 1; ++i)
      logic_.vassert_eq(in.payload_padded[115 + i],
                        static_cast<unsigned char>(array_to_issuer[i]));

    typename LogicCircuit::BitW selected = logic_.bit(0);
    std::array<v8, kJwkChars> jwk{};
    auto jwk_at = logic_.vadd(in.issuer_length, in.vct_length);
    jwk_at = logic_.vadd(jwk_at, 150);
    routing_.shift(jwk_at, jwk.size(), jwk.data(), in.payload_padded.size(),
                   in.payload_padded.data(), logic_.template vbit<8>(0), 3);
    for (std::size_t issuer = 1; issuer <= IssuerMax; ++issuer) {
      const auto issuer_branch = logic_.veq(in.issuer_length, issuer);
      for (std::size_t i = 0; i < sizeof(issuer_to_vct) - 1; ++i)
        logic_.assert_implies(issuer_branch,
            logic_.veq(in.payload_padded[126 + issuer + i],
                       static_cast<unsigned char>(issuer_to_vct[i])));
      for (std::size_t vct = 1; vct <= VctMax; ++vct) {
        const auto branch = logic_.land(issuer_branch,
                                        logic_.veq(in.vct_length, vct));
        selected = logic_.lor_exclusive(selected, branch);
        for (std::size_t i = 0; i < issuer; ++i) safe(branch, in.payload_padded[126 + i]);
        for (std::size_t i = 0; i < vct; ++i) safe(branch, in.payload_padded[135 + issuer + i]);
        const std::size_t cnf_at = 135 + issuer + vct;
        for (std::size_t i = 0; i < sizeof(cnf_prefix) - 1; ++i)
          logic_.assert_implies(branch,
              logic_.veq(in.payload_padded[cnf_at + i],
                         static_cast<unsigned char>(cnf_prefix[i])));
        const std::size_t jwk_offset = cnf_at + sizeof(cnf_prefix) - 1;
        const std::size_t cnf_close = jwk_offset + kJwkChars;
        logic_.assert_implies(branch, logic_.veq(in.payload_padded[cnf_close], '}'));
        const auto explicit_branch = logic_.land(branch, in.explicit_sha256);
        const auto omitted_branch = logic_.land(branch, logic_.lnot(in.explicit_sha256));
        const std::size_t explicit_size = cnf_close + sizeof(algorithm) - 1;
        const std::size_t omitted_size = cnf_close + 2;
        for (std::size_t i = 0; i < sizeof(algorithm) - 1; ++i)
          logic_.assert_implies(explicit_branch,
              logic_.veq(in.payload_padded[cnf_close + i],
                         static_cast<unsigned char>(algorithm[i])));
        logic_.assert_implies(omitted_branch,
                              logic_.veq(in.payload_padded[cnf_close + 1], '}'));
        logic_.assert_implies(explicit_branch,
                              logic_.veq(in.payload_length, explicit_size));
        logic_.assert_implies(omitted_branch,
                              logic_.veq(in.payload_length, omitted_size));
        for (std::size_t i = explicit_size; i < PaddedPayloadChars; ++i)
          logic_.assert_implies(explicit_branch, logic_.veq(in.payload_padded[i], 0));
        for (std::size_t i = omitted_size; i < PaddedPayloadChars; ++i)
          logic_.assert_implies(omitted_branch, logic_.veq(in.payload_padded[i], 0));
      }
    }
    logic_.assert1(selected);
    HolderCnfRelation<LogicCircuit>(logic_).assert_canonical_jwk(jwk, holder_x,
                                                                   holder_y);
  }

  void safe(const typename LogicCircuit::BitW& active, const v8& byte) const {
    logic_.assert_implies(active,
        logic_.land(logic_.vlt(0x20, byte), logic_.vlt(byte, 0x7f)));
    logic_.assert_implies(active, logic_.lnot(logic_.veq(byte, '"')));
    logic_.assert_implies(active, logic_.lnot(logic_.veq(byte, '\\')));
  }

  const LogicCircuit& logic_;
  proofs::Routing<LogicCircuit> routing_{logic_};
};

}  // namespace sd_jwt_zk
