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
#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "sd_jwt_zk/restricted_base64url_relation.h"

namespace sd_jwt_zk {
// Disclosure-side half of the authenticated payload bridge.  The issuer proof
// publishes digest bytes; this relation accepts an opening only when its exact
// compact `header_b64.payload_b64` SHA-256 agrees with those bytes and the
// parser payload is the canonical base64url decoding of that same segment.
template <class LogicCircuit, std::size_t HeaderCap, std::size_t PayloadCap,
          std::size_t ShaBlocks = 1>
class CompactOpeningBridgeRelation {
  using v8 = typename LogicCircuit::v8;
  using Index = typename LogicCircuit::template bitvec<8>;
  using Plucker = proofs::BitPlucker<LogicCircuit, 4>;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit, Plucker>;
 public:
  static constexpr std::size_t kDecoded = (PayloadCap * 6) / 8;
  struct Input {
    const std::array<v8, HeaderCap>& header; const Index& header_length;
    const std::array<v8, PayloadCap>& payload; const Index& payload_length;
    const std::array<v8, 64 * ShaBlocks>& padded;
    const std::array<typename Sha::BlockWitness, ShaBlocks>& witness;
    const typename LogicCircuit::v256& digest_bits;
    const v8& sha_block_count;
    const std::array<typename LogicCircuit::EltW, 32>& issuer_public_digest;
    std::array<v8, kDecoded>& decoded; const Index& decoded_length;
  };
  explicit CompactOpeningBridgeRelation(const LogicCircuit& logic) : logic_(logic) {}
  void assert_valid(const Input& in) const {
    typename LogicCircuit::BitW selected = logic_.bit(0);
    for (std::size_t h=2; h<=HeaderCap; ++h) for (std::size_t p=2; p<=PayloadCap; ++p) {
      if (h%4==1 || p%4==1 || h+p+10>64 * ShaBlocks) continue;
      const auto branch=logic_.land(logic_.veq(in.header_length,h),logic_.veq(in.payload_length,p));
      selected=logic_.lor_exclusive(selected,branch); const auto message=h+1+p;
      for(std::size_t i=0;i<HeaderCap;++i) logic_.assert_implies(branch,logic_.veq(in.header[i],i<h?in.padded[i]:logic_.template vbit<8>(0)));
      logic_.assert_implies(branch,logic_.veq(in.padded[h],'.'));
      for(std::size_t i=0;i<PayloadCap;++i) logic_.assert_implies(branch,logic_.veq(in.payload[i],i<p?in.padded[h+1+i]:logic_.template vbit<8>(0)));
      logic_.assert_implies(branch,logic_.veq(in.padded[message],0x80));
      const auto blocks=(message+9+63)/64;
      logic_.assert_implies(branch,logic_.veq(in.sha_block_count,blocks));
      for(std::size_t i=message+1;i<blocks*64-8;++i) logic_.assert_implies(branch,logic_.veq(in.padded[i],0));
      const std::uint64_t bits=message*8; for(std::size_t i=0;i<8;++i) logic_.assert_implies(branch,logic_.veq(in.padded[blocks*64-8+i],static_cast<unsigned char>(bits>>((7-i)*8))));
    }
    logic_.assert1(selected);
    Sha(logic_).assert_message_hash(ShaBlocks,in.sha_block_count,in.padded.data(),in.digest_bits,in.witness.data());
    for(std::size_t byte=0;byte<32;++byte) { Index b{}; for(std::size_t bit=0;bit<8;++bit)b[bit]=in.digest_bits[(31-byte)*8+bit]; logic_.assert_eq(logic_.as_scalar(b),in.issuer_public_digest[byte]); }
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode_active(in.payload,in.decoded,in.payload_length);
    const auto decoded_expected=logic_.template vbit<8>((PayloadCap*6)/8);
    (void)decoded_expected; // decode_active constrains canonical tail; caller binds active length below.
    // Base64url active output size is floor(6*n/8); select that exact length.
    typename LogicCircuit::BitW decoded_selected=logic_.bit(0);
    for(std::size_t p=2;p<=PayloadCap;++p) if(p%4!=1) { const auto branch=logic_.veq(in.payload_length,p); decoded_selected=logic_.lor_exclusive(decoded_selected,branch); logic_.assert_implies(branch,logic_.veq(in.decoded_length,(p*6)/8)); }
    logic_.assert1(decoded_selected);
  }
 private: const LogicCircuit& logic_;
};
} // namespace sd_jwt_zk
