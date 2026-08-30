#pragma once

#include <array>
#include <cstddef>

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "ec/p256.h"
#include "sd_jwt_zk/restricted_base64url_relation.h"
#include "sd_jwt_zk/restricted_json_relation.h"
#include "sd_jwt_zk/flat_disclosure_relation.h"

namespace sd_jwt_zk {

// Bounded issuer-JWS circuit composition.  All compact bytes, SHA advice,
// lengths, signature advice, and key coordinates are circuit inputs; native
// code may construct advice but is never an acceptance substitute.
template <class LogicCircuit, std::size_t SigningBlocks, std::size_t HeaderChars,
          std::size_t PayloadChars, std::size_t PaddedPayloadChars = 256,
          std::size_t IndexBits = 8>
class IssuerJwsRelation {
  using Field = typename LogicCircuit::Field;
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using EltW = typename LogicCircuit::EltW;
  using BitW = typename LogicCircuit::BitW;
  using Plucker = proofs::BitPlucker<LogicCircuit, 4>;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit, Plucker>;
  using Ecdsa = proofs::VerifyCircuit<LogicCircuit, Field, proofs::P256>;

 public:
  using Index = typename LogicCircuit::template bitvec<IndexBits>;
  struct Input {
    const std::array<v8, 64 * SigningBlocks>& sha_input;
    const std::array<typename Sha::BlockWitness, SigningBlocks>& sha_witness;
    const v256& digest_bits;
    const std::array<v8, HeaderChars>& header_b64;
    std::array<v8, (HeaderChars * 6) / 8>& header_decoded;
    const std::array<v8, PayloadChars>& payload_b64;
    std::array<v8, (PayloadChars * 6) / 8>& payload_decoded;
    const Index& header_b64_length;
    const Index& payload_b64_length;
    const std::array<v8, PaddedPayloadChars>& payload_padded;
    const Index& issuer_length;
    const Index& vct_length;
    const Index& payload_length;
    const BitW& explicit_sha256;
    const EltW& public_x;
    const EltW& public_y;
    const EltW& digest;
    const typename Ecdsa::Witness& ecdsa_witness;
    std::uint8_t sha_block_count;
  };

  // One SHA-256 block is sufficient for the V1 registry type bucket (1..32
  // printable bytes plus SHA padding).  The padded message and SHA advice are
  // private witness material; every meaningful byte is routed from the
  // issuer-signed payload below.
  struct RegistryVctHashInput {
    const std::array<v8, 64>& padded_message;
    const typename Sha::BlockWitness& sha_witness;
    const v256& digest_bits;
  };

  explicit IssuerJwsRelation(const LogicCircuit& logic) : logic_(logic) {}

  void assert_compact_separator(const std::array<v8, 64 * SigningBlocks>& signing,
                                const Index& header_length) const {
    typename LogicCircuit::BitW selected = logic_.bit(0);
    for (std::size_t length = 2; length <= HeaderChars; ++length) {
      if (length % 4 == 1) continue;
      const auto branch = logic_.veq(header_length, length);
      selected = logic_.lor_exclusive(selected, branch);
      logic_.assert_implies(branch, logic_.veq(signing[length], '.'));
    }
    logic_.assert1(selected);
  }

  // Composition hook for the flat bearer family: callers pass the `_sd`
  // bytes extracted from this authenticated payload to the disclosure SHA
  // relation, keeping the signed digest slot in the same circuit instance.
  template <std::size_t DisclosureBlocks, std::size_t DisclosureChars>
  void assert_disclosure_binding(
      const Input& issuer,
      const typename FlatDisclosureRelation<LogicCircuit, DisclosureBlocks, DisclosureChars>::Input& disclosure) const {
    // The digest comparison target is extracted from the same decoded payload
    // that assert_valid authenticates.  It is never independent host advice.
    for (std::size_t i = 0; i < 43; ++i)
      logic_.vassert_eq(disclosure.signed_digest_b64url[i], issuer.payload_padded[9 + i]);
    FlatDisclosureRelation<LogicCircuit, DisclosureBlocks, DisclosureChars>(logic_).assert_digest_match(disclosure);
  }

  // Authenticates the bounded compact JWS while leaving payload semantics to
  // a composing relation.  Full-disclosure families use their generic JSON
  // parser against the exported decoded payload; flat V1 additionally calls
  // assert_json below and therefore retains its fixed grammar.
  void assert_compact_authenticated(const Input& in) const {
    assert_sha(in);
    assert_compact_binding(in);
    decode_payload_bucket(in.payload_b64, in.payload_b64_length,
                          in.payload_decoded);
    assert_padded_payload(in.payload_decoded, in.payload_padded);
    assert_header(in, in.header_decoded);
    assert_ecdsa(in);
  }

  void assert_valid(const Input& in) const {
    assert_compact_authenticated(in);
    assert_json(in);
  }
  void assert_sha(const Input& in) const {
    Sha sha(logic_);
    sha.assert_message_hash(SigningBlocks, logic_.template vbit<8>(in.sha_block_count),
                            in.sha_input.data(), in.digest_bits, in.sha_witness.data());
  }
  void assert_compact_binding(const Input& in) const {
    for (std::size_t i = 0; i < HeaderChars; ++i) {
      const auto active = logic_.vlt(i, in.header_b64_length);
      logic_.assert_implies(active, logic_.veq(in.header_b64[i], in.sha_input[i]));
      logic_.assert_implies(logic_.lnot(active), logic_.veq(in.header_b64[i], 0));
    }
    constexpr std::size_t payload_offset = HeaderChars + 1;
    assert_compact_separator(in.sha_input, in.header_b64_length);
    for (std::size_t i = 0; i < PayloadChars; ++i) {
      const auto active = logic_.vlt(i, in.payload_b64_length);
      logic_.assert_implies(active, logic_.veq(in.payload_b64[i], in.sha_input[payload_offset + i]));
      logic_.assert_implies(logic_.lnot(active), logic_.veq(in.payload_b64[i], 0));
    }

  }
  void assert_header(const Input& in) const {
    std::array<v8, (HeaderChars * 6) / 8> header{};
    for (auto& byte : header) byte = logic_.template vbit<8>(0);
    assert_header(in, header);
  }
  void assert_header(const Input& in, std::array<v8, (HeaderChars * 6) / 8>& header) const {
    RestrictedBase64UrlRelation<LogicCircuit> base64(logic_);
    base64.decode_active(in.header_b64, header, in.header_b64_length);
    constexpr char expected_header[] =
        "{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\",\"profile_version\":\"swiss-profile-vc:1.0.0\"}";
    static_assert(sizeof(expected_header) - 1 == header.size());
    for (std::size_t i = 0; i < header.size(); ++i)
      logic_.vassert_eq(header[i], static_cast<unsigned char>(expected_header[i]));

  }
  void assert_json(const Input& in) const {
    RestrictedBase64UrlRelation<LogicCircuit> base64(logic_);
    Index start{};
    logic_.bits(8, start.data(), 0);
    RestrictedJsonRelation<LogicCircuit, PaddedPayloadChars, IndexBits> json(logic_);
    json.assert_literal_at(in.payload_padded, start, "{\"_sd\":[\"", 9);
    for (std::size_t i = 0; i < 43; ++i) {
      typename LogicCircuit::template bitvec<6> sextet{};
      base64.decode_char(in.payload_padded[9 + i], sextet);
    }
    json.assert_flat_payload(in.payload_padded, in.issuer_length, in.vct_length,
                             in.explicit_sha256, in.payload_length);

  }
  void assert_ecdsa(const Input& in) const {
    Ecdsa verifier(logic_, proofs::p256, proofs::n256_order);
    verifier.verify_signature3(in.public_x, in.public_y, in.digest, in.ecdsa_witness);
  }
  void assert_ecdsa_bound(const Input& in, const EltW& signature_r,
                          const EltW& signature_s) const {
    Ecdsa verifier(logic_, proofs::p256, proofs::n256_order);
    // VerifyWitness3 represents the third scalar as -s modulo the P-256
    // order.  Compact JWS carries the conventional positive s scalar.
    const auto negative_s = logic_.sub(
        logic_.konst(proofs::p256_base.to_montgomery(proofs::n256_order)),
        signature_s);
    verifier.verify_signature3_bound(in.public_x, in.public_y, in.digest,
                                     signature_r, negative_s,
                                     in.ecdsa_witness);
  }

  void assert_decode_padded_payload(const std::array<v8, PayloadChars>& payload_b64,
                                    const Index& payload_b64_length,
                                    const std::array<v8, PaddedPayloadChars>& payload_padded) const {
    std::array<v8, (PayloadChars * 6) / 8> payload{};
    for (auto& byte : payload) byte = logic_.template vbit<8>(0);
    decode_payload_bucket(payload_b64, payload_b64_length, payload);
    assert_padded_payload(payload, payload_padded);
  }

  // Exports a byte of the already authenticated, restricted `vct` slot.  The
  // caller supplies the slot offset; its only legal values are selected from
  // the same private issuer-length branches as assert_json().  This is the
  // composition boundary used by registry membership: host parsing cannot
  // substitute a type string after issuer signature verification.
  v8 authenticated_vct_byte(const Input& in, std::size_t byte_index) const {
    RestrictedJsonRelation<LogicCircuit, PaddedPayloadChars, IndexBits> json(logic_);
    typename LogicCircuit::template bitvec<IndexBits> start{};
    for (std::size_t bit = 0; bit < start.size(); ++bit) start[bit] = logic_.bit(0);
    // Canonical restricted JSON has vct bytes at 71 + issuer_length.  The
    // low-level add is constrained field arithmetic, not a host offset.
    start = logic_.vadd(in.issuer_length, 71 + byte_index);
    return json.routed_first(in.payload_padded, start);
  }

  void assert_registry_vct_hash(const Input& in,
                                const RegistryVctHashInput& hash_input) const {
    logic_.assert1(logic_.vleq(in.vct_length, 32));
    typename LogicCircuit::BitW selected = logic_.bit(0);
    for (std::size_t length = 1; length <= 32; ++length) {
      const auto branch = logic_.veq(in.vct_length, length);
      selected = logic_.lor_exclusive(selected, branch);
      for (std::size_t i = 0; i < length; ++i)
        logic_.assert_implies(branch, logic_.veq(
            hash_input.padded_message[i], authenticated_vct_byte(in, i)));
      logic_.assert_implies(branch,
          logic_.veq(hash_input.padded_message[length], 0x80));
      for (std::size_t i = length + 1; i < 56; ++i)
        logic_.assert_implies(branch, logic_.veq(hash_input.padded_message[i], 0));
      for (std::size_t i = 0; i < 8; ++i) {
        const auto bits = static_cast<std::uint8_t>((length * 8) >> (56 - 8 * i));
        logic_.assert_implies(branch,
            logic_.veq(hash_input.padded_message[56 + i], bits));
      }
    }
    logic_.assert1(selected);
    std::array<typename Sha::BlockWitness, 1> witness{hash_input.sha_witness};
    Sha(logic_).assert_message_hash(1, logic_.template vbit<8>(1),
                                    hash_input.padded_message.data(),
                                    hash_input.digest_bits, witness.data());
  }

  void decode_payload_bucket(const std::array<v8, PayloadChars>& payload_b64,
                             const Index& payload_b64_length,
                             std::array<v8, (PayloadChars * 6) / 8>& payload) const {
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode_active(payload_b64, payload, payload_b64_length);
  }

  void assert_padded_payload(const std::array<v8, (PayloadChars * 6) / 8>& payload,
                             const std::array<v8, PaddedPayloadChars>& payload_padded) const {
    static_assert((PayloadChars * 6) / 8 <= PaddedPayloadChars);
    for (std::size_t i = 0; i < payload.size(); ++i) logic_.vassert_eq(payload_padded[i], payload[i]);
    for (std::size_t i = payload.size(); i < payload_padded.size(); ++i) logic_.vassert_eq(payload_padded[i], 0);
  }

 private:
  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
