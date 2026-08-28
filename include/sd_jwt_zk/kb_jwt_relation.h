#pragma once

#include <array>
#include <cstddef>
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
#include <chrono>
#include <iostream>
#endif

#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "ec/p256.h"
#include "sd_jwt_zk/restricted_base64url_relation.h"
#include "sd_jwt_zk/presentation_hash_relation.h"
#include "sd_jwt_zk/active_presentation_message_relation.h"
#include "sd_jwt_zk/compact_es256_signature_relation.h"

namespace sd_jwt_zk {

// Canonical payload grammar for the initial holder-bound KB-JWT bucket.  The
// caller owns the decoded payload workspace and the public challenge wires;
// this relation only connects them.  `iat` is deliberately a fixed-width,
// ten-decimal-digit Unix timestamp in V1: that makes its public policy range
// comparison an arithmetic-circuit operation rather than a host-side check.
template <class LogicCircuit, std::size_t Capacity, std::size_t AudienceMax,
          std::size_t NonceMax>
class RestrictedKbJwtRelation {
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using Index = typename LogicCircuit::template bitvec<8>;

 public:
  static_assert(Capacity >= 8 + AudienceMax + 11 + NonceMax + 8 + 10 + 12 +
                                43 + 2,
                "KB payload bucket cannot hold its declared public limits");

  explicit RestrictedKbJwtRelation(const LogicCircuit& logic) : logic_(logic) {}

  // `audience` and `nonce` are zero-padded public byte slots.  Their lengths
  // are public too, and are compared to the private canonical JSON slots.
  // The time bounds are public, fixed-width decimal strings; this V1 bucket
  // intentionally rejects noncanonical (including leading-zero) `iat`.
  void assert_payload(
      const std::array<v8, Capacity>& payload,
      const std::array<v8, AudienceMax>& audience, const Index& audience_length,
      const std::array<v8, NonceMax>& nonce, const Index& nonce_length,
      const std::array<v8, 10>& time_min, const std::array<v8, 10>& time_max,
      const std::array<v8, 43>& sd_hash) const {
    assert_literal(payload, 0, "{\"aud\":\"");
    BitW selected = logic_.bit(0);
    for (std::size_t aud = 1; aud <= AudienceMax; ++aud) {
      const BitW aud_branch = logic_.veq(audience_length, aud);
      for (std::size_t i = 0; i < aud; ++i) {
        assert_safe(aud_branch, payload[8 + i]);
        logic_.assert_implies(aud_branch, logic_.veq(payload[8 + i], audience[i]));
      }
      for (std::size_t n = 1; n <= NonceMax; ++n) {
        const BitW branch = logic_.land(aud_branch, logic_.veq(nonce_length, n));
        selected = logic_.lor_exclusive(selected, branch);
        assert_literal_if(branch, payload, 8 + aud, "\",\"nonce\":\"");
        for (std::size_t i = 0; i < n; ++i) {
          assert_safe(branch, payload[19 + aud + i]);
          logic_.assert_implies(branch,
                                logic_.veq(payload[19 + aud + i], nonce[i]));
        }
        const std::size_t iat_at = 19 + aud + n;
        assert_literal_if(branch, payload, iat_at, "\",\"iat\":");
        std::array<v8, 10> iat{};
        for (std::size_t i = 0; i < iat.size(); ++i) {
          iat[i] = payload[iat_at + 8 + i];
          assert_decimal(branch, iat[i]);
        }
        logic_.assert_implies(branch, logic_.lnot(logic_.veq(iat[0], '0')));
        logic_.assert_implies(branch, decimal_leq(time_min, iat));
        logic_.assert_implies(branch, decimal_leq(iat, time_max));
        const std::size_t hash_at = iat_at + 18;
        assert_literal_if(branch, payload, hash_at, ",\"sd_hash\":\"");
        for (std::size_t i = 0; i < sd_hash.size(); ++i)
          logic_.assert_implies(branch,
                                logic_.veq(payload[hash_at + 12 + i], sd_hash[i]));
        logic_.assert_implies(branch,
                              logic_.veq(payload[hash_at + 55], '"'));
        logic_.assert_implies(branch,
                              logic_.veq(payload[hash_at + 56], '}'));
        for (std::size_t i = hash_at + 57; i < Capacity; ++i)
          logic_.assert_implies(branch, logic_.veq(payload[i], 0));
      }
    }
    logic_.assert1(selected);
  }

 private:
  void assert_literal(const std::array<v8, Capacity>& text, std::size_t at,
                      const char* literal) const {
    for (std::size_t i = 0; literal[i] != '\0'; ++i)
      logic_.vassert_eq(text[at + i], static_cast<unsigned char>(literal[i]));
  }

  void assert_literal_if(const BitW& condition,
                         const std::array<v8, Capacity>& text, std::size_t at,
                         const char* literal) const {
    for (std::size_t i = 0; literal[i] != '\0'; ++i)
      logic_.assert_implies(condition,
                            logic_.veq(text[at + i],
                                       static_cast<unsigned char>(literal[i])));
  }

  void assert_safe(const BitW& condition, const v8& byte) const {
    logic_.assert_implies(condition,
                          logic_.land(logic_.vlt(0x20, byte), logic_.vlt(byte, 0x7f)));
    logic_.assert_implies(condition, logic_.lnot(logic_.veq(byte, '"')));
    logic_.assert_implies(condition, logic_.lnot(logic_.veq(byte, '\\')));
  }

  void assert_decimal(const BitW& condition, const v8& byte) const {
    logic_.assert_implies(condition, logic_.lnot(logic_.vlt(byte, '0')));
    logic_.assert_implies(condition, logic_.vleq(byte, '9'));
  }

  BitW decimal_leq(const std::array<v8, 10>& left,
                   const std::array<v8, 10>& right) const {
    BitW equal = logic_.bit(1);
    BitW less = logic_.bit(0);
    for (std::size_t i = 0; i < left.size(); ++i) {
      less = logic_.lor_exclusive(
          less, logic_.land(equal, logic_.vlt(left[i], right[i])));
      equal = logic_.land(equal, logic_.veq(left[i], right[i]));
    }
    return logic_.lor_exclusive(less, equal);
  }

  const LogicCircuit& logic_;
};

// Full compact KB-JWT relation.  It is intentionally separate from
// IssuerJwsRelation: the `kb+jwt` header, public challenge binding, and holder
// key are different circuit-family inputs and cannot be made optional without
// changing a bearer circuit's identity.
template <class LogicCircuit, std::size_t SigningBlocks, std::size_t HeaderChars,
          std::size_t PayloadChars, std::size_t AudienceMax, std::size_t NonceMax>
class KbJwsRelation {
  using Field = typename LogicCircuit::Field;
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using EltW = typename LogicCircuit::EltW;
  using Plucker = proofs::BitPlucker<LogicCircuit, 4>;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit, Plucker>;
  using Ecdsa = proofs::VerifyCircuit<LogicCircuit, Field, proofs::P256>;
  using Index = typename LogicCircuit::template bitvec<8>;
  static constexpr std::size_t kDecodedPayload = (PayloadChars * 6) / 8;

 public:
  struct Input {
    const std::array<v8, 64 * SigningBlocks>& sha_input;
    const std::array<typename Sha::BlockWitness, SigningBlocks>& sha_witness;
    const v256& digest_bits;
    const std::array<v8, HeaderChars>& header_b64;
    std::array<v8, (HeaderChars * 6) / 8>& header_decoded;
    const std::array<v8, PayloadChars>& payload_b64;
    const std::array<v8,
        CompactEs256SignatureRelation<LogicCircuit>::kEncodedChars>& signature_b64;
    std::array<v8, kDecodedPayload>& payload_decoded;
    const Index& header_b64_length;
    const Index& payload_b64_length;
    const std::array<v8, AudienceMax>& audience;
    const Index& audience_length;
    const std::array<v8, NonceMax>& nonce;
    const Index& nonce_length;
    const std::array<v8, 10>& time_min;
    const std::array<v8, 10>& time_max;
    const std::array<v8, 43>& sd_hash;
    const EltW& holder_x;
    const EltW& holder_y;
    const EltW& signature_r;
    const EltW& signature_s;
    const EltW& digest;
    const typename Ecdsa::Witness& ecdsa_witness;
    std::uint8_t sha_block_count;
  };

  explicit KbJwsRelation(const LogicCircuit& logic) : logic_(logic) {}

  void assert_valid(const Input& in) const {
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
    const auto started = std::chrono::steady_clock::now();
    auto metric = [&](const char* stage) {
      std::cerr << "holder-kb stage=" << stage << " ms="
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - started).count()
                << '\n';
    };
#endif
    Sha(logic_).assert_message_hash(SigningBlocks,
        logic_.template vbit<8>(in.sha_block_count), in.sha_input.data(),
        in.digest_bits, in.sha_witness.data());
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
    metric("sha");
#endif
    assert_compact_binding(in);
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode_active(
        in.header_b64, in.header_decoded, in.header_b64_length);
    assert_header(in.header_decoded);
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
    metric("header");
#endif
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode_active(
        in.payload_b64, in.payload_decoded, in.payload_b64_length);
    RestrictedKbJwtRelation<LogicCircuit, kDecodedPayload, AudienceMax,
        NonceMax>(logic_).assert_payload(in.payload_decoded, in.audience,
        in.audience_length, in.nonce, in.nonce_length, in.time_min, in.time_max,
        in.sd_hash);
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
    metric("payload");
#endif
    CompactEs256SignatureRelation<LogicCircuit>(logic_).assert_decode(
        in.signature_b64, in.signature_r, in.signature_s);
    const auto negative_s = logic_.sub(
        logic_.konst(proofs::p256_base.to_montgomery(proofs::n256_order)),
        in.signature_s);
    Ecdsa(logic_, proofs::p256, proofs::n256_order).verify_signature3_bound(
        in.holder_x, in.holder_y, in.digest, in.signature_r, negative_s,
        in.ecdsa_witness);
#ifdef SD_JWT_ZK_HOLDER_FACTORY_METRICS
    metric("holder-ecdsa");
#endif
  }

  // The caller supplies this relation with the *same* private presentation
  // bytes used by the issuer/disclosure relation.  Its decoded digest is the
  // `sd_hash` wire consumed above, so a KB-JWT cannot be replayed for a
  // reordered, truncated, or substituted presentation.
  template <std::size_t PresentationBlocks, std::size_t IssuerChars,
            std::size_t DisclosureChars>
  void assert_presentation_binding(
      const Input& kb,
      const typename PresentationHashRelation<LogicCircuit, PresentationBlocks,
          IssuerChars, DisclosureChars>::Input& presentation) const {
    PresentationHashRelation<LogicCircuit, PresentationBlocks, IssuerChars,
        DisclosureChars>(logic_).assert_valid(presentation);
    for (std::size_t i = 0; i < kb.sd_hash.size(); ++i)
      logic_.vassert_eq(kb.sd_hash[i], presentation.sd_hash_b64url[i]);
  }

  // Active-length form of the presentation binding.  The same KB-JWT
  // `sd_hash` wire is decoded from the SHA-256 digest selected by the bounded
  // issuer and disclosure bucket lengths.
  template <std::size_t PresentationBlocks, std::size_t IssuerCapacity,
            std::size_t DisclosureCapacity, std::size_t IndexBits = 9>
  void assert_active_presentation_binding(
      const Input& kb,
      const typename ActivePresentationHashRelation<LogicCircuit,
          IssuerCapacity, DisclosureCapacity, PresentationBlocks,
          IndexBits>::Input& presentation) const {
    ActivePresentationHashRelation<LogicCircuit, IssuerCapacity,
        DisclosureCapacity, PresentationBlocks, IndexBits>(logic_).assert_valid(
            presentation);
    for (std::size_t i = 0; i < kb.sd_hash.size(); ++i)
      logic_.vassert_eq(kb.sd_hash[i], presentation.sd_hash_b64url[i]);
  }

 private:
  void assert_compact_binding(const Input& in) const {
    logic_.assert_implies(logic_.veq(in.header_b64_length, HeaderChars),
                          logic_.veq(in.sha_input[HeaderChars], '.'));
    logic_.assert1(logic_.veq(in.header_b64_length, HeaderChars));
    logic_.assert1(logic_.veq(in.payload_b64_length, PayloadChars));
    for (std::size_t i = 0; i < HeaderChars; ++i)
      logic_.vassert_eq(in.header_b64[i], in.sha_input[i]);
    for (std::size_t i = 0; i < PayloadChars; ++i)
      logic_.vassert_eq(in.payload_b64[i], in.sha_input[HeaderChars + 1 + i]);
  }

  void assert_header(const std::array<v8, (HeaderChars * 6) / 8>& header) const {
    constexpr char expected[] = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}";
    static_assert(sizeof(expected) - 1 == (HeaderChars * 6) / 8);
    for (std::size_t i = 0; i < header.size(); ++i)
      logic_.vassert_eq(header[i], static_cast<unsigned char>(expected[i]));
  }

  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
