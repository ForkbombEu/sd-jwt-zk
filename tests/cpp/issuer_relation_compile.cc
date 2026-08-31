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

#include "sd_jwt_zk/restricted_base64url_relation.h"
#include "sd_jwt_zk/restricted_json_relation.h"
#include "sd_jwt_zk/issuer_jws_relation.h"

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/routing.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"
#include "sd_jwt_zk/api.h"
#include <fstream>

using FixtureField = proofs::Fp256Base;
using FixtureBackend = proofs::EvaluationBackend<FixtureField>;
using FixtureLogic = proofs::Logic<FixtureField, FixtureBackend>;

struct Fixture140 {
  using Plucker = proofs::BitPlucker<FixtureLogic, 4>;
  using Sha = proofs::FlatSHA256Circuit<FixtureLogic, Plucker>;
  using Ecdsa = proofs::VerifyCircuit<FixtureLogic, FixtureField, proofs::P256>;
  using Production = sd_jwt_zk::IssuerJwsRelation<FixtureLogic, 5, 102, 140>;

  static constexpr char kSigning[] =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ."
      "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSJ9";
  static constexpr char kHeader64[] =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
  static constexpr char kHeaderJson[] =
      "{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\",\"profile_version\":\"swiss-profile-vc:1.0.0\"}";
  static constexpr char kPayload64[] =
      "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSJ9";
  static constexpr char kPayloadJson[] =
      "{\"_sd\":[\"EKD2INGReZFmAt7-vAncecedQToox359FGXYGgYQBL8\"],\"iss\":\"https://issuer.example\",\"vct\":\"example\"}";
  static constexpr char kSignature[] =
      "FQp4GsBBvr3_xbX1UtKSc7mtcw1ygaZ7Z-suRyHET3oggdcr1KqoyH-LA8Yy8pHr3xGkKrrQCu-7fCAbYrTljg";
  static constexpr char kX[] =
      "Jl-RmGfWH_k-UmeHbUnLL58NFLxBz6qOzZqP7z_qxY4";
  static constexpr char kY[] =
      "VBuaEu3T_57clPlJDLwm8xnw1PHFyR4kbXUHyGsK9TU";

  static_assert(sizeof(kHeader64) - 1 == 102);
  static_assert(sizeof(kHeaderJson) - 1 == (102 * 6) / 8);
  static_assert(sizeof(kPayload64) - 1 == 136);

  FixtureField field;
  FixtureBackend backend;
  FixtureLogic logic;
  std::array<FixtureLogic::v8, 102> header_b64{};
  std::array<FixtureLogic::v8, 76> header_decoded{};
  std::array<FixtureLogic::v8, 140> payload_b64{};
  std::array<FixtureLogic::v8, 105> payload_decoded{};
  std::array<FixtureLogic::v8, 256> payload_padded{};
  FixtureLogic::bitvec<8> header_length{}, payload_length{};
  FixtureLogic::bitvec<8> issuer_length{}, vct_length{}, decoded_payload_length{};
  FixtureLogic::BitW explicit_sha256{};
  FixtureLogic::EltW public_x{}, public_y{}, digest{};
  std::array<FixtureLogic::v8, 320> signing{};
  std::array<typename Sha::BlockWitness, 5> sha_witness{};
  FixtureLogic::v256 digest_bits{};
  typename Ecdsa::Witness ecdsa_witness{};
  std::uint8_t sha_block_count = 0;
  bool initialized = false;
  Production relation;

  explicit Fixture140(bool nonzero_payload_tail = false)
      : backend(field, false), logic(&backend, field), relation(logic) {
    const auto key = sd_jwt_zk::decode_p256_jwk(kX, kY);
    const auto sig = sd_jwt_zk::decode_es256_signature(kSignature);
    if (!key || !sig) {
      logic.assert0(logic.bit(1));
      return;
    }

    auto to_nat = [](const auto& bytes) {
      std::array<std::uint8_t, 32> little{};
      for (std::size_t i = 0; i < little.size(); ++i)
        little[i] = bytes[little.size() - 1 - i];
      return proofs::Fp256Nat::of_bytes(little.data());
    };

    const auto native_digest = sd_jwt_zk::sha256_ascii(kSigning);
    const auto digest_nat = to_nat(native_digest);
    const auto r_nat = to_nat(sig.value->r);
    const auto s_nat = to_nat(sig.value->s);
    const auto px = proofs::p256_base.to_montgomery(to_nat(key.value->x));
    const auto py = proofs::p256_base.to_montgomery(to_nat(key.value->y));
    const auto e = proofs::p256_base.to_montgomery(digest_nat);

    std::array<std::uint8_t, 320> padded{};
    std::array<proofs::FlatSHA256Witness::BlockWitness, 5> advice{};
    proofs::FlatSHA256Witness::transform_and_witness_message(
        sizeof(kSigning) - 1,
        reinterpret_cast<const std::uint8_t*>(kSigning), 5,
        sha_block_count, padded.data(), advice.data());
    for (std::size_t i = 0; i < signing.size(); ++i)
      signing[i] = logic.template vbit<8>(padded[i]);

    for (std::size_t i = 0; i < digest_bits.size(); ++i)
      digest_bits[i] = logic.bit(digest_nat.bit(i));
    proofs::BitPluckerEncoder<FixtureField, 4> encoder(proofs::p256_base);
    for (std::size_t block = 0; block < sha_witness.size(); ++block) {
      for (std::size_t word = 0; word < 48; ++word)
        sha_witness[block].outw[word] =
            logic.konst(encoder.mkpacked_v32(advice[block].outw[word]));
      for (std::size_t word = 0; word < 64; ++word) {
        sha_witness[block].oute[word] =
            logic.konst(encoder.mkpacked_v32(advice[block].oute[word]));
        sha_witness[block].outa[word] =
            logic.konst(encoder.mkpacked_v32(advice[block].outa[word]));
      }
      for (std::size_t word = 0; word < 8; ++word)
        sha_witness[block].h1[word] =
            logic.konst(encoder.mkpacked_v32(advice[block].h1[word]));
    }

    for (std::size_t i = 0; i < header_b64.size(); ++i)
      header_b64[i] = logic.template vbit<8>(kHeader64[i]);
    for (std::size_t i = 0; i < header_decoded.size(); ++i)
      header_decoded[i] = logic.template vbit<8>(kHeaderJson[i]);
    for (std::size_t i = 0; i < payload_b64.size(); ++i) {
      const auto byte = i < sizeof(kPayload64) - 1
                            ? static_cast<unsigned char>(kPayload64[i])
                            : 0;
      payload_b64[i] = logic.template vbit<8>(
          nonzero_payload_tail && i == sizeof(kPayload64) - 1 ? 'A' : byte);
    }
    for (std::size_t i = 0; i < payload_padded.size(); ++i) {
      const auto byte = i < sizeof(kPayloadJson) - 1
                            ? static_cast<unsigned char>(kPayloadJson[i])
                            : 0;
      payload_padded[i] = logic.template vbit<8>(byte);
    }
    for (std::size_t i = 0; i < payload_decoded.size(); ++i) {
      const auto byte = i < sizeof(kPayloadJson) - 1
                            ? static_cast<unsigned char>(kPayloadJson[i])
                            : 0;
      payload_decoded[i] = logic.template vbit<8>(byte);
    }
    logic.bits(8, header_length.data(), sizeof(kHeader64) - 1);
    logic.bits(8, payload_length.data(), sizeof(kPayload64) - 1);
    logic.bits(8, issuer_length.data(), 22);
    logic.bits(8, vct_length.data(), 7);
    logic.bits(8, decoded_payload_length.data(), sizeof(kPayloadJson) - 1);
    explicit_sha256 = logic.bit(0);
    public_x = logic.konst(px);
    public_y = logic.konst(py);
    digest = logic.konst(e);

    proofs::VerifyWitness3<proofs::P256, proofs::Fp256Scalar> witness(
        proofs::p256_scalar, proofs::p256);
    if (!witness.compute_witness(px, py, digest_nat, r_nat, s_nat)) {
      logic.assert0(logic.bit(1));
      return;
    }
    ecdsa_witness.rx = logic.konst(witness.rx_);
    ecdsa_witness.ry = logic.konst(witness.ry_);
    ecdsa_witness.rx_inv = logic.konst(witness.rx_inv_);
    ecdsa_witness.s_inv = logic.konst(witness.s_inv_);
    ecdsa_witness.pk_inv = logic.konst(witness.pk_inv_);
    for (std::size_t i = 0; i < 8; ++i)
      ecdsa_witness.pre[i] = logic.konst(witness.pre_[i]);
    for (std::size_t i = 0; i < proofs::P256::kBits; ++i) {
      ecdsa_witness.bi[i] = logic.konst(witness.bi_[i]);
      if (i + 1 < proofs::P256::kBits) {
        ecdsa_witness.int_x[i] = logic.konst(witness.int_x_[i]);
        ecdsa_witness.int_y[i] = logic.konst(witness.int_y_[i]);
        ecdsa_witness.int_z[i] = logic.konst(witness.int_z_[i]);
      }
    }
    initialized = true;
  }

  bool assert_full() {
    if (!initialized) return false;
    auto input = make_input();
    relation.assert_valid(input);
    return !backend.assertion_failed();
  }

  const char* first_failed_stage() {
    if (!initialized) return "fixture";
    auto input = make_input();
    relation.assert_sha(input);
    if (backend.assertion_failed()) return "sha";
    relation.assert_compact_binding(input);
    if (backend.assertion_failed()) return "compact";
    relation.assert_decode_padded_payload(input.payload_b64,
                                          input.payload_b64_length,
                                          input.payload_padded);
    if (backend.assertion_failed()) return "payload";
    relation.assert_header(input, input.header_decoded);
    if (backend.assertion_failed()) return "header";
    relation.assert_json(input);
    if (backend.assertion_failed()) return "json";
    relation.assert_ecdsa(input);
    if (backend.assertion_failed()) return "ecdsa";
    return nullptr;
  }

 private:
  typename Production::Input make_input() {
    return typename Production::Input{
        signing, sha_witness, digest_bits, header_b64, header_decoded,
        payload_b64, payload_decoded, header_length, payload_length, payload_padded,
        issuer_length, vct_length, decoded_payload_length, explicit_sha256,
        public_x, public_y, digest, ecdsa_witness, sha_block_count};
  }
};

int main() {
  std::ofstream stage_result("sd-jwt-zk-issuer-stage-result.txt");
  stage_result << "stage=started\n";
  const proofs::Fp256Base field;
  proofs::EvaluationBackend<proofs::Fp256Base> backend(field, false);
  using Logic = proofs::Logic<proofs::Fp256Base, proofs::EvaluationBackend<proofs::Fp256Base>>;
  Logic logic(&backend, field);
  // Minimal nonzero routing reproduction: B[0] must be A[5].
  proofs::EvaluationBackend<proofs::Fp256Base> routing_backend(field, false);
  Logic routing_logic(&routing_backend, field);
  std::array<Logic::v8, 64> routing_input{};
  std::array<Logic::v8, 64> routing_output{};
  for (std::size_t i = 0; i < routing_input.size(); ++i)
    routing_input[i] = routing_logic.template vbit<8>(i);
  proofs::Routing<Logic> routing(routing_logic);
  Logic::bitvec<6> routing_amount{};
  routing_logic.bits(6, routing_amount.data(), 5);
  routing.shift(routing_amount, routing_output.size(),
                routing_output.data(), routing_input.size(), routing_input.data(),
                routing_logic.template vbit<8>(0), 3);
  bool routed = false;
  for (std::size_t candidate = 0; candidate < 64; ++candidate) {
    const auto expected = routing_logic.template vbit<8>(candidate);
    bool same = true;
    for (std::size_t bit = 0; bit < 8; ++bit)
      same = same && (routing_logic.eval(routing_output[0][bit]) == routing_logic.eval(expected[bit]));
    if (same) { routed = true; if (candidate != 5) return static_cast<int>(candidate + 10); break; }
  }
  if (!routed) return 99;
  sd_jwt_zk::RestrictedBase64UrlRelation<Logic> relation(logic);
  sd_jwt_zk::RestrictedJsonRelation<Logic, 256, 8> json_relation(logic);
  auto input = logic.template vbit<8>('A');
  Logic::bitvec<6> output;
  relation.decode_char(input, output);
  std::array<Logic::v8, 4> encoded{logic.template vbit<8>('Q'), logic.template vbit<8>('U'),
                                   logic.template vbit<8>('J'), logic.template vbit<8>('D')};
  std::array<Logic::v8, 3> decoded{};
  relation.decode(encoded, decoded);
  logic.vassert_eq(decoded[0], 'A');
  logic.vassert_eq(decoded[1], 'B');
  logic.vassert_eq(decoded[2], 'C');
  // Fixed L1 ES256 vector.  Its digest and raw JOSE (r||s) signature are
  // supplied as a private witness; the public P-256 coordinates are wired
  // directly into Longfellow's ECDSA relation.
  constexpr char signing[] =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ."
      "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSJ9";
  // Deterministic RFC 6979 ES256 fixture (private scalar 424242424242424242).
  // Its public components and raw JOSE signature are independently OpenSSL-verifiable.
  constexpr char signature[] = "FQp4GsBBvr3_xbX1UtKSc7mtcw1ygaZ7Z-suRyHET3oggdcr1KqoyH-LA8Yy8pHr3xGkKrrQCu-7fCAbYrTljg";
  constexpr char x[] = "Jl-RmGfWH_k-UmeHbUnLL58NFLxBz6qOzZqP7z_qxY4";
  constexpr char y[] = "VBuaEu3T_57clPlJDLwm8xnw1PHFyR4kbXUHyGsK9TU";
  const auto key = sd_jwt_zk::decode_p256_jwk(x, y);
  const auto sig = sd_jwt_zk::decode_es256_signature(signature);
  if (!key || !sig) return 1;
  auto to_nat = [](const auto& bytes) {
    std::array<std::uint8_t, 32> little{};
    for (std::size_t i = 0; i < little.size(); ++i) little[i] = bytes[little.size() - 1 - i];
    return proofs::Fp256Nat::of_bytes(little.data());
  };
  const auto digest = sd_jwt_zk::sha256_ascii(signing);
  const auto digest_nat = to_nat(digest);
  const auto r_nat = to_nat(sig.value->r);
  const auto s_nat = to_nat(sig.value->s);
  const auto px = proofs::p256_base.to_montgomery(to_nat(key.value->x));
  const auto py = proofs::p256_base.to_montgomery(to_nat(key.value->y));
  const auto e = proofs::p256_base.to_montgomery(digest_nat);
  // The SHA relation owns the padded signing-input witness and constrains its
  // output bit-for-bit to the ECDSA digest.  Native SHA only prepares advice.
  constexpr std::size_t kShaBlocks = 5;
  using Plucker = proofs::BitPlucker<Logic, 4>;
  using Sha = proofs::FlatSHA256Circuit<Logic, Plucker>;
  std::array<std::uint8_t, 64 * kShaBlocks> padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, kShaBlocks> sha_witness{};
  std::uint8_t block_count = 0;
  proofs::FlatSHA256Witness::transform_and_witness_message(
      sizeof(signing) - 1, reinterpret_cast<const std::uint8_t*>(signing),
      kShaBlocks, block_count, padded.data(), sha_witness.data());
  std::array<Logic::v8, 64 * kShaBlocks> sha_input{};
  for (std::size_t i = 0; i < sha_input.size(); ++i) {
    sha_input[i] = logic.template vbit<8>(padded[i]);
    if (i < sizeof(signing) - 1) logic.vassert_eq(sha_input[i], static_cast<unsigned char>(signing[i]));
  }
  Logic::v256 sha_bits{};
  for (std::size_t i = 0; i < sha_bits.size(); ++i) sha_bits[i] = logic.bit(digest_nat.bit(i));
  std::array<typename Sha::BlockWitness, kShaBlocks> sha_circuit_witness{};
  proofs::BitPluckerEncoder<proofs::Fp256Base, 4> encoder(proofs::p256_base);
  for (std::size_t block = 0; block < kShaBlocks; ++block) {
    for (std::size_t word = 0; word < 48; ++word)
      sha_circuit_witness[block].outw[word] = logic.konst(encoder.mkpacked_v32(sha_witness[block].outw[word]));
    for (std::size_t word = 0; word < 64; ++word) {
      sha_circuit_witness[block].oute[word] = logic.konst(encoder.mkpacked_v32(sha_witness[block].oute[word]));
      sha_circuit_witness[block].outa[word] = logic.konst(encoder.mkpacked_v32(sha_witness[block].outa[word]));
    }
    for (std::size_t word = 0; word < 8; ++word)
      sha_circuit_witness[block].h1[word] = logic.konst(encoder.mkpacked_v32(sha_witness[block].h1[word]));
  }
  // SHA is asserted by IssuerJwsRelation below.
  // Constrain the compact segments themselves and their decoded restricted
  // JSON grammar.  The canonical MVP grammar intentionally accepts no
  // whitespace, escapes, reordered keys, or trailing bytes.
  constexpr char header64[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
  constexpr char header_json[] = "{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\",\"profile_version\":\"swiss-profile-vc:1.0.0\"}";
  constexpr char payload64[] = "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSJ9";
  constexpr char payload_json[] = "{\"_sd\":[\"EKD2INGReZFmAt7-vAncecedQToox359FGXYGgYQBL8\"],\"iss\":\"https://issuer.example\",\"vct\":\"example\"}";
  std::array<Logic::v8, sizeof(header64) - 1> header_input{};
  std::array<Logic::v8, ((sizeof(header64) - 1) * 6) / 8> header_decoded{};
  for (std::size_t i = 0; i < header_input.size(); ++i) {
    header_input[i] = logic.template vbit<8>(header64[i]);
    logic.vassert_eq(header_input[i], sha_input[i]);
  }
  (void)header_decoded; (void)header_json;
  std::array<Logic::v8, 140> payload_input{};
  std::array<Logic::v8, ((sizeof(payload64) - 1) * 6) / 8> payload_decoded{};
  constexpr std::size_t payload_offset = sizeof(header64);
  for (std::size_t i = 0; i < payload_input.size(); ++i) {
    payload_input[i] = logic.template vbit<8>(i < sizeof(payload64) - 1 ? payload64[i] : 0);
    if (i < sizeof(payload64) - 1) logic.vassert_eq(payload_input[i], sha_input[payload_offset + i]);
  }
  (void)payload_decoded;
  std::array<Logic::v8, 256> payload_padded{};
  for (std::size_t i = 0; i < payload_padded.size(); ++i) {
    payload_padded[i] = logic.template vbit<8>(i < sizeof(payload_json) - 1 ?
        static_cast<unsigned char>(payload_json[i]) : 0);
  }
  // Isolate the 140-cell bucket / 136-cell active segment before composing
  // SHA, JSON and ECDSA.  The three decoded suffix bytes are zero padding.
  std::array<Logic::v8, (140 * 6) / 8> bucket_decoded{};
  for (std::size_t i = 0; i < bucket_decoded.size(); ++i)
    bucket_decoded[i] = logic.template vbit<8>(i < sizeof(payload_json) - 1 ?
        static_cast<unsigned char>(payload_json[i]) : 0);
  Logic::bitvec<8> payload_b64_length{}; logic.bits(8, payload_b64_length.data(), sizeof(payload64) - 1);
  relation.decode_active(payload_input, bucket_decoded, payload_b64_length);
  if (backend.assertion_failed()) return 46;
  Logic::bitvec<8> payload_start{}, digest_start{}, issuer_start{}, issuer_length{}, vct_length{}, payload_length{};
  logic.bits(8, payload_start.data(), 0); logic.bits(8, digest_start.data(), 9);
  logic.bits(8, issuer_start.data(), 62); logic.bits(8, issuer_length.data(), 22); logic.bits(8, vct_length.data(), 7);
  logic.bits(8, payload_length.data(), sizeof(payload_json) - 1);
  (void)json_relation; (void)payload_start;
  // Every `_sd` digest byte is independently constrained to the base64url
  // alphabet; no substring match can introduce an unparsed digest slot.
  (void)relation;
  (void)digest_start; (void)issuer_start; (void)issuer_length;
  proofs::VerifyWitness3<proofs::P256, proofs::Fp256Scalar> witness(proofs::p256_scalar, proofs::p256);
  if (!witness.compute_witness(px, py, digest_nat, r_nat, s_nat)) return 1;
  using Ecdsa = proofs::VerifyCircuit<Logic, proofs::Fp256Base, proofs::P256>;
  typename Ecdsa::Witness circuit_witness{};
  circuit_witness.rx = logic.konst(witness.rx_); circuit_witness.ry = logic.konst(witness.ry_);
  circuit_witness.rx_inv = logic.konst(witness.rx_inv_); circuit_witness.s_inv = logic.konst(witness.s_inv_);
  circuit_witness.pk_inv = logic.konst(witness.pk_inv_);
  for (std::size_t i = 0; i < 8; ++i) circuit_witness.pre[i] = logic.konst(witness.pre_[i]);
  for (std::size_t i = 0; i < proofs::P256::kBits; ++i) {
    circuit_witness.bi[i] = logic.konst(witness.bi_[i]);
    if (i + 1 < proofs::P256::kBits) {
      circuit_witness.int_x[i] = logic.konst(witness.int_x_[i]);
      circuit_witness.int_y[i] = logic.konst(witness.int_y_[i]);
      circuit_witness.int_z[i] = logic.konst(witness.int_z_[i]);
    }
  }
  // The production component owns the composed SHA, base64/grammar, and
  // ECDSA assertions; this fixture supplies only its bounded witness values.
  using Production = sd_jwt_zk::IssuerJwsRelation<Logic, kShaBlocks,
      sizeof(header64) - 1, 140>;
  {
    const proofs::Fp256Base header_field;
    proofs::EvaluationBackend<proofs::Fp256Base> header_backend(header_field, false);
    Logic header_logic(&header_backend, header_field);
    sd_jwt_zk::RestrictedBase64UrlRelation<Logic> header_decoder(header_logic);
    std::array<Logic::v8, sizeof(header64) - 1> encoded{};
    std::array<Logic::v8, ((sizeof(header64) - 1) * 6) / 8> decoded{};
    for (std::size_t i = 0; i < encoded.size(); ++i) encoded[i] = header_logic.template vbit<8>(header64[i]);
    for (std::size_t i = 0; i < decoded.size(); ++i) decoded[i] = header_logic.template vbit<8>(header_json[i]);
    Logic::bitvec<8> length{}; header_logic.bits(8, length.data(), sizeof(header64) - 1);
    header_decoder.decode_active(encoded, decoded, length);
    if (header_backend.assertion_failed()) return 35;
  }
  Logic::bitvec<8> header_b64_length{};
  logic.bits(8, header_b64_length.data(), sizeof(header64) - 1);
  // Fresh backend: decode/padded-buffer behavior is independent of SHA/ECDSA
  // witness assertions.  A zero bucket tail is valid; any nonzero tail is not.
  {
    const proofs::Fp256Base fresh_field;
    proofs::EvaluationBackend<proofs::Fp256Base> fresh_backend(fresh_field, false);
    Logic fresh_logic(&fresh_backend, fresh_field);
    using FreshProduction = sd_jwt_zk::IssuerJwsRelation<Logic, kShaBlocks, sizeof(header64) - 1, 140>;
    FreshProduction fresh(fresh_logic);
    std::array<Logic::v8, 140> fresh_payload{};
    std::array<Logic::v8, 256> fresh_padded{};
    for (std::size_t i = 0; i < fresh_payload.size(); ++i)
      fresh_payload[i] = fresh_logic.template vbit<8>(i < sizeof(payload64) - 1 ? payload64[i] : 0);
    for (std::size_t i = 0; i < fresh_padded.size(); ++i)
      fresh_padded[i] = fresh_logic.template vbit<8>(i < sizeof(payload_json) - 1 ? static_cast<unsigned char>(payload_json[i]) : 0);
    Logic::bitvec<8> fresh_length{}; fresh_logic.bits(8, fresh_length.data(), sizeof(payload64) - 1);
    std::array<Logic::v8, (140 * 6) / 8> fresh_decoded{};
    for (std::size_t i = 0; i < fresh_decoded.size(); ++i)
      fresh_decoded[i] = fresh_logic.template vbit<8>(i < sizeof(payload_json) - 1 ? static_cast<unsigned char>(payload_json[i]) : 0);
    fresh.decode_payload_bucket(fresh_payload, fresh_length, fresh_decoded);
    if (fresh_backend.assertion_failed()) return 44;
    fresh.assert_padded_payload(fresh_decoded, fresh_padded);
    if (fresh_backend.assertion_failed()) return 42;
    fresh_payload[136] = fresh_logic.template vbit<8>('A');
    fresh.assert_decode_padded_payload(fresh_payload, fresh_length, fresh_padded);
    if (!fresh_backend.assertion_failed()) return 43;
  }
  Production production(logic);
  std::array<Logic::v8, (140 * 6) / 8> shared_decoded{};
  for (std::size_t i = 0; i < shared_decoded.size(); ++i)
    shared_decoded[i] = logic.template vbit<8>(i < sizeof(payload_json) - 1 ? static_cast<unsigned char>(payload_json[i]) : 0);
  typename Production::Input production_input{sha_input, sha_circuit_witness, sha_bits,
      header_input, header_decoded, payload_input, shared_decoded, header_b64_length, payload_b64_length, payload_padded, issuer_length, vct_length,
      payload_length, logic.bit(0), logic.konst(px), logic.konst(py), logic.konst(e),
      circuit_witness, block_count};
  production.assert_sha(production_input); if (backend.assertion_failed()) return 41;
  production.assert_compact_binding(production_input); if (backend.assertion_failed()) return 40;
  production.decode_payload_bucket(payload_input, payload_b64_length, shared_decoded); if (backend.assertion_failed()) return 45;
  production.assert_padded_payload(shared_decoded, payload_padded); if (backend.assertion_failed()) return 36;
  std::array<Logic::v8, ((sizeof(header64) - 1) * 6) / 8> shared_header{};
  for (std::size_t i = 0; i < shared_header.size(); ++i) shared_header[i] = logic.template vbit<8>(header_json[i]);
  sd_jwt_zk::RestrictedBase64UrlRelation<Logic>(logic).decode_active(production_input.header_b64, shared_header, production_input.header_b64_length);
  if (backend.assertion_failed()) return 34;
  production.assert_header(production_input, shared_header); if (backend.assertion_failed()) { stage_result << "stage=header-failed\n"; return 39; }
  stage_result << "stage=header-passed\n";
  production.assert_json(production_input); if (backend.assertion_failed()) { stage_result << "stage=json-failed\n"; return 38; }
  stage_result << "stage=json-passed\n";
  production.assert_ecdsa(production_input); if (backend.assertion_failed()) { stage_result << "stage=ecdsa-failed\n"; return 37; }
  stage_result << "stage=ecdsa-passed\n";
  // Full relation evidence uses fresh backend-owned fixtures.  Replaying the
  // staged relation above would reuse wires and assertion state and therefore
  // would not demonstrate a valid production invocation.
  {
    Fixture140 accepted;
    if (!accepted.assert_full()) {
      stage_result << "full-140-136-failed\n";
      Fixture140 diagnosis;
      const char* failed_stage = diagnosis.first_failed_stage();
      stage_result << "full-140-136-first-failed-stage="
                   << (failed_stage == nullptr ? "none" : failed_stage) << '\n';
      return 47;
    }
    stage_result << "full-140-136-accepted\n";
  }
  {
    Fixture140 nonzero_tail(true);
    if (nonzero_tail.assert_full()) {
      stage_result << "full-140-136-nonzero-tail-accepted\n";
      return 48;
    }
    stage_result << "full-140-136-nonzero-tail-rejected\n";
  }
  constexpr char disclosure_ascii[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
  constexpr char signed_digest[] = "EKD2INGReZFmAt7-vAncecedQToox359FGXYGgYQBL8";
  using DisclosureSha = proofs::FlatSHA256Circuit<Logic, Plucker>;
  std::array<std::uint8_t, 64> disclosure_padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 1> disclosure_advice{};
  std::uint8_t disclosure_blocks = 0;
  proofs::FlatSHA256Witness::transform_and_witness_message(sizeof(disclosure_ascii) - 1,
      reinterpret_cast<const std::uint8_t*>(disclosure_ascii), 1, disclosure_blocks,
      disclosure_padded.data(), disclosure_advice.data());
  std::array<Logic::v8, 64> disclosure_sha_input{};
  for (std::size_t i = 0; i < disclosure_sha_input.size(); ++i)
    disclosure_sha_input[i] = logic.template vbit<8>(disclosure_padded[i]);
  Logic::v256 disclosure_bits{};
  const auto disclosure_hash = sd_jwt_zk::sha256_ascii(disclosure_ascii);
  const auto disclosure_nat = to_nat(disclosure_hash);
  for (std::size_t i = 0; i < disclosure_bits.size(); ++i) disclosure_bits[i] = logic.bit(disclosure_nat.bit(i));
  std::array<typename DisclosureSha::BlockWitness, 1> disclosure_witness{};
  for (std::size_t word = 0; word < 48; ++word)
    disclosure_witness[0].outw[word] = logic.konst(encoder.mkpacked_v32(disclosure_advice[0].outw[word]));
  for (std::size_t word = 0; word < 64; ++word) {
    disclosure_witness[0].oute[word] = logic.konst(encoder.mkpacked_v32(disclosure_advice[0].oute[word]));
    disclosure_witness[0].outa[word] = logic.konst(encoder.mkpacked_v32(disclosure_advice[0].outa[word]));
  }
  for (std::size_t word = 0; word < 8; ++word)
    disclosure_witness[0].h1[word] = logic.konst(encoder.mkpacked_v32(disclosure_advice[0].h1[word]));
  std::array<Logic::v8, sizeof(disclosure_ascii) - 1> disclosure_input{};
  std::array<Logic::v8, 43> signed_digest_input{};
  for (std::size_t i = 0; i < disclosure_input.size(); ++i) disclosure_input[i] = logic.template vbit<8>(disclosure_ascii[i]);
  for (std::size_t i = 0; i < signed_digest_input.size(); ++i) signed_digest_input[i] = logic.template vbit<8>(signed_digest[i]);
  using Disclosure = sd_jwt_zk::FlatDisclosureRelation<Logic, 1, sizeof(disclosure_ascii) - 1>;
  typename Disclosure::Input disclosure_input_relation{disclosure_input, disclosure_sha_input,
      disclosure_witness, disclosure_bits, signed_digest_input, disclosure_blocks};
  production.template assert_disclosure_binding<1, sizeof(disclosure_ascii) - 1>(production_input, disclosure_input_relation);
  if (backend.assertion_failed()) return 49;
  Disclosure disclosure_relation(logic);
  Logic::bitvec<8> salt_length{}, name_length{}, value_length{}, disclosure_length{};
  logic.bits(8, salt_length.data(), 9); logic.bits(8, name_length.data(), 8);
  logic.bits(8, value_length.data(), 4); logic.bits(8, disclosure_length.data(), 31);
  disclosure_relation.assert_decoded_three_string_grammar(disclosure_input, salt_length, name_length,
      value_length, disclosure_length, 9, 8, 4);
  if (backend.assertion_failed()) return 51;

  // A changed decoded `_sd` byte cannot be swapped in after issuer-JWS
  // authentication: the disclosure target comes from this exact payload slot.
  std::array<Logic::v8, 256> mutated_payload_padded{};
  for (std::size_t i = 0; i < mutated_payload_padded.size(); ++i) {
    const auto byte = i < sizeof(payload_json) - 1 ? static_cast<unsigned char>(payload_json[i]) : 0;
    mutated_payload_padded[i] = logic.template vbit<8>(i == 9 ? 'A' : byte);
  }
  typename Production::Input mutated_issuer_input{sha_input, sha_circuit_witness, sha_bits,
      header_input, header_decoded, payload_input, shared_decoded, header_b64_length, payload_b64_length, mutated_payload_padded, issuer_length, vct_length,
      payload_length, logic.bit(0), logic.konst(px), logic.konst(py), logic.konst(e),
      circuit_witness, block_count};
  production.template assert_disclosure_binding<1, sizeof(disclosure_ascii) - 1>(
      mutated_issuer_input, disclosure_input_relation);
  if (!backend.assertion_failed()) return 52;

  // Each negative relation is evaluated after the previous failure has been
  // observed.  EvaluationBackend::assertion_failed() consumes its flag, so
  // this is deliberately one executable run rather than dead code after the
  // first expected rejection.
  auto mutated_sha_input = disclosure_sha_input;
  mutated_sha_input[0] = logic.template vbit<8>('X');
  typename Disclosure::Input mutated_sha_relation{disclosure_input, mutated_sha_input,
      disclosure_witness, disclosure_bits, signed_digest_input, disclosure_blocks};
  production.template assert_disclosure_binding<1, sizeof(disclosure_ascii) - 1>(production_input, mutated_sha_relation);
  if (!backend.assertion_failed()) return 53;

  Logic::v256 mutated_disclosure_bits{};
  for (std::size_t i = 0; i < mutated_disclosure_bits.size(); ++i)
    mutated_disclosure_bits[i] = logic.bit(disclosure_nat.bit(i) ^ (i == 0));
  typename Disclosure::Input mutated_hash_relation{disclosure_input, disclosure_sha_input,
      disclosure_witness, mutated_disclosure_bits, signed_digest_input, disclosure_blocks};
  production.template assert_disclosure_binding<1, sizeof(disclosure_ascii) - 1>(production_input, mutated_hash_relation);
  if (!backend.assertion_failed()) return 54;

  auto mutated_signed_digest = signed_digest_input;
  mutated_signed_digest[0] = logic.template vbit<8>('A');
  typename Disclosure::Input mutated_digest_relation{disclosure_input, disclosure_sha_input,
      disclosure_witness, disclosure_bits, mutated_signed_digest, disclosure_blocks};
  production.template assert_disclosure_binding<1, sizeof(disclosure_ascii) - 1>(production_input, mutated_digest_relation);
  if (!backend.assertion_failed()) return 55;

  Logic::bitvec<8> bad_disclosure_length{};
  logic.bits(8, bad_disclosure_length.data(), 22);
  disclosure_relation.assert_decoded_three_string_grammar(disclosure_input, salt_length, name_length,
      value_length, bad_disclosure_length, 9, 8, 4);
  if (!backend.assertion_failed()) return 56;

  auto bad_disclosure_delimiter = disclosure_input;
  // This remains base64url but decodes the first JSON comma/quote delimiter
  // to a non-delimiter byte.
  bad_disclosure_delimiter[14] = logic.template vbit<8>('B');
  disclosure_relation.assert_decoded_three_string_grammar(bad_disclosure_delimiter, salt_length,
      name_length, value_length, disclosure_length, 9, 8, 4);
  if (!backend.assertion_failed()) return 57;

  auto bad_disclosure_end = disclosure_input;
  // The unpadded final base64url sextet is still significant: this changes
  // the decoded closing `]` while preserving the base64url alphabet.
  bad_disclosure_end[41] = logic.template vbit<8>('A');
  disclosure_relation.assert_decoded_three_string_grammar(bad_disclosure_end, salt_length,
      name_length, value_length, disclosure_length, 9, 8, 4);
  if (!backend.assertion_failed()) return 58;

  auto bad_separator = sha_input;
  bad_separator[sizeof(header64) - 1] = logic.template vbit<8>('!');
  production.assert_compact_separator(bad_separator, header_b64_length);
  if (!backend.assertion_failed()) return 59;

  // The decoded disclosure relation has an exact 23-byte capacity.  Exercise
  // the configured padded grammar bucket separately so no nonzero tail can
  // become an unconstrained witness suffix.
  {
    const proofs::Fp256Base grammar_field;
    proofs::EvaluationBackend<proofs::Fp256Base> grammar_backend(grammar_field, false);
    Logic grammar_logic(&grammar_backend, grammar_field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> grammar_relation(grammar_logic);
    std::array<Logic::v8, 32> padded_json{};
    constexpr char json_text[] = "[\"salt\",\"name\",\"value\"]";
    for (std::size_t i = 0; i < padded_json.size(); ++i)
      padded_json[i] = grammar_logic.template vbit<8>(
          i < sizeof(json_text) - 1 ? static_cast<unsigned char>(json_text[i]) : 0);
    Logic::bitvec<8> grammar_salt{}, grammar_name{}, grammar_value{}, grammar_total{};
    grammar_logic.bits(8, grammar_salt.data(), 4);
    grammar_logic.bits(8, grammar_name.data(), 4);
    grammar_logic.bits(8, grammar_value.data(), 5);
    grammar_logic.bits(8, grammar_total.data(), sizeof(json_text) - 1);
    grammar_relation.assert_three_string_active_grammar(padded_json, grammar_salt, grammar_name,
        grammar_value, grammar_total, 4, 4, 5);
    if (grammar_backend.assertion_failed()) return 60;
    padded_json[sizeof(json_text) - 1] = grammar_logic.template vbit<8>('x');
    grammar_relation.assert_three_string_active_grammar(padded_json, grammar_salt, grammar_name,
        grammar_value, grammar_total, 4, 4, 5);
    if (!grammar_backend.assertion_failed()) return 61;
  }
  return 0;
}
