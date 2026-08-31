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

#include "sd_jwt_zk/holder_kb_witness.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>

#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/sha/flatsha256_witness.h"

namespace sd_jwt_zk {
namespace {

proofs::Fp256Nat to_nat(const std::array<std::uint8_t, 32>& bytes) {
  std::array<std::uint8_t, 32> little{};
  for (std::size_t i = 0; i < little.size(); ++i)
    little[i] = bytes[little.size() - 1 - i];
  return proofs::Fp256Nat::of_bytes(little.data());
}

void fill_v8(proofs::DenseFiller<HolderKbFieldV1>& filler,
             std::uint8_t byte) {
  filler.push_back(byte, 8, proofs::p256_base);
}

bool decimal10(std::uint64_t value, std::array<std::uint8_t, 10>& out) {
  if (value < 1000000000ULL || value > 9999999999ULL) return false;
  std::array<char, 20> text{};
  const auto converted = std::to_chars(text.data(), text.data() + text.size(), value);
  if (converted.ec != std::errc{} || converted.ptr - text.data() != 10) return false;
  std::copy(text.begin(), text.begin() + 10, out.begin());
  return true;
}

}  // namespace

HolderKbFieldV1::Elt holder_bridge_digest_field_v1(
    const std::array<std::uint8_t, 32>& digest) {
  // This mirrors HolderBridgeMacRelation::bind_digest exactly: digest bit
  // vectors use reverse byte groups and the relation folds each successive
  // little-endian bit with a successively doubled coefficient.
  auto packed = proofs::p256_base.zero();
  auto two = proofs::p256_base.one();
  for (std::size_t i = 0; i < 256; ++i) {
    const std::size_t byte = 31 - i / 8;
    packed = proofs::p256_base.addf(
        packed,
        proofs::p256_base.mulf(
            two, proofs::p256_base.of_scalar((digest[byte] >> (i % 8)) & 1)));
    two = proofs::p256_base.addf(two, two);
  }
  return packed;
}

Result<HolderKbWitnessV1> holder_kb_witness_from_compact_jwt_v1(
    std::string_view compact_jwt, std::string_view holder_x,
    std::string_view holder_y, const Limits& limits) {
  if (compact_jwt.size() > limits.max_input)
    return Result<HolderKbWitnessV1>::fail(ErrorCode::limit,
                                           "KB-JWT exceeds input bound");
  const auto compact = split_compact_jws(compact_jwt, limits);
  const auto key = decode_p256_jwk(holder_x, holder_y);
  if (!compact || !key)
    return Result<HolderKbWitnessV1>::fail(ErrorCode::malformed,
                                           "invalid KB-JWT or holder key");
  const auto signature = decode_es256_signature(compact.value->signature);
  const auto header = base64url_decode(compact.value->protected_header,
                                       limits.max_field);
  const auto payload = base64url_decode(compact.value->payload, limits.max_field);
  if (!signature || !header || !payload || header.value->size() != 30 ||
      payload.value->size() != 132)
    return Result<HolderKbWitnessV1>::fail(ErrorCode::malformed,
                                           "KB-JWT is outside the V1 bucket");
  const auto claims = parse_restricted_kb_jwt_payload(
      std::string_view(reinterpret_cast<const char*>(payload.value->data()),
                       payload.value->size()),
      limits);
  if (!claims || claims.value->sd_hash.size() != 43)
    return Result<HolderKbWitnessV1>::fail(ErrorCode::malformed,
                                           "invalid restricted KB-JWT claims");
  const std::string signing = compact.value->protected_header + "." +
                              compact.value->payload;
  if (!verify_es256_signature(*key.value, signing, *signature.value))
    return Result<HolderKbWitnessV1>::fail(ErrorCode::malformed,
                                           "holder ES256 verification failed");
  HolderKbWitnessV1 out{*compact.value, *key.value, *signature.value,
                        *claims.value, sha256_ascii(signing)};
  return Result<HolderKbWitnessV1>::ok(std::move(out));
}

bool FillHolderKbDenseWitnessV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderDenseLayoutV1& layout,
    const HolderKbPublicInputsV1& public_inputs,
    const HolderKbWitnessV1& witness,
    const HolderKbBridgeWriterV1& bridge_writer) {
  constexpr std::size_t kSigningBlocks = 4;
  constexpr std::size_t kHeaderChars = 40;
  constexpr std::size_t kPayloadChars = 176;
  constexpr std::size_t kAudienceChars = 24;
  constexpr std::size_t kNonceChars = 14;
  if (inputs.n0_ != 1 || layout.ranges.size() != 3 ||
      layout.ranges[0].name != "kb-jwt" ||
      layout.ranges[1].name != "bridge-digest" ||
      layout.ranges[2].name != "bridge-mac-advice" ||
      layout.total_inputs != inputs.n1_ ||
      layout.ranges[0].first != layout.public_inputs ||
      public_inputs.audience.size() > kAudienceChars ||
      public_inputs.nonce.size() > kNonceChars ||
      witness.compact.protected_header.size() != kHeaderChars ||
      witness.compact.payload.size() != kPayloadChars ||
      witness.compact.signature.size() != 86 ||
      witness.claims.sd_hash.size() != 43 || !bridge_writer)
    return false;

  std::array<std::uint8_t, 10> time_min{};
  std::array<std::uint8_t, 10> time_max{};
  if (!decimal10(public_inputs.time_min, time_min) ||
      !decimal10(public_inputs.time_max, time_max) ||
      public_inputs.time_min > public_inputs.time_max ||
      witness.claims.audience != public_inputs.audience ||
      witness.claims.nonce != public_inputs.nonce ||
      witness.claims.issued_at < public_inputs.time_min ||
      witness.claims.issued_at > public_inputs.time_max)
    return false;

  const std::string signing = witness.compact.protected_header + "." +
                              witness.compact.payload;
  if (witness.signing_digest != sha256_ascii(signing)) return false;
  const auto header = base64url_decode(witness.compact.protected_header);
  const auto payload = base64url_decode(witness.compact.payload);
  const auto hash = base64url_decode(witness.claims.sd_hash);
  if (!header || !payload || !hash || header.value->size() != 30 ||
      payload.value->size() != 132 || hash.value->size() != 32)
    return false;

  std::array<std::uint8_t, 64 * kSigningBlocks> padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, kSigningBlocks> sha{};
  std::uint8_t blocks{};
  proofs::FlatSHA256Witness::transform_and_witness_message(
      signing.size(), reinterpret_cast<const std::uint8_t*>(signing.data()),
      kSigningBlocks, blocks, padded.data(), sha.data());
  if (blocks != kSigningBlocks) return false;

  const auto holder_x = proofs::p256_base.to_montgomery(to_nat(witness.holder_key.x));
  const auto holder_y = proofs::p256_base.to_montgomery(to_nat(witness.holder_key.y));
  const auto digest_nat = to_nat(witness.signing_digest);
  proofs::VerifyWitness3<proofs::P256, proofs::Fp256Scalar> ecdsa(
      proofs::p256_scalar, proofs::p256);
  if (!ecdsa.compute_witness(holder_x, holder_y, digest_nat,
                             to_nat(witness.signature.r),
                             to_nat(witness.signature.s)))
    return false;

  proofs::DenseFiller<HolderKbFieldV1> filler(inputs);
  filler.push_back(proofs::p256_base.one());
  for (const auto& tag : public_inputs.bridge_tags)
    proofs::fill_gf2k<proofs::GF2_128<>, HolderKbFieldV1>(
        tag, filler, proofs::p256_base);
  proofs::fill_gf2k<proofs::GF2_128<>, HolderKbFieldV1>(
      public_inputs.bridge_challenge, filler, proofs::p256_base);
  for (std::size_t i = 0; i < kAudienceChars; ++i)
    fill_v8(filler, i < public_inputs.audience.size()
                        ? static_cast<std::uint8_t>(public_inputs.audience[i])
                        : 0);
  fill_v8(filler, static_cast<std::uint8_t>(public_inputs.audience.size()));
  for (std::size_t i = 0; i < kNonceChars; ++i)
    fill_v8(filler, i < public_inputs.nonce.size()
                        ? static_cast<std::uint8_t>(public_inputs.nonce[i])
                        : 0);
  fill_v8(filler, static_cast<std::uint8_t>(public_inputs.nonce.size()));
  for (const auto byte : time_min) fill_v8(filler, byte);
  for (const auto byte : time_max) fill_v8(filler, byte);
  if (filler.size() != layout.public_inputs) return false;

  for (const auto byte : padded) fill_v8(filler, byte);
  proofs::BitPluckerEncoder<HolderKbFieldV1, 4> encoder(proofs::p256_base);
  for (const auto& block : sha) {
    for (std::size_t i = 0; i < 48; ++i)
      filler.push_back(encoder.mkpacked_v32(block.outw[i]));
    for (std::size_t i = 0; i < 64; ++i) {
      filler.push_back(encoder.mkpacked_v32(block.oute[i]));
      filler.push_back(encoder.mkpacked_v32(block.outa[i]));
    }
    for (std::size_t i = 0; i < 8; ++i)
      filler.push_back(encoder.mkpacked_v32(block.h1[i]));
  }
  for (std::size_t i = 0; i < 256; ++i)
    filler.push_back(proofs::p256_base.of_scalar(digest_nat.bit(i)));
  for (const char byte : witness.compact.protected_header)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  for (const auto byte : *header.value) fill_v8(filler, byte);
  for (const char byte : witness.compact.payload)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  for (const char byte : witness.compact.signature)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  for (const auto byte : *payload.value) fill_v8(filler, byte);
  fill_v8(filler,
          static_cast<std::uint8_t>(witness.compact.protected_header.size()));
  fill_v8(filler, static_cast<std::uint8_t>(witness.compact.payload.size()));
  filler.push_back(holder_x);
  filler.push_back(holder_y);
  filler.push_back(proofs::p256_base.to_montgomery(to_nat(witness.signature.r)));
  filler.push_back(proofs::p256_base.to_montgomery(to_nat(witness.signature.s)));
  filler.push_back(proofs::p256_base.to_montgomery(digest_nat));
  ecdsa.fill_witness(filler);
  for (const char byte : witness.claims.sd_hash)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  if (filler.size() != layout.ranges[1].first) return false;

  HolderKbBridgeValuesV1 bridge{};
  bridge.fields[0] = holder_x;
  bridge.fields[1] = holder_y;
  std::copy(hash.value->begin(), hash.value->end(), bridge.messages[2].begin());
  bridge.fields[2] = holder_bridge_digest_field_v1(bridge.messages[2]);
  for (std::size_t i = 0; i < 2; ++i)
    proofs::p256_base.to_bytes_field(bridge.messages[i].data(), bridge.fields[i]);
  proofs::p256_base.to_bytes_field(bridge.messages[2].data(), bridge.fields[2]);
  filler.push_back(bridge.fields[2]);
  if (filler.size() != layout.ranges[2].first) return false;
  return bridge_writer(filler, bridge) && filler.size() == layout.total_inputs;
}

bool FillHolderKbPublicInputsV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderKbPublicInputsV1& public_inputs) {
  constexpr std::size_t kAudienceChars = 24;
  constexpr std::size_t kNonceChars = 14;
  std::array<std::uint8_t, 10> time_min{};
  std::array<std::uint8_t, 10> time_max{};
  if (inputs.n0_ != 1 || public_inputs.audience.size() > kAudienceChars ||
      public_inputs.nonce.size() > kNonceChars ||
      !decimal10(public_inputs.time_min, time_min) ||
      !decimal10(public_inputs.time_max, time_max) ||
      public_inputs.time_min > public_inputs.time_max)
    return false;
  proofs::DenseFiller<HolderKbFieldV1> filler(inputs);
  filler.push_back(proofs::p256_base.one());
  for (const auto& tag : public_inputs.bridge_tags)
    proofs::fill_gf2k<proofs::GF2_128<>, HolderKbFieldV1>(
        tag, filler, proofs::p256_base);
  proofs::fill_gf2k<proofs::GF2_128<>, HolderKbFieldV1>(
      public_inputs.bridge_challenge, filler, proofs::p256_base);
  for (std::size_t i = 0; i < kAudienceChars; ++i)
    fill_v8(filler, i < public_inputs.audience.size()
                        ? static_cast<std::uint8_t>(public_inputs.audience[i])
                        : 0);
  fill_v8(filler, static_cast<std::uint8_t>(public_inputs.audience.size()));
  for (std::size_t i = 0; i < kNonceChars; ++i)
    fill_v8(filler, i < public_inputs.nonce.size()
                        ? static_cast<std::uint8_t>(public_inputs.nonce[i])
                        : 0);
  fill_v8(filler, static_cast<std::uint8_t>(public_inputs.nonce.size()));
  for (const auto byte : time_min) fill_v8(filler, byte);
  for (const auto byte : time_max) fill_v8(filler, byte);
  return filler.size() == inputs.n1_;
}

}  // namespace sd_jwt_zk
