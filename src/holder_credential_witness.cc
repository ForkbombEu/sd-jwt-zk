#include "sd_jwt_zk/holder_credential_witness.h"

#include <algorithm>
#include <array>

#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/mac/mac_reference.h"
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

struct DisclosureShape {
  std::uint8_t salt{};
  std::uint8_t name{};
  std::uint8_t value{};
  std::uint8_t total{};
};

std::optional<DisclosureShape> disclosure_shape(const Bytes& decoded) {
  const std::string json(decoded.begin(), decoded.end());
  if (!json.starts_with("[\"") || !json.ends_with("\"]")) return std::nullopt;
  const auto first = json.find("\",\"", 2);
  const auto second = first == std::string::npos
                          ? std::string::npos
                          : json.find("\",\"", first + 3);
  if (first == std::string::npos || second == std::string::npos) return std::nullopt;
  const auto salt = first - 2;
  const auto name = second - first - 3;
  const auto value = json.size() - second - 5;
  if (salt > 9 || name > 8 || value > 4 || json.size() > 255) return std::nullopt;
  return DisclosureShape{static_cast<std::uint8_t>(salt),
                         static_cast<std::uint8_t>(name),
                         static_cast<std::uint8_t>(value),
                         static_cast<std::uint8_t>(json.size())};
}

}  // namespace

Result<HolderCredentialWitnessV1> holder_credential_witness_from_presentation_v1(
    std::string_view presentation, const P256Key& issuer_key,
    const Limits& limits) {
  const auto parsed = build_native_witness(presentation, limits);
  if (!parsed || parsed.value->kb_jwt || parsed.value->disclosures.size() != 1)
    return Result<HolderCredentialWitnessV1>::fail(
        ErrorCode::malformed, "not a bounded holder credential presentation");
  const auto payload_bytes = base64url_decode(parsed.value->issuer.payload,
                                               limits.max_field);
  const auto signature = decode_es256_signature(parsed.value->issuer.signature);
  if (!payload_bytes || !signature)
    return Result<HolderCredentialWitnessV1>::fail(
        ErrorCode::malformed, "invalid holder issuer encoding");
  const auto payload = parse_restricted_issuer_payload(
      std::string_view(reinterpret_cast<const char*>(payload_bytes.value->data()),
                       payload_bytes.value->size()),
      limits);
  if (!payload || !payload.value->holder_key)
    return Result<HolderCredentialWitnessV1>::fail(
        ErrorCode::malformed, "not a bounded holder credential presentation");
  const auto& issuer = parsed.value->issuer;
  const std::string signing = issuer.protected_header + "." + issuer.payload;
  if (!verify_es256_signature(issuer_key, signing, *signature.value))
    return Result<HolderCredentialWitnessV1>::fail(
        ErrorCode::malformed, "holder issuer ES256 verification failed");
  FlatBearerWitness credential{
      issuer, issuer_key, *signature.value, Bytes(signing.begin(), signing.end()),
      sha256_ascii(signing), parsed.value->disclosures, {}, *payload.value};
  for (const auto& item : credential.disclosures) {
    const auto digest = sha256_ascii(item);
    if (base64url_encode(Bytes(digest.begin(), digest.end())) !=
        credential.payload.digest)
      return Result<HolderCredentialWitnessV1>::fail(
          ErrorCode::malformed, "holder disclosure is not issuer-bound");
    credential.disclosure_digests.push_back(digest);
  }
  const std::string compact = issuer.protected_header + "." + issuer.payload +
                              "." + issuer.signature;
  const std::string expected = compact + "~" +
                               credential.disclosures.front() + "~";
  if (expected != presentation)
    return Result<HolderCredentialWitnessV1>::fail(
        ErrorCode::noncanonical, "holder presentation is not canonical");
  HolderCredentialWitnessV1 out{std::move(credential), compact,
                                sha256_ascii(presentation)};
  return Result<HolderCredentialWitnessV1>::ok(std::move(out));
}

bool FillHolderCredentialDenseWitnessV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderDenseLayoutV1& layout,
    const HolderCredentialPublicInputsV1& public_inputs,
    const HolderCredentialWitnessV1& witness,
    const HolderKbBridgeWriterV1& bridge_writer) {
  constexpr std::size_t kSigningBlocks = 7;
  constexpr std::size_t kHeaderChars = 102;
  constexpr std::size_t kPayloadChars = 472;
  constexpr std::size_t kPayloadDecoded = 354;
  constexpr std::size_t kPayloadPadded = 384;
  constexpr std::size_t kCompactChars = 662;
  constexpr std::size_t kDisclosureChars = 42;
  constexpr std::size_t kPresentationBlocks = 9;
  if (inputs.n0_ != 1 || layout.ranges.size() != 3 ||
      layout.ranges[0].name != "issuer-cnf-and-signature" ||
      layout.ranges[1].name != "active-presentation" ||
      layout.ranges[2].name != "bridge-mac" ||
      layout.total_inputs != inputs.n1_ ||
      witness.credential.issuer.protected_header.size() != kHeaderChars ||
      witness.credential.issuer.payload.size() > kPayloadChars ||
      witness.credential.payload.vct.empty() || witness.credential.payload.vct.size() > 32 ||
      witness.credential.issuer.signature.size() != 86 ||
      witness.compact_issuer.size() > kCompactChars ||
      witness.credential.disclosures.size() != 1 ||
      witness.credential.disclosures.front().size() != kDisclosureChars ||
      !witness.credential.payload.holder_key || !bridge_writer)
    return false;

  const auto header = base64url_decode(
      witness.credential.issuer.protected_header);
  const auto payload = base64url_decode(witness.credential.issuer.payload);
  const auto disclosure = base64url_decode(
      witness.credential.disclosures.front());
  if (!header || !payload || !disclosure || header.value->size() != 76 ||
      payload.value->size() > kPayloadDecoded)
    return false;
  const auto shape = disclosure_shape(*disclosure.value);
  if (!shape) return false;

  std::array<std::uint8_t, 64 * kSigningBlocks> signing_padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, kSigningBlocks>
      signing_sha{};
  std::uint8_t signing_blocks{};
  proofs::FlatSHA256Witness::transform_and_witness_message(
      witness.credential.signing_input.size(),
      witness.credential.signing_input.data(), kSigningBlocks, signing_blocks,
      signing_padded.data(), signing_sha.data());
  if (signing_blocks != kSigningBlocks) return false;

  std::array<std::uint8_t, 64> disclosure_padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 1> disclosure_sha{};
  std::uint8_t disclosure_blocks{};
  proofs::FlatSHA256Witness::transform_and_witness_message(
      kDisclosureChars,
      reinterpret_cast<const std::uint8_t*>(
          witness.credential.disclosures.front().data()),
      1, disclosure_blocks, disclosure_padded.data(), disclosure_sha.data());
  if (disclosure_blocks != 1) return false;

  const std::string presentation = witness.compact_issuer + "~" +
      witness.credential.disclosures.front() + "~";
  if (sha256_ascii(presentation) != witness.presentation_digest) return false;
  std::array<std::uint8_t, 64 * kPresentationBlocks> presentation_padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, kPresentationBlocks>
      presentation_sha{};
  std::uint8_t presentation_blocks{};
  proofs::FlatSHA256Witness::transform_and_witness_message(
      presentation.size(),
      reinterpret_cast<const std::uint8_t*>(presentation.data()),
      kPresentationBlocks, presentation_blocks, presentation_padded.data(),
      presentation_sha.data());
  if (presentation_blocks == 0 || presentation_blocks > kPresentationBlocks)
    return false;

  const auto digest_nat = to_nat(witness.credential.signing_digest);
  const auto disclosure_nat =
      to_nat(witness.credential.disclosure_digests.front());
  const auto presentation_nat = to_nat(witness.presentation_digest);
  const auto issuer_x = proofs::p256_base.to_montgomery(
      to_nat(witness.credential.issuer_key.x));
  const auto issuer_y = proofs::p256_base.to_montgomery(
      to_nat(witness.credential.issuer_key.y));
  const auto holder_x = proofs::p256_base.to_montgomery(
      to_nat(witness.credential.payload.holder_key->x));
  const auto holder_y = proofs::p256_base.to_montgomery(
      to_nat(witness.credential.payload.holder_key->y));
  proofs::VerifyWitness3<proofs::P256, proofs::Fp256Scalar> ecdsa(
      proofs::p256_scalar, proofs::p256);
  if (!ecdsa.compute_witness(issuer_x, issuer_y, digest_nat,
                             to_nat(witness.credential.issuer_signature.r),
                             to_nat(witness.credential.issuer_signature.s)))
    return false;

  proofs::DenseFiller<HolderKbFieldV1> filler(inputs);
  filler.push_back(proofs::p256_base.one());
  for (const auto& tag : public_inputs.bridge_tags)
    proofs::fill_gf2k<proofs::GF2_128<>, HolderKbFieldV1>(
        tag, filler, proofs::p256_base);
  proofs::fill_gf2k<proofs::GF2_128<>, HolderKbFieldV1>(
      public_inputs.bridge_challenge, filler, proofs::p256_base);
  filler.push_back(proofs::p256_base.of_scalar(public_inputs.policy_result));
  filler.push_back(proofs::p256_base.of_scalar(public_inputs.status_required));
  for (int shift = 56; shift >= 0; shift -= 8)
    fill_v8(filler, static_cast<std::uint8_t>(
                        public_inputs.status_credential_id >> shift));
  filler.push_back(issuer_x);
  filler.push_back(issuer_y);
  if (filler.size() != layout.public_inputs) return false;

  for (const auto byte : signing_padded) fill_v8(filler, byte);
  proofs::BitPluckerEncoder<HolderKbFieldV1, 4> encoder(proofs::p256_base);
  auto fill_sha = [&](const auto& blocks) {
    for (const auto& block : blocks) {
      for (std::size_t i = 0; i < 48; ++i)
        filler.push_back(encoder.mkpacked_v32(block.outw[i]));
      for (std::size_t i = 0; i < 64; ++i) {
        filler.push_back(encoder.mkpacked_v32(block.oute[i]));
        filler.push_back(encoder.mkpacked_v32(block.outa[i]));
      }
      for (std::size_t i = 0; i < 8; ++i)
        filler.push_back(encoder.mkpacked_v32(block.h1[i]));
    }
  };
  fill_sha(signing_sha);
  for (std::size_t i = 0; i < 256; ++i)
    filler.push_back(proofs::p256_base.of_scalar(digest_nat.bit(i)));
  for (const char byte : witness.credential.issuer.protected_header)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  for (const auto byte : *header.value) fill_v8(filler, byte);
  for (std::size_t i = 0; i < kPayloadChars; ++i)
    fill_v8(filler, i < witness.credential.issuer.payload.size()
                        ? static_cast<std::uint8_t>(
                              witness.credential.issuer.payload[i])
                        : 0);
  for (std::size_t i = 0; i < kPayloadDecoded; ++i)
    fill_v8(filler, i < payload.value->size() ? (*payload.value)[i] : 0);
  for (std::size_t i = 0; i < kPayloadPadded; ++i)
    fill_v8(filler, i < payload.value->size() ? (*payload.value)[i] : 0);
  filler.push_back(witness.credential.issuer.protected_header.size(), 9,
                   proofs::p256_base);
  filler.push_back(witness.credential.issuer.payload.size(), 9,
                   proofs::p256_base);
  filler.push_back(witness.credential.payload.issuer.size(), 9,
                   proofs::p256_base);
  filler.push_back(witness.credential.payload.vct.size(), 9,
                   proofs::p256_base);
  filler.push_back(payload.value->size(), 9, proofs::p256_base);
  filler.push_back(proofs::p256_base.of_scalar(
      witness.credential.payload.explicit_sha256));
  filler.push_back(proofs::p256_base.to_montgomery(digest_nat));
  ecdsa.fill_witness(filler);
  for (const char byte : witness.credential.issuer.signature)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  filler.push_back(proofs::p256_base.to_montgomery(
      to_nat(witness.credential.issuer_signature.r)));
  filler.push_back(proofs::p256_base.to_montgomery(
      to_nat(witness.credential.issuer_signature.s)));
  filler.push_back(holder_x);
  filler.push_back(holder_y);
  if (filler.size() != layout.ranges[1].first) return false;

  for (std::size_t i = 0; i < kCompactChars; ++i)
    fill_v8(filler, i < witness.compact_issuer.size()
                        ? static_cast<std::uint8_t>(witness.compact_issuer[i])
                        : 0);
  filler.push_back(witness.compact_issuer.size(), 10, proofs::p256_base);
  for (const char byte : witness.credential.disclosures.front())
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  for (const auto byte : disclosure_padded) fill_v8(filler, byte);
  fill_sha(disclosure_sha);
  for (std::size_t i = 0; i < 256; ++i)
    filler.push_back(proofs::p256_base.of_scalar(disclosure_nat.bit(i)));
  for (const char byte : witness.credential.payload.digest)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  fill_v8(filler, shape->salt);
  fill_v8(filler, shape->name);
  fill_v8(filler, shape->value);
  fill_v8(filler, shape->total);
  for (const auto byte : presentation_padded) fill_v8(filler, byte);
  fill_sha(presentation_sha);
  for (std::size_t i = 0; i < 256; ++i)
    filler.push_back(proofs::p256_base.of_scalar(presentation_nat.bit(i)));
  const auto sd_hash = base64url_encode(
      Bytes(witness.presentation_digest.begin(), witness.presentation_digest.end()));
  if (sd_hash.size() != 43) return false;
  for (const char byte : sd_hash)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  if (filler.size() != layout.ranges[2].first) return false;

  HolderKbBridgeValuesV1 bridge{};
  bridge.fields = {holder_x, holder_y,
                   holder_bridge_digest_field_v1(witness.presentation_digest)};
  for (std::size_t i = 0; i < bridge.fields.size(); ++i)
    proofs::p256_base.to_bytes_field(bridge.messages[i].data(), bridge.fields[i]);
  filler.push_back(bridge.fields[2]);
  return bridge_writer(filler, bridge) && filler.size() == layout.total_inputs;
}

bool FillHolderCredentialPublicInputsV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderCredentialPublicInputsV1& public_inputs,
    const P256Key& issuer_key) {
  if (inputs.n0_ != 1) return false;
  proofs::DenseFiller<HolderKbFieldV1> filler(inputs);
  filler.push_back(proofs::p256_base.one());
  for (const auto& tag : public_inputs.bridge_tags)
    proofs::fill_gf2k<proofs::GF2_128<>, HolderKbFieldV1>(
        tag, filler, proofs::p256_base);
  proofs::fill_gf2k<proofs::GF2_128<>, HolderKbFieldV1>(
      public_inputs.bridge_challenge, filler, proofs::p256_base);
  filler.push_back(proofs::p256_base.of_scalar(public_inputs.policy_result));
  filler.push_back(proofs::p256_base.of_scalar(public_inputs.status_required));
  for (int shift = 56; shift >= 0; shift -= 8)
    fill_v8(filler, static_cast<std::uint8_t>(
                        public_inputs.status_credential_id >> shift));
  filler.push_back(proofs::p256_base.to_montgomery(to_nat(issuer_key.x)));
  filler.push_back(proofs::p256_base.to_montgomery(to_nat(issuer_key.y)));
  return filler.size() == inputs.n1_;
}

}  // namespace sd_jwt_zk
