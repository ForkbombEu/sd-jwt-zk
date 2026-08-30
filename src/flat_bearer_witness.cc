#include "sd_jwt_zk/flat_bearer_proof.h"

#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace sd_jwt_zk {
namespace {
proofs::Fp256Nat to_nat(const std::array<std::uint8_t, 32>& bytes) {
  std::array<std::uint8_t, 32> little{};
  for (std::size_t i = 0; i < little.size(); ++i)
    little[i] = bytes[little.size() - 1 - i];
  return proofs::Fp256Nat::of_bytes(little.data());
}

void fill_v8(proofs::DenseFiller<FlatBearerField>& filler,
             std::uint8_t value) {
  filler.push_back(value, 8, proofs::p256_base);
}

struct DisclosureShape {
  std::uint8_t salt;
  std::uint8_t name;
  std::uint8_t value;
  std::uint8_t total;
};

std::optional<DisclosureShape> disclosure_shape(const Bytes& decoded) {
  const std::string json(decoded.begin(), decoded.end());
  if (json.size() > 255 || !json.starts_with("[\"") ||
      !json.ends_with("\"]"))
    return std::nullopt;
  const auto first = json.find("\",\"", 2);
  if (first == std::string::npos) return std::nullopt;
  const auto second = json.find("\",\"", first + 3);
  if (second == std::string::npos ||
      json.find("\",\"", second + 3) != std::string::npos)
    return std::nullopt;
  const auto salt = first - 2;
  const auto name = second - (first + 3);
  const auto value = json.size() - (second + 3) - 2;
  if (salt == 0 || salt > 9 || name == 0 || name > 8 || value == 0 ||
      value > 4)
    return std::nullopt;
  return DisclosureShape{static_cast<std::uint8_t>(salt),
                         static_cast<std::uint8_t>(name),
                         static_cast<std::uint8_t>(value),
                         static_cast<std::uint8_t>(json.size())};
}

bool verify_es256(const P256Key& key, std::string_view input,
                  const P256Signature& signature) {
  std::array<unsigned char, 65> encoded_key{4};
  std::copy(key.x.begin(), key.x.end(), encoded_key.begin() + 1);
  std::copy(key.y.begin(), key.y.end(), encoded_key.begin() + 33);
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                       const_cast<char*>("prime256v1"), 0),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                        encoded_key.data(), encoded_key.size()),
      OSSL_PARAM_construct_end()};
  EVP_PKEY_CTX* key_context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* pkey = nullptr;
  bool ok = key_context && EVP_PKEY_fromdata_init(key_context) == 1 &&
            EVP_PKEY_fromdata(key_context, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1;
  EVP_MD_CTX* context = ok ? EVP_MD_CTX_new() : nullptr;
  ECDSA_SIG* sig = ok && context ? ECDSA_SIG_new() : nullptr;
  BIGNUM* r = sig ? BN_bin2bn(signature.r.data(), signature.r.size(), nullptr) : nullptr;
  BIGNUM* s = sig ? BN_bin2bn(signature.s.data(), signature.s.size(), nullptr) : nullptr;
  const bool signature_owns = r && s && ECDSA_SIG_set0(sig, r, s) == 1;
  ok = signature_owns;
  if (ok) {
    const int der_size = i2d_ECDSA_SIG(sig, nullptr);
    Bytes der(static_cast<std::size_t>(der_size));
    unsigned char* at = der.data();
    i2d_ECDSA_SIG(sig, &at);
    ok = EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
         EVP_DigestVerify(context, der.data(), der.size(),
                          reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1;
  }
  if (!signature_owns) { BN_free(r); BN_free(s); }
  ECDSA_SIG_free(sig); EVP_MD_CTX_free(context); EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(key_context);
  return ok;
}
}  // namespace

Result<FlatBearerWitness> flat_bearer_witness_from_presentation(
    std::string_view presentation, const P256Key& issuer_key, const Limits& limits) {
  auto parsed = build_native_witness(presentation, limits);
  if (!parsed || parsed.value->kb_jwt || parsed.value->disclosures.empty())
    return Result<FlatBearerWitness>::fail(ErrorCode::malformed, "not a bounded bearer presentation");
  const auto& issuer = parsed.value->issuer;
  auto payload_bytes = base64url_decode(issuer.payload, limits.max_field);
  auto signature = decode_es256_signature(issuer.signature);
  if (!payload_bytes || !signature || !es256_signature_is_low_s(*signature.value))
    return Result<FlatBearerWitness>::fail(ErrorCode::malformed, "invalid issuer signature encoding");
  std::string payload(payload_bytes.value->begin(), payload_bytes.value->end());
  auto restricted = parse_restricted_issuer_payload(payload, limits);
  if (!restricted) return Result<FlatBearerWitness>::fail(restricted.error->code, restricted.error->message);
  std::string signing = issuer.protected_header + "." + issuer.payload;
  if (!verify_es256(issuer_key, signing, *signature.value))
    return Result<FlatBearerWitness>::fail(ErrorCode::malformed, "issuer ES256 verification failed");
  FlatBearerWitness out{issuer, issuer_key, *signature.value,
                        Bytes(signing.begin(), signing.end()), sha256_ascii(signing),
                        parsed.value->disclosures, {}, *restricted.value};
  for (const auto& disclosure : out.disclosures) {
    auto digest = sha256_ascii(disclosure);
    if (base64url_encode(Bytes(digest.begin(), digest.end())) != out.payload.digest)
      return Result<FlatBearerWitness>::fail(ErrorCode::malformed, "disclosure is not bound by _sd");
    out.disclosure_digests.push_back(digest);
  }
  return Result<FlatBearerWitness>::ok(std::move(out));
}

bool FillFlatBearerPublicInputsV1(
    proofs::Dense<FlatBearerField>& inputs,
    const std::array<std::uint8_t, 32>& public_statement,
    bool policy_result,
    const P256Key& issuer_key, bool status_required,
    std::uint64_t status_credential_id) {
  if (inputs.n0_ != 1 || inputs.n1_ != kFlatBearerPublicInputsV1)
    return false;
  proofs::DenseFiller<FlatBearerField> filler(inputs);
  filler.push_back(proofs::p256_base.one());
  for (const auto byte : public_statement)
    filler.push_back(proofs::p256_base.of_scalar(byte));
  filler.push_back(proofs::p256_base.of_scalar(policy_result));
  filler.push_back(
      proofs::p256_base.to_montgomery(to_nat(issuer_key.x)));
  filler.push_back(
      proofs::p256_base.to_montgomery(to_nat(issuer_key.y)));
  filler.push_back(proofs::p256_base.of_scalar(status_required));
  for (int shift = 56; shift >= 0; shift -= 8)
    fill_v8(filler, static_cast<std::uint8_t>(status_credential_id >> shift));
  return filler.size() == inputs.n1_;
}

bool FillFlatBearerDenseWitnessV1(
    proofs::Dense<FlatBearerField>& inputs,
    const std::array<std::uint8_t, 32>& public_statement,
    bool policy_result,
    const FlatBearerWitness& witness, bool status_required,
    std::uint64_t status_credential_id) {
  constexpr std::size_t kSigningBlocks = 5;
  constexpr std::size_t kHeaderChars = 102;
  constexpr std::size_t kPayloadChars = 140;
  constexpr std::size_t kPayloadDecoded = (kPayloadChars * 6) / 8;
  if (inputs.n0_ != 1 || inputs.n1_ != kFlatBearerDenseInputsV1 ||
      witness.issuer.protected_header.size() != kHeaderChars ||
      witness.issuer.payload.size() > kPayloadChars ||
      witness.signing_input.size() > 64 * kSigningBlocks ||
      witness.payload.issuer.size() > 255 || witness.payload.vct.empty() || witness.payload.vct.size() > 32 ||
      witness.disclosures.size() != 1 ||
      witness.disclosures.front().size() != 42 ||
      witness.payload.digest.size() != 43)
    return false;

  const std::string expected_signing = witness.issuer.protected_header + "." +
                                       witness.issuer.payload;
  if (witness.signing_input !=
          Bytes(expected_signing.begin(), expected_signing.end()) ||
      witness.signing_digest != sha256_ascii(expected_signing))
    return false;
  const auto decoded_header = base64url_decode(witness.issuer.protected_header);
  const auto decoded_payload = base64url_decode(witness.issuer.payload);
  if (!decoded_header || !decoded_payload || decoded_header.value->size() != 76 ||
      decoded_payload.value->size() > kPayloadDecoded ||
      decoded_payload.value->size() > 255)
    return false;
  const auto decoded_disclosure = base64url_decode(witness.disclosures.front());
  if (!decoded_disclosure) return false;
  const auto shape = disclosure_shape(*decoded_disclosure.value);
  if (!shape) return false;

  std::array<std::uint8_t, 64 * kSigningBlocks> padded_signing{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, kSigningBlocks>
      sha_advice{};
  std::uint8_t sha_block_count = 0;
  if (!make_compact_sha_advice(
          std::string_view(reinterpret_cast<const char*>(
                               witness.signing_input.data()),
                           witness.signing_input.size()),
          padded_signing, sha_advice, sha_block_count))
    return false;
  // Header 102 + separator + payload at most 140 always occupies four SHA
  // blocks after canonical SHA-256 padding.  Block five remains zero-padded
  // advice and is still fully constrained by the circuit.
  if (sha_block_count != 4) return false;

  std::array<std::uint8_t, 64> padded_disclosure{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 1> disclosure_advice{};
  std::uint8_t disclosure_block_count = 0;
  proofs::FlatSHA256Witness::transform_and_witness_message(
      witness.disclosures.front().size(),
      reinterpret_cast<const std::uint8_t*>(witness.disclosures.front().data()),
      1, disclosure_block_count, padded_disclosure.data(),
      disclosure_advice.data());
  if (disclosure_block_count != 1) return false;
  const auto disclosure_hash = sha256_ascii(witness.disclosures.front());
  const auto disclosure_digest_nat = to_nat(disclosure_hash);
  std::array<std::uint8_t, 64> registry_vct_padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 1> registry_vct_advice{};
  std::uint8_t registry_vct_blocks{};
  proofs::FlatSHA256Witness::transform_and_witness_message(
      witness.payload.vct.size(),
      reinterpret_cast<const std::uint8_t*>(witness.payload.vct.data()), 1,
      registry_vct_blocks, registry_vct_padded.data(), registry_vct_advice.data());
  if (registry_vct_blocks != 1) return false;
  const auto registry_vct_nat = to_nat(sha256_ascii(witness.payload.vct));

  const auto digest_nat = to_nat(witness.signing_digest);
  const auto r_nat = to_nat(witness.issuer_signature.r);
  const auto s_nat = to_nat(witness.issuer_signature.s);
  const auto public_x =
      proofs::p256_base.to_montgomery(to_nat(witness.issuer_key.x));
  const auto public_y =
      proofs::p256_base.to_montgomery(to_nat(witness.issuer_key.y));
  const auto digest = proofs::p256_base.to_montgomery(digest_nat);
  proofs::VerifyWitness3<proofs::P256, proofs::Fp256Scalar> ecdsa(
      proofs::p256_scalar, proofs::p256);
  if (!ecdsa.compute_witness(public_x, public_y, digest_nat, r_nat, s_nat))
    return false;

  proofs::DenseFiller<FlatBearerField> filler(inputs);
  filler.push_back(proofs::p256_base.one());
  // Public statement followed by the equality-bound private statement copy.
  for (const auto byte : public_statement)
    filler.push_back(proofs::p256_base.of_scalar(byte));
  filler.push_back(proofs::p256_base.of_scalar(policy_result));
  filler.push_back(public_x);
  filler.push_back(public_y);
  filler.push_back(proofs::p256_base.of_scalar(status_required));
  for (int shift = 56; shift >= 0; shift -= 8)
    fill_v8(filler, static_cast<std::uint8_t>(status_credential_id >> shift));
  const auto registry_x_nat = to_nat(witness.issuer_key.x);
  const auto registry_y_nat = to_nat(witness.issuer_key.y);
  for (std::size_t bit = 0; bit < 256; ++bit)
    filler.push_back(proofs::p256_base.of_scalar(registry_x_nat.bit(bit)));
  for (std::size_t bit = 0; bit < 256; ++bit)
    filler.push_back(proofs::p256_base.of_scalar(registry_y_nat.bit(bit)));
  for (const auto byte : public_statement)
    filler.push_back(proofs::p256_base.of_scalar(byte));
  for (const auto byte : padded_signing) fill_v8(filler, byte);

  proofs::BitPluckerEncoder<FlatBearerField, 4> encoder(proofs::p256_base);
  for (const auto& block : sha_advice) {
    for (std::size_t word = 0; word < 48; ++word)
      filler.push_back(encoder.mkpacked_v32(block.outw[word]));
    for (std::size_t word = 0; word < 64; ++word) {
      filler.push_back(encoder.mkpacked_v32(block.oute[word]));
      filler.push_back(encoder.mkpacked_v32(block.outa[word]));
    }
    for (std::size_t word = 0; word < 8; ++word)
      filler.push_back(encoder.mkpacked_v32(block.h1[word]));
  }
  for (std::size_t bit = 0; bit < 256; ++bit)
    filler.push_back(proofs::p256_base.of_scalar(digest_nat.bit(bit)));
  for (const auto byte : witness.issuer.protected_header)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  for (const auto byte : *decoded_header.value) fill_v8(filler, byte);
  for (std::size_t i = 0; i < kPayloadChars; ++i)
    fill_v8(filler, i < witness.issuer.payload.size()
                        ? static_cast<std::uint8_t>(witness.issuer.payload[i])
                        : 0);
  for (std::size_t i = 0; i < kPayloadDecoded; ++i)
    fill_v8(filler, i < decoded_payload.value->size()
                        ? (*decoded_payload.value)[i]
                        : 0);
  for (std::size_t i = 0; i < 256; ++i)
    fill_v8(filler, i < decoded_payload.value->size()
                        ? (*decoded_payload.value)[i]
                        : 0);
  fill_v8(filler,
          static_cast<std::uint8_t>(witness.issuer.protected_header.size()));
  fill_v8(filler, static_cast<std::uint8_t>(witness.issuer.payload.size()));
  fill_v8(filler, static_cast<std::uint8_t>(witness.payload.issuer.size()));
  fill_v8(filler, static_cast<std::uint8_t>(witness.payload.vct.size()));
  fill_v8(filler, static_cast<std::uint8_t>(decoded_payload.value->size()));
  filler.push_back(proofs::p256_base.of_scalar(witness.payload.explicit_sha256));
  filler.push_back(digest);
  ecdsa.fill_witness(filler);
  for (const auto byte : witness.disclosures.front())
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  for (const auto byte : padded_disclosure) fill_v8(filler, byte);
  for (std::size_t word = 0; word < 48; ++word)
    filler.push_back(
        encoder.mkpacked_v32(disclosure_advice[0].outw[word]));
  for (std::size_t word = 0; word < 64; ++word) {
    filler.push_back(
        encoder.mkpacked_v32(disclosure_advice[0].oute[word]));
    filler.push_back(
        encoder.mkpacked_v32(disclosure_advice[0].outa[word]));
  }
  for (std::size_t word = 0; word < 8; ++word)
    filler.push_back(
        encoder.mkpacked_v32(disclosure_advice[0].h1[word]));
  for (std::size_t bit = 0; bit < 256; ++bit)
    filler.push_back(
        proofs::p256_base.of_scalar(disclosure_digest_nat.bit(bit)));
  for (const auto byte : witness.payload.digest)
    fill_v8(filler, static_cast<std::uint8_t>(byte));
  fill_v8(filler, shape->salt);
  fill_v8(filler, shape->name);
  fill_v8(filler, shape->value);
  fill_v8(filler, shape->total);
  for (const auto byte : registry_vct_padded) fill_v8(filler, byte);
  for (std::size_t word = 0; word < 48; ++word)
    filler.push_back(encoder.mkpacked_v32(registry_vct_advice[0].outw[word]));
  for (std::size_t word = 0; word < 64; ++word) {
    filler.push_back(encoder.mkpacked_v32(registry_vct_advice[0].oute[word]));
    filler.push_back(encoder.mkpacked_v32(registry_vct_advice[0].outa[word]));
  }
  for (std::size_t word = 0; word < 8; ++word)
    filler.push_back(encoder.mkpacked_v32(registry_vct_advice[0].h1[word]));
  for (std::size_t bit = 0; bit < 256; ++bit)
    filler.push_back(proofs::p256_base.of_scalar(registry_vct_nat.bit(bit)));
  return filler.size() == inputs.n1_;
}
}  // namespace sd_jwt_zk
