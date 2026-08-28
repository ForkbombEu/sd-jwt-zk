#include "sd_jwt_zk/restricted_base64url_relation.h"
#include "sd_jwt_zk/flat_disclosure_relation.h"
#include "sd_jwt_zk/restricted_json_relation.h"
#include "sd_jwt_zk/holder_cnf_relation.h"
#include "sd_jwt_zk/kb_jwt_relation.h"
#include "sd_jwt_zk/presentation_hash_relation.h"
#include "sd_jwt_zk/compact_es256_signature_relation.h"
#include "sd_jwt_zk/api.h"

#include <array>
#include <string>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "ec/p256.h"

namespace {

using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;

bool active_b64_accepts(const char* text, std::size_t length, bool dirty_inactive = false) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  sd_jwt_zk::RestrictedBase64UrlRelation<Logic> relation(logic);
  std::array<Logic::v8, 4> input{};
  for (std::size_t i = 0; i < input.size(); ++i)
    input[i] = logic.template vbit<8>(i < length ? static_cast<unsigned char>(text[i]) : (dirty_inactive ? 'A' : 0));
  std::array<Logic::v8, 3> output{};
  const char expected[] = {'M', 'a', 'n'};
  for (std::size_t i = 0; i < output.size(); ++i) output[i] = logic.template vbit<8>(i < (length * 6) / 8 ? expected[i] : 0);
  Logic::bitvec<8> active{}; logic.bits(8, active.data(), length);
  relation.decode_active(input, output, active);
  return !backend.assertion_failed();
}

bool accepts_compact_es256_signature(bool splice) {
  constexpr char signature[] =
      "zC41XCiPUiMI38m0IrKCHoC0XmOW6I0N0Sx5QEUKKmTXNbvW0DxK_4zXPqai0K1-vi0MwVzUl835id3-znLG0w";
  auto parsed = sd_jwt_zk::decode_es256_signature(signature);
  if (!parsed) return false;
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, 86> encoded{};
  for (std::size_t i = 0; i < encoded.size(); ++i)
    encoded[i] = logic.template vbit<8>(
        static_cast<unsigned char>((splice && i == 7) ? 'A' : signature[i]));
  auto nat = [](const std::array<std::uint8_t, 32>& bytes) {
    std::array<std::uint8_t, 32> little{};
    for (std::size_t i = 0; i < little.size(); ++i) little[i] = bytes[31 - i];
    return proofs::Fp256Nat::of_bytes(little.data());
  };
  sd_jwt_zk::CompactEs256SignatureRelation<Logic>(logic).assert_decode(
      encoded, logic.konst(field.to_montgomery(nat(parsed.value->r))),
      logic.konst(field.to_montgomery(nat(parsed.value->s))));
  return !backend.assertion_failed();
}

bool accepts(std::string payload, std::size_t issuer_length, std::size_t vct_length,
             bool explicit_sha256, std::size_t active_length) {
  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  sd_jwt_zk::RestrictedBase64UrlRelation<Logic> base64(logic);
  sd_jwt_zk::RestrictedJsonRelation<Logic, 256, 8> json(logic);
  std::array<Logic::v8, 256> text{};
  for (std::size_t i = 0; i < text.size(); ++i)
    text[i] = logic.template vbit<8>(i < payload.size() ? static_cast<unsigned char>(payload[i]) : 0);
  Logic::bitvec<8> start{}, issuer{}, vct{}, length{};
  logic.bits(8, start.data(), 0);
  logic.bits(8, issuer.data(), issuer_length);
  logic.bits(8, vct.data(), vct_length);
  logic.bits(8, length.data(), active_length);
  json.assert_literal_at(text, start, "{\"_sd\":[\"", 9);
  for (std::size_t i = 0; i < 43; ++i) {
    Logic::bitvec<6> sextet{};
    base64.decode_char(text[9 + i], sextet);
  }
  json.assert_flat_payload(text, issuer, vct, logic.bit(explicit_sha256), length, 18, 13);
  return !backend.assertion_failed();
}

bool accepts_header(std::string header64) {
  constexpr char header_json[] =
      "{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\",\"profile_version\":\"swiss-profile-vc:1.0.0\"}";
  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  sd_jwt_zk::RestrictedBase64UrlRelation<Logic> base64(logic);
  std::array<Logic::v8, 102> encoded{};
  std::array<Logic::v8, 76> decoded{};
  for (std::size_t i = 0; i < encoded.size(); ++i)
    encoded[i] = logic.template vbit<8>(static_cast<unsigned char>(header64[i]));
  base64.decode(encoded, decoded);
  for (std::size_t i = 0; i < decoded.size(); ++i)
    logic.vassert_eq(decoded[i], static_cast<unsigned char>(header_json[i]));
  return !backend.assertion_failed();
}

// Keep this as an isolated regression for the full-width KB-JWT payload
// segment.  It uses the same active-length wire convention as
// IssuerJwsRelation::decode_payload_bucket, but has no JSON or signature
// constraints that could obscure a decoder failure.
bool accepts_kb_payload_active_decode(std::size_t active_length = 176) {
  constexpr char encoded[] =
      "eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUiLCJub25jZSI6ImNoYWxsZW5nZS0wMDAxIiwiaWF0IjoxNzc3MzM0NDAwLCJzZF9oYXNoIjoiRkY3THRhUGtZdXJzd2xob1ZBSk1vSnZTS0FXdjViMUYxQkswaDRQVVN6ayJ9";
  constexpr char decoded[] =
      "{\"aud\":\"https://verifier.example\",\"nonce\":\"challenge-0001\",\"iat\":1777334400,\"sd_hash\":\"FF7LtaPkYurswlhoVAJMoJvSKAWv5b1F1BK0h4PUSzk\"}";
  static_assert(sizeof(encoded) - 1 == 176);
  static_assert(sizeof(decoded) - 1 == 132);
  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  std::array<Logic::v8, 176> input{};
  std::array<Logic::v8, 132> output{};
  for (std::size_t i = 0; i < input.size(); ++i)
    input[i] = logic.template vbit<8>(static_cast<unsigned char>(encoded[i]));
  for (std::size_t i = 0; i < output.size(); ++i)
    output[i] = logic.template vbit<8>(static_cast<unsigned char>(decoded[i]));
  Logic::bitvec<8> active{};
  logic.bits(8, active.data(), active_length);
  sd_jwt_zk::RestrictedBase64UrlRelation<Logic>(logic).decode_active(
      input, output, active);
  return !backend.assertion_failed();
}

bool accepts_kb_payload_relation(bool mutate_audience = false,
                                 bool mutate_nonce = false,
                                 bool mutate_time = false,
                                 bool mutate_hash = false) {
  constexpr char json[] =
      "{\"aud\":\"https://verifier.example\",\"nonce\":\"challenge-0001\",\"iat\":1777334400,\"sd_hash\":\"FF7LtaPkYurswlhoVAJMoJvSKAWv5b1F1BK0h4PUSzk\"}";
  constexpr char audience[] = "https://verifier.example";
  constexpr char nonce[] = "challenge-0001";
  constexpr char minimum[] = "1777334300";
  constexpr char maximum[] = "1777334500";
  constexpr char hash[] = "FF7LtaPkYurswlhoVAJMoJvSKAWv5b1F1BK0h4PUSzk";
  static_assert(sizeof(json) - 1 == 132);
  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  std::array<Logic::v8, 132> payload{};
  std::array<Logic::v8, 24> audience_wire{};
  std::array<Logic::v8, 14> nonce_wire{};
  std::array<Logic::v8, 10> minimum_wire{}, maximum_wire{};
  std::array<Logic::v8, 43> hash_wire{};
  for (std::size_t i = 0; i < payload.size(); ++i) {
    char byte = json[i];
    if (mutate_audience && i == 8) byte = 'X';
    if (mutate_nonce && i == 43) byte = 'X';
    if (mutate_time && i == 65) byte = '9';
    if (mutate_hash && i == 87) byte = 'A';
    payload[i] = logic.template vbit<8>(static_cast<unsigned char>(byte));
  }
  for (std::size_t i = 0; i < audience_wire.size(); ++i)
    audience_wire[i] = logic.template vbit<8>(
        i < sizeof(audience) - 1 ? static_cast<unsigned char>(audience[i]) : 0);
  for (std::size_t i = 0; i < nonce_wire.size(); ++i)
    nonce_wire[i] = logic.template vbit<8>(
        i < sizeof(nonce) - 1 ? static_cast<unsigned char>(nonce[i]) : 0);
  for (std::size_t i = 0; i < minimum_wire.size(); ++i) {
    minimum_wire[i] = logic.template vbit<8>(minimum[i]);
    maximum_wire[i] = logic.template vbit<8>(maximum[i]);
  }
  for (std::size_t i = 0; i < hash_wire.size(); ++i)
    hash_wire[i] = logic.template vbit<8>(hash[i]);
  Logic::bitvec<8> audience_length{}, nonce_length{};
  logic.bits(8, audience_length.data(), sizeof(audience) - 1);
  logic.bits(8, nonce_length.data(), sizeof(nonce) - 1);
  sd_jwt_zk::RestrictedKbJwtRelation<Logic, 132, 24, 14>(logic).assert_payload(
      payload, audience_wire, audience_length, nonce_wire, nonce_length,
      minimum_wire, maximum_wire, hash_wire);
  return !backend.assertion_failed();
}

bool accepts_presentation_hash_relation(bool mutate_issuer = false,
                                       bool mutate_disclosure = false,
                                       bool mutate_tilde = false,
                                       bool mutate_hash = false) {
  constexpr char issuer[] =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ.eyJfc2QiOlsickxFZ2lmWmdPaGdVVUxiT0xlTVZrc1oyQVVJeDF6Z1NzT0pSenFMYWJuVSJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSIsIl9zZF9hbGciOiJzaGEtMjU2In0.RS6qxwyHcY1UIV7JU60XommQaDyhl1NTMyE-EESB6-ViM6WjVNJC56lUFwZLW82dtNMbySOKZBphd8jfRAICBQ";
  constexpr char disclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsdHJ1ZV0";
  constexpr char hash[] = "FF7LtaPkYurswlhoVAJMoJvSKAWv5b1F1BK0h4PUSzk";
  constexpr std::size_t kBlocks = 7;
  static_assert(sizeof(issuer) - 1 == 353);
  static_assert(sizeof(disclosure) - 1 == 39);
  const std::string presentation = std::string(issuer) + "~" + disclosure + "~";
  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  using Plucker = proofs::BitPlucker<Logic, 4>;
  using Sha = proofs::FlatSHA256Circuit<Logic, Plucker>;
  using Relation = sd_jwt_zk::PresentationHashRelation<Logic, kBlocks,
      sizeof(issuer) - 1, sizeof(disclosure) - 1>;
  std::array<std::uint8_t, 64 * kBlocks> padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, kBlocks> advice{};
  std::uint8_t block_count = 0;
  proofs::FlatSHA256Witness::transform_and_witness_message(
      presentation.size(), reinterpret_cast<const std::uint8_t*>(presentation.data()),
      kBlocks, block_count, padded.data(), advice.data());
  if (block_count != kBlocks) return false;
  std::array<Logic::v8, sizeof(issuer) - 1> issuer_wire{};
  std::array<Logic::v8, sizeof(disclosure) - 1> disclosure_wire{};
  std::array<Logic::v8, 64 * kBlocks> sha_input{};
  std::array<Logic::v8, 43> hash_wire{};
  for (std::size_t i = 0; i < issuer_wire.size(); ++i)
    issuer_wire[i] = logic.template vbit<8>(
        static_cast<unsigned char>((mutate_issuer && i == 0) ? 'X' : issuer[i]));
  for (std::size_t i = 0; i < disclosure_wire.size(); ++i)
    disclosure_wire[i] = logic.template vbit<8>(
        static_cast<unsigned char>((mutate_disclosure && i == 0) ? 'X' : disclosure[i]));
  for (std::size_t i = 0; i < sha_input.size(); ++i)
    sha_input[i] = logic.template vbit<8>(
        (mutate_tilde && i == sizeof(issuer) - 1) ? '.' : padded[i]);
  for (std::size_t i = 0; i < hash_wire.size(); ++i)
    hash_wire[i] = logic.template vbit<8>(
        static_cast<unsigned char>((mutate_hash && i == 0) ? 'A' : hash[i]));
  const auto digest = sd_jwt_zk::sha256_ascii(presentation);
  std::array<std::uint8_t, 32> little{};
  for (std::size_t i = 0; i < little.size(); ++i) little[i] = digest[little.size() - 1 - i];
  const auto digest_nat = proofs::Fp256Nat::of_bytes(little.data());
  Logic::v256 digest_bits{};
  for (std::size_t i = 0; i < digest_bits.size(); ++i)
    digest_bits[i] = logic.bit(digest_nat.bit(i));
  proofs::BitPluckerEncoder<Field, 4> encoder(proofs::p256_base);
  std::array<typename Sha::BlockWitness, kBlocks> witness{};
  for (std::size_t block = 0; block < kBlocks; ++block) {
    for (std::size_t word = 0; word < 48; ++word)
      witness[block].outw[word] = logic.konst(encoder.mkpacked_v32(advice[block].outw[word]));
    for (std::size_t word = 0; word < 64; ++word) {
      witness[block].oute[word] = logic.konst(encoder.mkpacked_v32(advice[block].oute[word]));
      witness[block].outa[word] = logic.konst(encoder.mkpacked_v32(advice[block].outa[word]));
    }
    for (std::size_t word = 0; word < 8; ++word)
      witness[block].h1[word] = logic.konst(encoder.mkpacked_v32(advice[block].h1[word]));
  }
  Relation(logic).assert_valid({issuer_wire, disclosure_wire, sha_input, witness,
                                digest_bits, hash_wire});
  return !backend.assertion_failed();
}

bool compiles_kb_jws_composition() {
  // This instantiates the complete KB relation's assertion path.  The
  // individual evaluation tests above exercise the decoded payload and
  // presentation hash mutations; issuer_relation_compile owns the expensive
  // ECDSA witness fixture machinery used by the production family.
  using Relation = sd_jwt_zk::KbJwsRelation<Logic, 4, 40, 176, 24, 14>;
  // Taking the member address forces the complete non-template assertion body
  // (SHA, active decoding, payload relation, and ECDSA verifier) through this
  // executable's compilation boundary.  The presentation-binding member is
  // independently evaluated by accepts_presentation_hash_relation above.
  auto valid = &Relation::assert_valid;
  (void)valid;
  static_assert(sizeof(Relation) >= sizeof(const Logic*));
  return true;
}

bool accepts_cnf_jwk(std::string jwk, const sd_jwt_zk::P256Key& key) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, sd_jwt_zk::HolderCnfRelation<Logic>::kJwkChars> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i)
    bytes[i] = logic.template vbit<8>(static_cast<unsigned char>(jwk[i]));
  auto to_nat = [](const std::array<std::uint8_t, 32>& source) {
    std::array<std::uint8_t, 32> little{};
    for (std::size_t i = 0; i < little.size(); ++i) little[i] = source[little.size() - 1 - i];
    return proofs::Fp256Nat::of_bytes(little.data());
  };
  sd_jwt_zk::HolderCnfRelation<Logic>(logic).assert_canonical_jwk(
      bytes, logic.konst(field.to_montgomery(to_nat(key.x))),
      logic.konst(field.to_montgomery(to_nat(key.y))));
  return !backend.assertion_failed();
}


std::string payload(std::string digest, std::string issuer, std::string vct, bool explicit_sha256) {
  return "{\"_sd\":[\"" + std::move(digest) + "\"],\"iss\":\"" + std::move(issuer) +
      "\",\"vct\":\"" + std::move(vct) + "\"" +
      (explicit_sha256 ? ",\"_sd_alg\":\"sha-256\"}" : "}");
}

}  // namespace

int main() {
  if (!accepts_compact_es256_signature(false) ||
      accepts_compact_es256_signature(true)) return 33;
  if (!active_b64_accepts("TWFu", 4) || !active_b64_accepts("TWE", 3) || !active_b64_accepts("TQ", 2)) return 25;
  if (active_b64_accepts("T", 1) || active_b64_accepts("TQ", 2, true) || active_b64_accepts("TR", 2) || active_b64_accepts("TWF", 3)) return 26;
  if (!accepts_kb_payload_active_decode() ||
      accepts_kb_payload_active_decode(132)) return 29;
  if (!accepts_kb_payload_relation() || accepts_kb_payload_relation(true) ||
      accepts_kb_payload_relation(false, true) ||
      accepts_kb_payload_relation(false, false, true) ||
      accepts_kb_payload_relation(false, false, false, true)) return 30;
  if (!accepts_presentation_hash_relation() ||
      accepts_presentation_hash_relation(true) ||
      accepts_presentation_hash_relation(false, true) ||
      accepts_presentation_hash_relation(false, false, true) ||
      accepts_presentation_hash_relation(false, false, false, true)) return 31;
  if (!compiles_kb_jws_composition()) return 32;
  std::string header = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
  if (!accepts_header(header)) return 10;
  auto bad_alg = header; bad_alg[10] = bad_alg[10] == 'A' ? 'B' : 'A';
  if (accepts_header(bad_alg)) return 11;
  auto bad_typ = header; bad_typ[30] = bad_typ[30] == 'A' ? 'B' : 'A';
  if (accepts_header(bad_typ)) return 12;
  auto bad_profile = header; bad_profile[75] = bad_profile[75] == 'A' ? 'B' : 'A';
  if (accepts_header(bad_profile)) return 13;
  auto bad_base64 = header; bad_base64[0] = '!';
  if (accepts_header(bad_base64)) return 14;
  constexpr char digest[] = "rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU";
  const auto omitted = payload(digest, "i", "v", false);
  const auto explicit_form = payload("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                                     "did:example:issuer", "different-vct", true);
  if (!accepts(omitted, 1, 1, false, omitted.size())) return 1;
  if (!accepts(explicit_form, 18, 13, true, explicit_form.size())) return 2;

  auto bad_delimiter = omitted; bad_delimiter[52] = ' ';
  if (accepts(bad_delimiter, 1, 1, false, bad_delimiter.size())) return 3;
  auto bad_digest = omitted; bad_digest[9] = '!';
  if (accepts(bad_digest, 1, 1, false, bad_digest.size())) return 4;
  auto escaped_issuer = omitted; escaped_issuer[62] = '\\';
  if (accepts(escaped_issuer, 1, 1, false, escaped_issuer.size())) return 5;
  auto trailing = omitted + "x";
  if (accepts(trailing, 1, 1, false, trailing.size())) return 6;
  if (accepts(omitted, 1, 1, true, omitted.size())) return 7;
  if (accepts(omitted, 2, 1, false, omitted.size())) return 8;
  {
    const std::array<std::uint8_t, 32> x{
        0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
        0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96};
    const std::array<std::uint8_t, 32> y{
        0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
        0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
    sd_jwt_zk::P256Key key{x, y};
    const auto bx = sd_jwt_zk::base64url_encode({x.begin(), x.end()});
    const auto by = sd_jwt_zk::base64url_encode({y.begin(), y.end()});
    const auto jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + bx +
                     "\",\"y\":\"" + by + "\"}";
    if (!accepts_cnf_jwk(jwk, key)) return 27;
    auto altered = jwk; altered[33] = altered[33] == 'A' ? 'B' : 'A';
    if (accepts_cnf_jwk(altered, key)) return 28;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<Logic::v8, 3> private_value{logic.template vbit<8>('v'), logic.template vbit<8>('a'), logic.template vbit<8>('l')};
    std::array<Logic::v8, 3> public_value = private_value;
    disclosure.assert_string_policy(private_value, public_value, logic.bit(1));
    disclosure.assert_reveal_policy(private_value, public_value);
    if (backend.assertion_failed()) return 9;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<Logic::v8, 3> private_value{logic.template vbit<8>('v'), logic.template vbit<8>('a'), logic.template vbit<8>('l')};
    std::array<Logic::v8, 3> operand{logic.template vbit<8>('b'), logic.template vbit<8>('a'), logic.template vbit<8>('l')};
    disclosure.assert_string_policy(private_value, operand, logic.bit(0));
    if (backend.assertion_failed()) return 15;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<Logic::v8, 3> private_value{logic.template vbit<8>('v'), logic.template vbit<8>('a'), logic.template vbit<8>('l')};
    disclosure.assert_string_policy(private_value, private_value, logic.bit(0));
    if (!backend.assertion_failed()) return 16;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<std::array<Logic::v8, 43>, 2> signed_slots{};
    std::array<std::array<Logic::v8, 43>, 1> presented_slots{};
    for (std::size_t i = 0; i < 43; ++i) {
      signed_slots[0][i] = logic.template vbit<8>('A');
      signed_slots[1][i] = logic.template vbit<8>('A');
      presented_slots[0][i] = logic.template vbit<8>('A');
    }
    Logic::bitvec<8> signed_active{}, presented_active{};
    logic.bits(8, signed_active.data(), 2); logic.bits(8, presented_active.data(), 1);
    disclosure.assert_unique_signed_matches(signed_slots, presented_slots, signed_active, presented_active);
    if (!backend.assertion_failed()) return 17;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<std::array<Logic::v8, 43>, 1> signed_slots{};
    std::array<std::array<Logic::v8, 43>, 2> presented_slots{};
    for (std::size_t i = 0; i < 43; ++i) {
      signed_slots[0][i] = logic.template vbit<8>('A');
      presented_slots[0][i] = logic.template vbit<8>('A');
      presented_slots[1][i] = logic.template vbit<8>('A');
    }
    Logic::bitvec<8> signed_active{}, presented_active{};
    logic.bits(8, signed_active.data(), 1); logic.bits(8, presented_active.data(), 2);
    disclosure.assert_unique_signed_matches(signed_slots, presented_slots, signed_active, presented_active);
    if (!backend.assertion_failed()) return 22;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<std::array<Logic::v8, 3>, 2> names{};
    for (std::size_t slot = 0; slot < names.size(); ++slot)
      for (std::size_t i = 0; i < 3; ++i) names[slot][i] = logic.template vbit<8>("age"[i]);
    Logic::bitvec<8> active{}; logic.bits(8, active.data(), 2);
    disclosure.assert_unique_presented_names(names, active);
    if (!backend.assertion_failed()) return 18;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<Logic::v8, 4> slot{logic.template vbit<8>('s'), logic.template vbit<8>('a'), logic.template vbit<8>(0), logic.template vbit<8>(0)};
    Logic::bitvec<8> active{}; logic.bits(8, active.data(), 2);
    disclosure.assert_active_string(slot, active);
    if (backend.assertion_failed()) return 19;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<Logic::v8, 4> slot{logic.template vbit<8>('s'), logic.template vbit<8>('a'), logic.template vbit<8>('x'), logic.template vbit<8>(0)};
    Logic::bitvec<8> active{}; logic.bits(8, active.data(), 2);
    disclosure.assert_active_string(slot, active);
    if (!backend.assertion_failed()) return 20;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<Logic::v8, 32> json{};
    constexpr char text[] = "[\"salt\",\"name\",\"value\"]";
    for (std::size_t i = 0; i < json.size(); ++i) json[i] = logic.template vbit<8>(i < sizeof(text) - 1 ? text[i] : 0);
    Logic::bitvec<8> salt{}, name{}, value{}, total{};
    logic.bits(8, salt.data(), 4); logic.bits(8, name.data(), 4); logic.bits(8, value.data(), 5); logic.bits(8, total.data(), sizeof(text) - 1);
    disclosure.assert_three_string_active_grammar(json, salt, name, value, total, 4, 4, 5);
    if (backend.assertion_failed()) return 21;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<Logic::v8, 32> json{};
    constexpr char text[] = "[\"salt\",\"_sd\",\"value\"]";
    for (std::size_t i = 0; i < json.size(); ++i)
      json[i] = logic.template vbit<8>(i < sizeof(text) - 1 ? text[i] : 0);
    Logic::bitvec<8> salt{}, name{}, value{}, total{};
    logic.bits(8, salt.data(), 4); logic.bits(8, name.data(), 3);
    logic.bits(8, value.data(), 5); logic.bits(8, total.data(), sizeof(text) - 1);
    disclosure.assert_three_string_active_grammar(json, salt, name, value, total, 4, 4, 5);
    if (!backend.assertion_failed()) return 23;
  }
  {
    const Field field;
    Backend backend(field, false);
    Logic logic(&backend, field);
    sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 4> disclosure(logic);
    std::array<Logic::v8, 32> json{};
    constexpr char text[] = "[\"salt\",\"name\",\"value\"]";
    for (std::size_t i = 0; i < json.size(); ++i)
      json[i] = logic.template vbit<8>(i < sizeof(text) - 1 ? text[i] : 0);
    json[2] = logic.template vbit<8>(0x1f);
    Logic::bitvec<8> salt{}, name{}, value{}, total{};
    logic.bits(8, salt.data(), 4); logic.bits(8, name.data(), 4);
    logic.bits(8, value.data(), 5); logic.bits(8, total.data(), sizeof(text) - 1);
    disclosure.assert_three_string_active_grammar(json, salt, name, value, total, 4, 4, 5);
    if (!backend.assertion_failed()) return 24;
  }
  return 0;
}
