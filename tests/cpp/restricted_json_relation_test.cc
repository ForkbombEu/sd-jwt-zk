#include "sd_jwt_zk/restricted_base64url_relation.h"
#include "sd_jwt_zk/flat_disclosure_relation.h"
#include "sd_jwt_zk/restricted_json_relation.h"

#include <array>
#include <string>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
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

std::string payload(std::string digest, std::string issuer, std::string vct, bool explicit_sha256) {
  return "{\"_sd\":[\"" + std::move(digest) + "\"],\"iss\":\"" + std::move(issuer) +
      "\",\"vct\":\"" + std::move(vct) + "\"" +
      (explicit_sha256 ? ",\"_sd_alg\":\"sha-256\"}" : "}");
}

}  // namespace

int main() {
  if (!active_b64_accepts("TWFu", 4) || !active_b64_accepts("TWE", 3) || !active_b64_accepts("TQ", 2)) return 25;
  if (active_b64_accepts("T", 1) || active_b64_accepts("TQ", 2, true) || active_b64_accepts("TR", 2) || active_b64_accepts("TWF", 3)) return 26;
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
