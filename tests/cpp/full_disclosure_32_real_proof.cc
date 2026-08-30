#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sd_jwt_zk/full_disclosure_circuit.h"
#include "sd_jwt_zk/full_disclosure_layout.h"
#include "sd_jwt_zk/bounded_json.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace {
using Field = proofs::Fp256Base;
using Field2 = proofs::Fp2<Field>;
using Fft = proofs::FFTExtConvolutionFactory<Field, Field2>;
using Rs = proofs::ReedSolomonFactory<Field, Fft>;

struct Encoder {
  proofs::DenseFiller<Field> out;
  explicit Encoder(proofs::Dense<Field>& dense) : out(dense) {
    out.push_back(proofs::p256_base.one());
  }
  void bit(std::uint8_t value) { out.push_back(proofs::p256_base.of_scalar(value & 1U)); }
  template <std::size_t N> void bits(std::uint64_t value) {
    for (std::size_t i = 0; i < N; ++i) bit(value >> i);
  }
  void byte(std::uint8_t value) { bits<8>(value); }
  template <std::size_t N> void bytes(const std::array<std::uint8_t, N>& value) {
    for (auto byte_value : value) byte(byte_value);
  }
  template <class T, std::size_t N> void packed(const std::array<T, N>& value) {
    for (const auto& element : value) out.push_back(element);
  }
};

bool encode_json(Encoder& e, const std::string& input) {
  const auto parsed = sd_jwt_zk::tokenize_bounded_json(input, {16, 3, 8});
  if (!parsed) return false;
  const auto& native = *parsed.value;
  for (std::size_t i = 0; i < 16; ++i)
    e.byte(i < input.size() ? static_cast<std::uint8_t>(input[i]) : 0);
  e.bits<5>(input.size()); e.bits<5>(native.size());
  for (std::size_t token = 0; token < 8; ++token) {
    const bool active = token < native.size();
    e.byte(active ? native[token].kind : 0);
    e.bits<5>(active ? native[token].begin : 0);
    e.bits<5>(active ? native[token].end : 0);
  }
  for (std::size_t token = 0; token < 8; ++token) {
    struct Unit { std::size_t begin{}, end{}; std::uint32_t cp{}; };
    std::vector<Unit> units;
    if (token < native.size() && native[token].kind == 2) {
      for (std::size_t i = native[token].begin + 1; i + 1 < native[token].end;) {
        const auto first = static_cast<std::uint8_t>(input[i]);
        if (first < 0x80) { units.push_back({i, i + 1, first}); ++i; }
        else if ((first & 0xe0U) == 0xc0U && i + 1 < native[token].end - 1) {
          const auto second = static_cast<std::uint8_t>(input[i + 1]);
          units.push_back({i, i + 2, static_cast<std::uint32_t>(((first & 0x1fU) << 6) | (second & 0x3fU))}); i += 2;
        } else return false;
      }
    }
    e.bits<5>(units.size());
    for (std::size_t unit = 0; unit < 16; ++unit) {
      const bool active = unit < units.size();
      e.bits<5>(active ? units[unit].begin : 0);
      e.bits<5>(active ? units[unit].end : 0);
      e.bits<21>(active ? units[unit].cp : 0);
    }
  }
  for (std::size_t token = 0; token < 8; ++token) {
    e.bit(0); e.bit(0);
    for (std::size_t i = 0; i < 5; ++i) e.bits<5>(0);
    for (std::size_t i = 0; i < 16; ++i) e.bits<5>(0);
    for (std::size_t i = 0; i < 16; ++i) e.byte(0);
    for (std::size_t i = 0; i < 17; ++i) e.byte(0);
    for (std::size_t i = 0; i < 17; ++i) e.bits<66>(0);
    e.bits<66>(0);
  }
  std::array<std::array<std::uint8_t, 9>, 9> frame_values{};
  std::array<std::array<std::size_t, 9>, 9> id_values{};
  std::array<std::size_t, 9> depth_values{};
  std::vector<std::uint8_t> frames{1}; std::vector<std::size_t> ids{0};
  depth_values[0] = 1; frame_values[0][0] = 1;
  const auto scalar = [](std::uint8_t kind) { return kind == 2 || kind == 3 || kind == 4 || kind == 5 || kind == 6; };
  for (std::size_t step = 0; step < native.size(); ++step) {
    const auto kind = native[step].kind; const auto depth = frames.size();
    auto& state = frames.back(); bool valid = kind == 1;
    if (!valid && (state == 1 || state == 6 || state == 8 || state == 9) && scalar(kind)) { state = state == 1 ? 2 : state == 6 ? 7 : 10; valid = true; }
    else if (!valid && (state == 1 || state == 6 || state == 8 || state == 9) && (kind == 7 || kind == 9)) { if (depth == 4) return false; state = state == 1 ? 2 : state == 6 ? 7 : 10; frames.push_back(kind == 7 ? 3 : 8); ids.push_back(step + 1); valid = true; }
    else if (!valid && (state == 3 || state == 4) && kind == 2) { state = 5; valid = true; }
    else if (!valid && state == 5 && kind == 12) { state = 6; valid = true; }
    else if (!valid && state == 7 && kind == 11) { state = 4; valid = true; }
    else if (!valid && state == 10 && kind == 11) { state = 9; valid = true; }
    else if (!valid && depth > 1 && (((state == 3 || state == 7) && kind == 8) || ((state == 8 || state == 10) && kind == 10))) { frames.pop_back(); ids.pop_back(); valid = true; }
    if (!valid) return false;
    depth_values[step + 1] = frames.size();
    for (std::size_t slot = 0; slot < frames.size(); ++slot) { frame_values[step + 1][slot] = frames[slot]; id_values[step + 1][slot] = ids[slot]; }
  }
  if (frames.size() != 1 || frames[0] != 2) return false;
  for (std::size_t step = 0; step < 9; ++step) e.bits<5>(depth_values[step]);
  for (std::size_t step = 0; step < 9; ++step)
    for (std::size_t slot = 0; slot < 9; ++slot)
      e.byte(frame_values[step][slot]);
  for (std::size_t step = 0; step < 9; ++step)
    for (std::size_t slot = 0; slot < 9; ++slot) e.bits<5>(id_values[step][slot]);
  return true;
}

template <std::size_t N>
void set(std::array<std::uint8_t, N>& out, const char (&text)[N + 1]) {
  std::memcpy(out.data(), text, N);
}

sd_jwt_zk::FullDisclosureAdviceV1<32> valid_advice() {
  sd_jwt_zk::FullDisclosureAdviceV1<32> a{};
  a.active = 1; a.supplied[0][0] = a.references[0][0] = 'd';
  set(a.vct_name, "vct"); set(a.private_vct, "examp"); a.requested_vct = a.private_vct;
  a.equality_result = 1; set(a.alg, "ES256"); set(a.typ, "dc+sd-jwt");
  set(a.profile, "swiss-profile-vc:1.0.0");
  for (auto& claim : a.registered_claims) claim = {0, 1, 1};
  a.nbf = 10; a.exp = 20; a.iat = 15; a.now = 15; a.time_result = a.iat_result = 1;
  a.policy_path = {'a', 0}; a.other_policy_path = {'b', 0}; a.policy_kind = 4;
  a.boolean_value = a.boolean_result = 1;
  a.integer_value = a.integer_low = 18; a.integer_high = 20; a.integer_result = 1;
  a.date_value = a.date_low = 10; a.date_high = 12; a.date_result = 1;
  a.set_value[0] = a.set_options[0][0] = 'a'; a.set_options[1][0] = 'b'; a.set_result = 1;
  a.issuer_key[0] = a.exact_trust_key[0] = a.registry_authorized_key[0] = 'i';
  a.registry_root[0] = a.registry_selected_root[0] = 'r';
  a.credential_holder_key[0] = a.kb_signer_key[0] = 'h';
  a.presentation_hash[0] = a.kb_sd_hash[0] = 'p';
  a.challenge[0] = a.kb_challenge[0] = 'c';
  a.graph_supplied_active = a.graph_reference_active = 1;
  a.graph_source_lengths[0] = 63; a.graph_source_lengths[1] = 23;
  const std::string disclosure = "WyJzIiwibiIsMV0";
  const auto hash = sd_jwt_zk::sha256_ascii(disclosure);
  const auto digest = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(hash.begin(), hash.end()));
  for (std::size_t i = 0; i < 43; ++i)
    a.graph_nodes[0].digest[i] = a.graph_references[0].digest[i] = digest[i];
  auto& node = a.graph_nodes[0]; auto& reference = a.graph_references[0];
  node.kind = reference.kind = 1; node.arity = 3; node.source = 1;
  node.depth = 1; node.disclosure_end = 23; node.value_begin = 9;
  node.value_end = 22; node.path = {'/','a'}; node.path_length = 2;
  reference.begin = 5; reference.end = 50;
  a.graph_token_counts[0] = 1; a.graph_tokens[0][0] = {2,5,50};
  a.graph_token_depths[0][0] = 3;
  a.graph_token_counts[1] = 13;
  const std::array<sd_jwt_zk::FullDisclosureRangeTokenAdviceV1,13> tokens{{
      {9,0,1},{2,1,4},{11,4,5},{2,5,8},{11,8,9},{7,9,10},
      {2,10,15},{12,15,16},{9,16,17},{2,17,20},{10,20,21},
      {8,21,22},{10,22,23}}};
  const std::array<std::uint8_t,13> depths{{1,2,2,2,2,2,3,3,3,4,4,3,2}};
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    a.graph_tokens[1][i] = tokens[i]; a.graph_token_depths[1][i] = depths[i];
  }
  const auto inactive_hash = sd_jwt_zk::sha256_ascii("MA");
  const auto inactive_digest = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(inactive_hash.begin(), inactive_hash.end()));
  for (std::size_t slot = 1; slot < a.graph_nodes.size(); ++slot)
    for (std::size_t i = 0; i < 43; ++i) a.graph_nodes[slot].digest[i] = inactive_digest[i];
  return a;
}

template <sd_jwt_zk::Trust Trust>
bool encode_advice(Encoder& e, const sd_jwt_zk::FullDisclosureAdviceV1<32>& a,
                   const sd_jwt_zk::FlatBearerWitness& issuer_witness,
                   bool splice_signature, bool include_flat_bearer_tail = true) {
  for (const auto& digest : a.supplied) e.bytes(digest);
  for (const auto& digest : a.references) e.bytes(digest);
  e.bits<6>(a.active); for (auto depth : a.depths) e.bits<6>(depth);
  e.bytes(a.vct_name); e.bytes(a.private_vct); e.bytes(a.requested_vct);
  e.bytes(a.alg); e.bytes(a.typ); e.bytes(a.profile); e.bytes(a.policy_path); e.bytes(a.other_policy_path);
  e.bit(a.equality_result);
  for (const auto& claim : a.registered_claims) { e.bit(claim.top_level); e.bit(claim.is_string); e.bit(claim.present); }
  for (auto value : {a.nbf, a.exp, a.iat, a.now}) e.bits<5>(value);
  e.bit(a.time_result); e.bit(a.iat_result); e.bits<3>(a.policy_kind);
  e.bit(a.boolean_value); e.bit(a.boolean_result);
  for (auto value : {a.integer_value,a.integer_low,a.integer_high,a.date_value,a.date_low,a.date_high}) e.bits<5>(value);
  e.bit(a.integer_result); e.bit(a.date_result); e.bytes(a.set_value);
  for (const auto& option : a.set_options) e.bytes(option); e.bit(a.set_result);
  e.bytes(a.issuer_key);
  e.bytes(a.exact_trust_key);
  e.bytes(a.registry_root); e.bytes(a.registry_selected_root);
  e.bytes(a.credential_holder_key); e.bytes(a.kb_signer_key);
  e.bytes(a.presentation_hash); e.bytes(a.kb_sd_hash); e.bytes(a.challenge); e.bytes(a.kb_challenge);
  for (const auto& node : a.graph_nodes) {
    e.bytes(node.digest); e.byte(node.kind); e.byte(node.arity);
    for (auto value : {node.source,node.parent,node.depth,node.reference_index,
                       node.disclosure_begin,node.disclosure_end,node.value_begin,node.value_end})
      e.bits<6>(value);
    e.bytes(node.path); e.bits<6>(node.path_length);
  }
  for (const auto& reference : a.graph_references) {
    e.bytes(reference.digest); e.byte(reference.kind);
    for (auto value : {reference.source,reference.begin,reference.end}) e.bits<6>(value);
  }
  e.bits<6>(a.graph_supplied_active); e.bits<6>(a.graph_reference_active);
  for (auto value : a.graph_source_lengths) e.bits<6>(value);
  for (const auto& source_tokens : a.graph_tokens)
    for (const auto& token : source_tokens) {
      e.byte(token.kind); e.bits<6>(token.begin); e.bits<6>(token.end);
    }
  for (auto value : a.graph_token_counts) e.bits<6>(value);
  for (const auto& source_depths : a.graph_token_depths)
    for (auto value : source_depths) e.bits<6>(value);
  e.bits<6>(a.graph_selected.node_index); e.bytes(a.graph_selected.path);
  e.bits<6>(a.graph_selected.path_length); e.byte(a.graph_selected.kind);
  e.bits<6>(a.graph_selected.source); e.bits<6>(a.graph_selected.value_begin);
  e.bits<6>(a.graph_selected.value_end); e.bits<6>(a.graph_selected_active);
  for (const auto& placement : a.graph_placements)
    for (auto value : {placement.marker_token,placement.colon_token,
                       placement.value_open_token,placement.reference_token,
                       placement.object_open_token,placement.object_close_token,
                       placement.parent_array_open_token,placement.component_token,
                       placement.array_index}) e.bits<6>(value);
  e.bits<6>(a.graph_authenticated_selected.node_index);
  e.byte(a.graph_authenticated_selected.kind);
  for (auto value : {a.graph_authenticated_selected.component_token,
                     a.graph_authenticated_selected.array_index,
                     a.graph_authenticated_selected.source,
                     a.graph_authenticated_selected.value_begin,
                     a.graph_authenticated_selected.value_end}) e.bits<6>(value);
  e.bits<6>(a.graph_authenticated_selected_active);
  // BindFullDisclosureAdviceV1 allocates the authenticated issuer parser
  // before the per-disclosure parsers.  Keep this order synchronized with the
  // factory so dense replay cannot silently substitute an unbound source.
  const auto encode_string = [&e](const auto& string) {
    e.bits<6>(string.unit_count);
    for (const auto& unit : string.units) {
      e.bits<6>(unit.begin); e.bits<6>(unit.end); e.bits<21>(unit.codepoint);
    }
  };
  const auto encode_number = [&e](const auto& number) {
    e.bit(number.negative); e.bit(number.exponent_negative);
    for (auto value : {number.digit_count, number.fraction_count,
                       number.significant_begin, number.significant_end,
                       number.significant_length}) e.bits<6>(value);
    for (auto value : number.digit_offsets) e.bits<6>(value);
    for (auto value : number.significand) e.byte(value);
    for (auto value : number.states) e.byte(value);
    for (const auto& value : number.exponent_accumulator)
      for (auto bit : value) e.bit(bit);
    for (auto bit : number.scale) e.bit(bit);
  };
  for (const auto& string : a.issuer_parser_strings) encode_string(string);
  for (const auto& stack : a.issuer_parser_frames)
    for (auto frame : stack) e.byte(frame);
  for (const auto& stack : a.issuer_parser_container_ids)
    for (auto id : stack) e.bits<6>(id);
  e.bytes(a.issuer_parser_text);
  for (const auto& token : a.issuer_parser_tokens) {
    e.byte(token.kind); e.bits<6>(token.begin); e.bits<6>(token.end);
  }
  for (const auto& number : a.issuer_parser_numbers) encode_number(number);
  for (const auto& source_strings : a.disclosure_parser_strings)
    for (const auto& string : source_strings) encode_string(string);
  for (const auto& source_frames : a.disclosure_parser_frames)
    for (const auto& stack : source_frames)
      for (auto frame : stack) e.byte(frame);
  for (const auto& source_ids : a.disclosure_parser_container_ids)
    for (const auto& stack : source_ids)
      for (auto id : stack) e.bits<6>(id);
  for (const auto& source_tokens : a.disclosure_parser_tokens)
    for (const auto& token : source_tokens) {
      e.byte(token.kind); e.bits<6>(token.begin); e.bits<6>(token.end);
    }
  for (const auto& source_numbers : a.disclosure_parser_numbers)
    for (const auto& number : source_numbers) encode_number(number);
  proofs::BitPluckerEncoder<Field, 4> plucker(proofs::p256_base);
  for (std::size_t slot = 0; slot < 32; ++slot) {
    const std::string disclosure = slot == 0 ? "WyJzIiwibiIsMV0" : "MA";
    const auto decoded = sd_jwt_zk::base64url_decode(disclosure);
    if (!decoded) return false;
    for (std::size_t i = 0; i < 43; ++i) e.byte(i < disclosure.size() ? disclosure[i] : 0);
    e.bits<6>(disclosure.size());
    for (std::size_t i = 0; i < 32; ++i)
      e.byte(i < decoded.value->size() ? (*decoded.value)[i] : 0);
    e.bits<6>(decoded.value->size());
    std::array<std::uint8_t,64> padded{};
    std::array<proofs::FlatSHA256Witness::BlockWitness,1> raw{};
    std::uint8_t blocks{};
    proofs::FlatSHA256Witness::transform_and_witness_message(
        disclosure.size(), reinterpret_cast<const std::uint8_t*>(disclosure.data()),
        1, blocks, padded.data(), raw.data());
    for (auto value : padded) e.byte(value);
    for (const auto& value : raw[0].outw) e.packed(plucker.mkpacked_v32(value));
    for (std::size_t i = 0; i < 64; ++i) {
      e.packed(plucker.mkpacked_v32(raw[0].oute[i]));
      e.packed(plucker.mkpacked_v32(raw[0].outa[i]));
    }
    for (const auto& value : raw[0].h1) e.packed(plucker.mkpacked_v32(value));
    const auto hash = sd_jwt_zk::sha256_ascii(disclosure);
    for (std::size_t byte = 0; byte < 32; ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit) e.bit((hash[31-byte] >> bit) & 1U);
    e.byte(blocks);
  }
  if (!include_flat_bearer_tail) return true;
  auto signed_witness = issuer_witness;
  if (splice_signature) signed_witness.issuer_signature.r[0] ^= 1;
  proofs::Dense<Field> issuer_dense(1, sd_jwt_zk::kFlatBearerDenseInputsV1);
  std::array<std::uint8_t, 32> statement{};
  if (!sd_jwt_zk::FillFlatBearerDenseWitnessV1(
          issuer_dense, statement, true, signed_witness)) return false;
  for (std::size_t i = 1; i < issuer_dense.v_.size(); ++i)
    e.out.push_back(issuer_dense.v_[i]);
  return true;
}

sd_jwt_zk::Result<sd_jwt_zk::FlatBearerWitness> issuer_fixture() {
  constexpr char header[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
  constexpr char payload[] = "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSJ9";
  constexpr char signature[] = "FQp4GsBBvr3_xbX1UtKSc7mtcw1ygaZ7Z-suRyHET3oggdcr1KqoyH-LA8Yy8pHr3xGkKrrQCu-7fCAbYrTljg";
  constexpr char disclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
  const auto key = sd_jwt_zk::decode_p256_jwk(
      "Jl-RmGfWH_k-UmeHbUnLL58NFLxBz6qOzZqP7z_qxY4",
      "VBuaEu3T_57clPlJDLwm8xnw1PHFyR4kbXUHyGsK9TU");
  if (!key) return sd_jwt_zk::Result<sd_jwt_zk::FlatBearerWitness>::fail(
      sd_jwt_zk::ErrorCode::malformed, "issuer fixture key");
  return sd_jwt_zk::flat_bearer_witness_from_presentation(
      std::string(header) + "." + payload + "." + signature + "~" +
          disclosure + "~",
      *key.value);
}

template <sd_jwt_zk::Binding Binding, sd_jwt_zk::Trust Trust>
int run(const char* mutation) {
  const bool repeat = !std::strcmp(mutation, "repeat");
  const bool cross = !std::strcmp(mutation, "cross-circuit");
  const bool conformance = !std::strcmp(mutation, "array") ||
      !std::strcmp(mutation, "recursive") || !std::strcmp(mutation, "unicode") ||
      !std::strcmp(mutation, "maximum-bytes") || !std::strcmp(mutation, "maximum-tokens") ||
      !std::strcmp(mutation, "typed-policy");
  const bool expect_reject = mutation[0] != '\0' && !repeat && !cross && !conformance;
  std::string json = "null";
  if (!std::strcmp(mutation, "array")) json = "[null]";
  if (!std::strcmp(mutation, "recursive")) json = "[[\"x\"]]";
  if (!std::strcmp(mutation, "unicode")) json = "[\"\xc3\xa9\"]";
  if (!std::strcmp(mutation, "maximum-bytes")) json = "[\"abcdefghijkl\"]";
  if (!std::strcmp(mutation, "maximum-tokens")) json = "[null, null ]";
  if (!std::strcmp(mutation, "overflow-byte")) json = "[\"abcdefghijklm\"]";
  if (!std::strcmp(mutation, "overflow-token")) json = "[ null , null ]";
  if (!std::strcmp(mutation, "overflow-depth")) json = "[[[[]]]]";
  if (!sd_jwt_zk::tokenize_bounded_json(json, {16, 3, 8}))
    return expect_reject ? 0 : 13;
  proofs::QuadCircuit<Field> q(proofs::p256_base);
  auto circuit = sd_jwt_zk::BuildFullDisclosureCircuitV1<Binding, Trust, 32>(&q);
  proofs::Dense<Field> inputs(1, circuit->ninputs);
  auto advice = valid_advice();
  auto issuer = issuer_fixture();
  if (!issuer) return 14;
  std::copy_n(issuer.value->issuer_key.x.begin(), advice.issuer_key.size(),
              advice.issuer_key.begin());
  advice.exact_trust_key = advice.issuer_key;
  for (std::size_t i = 0; i < advice.references[0].size(); ++i)
    advice.supplied[0][i] = advice.references[0][i] =
        static_cast<std::uint8_t>(issuer.value->payload.digest[i]);
  if (!std::strcmp(mutation, "recursive")) {
    advice.active = 2;
    advice.supplied[1][0] = advice.references[1][0] = 'e';
    advice.depths[1] = 1;
  }
  if (!std::strcmp(mutation, "maximum-bytes")) {
    advice.active = 32;
    for (std::size_t i = 1; i < 32; ++i)
      advice.supplied[i][0] = advice.references[i][0] =
          static_cast<std::uint8_t>(i + 1);
  }
  Encoder encoder(inputs); if (!encode_json(encoder, json)) return 12;
  if (!encode_advice<Trust>(encoder, advice,
                            *issuer.value,
                            !std::strcmp(mutation, "signature-splice")))
    return expect_reject ? 0 : 7;
  if (encoder.out.size() != inputs.n1_) { std::cerr << "dense-layout-mismatch\n"; return 3; }
  Field2 ext(proofs::p256_base);
  auto omega = ext.of_string("112649224146410281873500457609690258373018840430489408729223714171582664680802", "84087994358540907695740461427818660560182168997182378749313018254450460212908");
  Fft fft(proofs::p256_base, ext, omega, 1ull << 31); Rs rs(fft, proofs::p256_base);
  proofs::ZkProof<Field> proof(*circuit, 4, 128);
  proofs::ZkProver<Field, Rs> prover(*circuit, proofs::p256_base, rs);
  const std::array<std::uint8_t, 4> statement{'L','6','.','4'};
  proofs::Transcript prover_transcript(statement.data(), statement.size()); proofs::SecureRandomEngine random;
  prover.commit(proof, inputs, prover_transcript, random);
  if (!prover.prove(proof, inputs, prover_transcript)) {
    if (expect_reject) { std::cout << "invalid-witness-rejected\n"; return 0; }
    std::cerr << "valid-witness-rejected\n"; return 4;
  }
  if (expect_reject) { std::cerr << "invalid-witness-accepted\n"; return 8; }
  proofs::Dense<Field> public_inputs(1, circuit->npub_in);
  proofs::Transcript verifier_transcript(statement.data(), statement.size()); proofs::ZkVerifier<Field, Rs> verifier(*circuit, rs, 4, 128, proofs::p256_base);
  verifier.recv_commitment(proof, verifier_transcript);
  if (!verifier.verify(proof, public_inputs, verifier_transcript)) return 5;
  std::vector<std::uint8_t> encoded; proof.write(encoded, proofs::p256_base);
  if (repeat) {
    proofs::ZkProof<Field> second(*circuit, 4, 128);
    proofs::Transcript second_transcript(statement.data(), statement.size());
    proofs::SecureRandomEngine second_random;
    prover.commit(second, inputs, second_transcript, second_random);
    if (!prover.prove(second, inputs, second_transcript)) return 9;
    std::vector<std::uint8_t> second_encoded;
    second.write(second_encoded, proofs::p256_base);
    if (encoded == second_encoded) return 10;
    std::cout << "repeated-proof-bytes-differ\n";
  }
  if (cross) {
    proofs::QuadCircuit<Field> wrong_quad(proofs::p256_base);
    auto wrong_circuit =
        sd_jwt_zk::BuildFullDisclosureCircuitV1<
            Binding == sd_jwt_zk::Binding::bearer
                ? sd_jwt_zk::Binding::holder_bound
                : sd_jwt_zk::Binding::bearer,
            Trust, 32>(&wrong_quad);
    proofs::ReadBuffer reader(encoded);
    proofs::ZkProof<Field> wrong_proof(*wrong_circuit, 4, 128);
    if (wrong_proof.read(reader, proofs::p256_base) && reader.remaining() == 0) {
      proofs::Dense<Field> wrong_public(1, wrong_circuit->npub_in);
      proofs::Transcript wrong_transcript(statement.data(), statement.size());
      proofs::ZkVerifier<Field, Rs> wrong_verifier(
          *wrong_circuit, rs, 4, 128, proofs::p256_base);
      wrong_verifier.recv_commitment(wrong_proof, wrong_transcript);
      if (wrong_verifier.verify(wrong_proof, wrong_public, wrong_transcript))
        return 11;
    }
    std::cout << "cross-circuit-proof-rejected\n";
  }
  std::cout << "proof-bytes=" << encoded.size() << " terms=" << circuit->nterms() << '\n'; return 0;
}
}  // namespace

int main(int argc, char** argv) {
  const char* lane = argc > 1 ? argv[1] : "bearer-exact";
  const char* mutation = argc > 2 ? argv[2] : "";
  if (!std::strcmp(lane,"bearer-exact")) return run<sd_jwt_zk::Binding::bearer,sd_jwt_zk::Trust::exact_key>(mutation);
  if (!std::strcmp(lane,"holder-exact")) return run<sd_jwt_zk::Binding::holder_bound,sd_jwt_zk::Trust::exact_key>(mutation);
  return 2;
}
