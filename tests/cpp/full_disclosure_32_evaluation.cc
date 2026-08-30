#include <array>
#include <cstring>
#include <vector>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "sd_jwt_zk/full_disclosure_circuit.h"

namespace {
using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Layout = sd_jwt_zk::FullDisclosureAdviceV1<2>;
using Graph = sd_jwt_zk::FullDisclosureGraphRelation<Logic, 2>;
using Sha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;

proofs::Fp256Nat digest_nat(const std::array<std::uint8_t, 32>& bytes) {
  std::array<std::uint8_t, 32> little{};
  for (std::size_t i = 0; i < bytes.size(); ++i)
    little[i] = bytes[bytes.size() - 1 - i];
  return proofs::Fp256Nat::of_bytes(little.data());
}

bool digest_accepts(bool mutate_ascii, bool mutate_reference, bool live) {
  constexpr std::string_view encoded = "WyJzIiwibiIsMV0";
  constexpr std::size_t chars = encoded.size();
  const std::string disclosure = live ? std::string(encoded) : std::string("MA");
  const auto hash = sd_jwt_zk::sha256_ascii(disclosure);
  const auto hash_text = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(hash.begin(), hash.end()));
  std::array<std::uint8_t, 64> padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 1> raw{};
  std::uint8_t blocks{};
  proofs::FlatSHA256Witness::transform_and_witness_message(
      disclosure.size(), reinterpret_cast<const std::uint8_t*>(disclosure.data()),
      1, blocks, padded.data(), raw.data());
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  Graph::Node node{};
  for (std::size_t i = 0; i < node.supplied_digest.size(); ++i)
    node.supplied_digest[i] = logic.template vbit<8>(
        static_cast<std::uint8_t>(hash_text[i]) ^ (mutate_reference && i == 0));
  std::array<Logic::v8, chars> ascii{};
  for (std::size_t i = 0; i < chars; ++i)
    ascii[i] = logic.template vbit<8>(
        static_cast<std::uint8_t>(i < disclosure.size() ? disclosure[i] : 0) ^
        (mutate_ascii && i == 0));
  Logic::bitvec<4> active_length{};
  logic.bits(4, active_length.data(), disclosure.size());
  std::array<Logic::v8, (chars * 6) / 8> decoded{};
  const auto decoded_bytes = sd_jwt_zk::base64url_decode(disclosure);
  if (!decoded_bytes) return false;
  for (std::size_t i = 0; i < decoded.size(); ++i)
    decoded[i] = logic.template vbit<8>(
        i < decoded_bytes.value->size() ? (*decoded_bytes.value)[i] : 0);
  Logic::bitvec<4> decoded_length{};
  logic.bits(4, decoded_length.data(), decoded_bytes.value->size());
  std::array<Logic::v8, 64> sha_input{};
  for (std::size_t i = 0; i < 64; ++i)
    sha_input[i] = logic.template vbit<8>(padded[i]);
  proofs::BitPluckerEncoder<Field, 4> encoder(proofs::p256_base);
  std::array<Sha::BlockWitness, 1> witness{};
  for (std::size_t i = 0; i < 48; ++i)
    witness[0].outw[i] = logic.konst(encoder.mkpacked_v32(raw[0].outw[i]));
  for (std::size_t i = 0; i < 64; ++i) {
    witness[0].oute[i] = logic.konst(encoder.mkpacked_v32(raw[0].oute[i]));
    witness[0].outa[i] = logic.konst(encoder.mkpacked_v32(raw[0].outa[i]));
  }
  for (std::size_t i = 0; i < 8; ++i)
    witness[0].h1[i] = logic.konst(encoder.mkpacked_v32(raw[0].h1[i]));
  const auto natural = digest_nat(hash); Logic::v256 digest_bits{};
  for (std::size_t i = 0; i < 256; ++i) digest_bits[i] = logic.bit(natural.bit(i));
  Graph(logic).assert_bounded_digest_link<1, chars>(
      node, ascii, active_length, decoded, decoded_length, sha_input, witness, digest_bits,
      logic.template vbit<8>(blocks), logic.bit(live));
  return !backend.assertion_failed();
}

template <std::size_t N>
void assign(std::array<std::uint8_t, N>& output, const char (&input)[N + 1]) {
  for (std::size_t i = 0; i < N; ++i) output[i] = static_cast<std::uint8_t>(input[i]);
}

struct WitnessSource {
  Logic& logic;
  std::vector<std::uint8_t> bytes;
  std::vector<std::uint8_t> bits;
  std::vector<Sha::packed_v32> packed_values;
  std::size_t byte_index{};
  std::size_t bit_index{};
  std::size_t packed_index{};
  Logic::v8 byte() { return logic.template vbit<8>(bytes.at(byte_index++)); }
  Logic::BitW bit() { return logic.bit(bits.at(bit_index++)); }
  Sha::packed_v32 packed() { return packed_values.at(packed_index++); }
};

template <std::size_t N>
void push_bytes(std::vector<std::uint8_t>& output, const std::array<std::uint8_t, N>& input) {
  output.insert(output.end(), input.begin(), input.end());
}

template <std::size_t N>
void push_bits(std::vector<std::uint8_t>& output, std::uint8_t input) {
  for (std::size_t i = 0; i < N; ++i) output.push_back((input >> i) & 1U);
}

template <sd_jwt_zk::Trust Trust>
WitnessSource source(Logic& logic, const Layout& advice) {
  WitnessSource result{logic};
  for (const auto& digest : advice.supplied) push_bytes(result.bytes, digest);
  for (const auto& digest : advice.references) push_bytes(result.bytes, digest);
  push_bits<6>(result.bits, advice.active);
  for (const auto depth : advice.depths) push_bits<6>(result.bits, depth);
  push_bytes(result.bytes, advice.vct_name);
  push_bytes(result.bytes, advice.private_vct);
  push_bytes(result.bytes, advice.requested_vct);
  push_bytes(result.bytes, advice.alg);
  push_bytes(result.bytes, advice.typ);
  push_bytes(result.bytes, advice.profile);
  push_bytes(result.bytes, advice.policy_path);
  push_bytes(result.bytes, advice.other_policy_path);
  result.bits.push_back(advice.equality_result);
  for (const auto& claim : advice.registered_claims) {
    result.bits.push_back(claim.top_level);
    result.bits.push_back(claim.is_string);
    result.bits.push_back(claim.present);
  }
  for (const auto value : {advice.nbf, advice.exp, advice.iat, advice.now}) push_bits<5>(result.bits, value);
  result.bits.push_back(advice.time_result); result.bits.push_back(advice.iat_result);
  push_bits<3>(result.bits, advice.policy_kind);
  result.bits.push_back(advice.boolean_value); result.bits.push_back(advice.boolean_result);
  for (const auto value : {advice.integer_value, advice.integer_low, advice.integer_high,
                           advice.date_value, advice.date_low, advice.date_high}) push_bits<5>(result.bits, value);
  result.bits.push_back(advice.integer_result); result.bits.push_back(advice.date_result);
  push_bytes(result.bytes, advice.set_value);
  for (const auto& option : advice.set_options) push_bytes(result.bytes, option);
  result.bits.push_back(advice.set_result);
  push_bytes(result.bytes, advice.issuer_key);
  if constexpr (Trust == sd_jwt_zk::Trust::exact_key)
    push_bytes(result.bytes, advice.exact_trust_key);
  else
    push_bytes(result.bytes, advice.registry_authorized_key);
  push_bytes(result.bytes, advice.registry_root);
  push_bytes(result.bytes, advice.registry_selected_root);
  push_bytes(result.bytes, advice.credential_holder_key);
  push_bytes(result.bytes, advice.kb_signer_key);
  push_bytes(result.bytes, advice.presentation_hash);
  push_bytes(result.bytes, advice.kb_sd_hash);
  push_bytes(result.bytes, advice.challenge);
  push_bytes(result.bytes, advice.kb_challenge);
  for (const auto& node : advice.graph_nodes) {
    push_bytes(result.bytes, node.digest); result.bytes.push_back(node.kind);
    result.bytes.push_back(node.arity);
    for (const auto value : {node.source,node.parent,node.depth,node.reference_index,
                             node.disclosure_begin,node.disclosure_end,
                             node.value_begin,node.value_end})
      push_bits<8>(result.bits, value);
    push_bytes(result.bytes, node.path); push_bits<8>(result.bits, node.path_length);
  }
  for (const auto& reference : advice.graph_references) {
    push_bytes(result.bytes, reference.digest); result.bytes.push_back(reference.kind);
    for (const auto value : {reference.source,reference.begin,reference.end})
      push_bits<8>(result.bits, value);
  }
  push_bits<8>(result.bits, advice.graph_supplied_active);
  push_bits<8>(result.bits, advice.graph_reference_active);
  for (const auto length : advice.graph_source_lengths) push_bits<8>(result.bits, length);
  for (const auto& source_tokens : advice.graph_tokens)
    for (const auto& token : source_tokens) {
      result.bytes.push_back(token.kind); push_bits<8>(result.bits, token.begin);
      push_bits<8>(result.bits, token.end);
    }
  for (const auto count : advice.graph_token_counts) push_bits<8>(result.bits, count);
  for (const auto& source_depths : advice.graph_token_depths)
    for (const auto depth : source_depths) push_bits<8>(result.bits, depth);
  push_bits<8>(result.bits, advice.graph_selected.node_index);
  push_bytes(result.bytes, advice.graph_selected.path);
  push_bits<8>(result.bits, advice.graph_selected.path_length);
  result.bytes.push_back(advice.graph_selected.kind);
  for (const auto value : {advice.graph_selected.source,
                           advice.graph_selected.value_begin,
                           advice.graph_selected.value_end})
    push_bits<8>(result.bits, value);
  push_bits<8>(result.bits, advice.graph_selected_active);
  for (const auto& placement : advice.graph_placements)
    for (const auto value : {placement.marker_token, placement.colon_token,
                             placement.value_open_token, placement.reference_token,
                             placement.object_open_token, placement.object_close_token,
                             placement.parent_array_open_token, placement.component_token,
                             placement.array_index})
      push_bits<8>(result.bits, value);
  push_bits<8>(result.bits, advice.graph_authenticated_selected.node_index);
  result.bytes.push_back(advice.graph_authenticated_selected.kind);
  for (const auto value : {advice.graph_authenticated_selected.component_token,
                           advice.graph_authenticated_selected.array_index,
                           advice.graph_authenticated_selected.source,
                           advice.graph_authenticated_selected.value_begin,
                           advice.graph_authenticated_selected.value_end})
    push_bits<8>(result.bits, value);
  push_bits<8>(result.bits, advice.graph_authenticated_selected_active);
  const auto push_strings = [&](const auto& strings) {
    for (const auto& string : strings) {
      push_bits<8>(result.bits, string.unit_count);
      for (const auto& unit : string.units) {
        push_bits<8>(result.bits, unit.begin); push_bits<8>(result.bits, unit.end);
        push_bits<21>(result.bits, unit.codepoint);
      }
    }
  };
  const auto push_frames = [&](const auto& frames) {
    for (const auto& stack : frames)
      result.bytes.insert(result.bytes.end(), stack.begin(), stack.end());
  };
  const auto push_ids = [&](const auto& ids) {
    for (const auto& stack : ids)
      for (const auto id : stack) push_bits<8>(result.bits, id);
  };
  const auto push_tokens = [&](const auto& tokens) {
    for (const auto& token : tokens) {
      result.bytes.push_back(token.kind); push_bits<8>(result.bits, token.begin);
      push_bits<8>(result.bits, token.end);
    }
  };
  const auto push_numbers = [&](const auto& source_numbers) {
    for (const auto& number : source_numbers) {
      result.bits.push_back(number.negative); result.bits.push_back(number.exponent_negative);
      for (auto value : {number.digit_count,number.fraction_count,number.significant_begin,
                         number.significant_end,number.significant_length}) push_bits<8>(result.bits,value);
      for (auto value : number.digit_offsets) push_bits<8>(result.bits,value);
      push_bytes(result.bytes, number.significand); push_bytes(result.bytes, number.states);
      for (const auto& accumulator : number.exponent_accumulator)
        result.bits.insert(result.bits.end(), accumulator.begin(), accumulator.end());
      result.bits.insert(result.bits.end(), number.scale.begin(), number.scale.end());
    }
  };
  push_strings(advice.issuer_parser_strings);
  push_frames(advice.issuer_parser_frames);
  push_ids(advice.issuer_parser_container_ids);
  push_bytes(result.bytes, advice.issuer_parser_text);
  push_tokens(advice.issuer_parser_tokens);
  push_numbers(advice.issuer_parser_numbers);
  for (const auto& source_strings : advice.disclosure_parser_strings) {
    push_strings(source_strings);
  }
  for (const auto& source_frames : advice.disclosure_parser_frames) {
    push_frames(source_frames);
  }
  for (const auto& source_ids : advice.disclosure_parser_container_ids) {
    push_ids(source_ids);
  }
  for (const auto& source_tokens : advice.disclosure_parser_tokens) {
    push_tokens(source_tokens);
  }
  for (const auto& source_numbers : advice.disclosure_parser_numbers) {
    push_numbers(source_numbers);
  }
  for (std::size_t slot = 0; slot < advice.graph_nodes.size(); ++slot) {
    const std::string disclosure = slot == 0 ? "WyJzIiwibiIsMV0"
        : slot == 1 ? "WyJ0IiwibjIiXQ" : "MA";
    const auto decoded = sd_jwt_zk::base64url_decode(disclosure);
    if (!decoded) throw std::runtime_error("graph disclosure fixture");
    for (std::size_t i = 0; i < 86; ++i)
      result.bytes.push_back(i < disclosure.size()
                                 ? static_cast<std::uint8_t>(disclosure[i])
                                 : 0);
    push_bits<8>(result.bits, disclosure.size());
    for (std::size_t i = 0; i < 64; ++i)
      result.bytes.push_back(i < decoded.value->size() ? (*decoded.value)[i] : 0);
    push_bits<8>(result.bits, decoded.value->size());
    std::array<std::uint8_t, 128> padded{};
    std::array<proofs::FlatSHA256Witness::BlockWitness, 2> raw{};
    std::uint8_t blocks{};
    proofs::FlatSHA256Witness::transform_and_witness_message(
        disclosure.size(), reinterpret_cast<const std::uint8_t*>(disclosure.data()),
        2, blocks, padded.data(), raw.data());
    result.bytes.insert(result.bytes.end(), padded.begin(), padded.end());
    proofs::BitPluckerEncoder<Field, 4> encoder(proofs::p256_base);
    for (const auto& block : raw) {
      for (const auto& value : block.outw)
        result.packed_values.push_back(logic.konst(encoder.mkpacked_v32(value)));
      for (std::size_t i = 0; i < 64; ++i) {
        result.packed_values.push_back(logic.konst(encoder.mkpacked_v32(block.oute[i])));
        result.packed_values.push_back(logic.konst(encoder.mkpacked_v32(block.outa[i])));
      }
      for (const auto& value : block.h1)
        result.packed_values.push_back(logic.konst(encoder.mkpacked_v32(value)));
    }
    const auto digest = sd_jwt_zk::sha256_ascii(disclosure);
    const auto natural = digest_nat(digest);
    for (std::size_t bit = 0; bit < 256; ++bit)
      result.bits.push_back(natural.bit(bit));
    result.bytes.push_back(blocks);
  }
  return result;
}

Layout valid_advice() {
  Layout advice{};
  advice.active = 1; advice.supplied[0][0] = advice.references[0][0] = 'd';
  assign(advice.vct_name, "vct"); assign(advice.private_vct, "examp");
  advice.requested_vct = advice.private_vct; advice.equality_result = 1;
  assign(advice.alg, "ES256"); assign(advice.typ, "dc+sd-jwt");
  assign(advice.profile, "swiss-profile-vc:1.0.0");
  for (auto& claim : advice.registered_claims) claim = {0, 1, 1};
  advice.nbf = 10; advice.exp = 20; advice.iat = 15; advice.now = 15;
  advice.time_result = 1; advice.iat_result = 1;
  advice.policy_path = {'a', 0}; advice.other_policy_path = {'b', 0}; advice.policy_kind = 4;
  advice.boolean_value = 1; advice.boolean_result = 1;
  advice.integer_value = 18; advice.integer_low = 18; advice.integer_high = 20; advice.integer_result = 1;
  advice.date_value = 10; advice.date_low = 10; advice.date_high = 12; advice.date_result = 1;
  advice.set_value[0] = 'a'; advice.set_options[0][0] = 'a'; advice.set_options[1][0] = 'b'; advice.set_result = 1;
  advice.issuer_key[0] = advice.exact_trust_key[0] = 'i';
  advice.registry_root[0] = advice.registry_selected_root[0] = 'r';
  advice.credential_holder_key[0] = advice.kb_signer_key[0] = 'h';
  advice.presentation_hash[0] = advice.kb_sd_hash[0] = 'p';
  advice.challenge[0] = advice.kb_challenge[0] = 'c';
  advice.graph_supplied_active = advice.graph_reference_active = 2;
  advice.graph_source_lengths[0] = 63;
  advice.graph_source_lengths[1] = 23;
  advice.graph_source_lengths[2] = 7;
  for (std::size_t slot = 0; slot < 2; ++slot) {
    auto& node = advice.graph_nodes[slot];
    auto& reference = advice.graph_references[slot];
    const std::string disclosure = slot == 0 ? "WyJzIiwibiIsMV0" : "WyJ0IiwibjIiXQ";
    const auto digest = sd_jwt_zk::sha256_ascii(disclosure);
    const auto digest_text = sd_jwt_zk::base64url_encode(
        sd_jwt_zk::Bytes(digest.begin(), digest.end()));
    for (std::size_t i = 0; i < 43; ++i)
      node.digest[i] = reference.digest[i] =
          static_cast<std::uint8_t>(digest_text[i]);
    node.kind = reference.kind = slot == 0 ? 1 : 2;
    node.arity = slot == 0 ? 3 : 2; node.source = slot + 1;
    node.parent = slot == 0 ? 0 : 1; node.depth = slot + 1;
    node.reference_index = slot; node.disclosure_end = slot == 0 ? 23 : 7;
    node.value_begin = slot == 0 ? 9 : 5; node.value_end = slot == 0 ? 22 : 6;
    reference.source = slot == 0 ? 0 : 1;
    reference.begin = slot == 0 ? 5 : 17; reference.end = slot == 0 ? 50 : 20;
  }
  const auto inactive_hash = sd_jwt_zk::sha256_ascii("MA");
  const auto inactive_digest = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(inactive_hash.begin(), inactive_hash.end()));
  for (std::size_t slot = 2; slot < advice.graph_nodes.size(); ++slot)
    for (std::size_t i = 0; i < 43; ++i)
      advice.graph_nodes[slot].digest[i] =
          static_cast<std::uint8_t>(inactive_digest[i]);
  advice.graph_nodes[0].path = {'/', 'a'};
  advice.graph_nodes[0].path_length = 2;
  advice.graph_nodes[1].path = {'/', 'a', '/', '0'};
  advice.graph_nodes[1].path_length = 4;
  const auto token = [&](std::size_t source_index, std::size_t index,
                         std::uint8_t kind, std::uint8_t begin,
                         std::uint8_t end, std::uint8_t depth) {
    advice.graph_tokens[source_index][index] = {kind, begin, end};
    advice.graph_token_depths[source_index][index] = depth;
  };
  advice.graph_token_counts[0] = 7;
  token(0,0,7,0,1,1); token(0,1,2,1,6,2); token(0,2,12,6,7,2);
  token(0,3,9,7,8,2); token(0,4,2,8,53,3); token(0,5,10,53,54,3);
  token(0,6,8,54,55,2);
  advice.graph_token_counts[1] = 13;
  token(1,0,9,0,1,1); token(1,1,2,1,4,2); token(1,2,11,4,5,2);
  token(1,3,2,5,8,2); token(1,4,11,8,9,2); token(1,5,7,9,10,2);
  token(1,6,2,10,15,3); token(1,7,12,15,16,3); token(1,8,9,16,17,3);
  token(1,9,2,17,20,4); token(1,10,10,20,21,4);
  token(1,11,8,21,22,3); token(1,12,10,22,23,2);
  advice.graph_token_counts[2] = 5;
  token(2,0,9,0,1,1); token(2,1,2,1,4,2); token(2,2,11,4,5,2);
  token(2,3,3,5,6,2); token(2,4,10,6,7,2);
  auto& marker = advice.issuer_parser_strings[1]; marker.unit_count = 3;
  marker.units[0].codepoint = '_'; marker.units[1].codepoint = 's';
  marker.units[2].codepoint = 'd';
  auto& component = advice.disclosure_parser_strings[0][3]; component.unit_count = 1;
  component.units[0].codepoint = 'a';
  advice.issuer_parser_frames[1][1] = 3;
  advice.issuer_parser_container_ids[4][2] = 4;
  advice.graph_placements[0].marker_token = 1;
  advice.graph_placements[0].colon_token = 2;
  advice.graph_placements[0].value_open_token = 3;
  advice.graph_placements[0].reference_token = 4;
  advice.graph_placements[0].component_token = 3;
  auto& placeholder = advice.disclosure_parser_strings[0][7]; placeholder.unit_count = 3;
  placeholder.units[0].codepoint = placeholder.units[1].codepoint =
      placeholder.units[2].codepoint = '.';
  advice.disclosure_parser_frames[0][7][3] = 3;
  advice.disclosure_parser_container_ids[0][7][3] = 7;
  advice.disclosure_parser_container_ids[0][7][2] = 6;
  advice.graph_placements[1].marker_token = 7;
  advice.graph_placements[1].colon_token = 8;
  advice.graph_placements[1].reference_token = 9;
  advice.graph_placements[1].object_open_token = 6;
  advice.graph_placements[1].object_close_token = 10;
  advice.graph_placements[1].parent_array_open_token = 5;
  advice.issuer_parser_tokens = advice.graph_tokens[0];
  advice.disclosure_parser_tokens[0] = advice.graph_tokens[1];
  advice.disclosure_parser_tokens[1] = advice.graph_tokens[2];
  advice.graph_selected_active = 1;
  advice.graph_selected.node_index = 1; advice.graph_selected.path = {'/','a','/','0'};
  advice.graph_selected.path_length = 4; advice.graph_selected.kind = 2;
  advice.graph_selected.source = 2; advice.graph_selected.value_begin = 5;
  advice.graph_selected.value_end = 6;
  return advice;
}

template <sd_jwt_zk::Binding Binding, sd_jwt_zk::Trust Trust>
bool run(const char* mutation) {
  Layout advice = valid_advice();
  if (std::strcmp(mutation, "wrong-alg") == 0) advice.alg[1] = 'X';
  if (std::strcmp(mutation, "wrong-typ") == 0) advice.typ[8] = 'x';
  if (std::strcmp(mutation, "wrong-profile") == 0) advice.profile.back() = '1';
  if (std::strcmp(mutation, "wrong-vct-name") == 0) advice.vct_name.back() = 'x';
  if (std::strcmp(mutation, "wrong-vct") == 0) advice.private_vct.back() = 'x';
  if (std::strcmp(mutation, "wrong-placement") == 0) advice.registered_claims[0].top_level = 1;
  if (std::strcmp(mutation, "wrong-type") == 0) advice.registered_claims[0].is_string = 0;
  if (std::strcmp(mutation, "wrong-time") == 0) advice.now = 21;
  if (std::strcmp(mutation, "wrong-iat") == 0) advice.iat = 16;
  if (std::strcmp(mutation, "wrong-policy-type") == 0) advice.policy_kind = 5;
  if (std::strcmp(mutation, "wrong-range") == 0) advice.integer_value = 21;
  if (std::strcmp(mutation, "wrong-date") == 0) advice.date_value = 9;
  if (std::strcmp(mutation, "wrong-boolean") == 0) advice.boolean_value = 0;
  if (std::strcmp(mutation, "wrong-set") == 0) advice.set_value[0] = 'z';
  if (std::strcmp(mutation, "duplicate-path") == 0) advice.other_policy_path = advice.policy_path;
  if (std::strcmp(mutation, "wrong-exact-key") == 0) advice.exact_trust_key[0] ^= 1;
  if (std::strcmp(mutation, "wrong-registry-root") == 0) advice.registry_selected_root[0] ^= 1;
  if (std::strcmp(mutation, "wrong-holder-key") == 0) advice.kb_signer_key[0] ^= 1;
  if (std::strcmp(mutation, "wrong-presentation-hash") == 0) advice.kb_sd_hash[0] ^= 1;
  if (std::strcmp(mutation, "wrong-challenge") == 0) advice.kb_challenge[0] ^= 1;
  if (std::strcmp(mutation, "wrong-graph-digest") == 0)
    advice.graph_references[0].digest[0] ^= 1;
  if (std::strcmp(mutation, "wrong-graph-parent") == 0)
    advice.graph_nodes[0].parent = 1;
  if (std::strcmp(mutation, "wrong-graph-range") == 0)
    advice.graph_nodes[0].value_end = 24;
  if (std::strcmp(mutation, "wrong-graph-token") == 0)
    advice.graph_tokens[0][0].begin = 6;
  if (std::strcmp(mutation, "wrong-graph-shape") == 0)
    advice.graph_tokens[1][3].kind = 3;
  if (std::strcmp(mutation, "wrong-graph-selected") == 0)
    advice.graph_selected.path[3] = '1';
  if (std::strcmp(mutation, "wrong-placement-marker") == 0)
    advice.graph_placements[0].marker_token = 0;
  if (std::strcmp(mutation, "wrong-placement-component") == 0)
    advice.graph_placements[0].component_token = 1;
  if (std::strcmp(mutation, "wrong-placement-index") == 0)
    advice.graph_placements[1].array_index = 1;
  if (std::strcmp(mutation, "wrong-placement-container") == 0)
    advice.disclosure_parser_container_ids[0][7][3] = 0;
  if (std::strcmp(mutation, "wrong-placement-frame") == 0)
    advice.disclosure_parser_frames[0][7][3] = 0;
  if (std::strcmp(mutation, "graph-empty") == 0) {
    advice.graph_supplied_active = advice.graph_reference_active = 0;
    advice.graph_nodes[0] = {};
    advice.graph_references[0] = {};
  }
  advice.registry_authorized_key = advice.issuer_key;
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  auto witness = source<Trust>(logic, advice);
  auto circuit_advice = sd_jwt_zk::BindFullDisclosureAdviceV1<Logic, 2>(logic, witness);
  sd_jwt_zk::AssertFullDisclosureAdviceV1<Binding, Trust>(logic, circuit_advice);
  return !backend.assertion_failed() && witness.byte_index == witness.bytes.size() &&
         witness.bit_index == witness.bits.size() &&
         witness.packed_index == witness.packed_values.size();
}
}  // namespace

int main(int argc, char** argv) {
  const char* lane = argc > 1 ? argv[1] : "bearer-exact";
  const char* mutation = argc > 2 ? argv[2] : "";
  bool accepted = false;
  if (std::strcmp(lane, "bearer-exact") == 0)
    accepted = run<sd_jwt_zk::Binding::bearer, sd_jwt_zk::Trust::exact_key>(mutation);
  else if (std::strcmp(lane, "holder-exact") == 0)
    accepted = run<sd_jwt_zk::Binding::holder_bound, sd_jwt_zk::Trust::exact_key>(mutation);
  else return 2;
  const bool digest = digest_accepts(
      std::strcmp(mutation, "bad-digest-ascii") == 0,
      std::strcmp(mutation, "bad-digest-reference") == 0,
      std::strcmp(mutation, "bad-digest-inactive") != 0);
  const bool digest_mutation = std::strcmp(mutation, "bad-digest-ascii") == 0 ||
      std::strcmp(mutation, "bad-digest-reference") == 0;
  const bool inactive = std::strcmp(mutation, "bad-digest-inactive") == 0;
  const bool relation_expected = argc <= 2 || digest_mutation || inactive;
  const bool digest_expected = !digest_mutation;
  return accepted == relation_expected && digest == digest_expected ? 0 : 1;
}
