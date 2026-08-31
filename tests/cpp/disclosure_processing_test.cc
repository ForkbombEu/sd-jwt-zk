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

#include "sd_jwt_zk/disclosure_processing.h"
#include "sd_jwt_zk/full_disclosure_relation.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"

namespace {
using sd_jwt_zk::DisclosureProcessingLimits;
using sd_jwt_zk::DisclosureProcessingRequest;
using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Graph = sd_jwt_zk::FullDisclosureGraphRelation<Logic, 2, 8, 16>;
using Sha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;
struct PlacementUnit { Logic::bitvec<21> codepoint{}; };
struct PlacementString {
  Graph::Index unit_count{};
  std::array<PlacementUnit, 43> units{};
};
using PlacementFrame = std::array<Logic::v8, 14>;
using PlacementIds = std::array<Graph::Index, 14>;
using BoundSource = sd_jwt_zk::BoundedJsonCircuitInput<Logic, 63, 7, 8, 7>;
using IssuerBoundSource =
    sd_jwt_zk::BoundedJsonCircuitInput<Logic, 128, 13, 8, 13>;
using DisclosureBoundSource =
    sd_jwt_zk::BoundedJsonCircuitInput<Logic, 64, 13, 8, 13>;

[[maybe_unused]] void compile_bounded_source_contract(
    Graph& relation, const Graph::GraphInput& graph,
    const std::array<Graph::Placement, 2>& placements,
    const std::array<BoundSource, 3>& sources) {
  relation.assert_bounded_source_placements(graph, placements, sources);
}

[[maybe_unused]] void compile_heterogeneous_source_contract(
    Graph& relation, const Graph::GraphInput& graph,
    const std::array<Graph::Placement, 2>& placements,
    const IssuerBoundSource& issuer,
    const std::array<DisclosureBoundSource, 2>& disclosures) {
  relation.assert_heterogeneous_bounded_source_placements(
      graph, placements, issuer, disclosures);
}

std::string encode(std::string_view value) {
  return sd_jwt_zk::base64url_encode(sd_jwt_zk::Bytes(value.begin(), value.end()));
}

std::string digest(std::string_view value) {
  const auto hash = sd_jwt_zk::sha256_ascii(value);
  return sd_jwt_zk::base64url_encode(sd_jwt_zk::Bytes(hash.begin(), hash.end()));
}

bool expect(bool condition, int code, std::string_view description) {
  if (condition) return true;
  std::cerr << code << ": " << description << '\n';
  return false;
}

bool accepts(const std::string& payload,
             const std::vector<std::string>& disclosures,
             DisclosureProcessingLimits limits = {}) {
  const auto result =
      sd_jwt_zk::process_bounded_disclosures(payload, disclosures, limits);
  return static_cast<bool>(result);
}

template <std::size_t Bits>
void set_bits(Logic& logic, typename Logic::template bitvec<Bits>& output,
              std::size_t value) {
  logic.bits(Bits, output.data(), value);
}

void set_bytes(Logic& logic, std::array<Logic::v8, 43>& output,
               char value) {
  for (auto& byte : output) byte = logic.template vbit<8>(value);
}

void set_path(Logic& logic, std::array<Logic::v8, 16>& output,
              Graph::Index& length, std::string_view value) {
  for (std::size_t i = 0; i < output.size(); ++i)
    output[i] = logic.template vbit<8>(
        i < value.size() ? static_cast<unsigned char>(value[i]) : 0);
  set_bits(logic, length, value.size());
}

enum class GraphMutation {
  none,
  wrong_kind,
  wrong_arity,
  duplicate_reference,
  cycle,
  bad_depth,
  bad_range,
  bad_path,
  bad_selected,
  bad_token,
  bad_shape,
  bad_marker,
  bad_string,
  bad_frame,
  bad_container,
  issuer_overflow,
  truncated_issuer,
  heterogeneous_source,
  bad_component,
  bad_index,
  bad_placeholder,
};

bool circuit_graph_accepts(GraphMutation mutation) {
  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  Graph::GraphInput graph{};
  set_bits(logic, graph.supplied_active, 2);
  set_bits(logic, graph.reference_active, 2);
  set_bits(logic, graph.source_lengths[0],
           mutation == GraphMutation::truncated_issuer ? 52 : 102);
  set_bits(logic, graph.source_lengths[1], 23);
  set_bits(logic, graph.source_lengths[2], 7);
  for (std::size_t slot = 0; slot < 2; ++slot) {
    auto& node = graph.nodes[slot];
    auto& reference = graph.references[slot];
    set_bytes(logic, node.supplied_digest, slot == 0 ? 'a' : 'b');
    set_bytes(logic, reference.digest, slot == 0 ? 'a' : 'b');
    node.kind = logic.template vbit<8>(
        slot == 0
            ? static_cast<unsigned char>(
                  sd_jwt_zk::DisclosureKind::object_property)
            : static_cast<unsigned char>(
                  sd_jwt_zk::DisclosureKind::array_element));
    reference.kind = node.kind;
    node.arity = logic.template vbit<8>(slot == 0 ? 3 : 2);
    set_bits(logic, node.source, slot + 1);
    set_bits(logic, node.parent, slot == 0 ? 0 : 1);
    set_bits(logic, node.depth, slot + 1);
    set_bits(logic, node.reference_index, slot);
    set_bits(logic, node.disclosure_begin, 0);
    set_bits(logic, node.disclosure_end, slot == 0 ? 23 : 7);
    set_bits(logic, node.value_begin, slot == 0 ? 9 : 5);
    set_bits(logic, node.value_end, slot == 0 ? 22 : 6);
    set_bits(logic, reference.source, slot == 0 ? 0 : 1);
    set_bits(logic, reference.begin, slot == 0 ? 8 : 17);
    set_bits(logic, reference.end,
             slot == 0 ? (mutation == GraphMutation::issuer_overflow ? 103
                                                                     : 53)
                       : 20);
  }
  set_path(logic, graph.nodes[0].path, graph.nodes[0].path_length, "/a");
  set_path(logic, graph.nodes[1].path, graph.nodes[1].path_length, "/a/0");

  if (mutation == GraphMutation::wrong_kind)
    graph.references[1].kind = logic.template vbit<8>(
        static_cast<unsigned char>(sd_jwt_zk::DisclosureKind::object_property));
  if (mutation == GraphMutation::wrong_arity)
    graph.nodes[0].arity = logic.template vbit<8>(2);
  if (mutation == GraphMutation::duplicate_reference)
    set_bits(logic, graph.nodes[1].reference_index, 0);
  if (mutation == GraphMutation::cycle)
    set_bits(logic, graph.nodes[0].parent, 2);
  if (mutation == GraphMutation::bad_depth)
    set_bits(logic, graph.nodes[1].depth, 1);
  if (mutation == GraphMutation::bad_range)
    set_bits(logic, graph.references[1].end, 61);
  if (mutation == GraphMutation::bad_path)
    set_path(logic, graph.nodes[1].path, graph.nodes[1].path_length, "/x/0");
  if (mutation == GraphMutation::heterogeneous_source)
    set_bits(logic, graph.nodes[0].source, 2);

  Graph relation(logic);
  relation.assert_graph(graph, 2, true);

  constexpr std::size_t token_slots = 13;
  using ParserTables = Graph::PlacementParserTables<
      3, token_slots, PlacementString, PlacementFrame, PlacementIds>;
  ParserTables parser_tables{};
  auto& tokens = parser_tables.tokens;
  auto& token_counts = parser_tables.token_counts;
  auto& strings = parser_tables.strings;
  auto& depths = parser_tables.depths;
  auto& frames = parser_tables.frames;
  auto& ids = parser_tables.container_ids;
  for (std::size_t source = 0; source < tokens.size(); ++source) {
    for (auto& token : tokens[source]) {
      token.kind = logic.template vbit<8>(0);
      set_bits(logic, token.begin, 0);
      set_bits(logic, token.end, 0);
    }
    for (auto& depth : depths[source]) set_bits(logic, depth, 0);
  }
  const auto token = [&](std::size_t source, std::size_t index,
                         sd_jwt_zk::JsonLexeme kind, std::size_t begin,
                         std::size_t end, std::size_t depth) {
    tokens[source][index].kind = logic.template vbit<8>(
        static_cast<unsigned char>(kind));
    set_bits(logic, tokens[source][index].begin, begin);
    set_bits(logic, tokens[source][index].end, end);
    set_bits(logic, depths[source][index], depth);
  };
  set_bits(logic, token_counts[0], 7);
  token(0, 0, sd_jwt_zk::JsonLexeme::object_open, 0, 1, 1);
  token(0, 1, sd_jwt_zk::JsonLexeme::string, 1, 6, 2);
  token(0, 2, sd_jwt_zk::JsonLexeme::colon, 6, 7, 2);
  token(0, 3, sd_jwt_zk::JsonLexeme::array_open, 7, 8, 2);
  token(0, 4, sd_jwt_zk::JsonLexeme::string,
        mutation == GraphMutation::bad_token ? 9 : 8, 53, 3);
  token(0, 5, sd_jwt_zk::JsonLexeme::array_close, 53, 54, 3);
  token(0, 6, sd_jwt_zk::JsonLexeme::object_close, 54, 55, 2);
  set_bits(logic, token_counts[1], 13);
  token(1, 0, sd_jwt_zk::JsonLexeme::array_open, 0, 1, 1);
  token(1, 1, sd_jwt_zk::JsonLexeme::string, 1, 4, 2);
  token(1, 2, sd_jwt_zk::JsonLexeme::comma, 4, 5, 2);
  token(1, 3,
        mutation == GraphMutation::bad_shape ? sd_jwt_zk::JsonLexeme::number
                                             : sd_jwt_zk::JsonLexeme::string,
        5, 8, 2);
  token(1, 4, sd_jwt_zk::JsonLexeme::comma, 8, 9, 2);
  token(1, 5, sd_jwt_zk::JsonLexeme::array_open, 9, 10, 2);
  token(1, 6, sd_jwt_zk::JsonLexeme::object_open, 10, 11, 3);
  token(1, 7, sd_jwt_zk::JsonLexeme::string, 11, 16, 4);
  token(1, 8, sd_jwt_zk::JsonLexeme::colon, 16, 17, 4);
  token(1, 9, sd_jwt_zk::JsonLexeme::string, 17, 20, 4);
  token(1, 10, sd_jwt_zk::JsonLexeme::object_close, 20, 21, 4);
  token(1, 11, sd_jwt_zk::JsonLexeme::array_close, 21, 22, 3);
  token(1, 12, sd_jwt_zk::JsonLexeme::array_close, 22, 23, 2);
  set_bits(logic, token_counts[2], 5);
  token(2, 0, sd_jwt_zk::JsonLexeme::array_open, 0, 1, 1);
  token(2, 1, sd_jwt_zk::JsonLexeme::string, 1, 4, 2);
  token(2, 2, sd_jwt_zk::JsonLexeme::comma, 4, 5, 2);
  token(2, 3, sd_jwt_zk::JsonLexeme::number, 5, 6, 2);
  token(2, 4, sd_jwt_zk::JsonLexeme::array_close, 6, 7, 2);
  relation.assert_token_ranges(graph, tokens, token_counts);
  relation.assert_disclosure_shape(graph.nodes[0], token_counts[1], tokens[1],
                                   depths[1], logic.bit(1));
  relation.assert_disclosure_shape(graph.nodes[1], token_counts[2], tokens[2],
                                   depths[2], logic.bit(1));

  for (std::size_t source = 0; source < 3; ++source) {
    for (std::size_t token_index = 0; token_index < token_slots;
         ++token_index) {
      set_bits(logic, strings[source][token_index].unit_count, 0);
      for (auto& unit : strings[source][token_index].units)
        set_bits(logic, unit.codepoint, 0);
    }
    for (std::size_t step = 0; step <= token_slots; ++step) {
      for (auto& frame : frames[source][step])
        frame = logic.template vbit<8>(0);
      for (auto& id : ids[source][step]) set_bits(logic, id, 0);
    }
  }
  const auto decoded_string = [&](std::size_t source, std::size_t token_index,
                                  std::string_view value) {
    set_bits(logic, strings[source][token_index].unit_count, value.size());
    for (std::size_t index = 0; index < value.size(); ++index)
      set_bits(logic, strings[source][token_index].units[index].codepoint,
               static_cast<unsigned char>(value[index]));
  };
  decoded_string(0, 1,
                 mutation == GraphMutation::bad_string ? "xsd" : "_sd");
  decoded_string(0, 4, std::string(43, 'a'));
  decoded_string(1, 3, "a");
  decoded_string(1, 7, "...");
  decoded_string(1, 9, std::string(43, 'b'));
  frames[0][1][1] = logic.template vbit<8>(
      mutation == GraphMutation::bad_frame ? 6 : 3);
  frames[1][7][3] = logic.template vbit<8>(3);
  set_bits(logic, ids[0][4][2],
           mutation == GraphMutation::bad_container ? 5 : 4);
  set_bits(logic, ids[1][7][3], 7);  // Placeholder object opener 6 + 1.
  set_bits(logic, ids[1][7][2], 6);  // Parent array opener 5 + 1.

  std::array<Graph::Placement, 2> placements{};
  for (auto& placement : placements) {
    for (auto* field : {&placement.marker_token, &placement.colon_token,
                        &placement.value_open_token,
                        &placement.reference_token,
                        &placement.object_open_token,
                        &placement.object_close_token,
                        &placement.parent_array_open_token,
                        &placement.component_token, &placement.array_index})
      set_bits(logic, *field, 0);
  }
  set_bits(logic, placements[0].marker_token,
           mutation == GraphMutation::bad_marker ? 0 : 1);
  set_bits(logic, placements[0].colon_token, 2);
  set_bits(logic, placements[0].value_open_token, 3);
  set_bits(logic, placements[0].reference_token, 4);
  set_bits(logic, placements[0].component_token,
           mutation == GraphMutation::bad_component ? 1 : 3);
  set_bits(logic, placements[1].marker_token, 7);
  set_bits(logic, placements[1].colon_token, 8);
  set_bits(logic, placements[1].reference_token, 9);
  set_bits(logic, placements[1].object_open_token, 6);
  set_bits(logic, placements[1].object_close_token,
           mutation == GraphMutation::bad_placeholder ? 11 : 10);
  set_bits(logic, placements[1].parent_array_open_token, 5);
  set_bits(logic, placements[1].array_index,
           mutation == GraphMutation::bad_index ? 1 : 0);
  relation.assert_reference_placements(graph, placements, parser_tables);

  std::array<Graph::SelectedResult, 1> selected{};
  set_bits(logic, selected[0].node_index, 1);
  set_path(logic, selected[0].path, selected[0].path_length,
           mutation == GraphMutation::bad_selected ? "/a/1" : "/a/0");
  selected[0].kind = graph.nodes[1].kind;
  set_bits(logic, selected[0].source, 2);
  set_bits(logic, selected[0].value_begin, 5);
  set_bits(logic, selected[0].value_end, 6);
  Graph::Index selected_active{};
  set_bits(logic, selected_active, 1);
  relation.assert_selected_results(graph, selected, selected_active);
  std::array<Graph::AuthenticatedSelectedResult, 1> authenticated{};
  set_bits(logic, authenticated[0].node_index, 1);
  authenticated[0].kind = graph.nodes[1].kind;
  set_bits(logic, authenticated[0].component_token, 0);
  set_bits(logic, authenticated[0].array_index,
           mutation == GraphMutation::bad_selected ? 1 : 0);
  set_bits(logic, authenticated[0].source, 2);
  set_bits(logic, authenticated[0].value_begin, 5);
  set_bits(logic, authenticated[0].value_end, 6);
  relation.assert_authenticated_selected_results(
      graph, placements, authenticated, selected_active);
  return !backend.assertion_failed();
}

proofs::Fp256Nat digest_nat(const std::array<std::uint8_t, 32>& bytes) {
  std::array<std::uint8_t, 32> little{};
  for (std::size_t i = 0; i < bytes.size(); ++i)
    little[i] = bytes[bytes.size() - 1 - i];
  return proofs::Fp256Nat::of_bytes(little.data());
}

bool circuit_digest_accepts(bool mutate_ascii, bool mutate_reference,
                            bool live = true,
                            bool mutate_decoded_length = false) {
  constexpr std::string_view encoded = "WyJzIiwibiIsMV0";
  constexpr std::size_t capacity = 20;
  const std::string disclosure = live ? std::string(encoded) : "MA";
  const auto hash = sd_jwt_zk::sha256_ascii(disclosure);
  const auto hash_text = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(hash.begin(), hash.end()));
  std::array<std::uint8_t, 64> padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 1> raw{};
  std::uint8_t blocks = 0;
  proofs::FlatSHA256Witness::transform_and_witness_message(
      disclosure.size(),
      reinterpret_cast<const std::uint8_t*>(disclosure.data()), 1, blocks,
      padded.data(), raw.data());
  if (blocks != 1 || hash_text.size() != 43) return false;

  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  Graph::Node node{};
  for (std::size_t i = 0; i < node.supplied_digest.size(); ++i)
    node.supplied_digest[i] = logic.template vbit<8>(
        static_cast<unsigned char>(hash_text[i]) ^
        static_cast<unsigned char>(mutate_reference && i == 0));
  std::array<Logic::v8, capacity> ascii{};
  for (std::size_t i = 0; i < ascii.size(); ++i)
    ascii[i] = logic.template vbit<8>(
        static_cast<unsigned char>(i < disclosure.size() ? disclosure[i] : 0) ^
        static_cast<unsigned char>(mutate_ascii && i == 0));
  std::array<Logic::v8, 64> sha_input{};
  for (std::size_t i = 0; i < sha_input.size(); ++i)
    sha_input[i] = logic.template vbit<8>(padded[i]);
  proofs::BitPluckerEncoder<Field, 4> encoder(proofs::p256_base);
  std::array<Sha::BlockWitness, 1> witness{};
  for (std::size_t i = 0; i < 48; ++i)
    witness[0].outw[i] =
        logic.konst(encoder.mkpacked_v32(raw[0].outw[i]));
  for (std::size_t i = 0; i < 64; ++i) {
    witness[0].oute[i] =
        logic.konst(encoder.mkpacked_v32(raw[0].oute[i]));
    witness[0].outa[i] =
        logic.konst(encoder.mkpacked_v32(raw[0].outa[i]));
  }
  for (std::size_t i = 0; i < 8; ++i)
    witness[0].h1[i] = logic.konst(encoder.mkpacked_v32(raw[0].h1[i]));
  const auto natural = digest_nat(hash);
  Logic::v256 digest_bits{};
  for (std::size_t i = 0; i < digest_bits.size(); ++i)
    digest_bits[i] = logic.bit(natural.bit(i));
  Graph::Index active_length{};
  set_bits(logic, active_length, disclosure.size());
  Graph::Index decoded_length{};
  set_bits(logic, decoded_length,
           (disclosure.size() * 6) / 8 + mutate_decoded_length);
  std::array<Logic::v8, (capacity * 6) / 8> decoded_json{};
  const auto decoded = sd_jwt_zk::base64url_decode(disclosure);
  if (!decoded) return false;
  for (std::size_t i = 0; i < decoded_json.size(); ++i)
    decoded_json[i] = logic.template vbit<8>(
        i < decoded.value->size() ? (*decoded.value)[i] : 0);
  const auto block_count = logic.template vbit<8>(blocks);
  Graph(logic).assert_bounded_digest_link<1, capacity>(
      node, ascii, active_length, decoded_json, decoded_length, sha_input,
      witness, digest_bits, block_count, logic.bit(live));
  return !backend.assertion_failed();
}

}  // namespace

int main() {
  int code = 1;

  // RFC object-property disclosure.
  const auto flat = encode("[\"salt\",\"family_name\",\"Möbius\"]");
  if (!expect(accepts("{\"_sd\":[\"" + digest(flat) + "\"]}", {flat}),
              code++, "RFC object disclosure"))
    return code - 1;
  const std::string issuer_102 =
      "{\"_sd\":[\"" + digest(flat) + "\"],\"pad\":\"" +
      std::string(38, 'p') + "\"}";
  if (!expect(issuer_102.size() == 102 && accepts(issuer_102, {flat}), code++,
              "102-byte issuer and 8-bit source ranges"))
    return code - 1;

  // RFC array replacement keeps the issuer-signed array index in the path.
  const auto array_item = encode("[\"salt\",true]");
  const std::string array_payload =
      "{\"items\":[0,{\"...\":\"" + digest(array_item) + "\"},2]}";
  DisclosureProcessingRequest array_request;
  array_request.selected_paths = {"/items/1"};
  auto array_result = sd_jwt_zk::process_bounded_disclosures(
      array_payload, {array_item}, array_request);
  if (!expect(array_result && array_result.value->selected.size() == 1 &&
                  array_result.value->selected[0].path == "/items/1" &&
                  array_result.value->selected[0].value_json == "true",
              code++, "RFC array disclosure and selected result binding"))
    return code - 1;
  DisclosureProcessingRequest wrong_array_index;
  wrong_array_index.selected_paths = {"/items/0"};
  if (!expect(!sd_jwt_zk::process_bounded_disclosures(
                  array_payload, {array_item}, wrong_array_index),
              code++, "array order/index mutation"))
    return code - 1;

  // A recursive disclosed value authenticates its child through the parent.
  const auto child = encode("[\"s2\",\"child\",{\"ok\":true}]");
  const auto parent = encode("[\"s1\",\"parent\",{\"_sd\":[\"" +
                             digest(child) + "\"]}]");
  DisclosureProcessingLimits recursive_limits;
  recursive_limits.allow_structured_nonrecursive = true;
  const auto recursive = sd_jwt_zk::build_bounded_disclosure_graph(
      "{\"_sd\":[\"" + digest(parent) + "\"]}", {parent, child},
      recursive_limits);
  if (!expect(recursive && recursive.value->nodes.size() == 2 &&
                  recursive.value->nodes[0].path == "/parent" &&
                  recursive.value->nodes[1].path == "/parent/child" &&
                  recursive.value->nodes[1].parent == 0 &&
                  recursive.value->nodes[1].depth == 2,
              code++, "recursive authenticated graph")) {
    if (!recursive && recursive.error)
      std::cerr << "recursive error: " << recursive.error->message << '\n';
    return code - 1;
  }
  const auto array_graph = sd_jwt_zk::build_bounded_disclosure_graph(
      array_payload, {array_item});
  if (!expect(array_graph && array_graph.value->nodes.size() == 1 &&
                  array_graph.value->nodes[0].placement.array_index == 1 &&
                  array_graph.value->nodes[0].placement.marker_token <
                      array_graph.value->nodes[0].placement.reference_token,
              code++, "native parser-derived array placement/index"))
    return code - 1;
  const auto escaped_table =
      sd_jwt_zk::build_bounded_json_placement_table(
          "{\"\\u005f\\u0073\\u0064\":[\"x\"]}");
  if (!expect(
          escaped_table && escaped_table.value->tokens.size() == 7 &&
              escaped_table.value->strings[1].size() == 3 &&
              escaped_table.value->strings[1][0].codepoint == '_' &&
              escaped_table.value->strings[1][1].codepoint == 's' &&
              escaped_table.value->strings[1][2].codepoint == 'd' &&
              escaped_table.value->depths[4] == 3 &&
              escaped_table.value->frames[1][1] == 3 &&
              escaped_table.value->container_ids[4][2] == 4,
          code++, "native decoded string/frame/container placement table"))
    return code - 1;

  // Independent Swiss-shaped fixture: complete issuer image, explicit
  // algorithm, recursive object claim, and an authenticated array element.
  const auto swiss_leaf = encode("[\"ch-s2\",\"given_name\",\"Ada\"]");
  const auto swiss_parent = encode(
      "[\"ch-s1\",\"person\",{\"_sd\":[\"" + digest(swiss_leaf) +
      "\"]}]");
  const auto swiss_array = encode("[\"ch-a1\",\"CHE\"]");
  const std::string swiss_payload =
      "{\"vct\":\"urn:ch:example\",\"_sd_alg\":\"sha-256\",\"_sd\":[\"" +
      digest(swiss_parent) + "\"],\"nationalities\":[{\"...\":\"" +
      digest(swiss_array) + "\"}]}";
  DisclosureProcessingRequest swiss_request;
  swiss_request.limits.allow_structured_nonrecursive = true;
  swiss_request.selected_paths = {"/person/given_name", "/nationalities/0"};
  const auto swiss = sd_jwt_zk::process_bounded_disclosures(
      swiss_payload, {swiss_parent, swiss_leaf, swiss_array}, swiss_request);
  if (!expect(swiss && swiss.value->resolved_disclosure_count == 3 &&
                  swiss.value->selected.size() == 2 &&
                  swiss.value->selected[0].value_json == "\"Ada\"" &&
                  swiss.value->selected[1].value_json == "\"CHE\"",
              code++, "independent Swiss recursive/array fixture"))
    return code - 1;

  // Structured but non-recursive values are outside the Swiss support shape.
  const auto structured = encode("[\"s\",\"claim\",{\"plain\":1}]");
  if (!expect(!accepts("{\"_sd\":[\"" + digest(structured) + "\"]}",
                       {structured}),
              code++, "structured non-recursive rejection"))
    return code - 1;

  // Decoys/unresolved digests fail a complete holder credential, while a
  // presentation may omit an unopened disclosure from its supplied subset.
  const auto opened = encode("[\"s\",\"opened\",1]");
  const auto hidden = encode("[\"s\",\"hidden\",2]");
  const std::string selective_payload =
      "{\"_sd\":[\"" + digest(opened) + "\",\"" + digest(hidden) + "\"]}";
  if (!expect(!accepts(selective_payload, {opened}), code++,
              "issuance completeness/no-decoy rejection"))
    return code - 1;
  DisclosureProcessingRequest selective_request;
  selective_request.limits.require_issuance_completeness = false;
  selective_request.selected_paths = {"/opened"};
  const auto selective = sd_jwt_zk::process_bounded_disclosures(
      selective_payload, {opened}, selective_request);
  if (!expect(selective && selective.value->selected.size() == 1 &&
                  selective.value->selected[0].value_json == "1" &&
                  selective.value->signed_digest_count == 2,
              code++, "private selected presentation subset"))
    return code - 1;

  if (!expect(!accepts("{\"_sd\":[\"" + digest(opened) + "\",\"" +
                           digest(opened) + "\"]}",
                       {opened}),
              code++, "duplicate signed digest occurrence"))
    return code - 1;
  if (!expect(!accepts("{\"_sd\":[\"" + digest(opened) + "\"]}",
                       {opened, opened}),
              code++, "duplicate supplied disclosure"))
    return code - 1;
  if (!expect(!accepts("{\"items\":[{\"...\":\"" + digest(opened) +
                           "\"}]}",
                       {opened}),
              code++, "object disclosure at array placeholder"))
    return code - 1;
  if (!expect(!accepts("{\"_sd\":[\"" + digest(array_item) + "\"]}",
                       {array_item}),
              code++, "array disclosure at object reference"))
    return code - 1;
  if (!expect(!accepts("{\"items\":[{\"...\":7}]}", {}), code++,
              "wrong array placeholder"))
    return code - 1;
  if (!expect(!accepts("{\"items\":[{\"...\":\"" + digest(array_item) +
                           "\",\"extra\":1}]}",
                       {array_item}),
              code++, "non-exact array placeholder object"))
    return code - 1;
  if (!expect(!accepts("{}", {opened}), code++, "unused disclosure"))
    return code - 1;

  DisclosureProcessingLimits shallow = recursive_limits;
  shallow.max_disclosure_depth = 1;
  if (!expect(!accepts("{\"_sd\":[\"" + digest(parent) + "\"]}",
                       {parent, child}, shallow),
              code++, "excess disclosure-chain depth"))
    return code - 1;

  const auto nested_algorithm =
      encode("[\"s\",\"claim\",{\"_sd_alg\":\"sha-256\",\"x\":1}]");
  DisclosureProcessingLimits generic = recursive_limits;
  if (!expect(!accepts("{\"_sd\":[\"" + digest(nested_algorithm) + "\"]}",
                       {nested_algorithm}, generic),
              code++, "nested algorithm rejection"))
    return code - 1;
  if (!expect(!accepts("{\"_sd_alg\":\"sha-512\",\"_sd\":[\"" +
                           digest(opened) + "\"]}",
                       {opened}),
              code++, "unsupported root algorithm rejection"))
    return code - 1;

  const auto colliding = encode("[\"s\",\"name\",\"hidden\"]");
  if (!expect(!accepts("{\"name\":\"plain\",\"_sd\":[\"" +
                           digest(colliding) + "\"]}",
                       {colliding}),
              code++, "duplicate replacement path"))
    return code - 1;

  DisclosureProcessingRequest bad_selection;
  bad_selection.selected_paths = {"/not-opened"};
  if (!expect(!sd_jwt_zk::process_bounded_disclosures(
                  "{\"_sd\":[\"" + digest(opened) + "\"]}", {opened},
                  bad_selection),
              code++, "selected path must bind to resolved value"))
    return code - 1;

  // Native graph validation independently rejects forged cycles and ranges.
  auto forged = *recursive.value;
  forged.nodes[0].parent = 1;
  const std::string recursive_payload =
      "{\"_sd\":[\"" + digest(parent) + "\"]}";
  if (!expect(!sd_jwt_zk::validate_bounded_disclosure_graph(
                  forged, {parent, child}, recursive_payload,
                  recursive_limits),
              code++, "forged disclosure cycle"))
    return code - 1;
  forged = *recursive.value;
  forged.nodes[1].reference.end = 9999;
  if (!expect(!sd_jwt_zk::validate_bounded_disclosure_graph(
                  forged, {parent, child}, recursive_payload,
                  recursive_limits),
              code++, "forged tokenizer range"))
    return code - 1;
  forged = *recursive.value;
  ++forged.nodes[0].placement.component_token;
  if (!expect(!sd_jwt_zk::validate_bounded_disclosure_graph(
                  forged, {parent, child}, recursive_payload,
                  recursive_limits),
              code++, "forged native object path component"))
    return code - 1;
  auto forged_array = *array_graph.value;
  forged_array.nodes[0].placement.array_index = 0;
  if (!expect(!sd_jwt_zk::validate_bounded_disclosure_graph(
                  forged_array, {array_item}, array_payload),
              code++, "forged native array index"))
    return code - 1;
  forged = *recursive.value;
  ++forged.source_parser_tables[0].strings[1][0].codepoint;
  if (!expect(!sd_jwt_zk::validate_bounded_disclosure_graph(
                  forged, {parent, child}, recursive_payload,
                  recursive_limits),
              code++, "forged native decoded marker string"))
    return code - 1;
  forged = *recursive.value;
  ++forged.source_parser_tables[0].frames[1][1];
  if (!expect(!sd_jwt_zk::validate_bounded_disclosure_graph(
                  forged, {parent, child}, recursive_payload,
                  recursive_limits),
              code++, "forged native parser frame"))
    return code - 1;
  forged = *recursive.value;
  ++forged.source_parser_tables[0].container_ids[4][2];
  if (!expect(!sd_jwt_zk::validate_bounded_disclosure_graph(
                  forged, {parent, child}, recursive_payload,
                  recursive_limits),
              code++, "forged native parser container ID"))
    return code - 1;

  if (!expect(circuit_graph_accepts(GraphMutation::none), code++,
              "EvaluationBackend bounded graph positive"))
    return code - 1;
  for (const auto mutation : {GraphMutation::wrong_kind,
                              GraphMutation::wrong_arity,
                              GraphMutation::duplicate_reference,
                              GraphMutation::cycle,
                              GraphMutation::bad_depth,
                              GraphMutation::bad_range,
                              GraphMutation::bad_path,
                              GraphMutation::bad_selected,
                              GraphMutation::bad_token,
                              GraphMutation::bad_shape,
                              GraphMutation::bad_marker,
                              GraphMutation::bad_string,
                              GraphMutation::bad_frame,
                              GraphMutation::bad_container,
                              GraphMutation::issuer_overflow,
                              GraphMutation::truncated_issuer,
                              GraphMutation::heterogeneous_source,
                              GraphMutation::bad_component,
                              GraphMutation::bad_index,
                              GraphMutation::bad_placeholder}) {
    if (!expect(!circuit_graph_accepts(mutation), code++,
                "EvaluationBackend graph mutation rejection"))
      return code - 1;
  }
  if (!expect(circuit_digest_accepts(false, false), code++,
              "circuit exact SHA-256/base64url binding"))
    return code - 1;
  if (!expect(!circuit_digest_accepts(true, false), code++,
              "circuit disclosure ASCII mutation rejection"))
    return code - 1;
  if (!expect(!circuit_digest_accepts(false, true), code++,
              "circuit digest base64url mutation rejection"))
    return code - 1;
  if (!expect(circuit_digest_accepts(false, false, false), code++,
              "circuit canonical inactive SHA slot"))
    return code - 1;
  if (!expect(!circuit_digest_accepts(false, false, true, true), code++,
              "circuit decoded JSON length mutation rejection"))
    return code - 1;

  return 0;
}
