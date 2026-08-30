#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "sd_jwt_zk/bounded_json_circuit.h"
#include "sd_jwt_zk/bounded_json_relation.h"
#include "sd_jwt_zk/disclosure_processing.h"
#include "sd_jwt_zk/flat_disclosure_relation.h"

namespace sd_jwt_zk {

// EXPERIMENTAL/DEFERRED SUPPORT ONLY: this retained full-family graph plumbing
// serves historical diagnostics. The supported L6 proof gate is fixed,
// non-recursive, and two-slot; this API is not Swiss-profile conformance.

// Circuit mirror of DisclosureGraphWitness. A parent is encoded as zero for
// the issuer root and node-index+1 otherwise. Source zero is the issuer JSON;
// disclosure sources are one-based. This topological representation makes a
// back-edge/cycle unsatisfiable instead of trusting host-provided depth labels.
template <class LogicCircuit, std::size_t Slots, std::size_t IndexBits = 6,
          std::size_t PathBytes = 64>
class FullDisclosureGraphRelation {
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using Plucker = proofs::BitPlucker<LogicCircuit, 4>;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit, Plucker>;

 public:
  using Index = typename LogicCircuit::template bitvec<IndexBits>;

  struct Reference {
    std::array<v8, 43> digest{};
    v8 kind{};
    Index source{};
    Index begin{};
    Index end{};
  };

  struct Node {
    std::array<v8, 43> supplied_digest{};
    v8 kind{};
    v8 arity{};
    Index source{};
    Index parent{};
    Index depth{};
    Index reference_index{};
    Index disclosure_begin{};
    Index disclosure_end{};
    Index value_begin{};
    Index value_end{};
    std::array<v8, PathBytes> path{};
    Index path_length{};
  };

  struct GraphInput {
    std::array<Node, Slots> nodes{};
    std::array<Reference, Slots> references{};
    Index supplied_active{};
    Index reference_active{};
    std::array<Index, Slots + 1> source_lengths{};
  };

  struct RangeToken {
    v8 kind{};
    Index begin{};
    Index end{};
  };

  struct SelectedResult {
    Index node_index{};
    std::array<v8, PathBytes> path{};
    Index path_length{};
    v8 kind{};
    Index source{};
    Index value_begin{};
    Index value_end{};
  };

  // Parser-derived structural path component. Object nodes authenticate the
  // second disclosure item (`component_token`). Array nodes authenticate the
  // exact one-member placeholder and derive `array_index` from preceding
  // sibling commas in its parent array.
  struct Placement {
    Index marker_token{};
    Index colon_token{};
    Index value_open_token{};
    Index reference_token{};
    Index object_open_token{};
    Index object_close_token{};
    Index parent_array_open_token{};
    Index component_token{};
    Index array_index{};
  };

  // Canonical view of each constrained bounded JSON parser. These fields must
  // alias the wires already passed to BoundedJsonTokenRelation::assert_json;
  // they are not a second advice allocation. The view field order is token
  // triples (kind/begin/end), token_count, decoded string witnesses, parser
  // depths, parser frames, then container opener IDs. `depths`, `frames`, and
  // `container_ids` are parser states before token i, including the final
  // state at i == token_count. Unused token/string slots and state rows after
  // token_count are all-zero padding. An inactive disclosure source uses the
  // canonical accepted JSON text `0`: token_count=1, token[0]=number/[0,1),
  // depths[0]=depths[1]=1, frames[0][0]=root-value(1),
  // frames[1][0]=root-done(2), and every string/container/padded cell is zero.
  template <std::size_t Sources, std::size_t TokenSlots,
            class StringWitness, class GrammarStack,
            class ContainerIdStack>
  struct PlacementParserTables {
    static_assert(Sources == Slots + 1);
    std::array<std::array<RangeToken, TokenSlots>, Sources> tokens{};
    std::array<Index, Sources> token_counts{};
    std::array<std::array<StringWitness, TokenSlots>, Sources> strings{};
    std::array<std::array<Index, TokenSlots + 1>, Sources> depths{};
    std::array<std::array<GrammarStack, TokenSlots + 1>, Sources> frames{};
    std::array<std::array<ContainerIdStack, TokenSlots + 1>, Sources>
        container_ids{};
  };

  struct AuthenticatedSelectedResult {
    Index node_index{};
    v8 kind{};
    Index component_token{};
    Index array_index{};
    Index source{};
    Index value_begin{};
    Index value_end{};
  };

  explicit FullDisclosureGraphRelation(const LogicCircuit& logic)
      : logic_(logic) {}

  // Full cardinality, topology, shape, range, and padding relation. When
  // issuance_complete is false unresolved signed references may remain, but
  // every supplied disclosure must still have exactly one reference.
  void assert_graph(const GraphInput& graph, std::size_t max_depth,
                    bool issuance_complete) const {
    logic_.assert1(logic_.vleq(graph.supplied_active, Slots));
    logic_.assert1(logic_.vleq(graph.reference_active, Slots));
    if (issuance_complete)
      logic_.vassert_eq(graph.supplied_active, graph.reference_active);

    for (std::size_t slot = 0; slot < Slots; ++slot) {
      const auto live = logic_.vlt(slot, graph.supplied_active);
      const auto kind_ok = logic_.lor_exclusive(
          logic_.veq(graph.nodes[slot].kind,
                     static_cast<unsigned char>(DisclosureKind::object_property)),
          logic_.veq(graph.nodes[slot].kind,
                     static_cast<unsigned char>(DisclosureKind::array_element)));
      logic_.assert_implies(live, kind_ok);
      logic_.assert_implies(
          logic_.land(live, logic_.veq(graph.nodes[slot].kind,
                                       static_cast<unsigned char>(
                                           DisclosureKind::object_property))),
          logic_.veq(graph.nodes[slot].arity, 3));
      logic_.assert_implies(
          logic_.land(live, logic_.veq(graph.nodes[slot].kind,
                                       static_cast<unsigned char>(
                                           DisclosureKind::array_element))),
          logic_.veq(graph.nodes[slot].arity, 2));
      logic_.assert_implies(live, logic_.vlt(0, graph.nodes[slot].source));
      logic_.assert_implies(live, logic_.vleq(graph.nodes[slot].source, Slots));
      logic_.assert_implies(live,
                            logic_.vlt(graph.nodes[slot].disclosure_begin,
                                       graph.nodes[slot].disclosure_end));
      logic_.assert_implies(live,
                            logic_.vleq(graph.nodes[slot].disclosure_end,
                                        selected_source_length(
                                            graph.nodes[slot].source,
                                            graph.source_lengths)));
      logic_.assert_implies(live,
                            logic_.vleq(graph.nodes[slot].disclosure_begin,
                                        graph.nodes[slot].value_begin));
      logic_.assert_implies(live,
                            logic_.vlt(graph.nodes[slot].value_begin,
                                       graph.nodes[slot].value_end));
      logic_.assert_implies(live,
                            logic_.vleq(graph.nodes[slot].value_end,
                                        graph.nodes[slot].disclosure_end));
      assert_path_padding(graph.nodes[slot].path,
                          graph.nodes[slot].path_length, live);

      BitW valid_parent = logic_.bit(0);
      const auto root = logic_.land(live, logic_.veq(graph.nodes[slot].parent, 0));
      valid_parent = logic_.lor_exclusive(valid_parent, root);
      logic_.assert_implies(root, logic_.veq(graph.nodes[slot].depth, 1));
      for (std::size_t parent = 0; parent < slot; ++parent) {
        const auto selected = logic_.land(
            live, logic_.veq(graph.nodes[slot].parent, parent + 1));
        valid_parent = logic_.lor_exclusive(valid_parent, selected);
        logic_.assert_implies(selected,
                              logic_.vlt(parent, graph.supplied_active));
        for (std::size_t depth = 1; depth < max_depth; ++depth) {
          logic_.assert_implies(
              logic_.land(selected,
                          logic_.veq(graph.nodes[parent].depth, depth)),
              logic_.veq(graph.nodes[slot].depth, depth + 1));
        }
        logic_.assert_implies(
            logic_.land(selected,
                        logic_.veq(graph.nodes[parent].depth, max_depth)),
            logic_.bit(0));
        for (std::size_t parent_length = 1; parent_length < PathBytes;
             ++parent_length) {
          const auto length_selected = logic_.land(
              selected,
              logic_.veq(graph.nodes[parent].path_length, parent_length));
          logic_.assert_implies(
              length_selected,
              logic_.vlt(parent_length, graph.nodes[slot].path_length));
          logic_.assert_implies(
              length_selected,
              logic_.veq(graph.nodes[slot].path[parent_length], '/'));
          for (std::size_t byte = 0; byte < parent_length; ++byte)
            logic_.assert_implies(
                length_selected,
                logic_.veq(graph.nodes[slot].path[byte],
                           graph.nodes[parent].path[byte]));
        }
      }
      logic_.assert_implies(live, valid_parent);
      logic_.assert_implies(live,
                            logic_.vleq(graph.nodes[slot].depth, max_depth));

      BitW selected_reference = logic_.bit(0);
      for (std::size_t reference = 0; reference < Slots; ++reference) {
        const auto selected = logic_.land(
            live, logic_.veq(graph.nodes[slot].reference_index, reference));
        selected_reference = logic_.lor_exclusive(selected_reference, selected);
        logic_.assert_implies(selected,
                              logic_.vlt(reference, graph.reference_active));
        logic_.assert_implies(
            selected,
            same_digest(graph.nodes[slot].supplied_digest,
                        graph.references[reference].digest));
        logic_.assert_implies(
            selected, logic_.veq(graph.nodes[slot].kind,
                                 graph.references[reference].kind));
        const auto root_source = logic_.veq(graph.nodes[slot].parent, 0);
        logic_.assert_implies(logic_.land(selected, root_source),
                              logic_.veq(graph.references[reference].source, 0));
        for (std::size_t parent = 0; parent < slot; ++parent) {
          const auto parent_selected = logic_.land(
              selected,
              logic_.veq(graph.nodes[slot].parent, parent + 1));
          logic_.assert_implies(
              parent_selected,
              logic_.veq(graph.references[reference].source,
                          graph.nodes[parent].source));
        }
      }
      logic_.assert_implies(live, selected_reference);

      if (slot > 0) {
        for (std::size_t earlier = 0; earlier < slot; ++earlier) {
          const auto both = logic_.land(live,
                                        logic_.vlt(earlier,
                                                   graph.supplied_active));
          logic_.assert_implies(
              both,
              logic_.lnot(same_digest(graph.nodes[slot].supplied_digest,
                                      graph.nodes[earlier].supplied_digest)));
          logic_.assert_implies(
              both, logic_.lnot(logic_.veq(graph.nodes[slot].source,
                                           graph.nodes[earlier].source)));
          logic_.assert_implies(
              both,
              logic_.lnot(logic_.veq(graph.nodes[slot].reference_index,
                                     graph.nodes[earlier].reference_index)));
          logic_.assert_implies(
              both,
              logic_.lnot(same_path(graph.nodes[slot],
                                    graph.nodes[earlier])));
        }
      }
      assert_inactive_node(graph.nodes[slot], logic_.lnot(live));
    }

    for (std::size_t reference = 0; reference < Slots; ++reference) {
      const auto live = logic_.vlt(reference, graph.reference_active);
      logic_.assert_implies(
          live,
          logic_.lor_exclusive(
              logic_.veq(graph.references[reference].kind,
                         static_cast<unsigned char>(
                             DisclosureKind::object_property)),
              logic_.veq(graph.references[reference].kind,
                         static_cast<unsigned char>(
                             DisclosureKind::array_element))));
      logic_.assert_implies(live,
                            logic_.vlt(graph.references[reference].begin,
                                       graph.references[reference].end));
      logic_.assert_implies(
          live, logic_.vleq(graph.references[reference].end,
                            selected_source_length(
                                graph.references[reference].source,
                                graph.source_lengths)));
      BitW uses = logic_.bit(0);
      for (std::size_t node = 0; node < Slots; ++node) {
        uses = logic_.lor_exclusive(
            uses, logic_.land(logic_.vlt(node, graph.supplied_active),
                              logic_.veq(graph.nodes[node].reference_index,
                                         reference)));
      }
      if (issuance_complete) logic_.assert_implies(live, uses);
      for (std::size_t earlier = 0; earlier < reference; ++earlier) {
        logic_.assert_implies(
            logic_.land(live,
                        logic_.vlt(earlier, graph.reference_active)),
            logic_.lnot(same_digest(graph.references[reference].digest,
                                    graph.references[earlier].digest)));
      }
      assert_inactive_reference(graph.references[reference],
                                logic_.lnot(live));
    }
  }

  // Bind every reference and every node range to the same constrained token
  // tables consumed by BoundedJsonTokenRelation. Reference ranges must be
  // exact string tokens; disclosure/value ranges must start and end on token
  // boundaries in their declared source.
  template <std::size_t Sources, std::size_t TokenSlots>
  void assert_token_ranges(
      const GraphInput& graph,
      const std::array<std::array<RangeToken, TokenSlots>, Sources>& tokens,
      const std::array<Index, Sources>& token_counts) const {
    static_assert(Sources == Slots + 1);
    for (std::size_t reference = 0; reference < Slots; ++reference) {
      const auto live = logic_.vlt(reference, graph.reference_active);
      BitW exact = logic_.bit(0);
      for (std::size_t source = 0; source < Sources; ++source) {
        for (std::size_t token = 0; token < TokenSlots; ++token) {
          const auto selected = logic_.land(
              live,
              logic_.land(
                  logic_.veq(graph.references[reference].source, source),
                  logic_.land(
                      logic_.vlt(token, token_counts[source]),
                      logic_.land(
                          logic_.veq(tokens[source][token].kind,
                                     static_cast<unsigned char>(
                                         JsonLexeme::string)),
                          logic_.land(
                              logic_.veq(tokens[source][token].begin,
                                         graph.references[reference].begin),
                              logic_.veq(tokens[source][token].end,
                                         graph.references[reference].end))))));
          exact = logic_.lor_exclusive(exact, selected);
        }
      }
      logic_.assert_implies(live, exact);
    }
    for (std::size_t node = 0; node < Slots; ++node) {
      const auto live = logic_.vlt(node, graph.supplied_active);
      BitW disclosure_begin = logic_.bit(0);
      BitW disclosure_end = logic_.bit(0);
      BitW value_begin = logic_.bit(0);
      BitW value_end = logic_.bit(0);
      for (std::size_t source = 1; source < Sources; ++source) {
        for (std::size_t token = 0; token < TokenSlots; ++token) {
          const auto selected_source = logic_.land(
              live, logic_.land(logic_.veq(graph.nodes[node].source, source),
                                logic_.vlt(token, token_counts[source])));
          disclosure_begin = logic_.lor_exclusive(
              disclosure_begin,
              logic_.land(selected_source,
                          logic_.veq(tokens[source][token].begin,
                                     graph.nodes[node].disclosure_begin)));
          disclosure_end = logic_.lor_exclusive(
              disclosure_end,
              logic_.land(selected_source,
                          logic_.veq(tokens[source][token].end,
                                     graph.nodes[node].disclosure_end)));
          value_begin = logic_.lor_exclusive(
              value_begin,
              logic_.land(selected_source,
                          logic_.veq(tokens[source][token].begin,
                                     graph.nodes[node].value_begin)));
          value_end = logic_.lor_exclusive(
              value_end,
              logic_.land(selected_source,
                          logic_.veq(tokens[source][token].end,
                                     graph.nodes[node].value_end)));
        }
      }
      logic_.assert_implies(live, disclosure_begin);
      logic_.assert_implies(live, disclosure_end);
      logic_.assert_implies(live, value_begin);
      logic_.assert_implies(live, value_end);
    }
  }

  // Bind a two-/three-element disclosure kind to the constrained token table:
  // its top-level comma count is one/two, and required salt/name positions are
  // strings. General JSON values remain governed by the bounded JSON grammar.
  template <std::size_t TokenSlots>
  void assert_disclosure_shape(
      const Node& node, const Index& token_count,
      const std::array<RangeToken, TokenSlots>& tokens,
      const std::array<Index, TokenSlots + 1>& depths,
      const BitW& live) const {
    std::array<BitW, TokenSlots> top_commas{};
    BitW first_string = logic_.bit(0);
    BitW second_string = logic_.bit(0);
    for (std::size_t token = 0; token < TokenSlots; ++token) {
      const auto active = logic_.land(live, logic_.vlt(token, token_count));
      const auto top_comma = logic_.land(
          active,
          logic_.land(logic_.veq(depths[token], 2),
                      logic_.veq(tokens[token].kind,
                                 static_cast<unsigned char>(JsonLexeme::comma))));
      top_commas[token] = top_comma;
      BitW prior_xor = logic_.bit(0);
      BitW no_prior_pair = logic_.bit(1);
      BitW no_prior = logic_.bit(1);
      for (std::size_t earlier = 0; earlier < token; ++earlier) {
        prior_xor = logic_.lor_exclusive(prior_xor, top_commas[earlier]);
        no_prior = logic_.land(no_prior, logic_.lnot(top_commas[earlier]));
        for (std::size_t other = earlier + 1; other < token; ++other)
          no_prior_pair = logic_.land(
              no_prior_pair,
              logic_.lnot(
                  logic_.land(top_commas[earlier], top_commas[other])));
      }
      const auto exactly_one_prior =
          logic_.land(prior_xor, no_prior_pair);
      const auto string = logic_.land(
          active,
          logic_.land(logic_.veq(depths[token], 2),
                      logic_.veq(tokens[token].kind,
                                 static_cast<unsigned char>(JsonLexeme::string))));
      first_string = logic_.lor_exclusive(
          first_string, logic_.land(string, no_prior));
      second_string = logic_.lor_exclusive(
          second_string, logic_.land(string, exactly_one_prior));
    }
    BitW one_comma = logic_.bit(0);
    BitW comma_pair = logic_.bit(0);
    BitW no_comma_pair = logic_.bit(1);
    BitW no_comma_triple = logic_.bit(1);
    for (std::size_t first = 0; first < TokenSlots; ++first) {
      one_comma = logic_.lor_exclusive(one_comma, top_commas[first]);
      for (std::size_t second = first + 1; second < TokenSlots; ++second) {
        comma_pair = logic_.lor_exclusive(
            comma_pair,
            logic_.land(top_commas[first], top_commas[second]));
        no_comma_pair = logic_.land(
            no_comma_pair,
            logic_.lnot(logic_.land(top_commas[first], top_commas[second])));
        for (std::size_t third = second + 1; third < TokenSlots; ++third)
          no_comma_triple = logic_.land(
              no_comma_triple,
              logic_.lnot(logic_.land(
                  top_commas[first],
                  logic_.land(top_commas[second], top_commas[third]))));
      }
    }
    const auto exactly_one_comma =
        logic_.land(one_comma, no_comma_pair);
    const auto exactly_two_commas =
        logic_.land(comma_pair, no_comma_triple);
    const auto object = logic_.land(
        live, logic_.veq(node.kind,
                         static_cast<unsigned char>(
                             DisclosureKind::object_property)));
    const auto array = logic_.land(
        live, logic_.veq(node.kind,
                         static_cast<unsigned char>(
                             DisclosureKind::array_element)));
    logic_.assert_implies(object, exactly_two_commas);
    logic_.assert_implies(array, exactly_one_comma);
    logic_.assert_implies(live, first_string);
    logic_.assert_implies(object, second_string);
  }

  // Prove the semantic location of every digest reference from the exact
  // bounded-parser witnesses. This closes the gap left by a lexical range
  // match: a prover cannot relabel an `_sd` reference as an array placeholder
  // (or vice versa), choose the salt as an object path component, or forge an
  // array index.
  template <std::size_t Sources, std::size_t TokenSlots,
            class StringWitness, class GrammarStack,
            class ContainerIdStack>
  void assert_reference_placements(
      const GraphInput& graph,
      const std::array<Placement, Slots>& placements,
      const std::array<std::array<RangeToken, TokenSlots>, Sources>& tokens,
      const std::array<Index, Sources>& token_counts,
      const std::array<std::array<StringWitness, TokenSlots>, Sources>& strings,
      const std::array<std::array<Index, TokenSlots + 1>, Sources>& depths,
      const std::array<std::array<GrammarStack, TokenSlots + 1>, Sources>& frames,
      const std::array<std::array<ContainerIdStack, TokenSlots + 1>, Sources>&
          container_ids) const {
    static_assert(Sources == Slots + 1);
    constexpr unsigned object_first_key_or_end = 3, object_key = 4;
    const auto decoded_equals = [&](const StringWitness& witness,
                                    const std::array<unsigned char, 3>& text) {
      BitW same = logic_.veq(witness.unit_count, text.size());
      for (std::size_t index = 0; index < text.size(); ++index)
        same = logic_.land(
            same, logic_.veq(witness.units[index].codepoint, text[index]));
      return same;
    };
    const auto assert_adjacent = [&](std::size_t source, const Index& left,
                                     const Index& right,
                                     const BitW& branch) {
      for (std::size_t left_token = 0; left_token < TokenSlots; ++left_token) {
        for (std::size_t right_token = 0; right_token < TokenSlots;
             ++right_token) {
          const auto pair = logic_.land(
              branch,
              logic_.land(logic_.veq(left, left_token),
                          logic_.veq(right, right_token)));
          if (right_token <= left_token) {
            logic_.assert_implies(pair, logic_.bit(0));
            continue;
          }
          for (std::size_t between = left_token + 1;
               between < right_token; ++between)
            logic_.assert_implies(
                pair,
                logic_.veq(tokens[source][between].kind,
                           static_cast<unsigned char>(
                               JsonLexeme::whitespace)));
        }
      }
    };

    for (std::size_t node_index = 0; node_index < Slots; ++node_index) {
      const auto live = logic_.vlt(node_index, graph.supplied_active);
      const auto object = logic_.land(
          live, logic_.veq(graph.nodes[node_index].kind,
                           static_cast<unsigned char>(
                               DisclosureKind::object_property)));
      const auto array = logic_.land(
          live, logic_.veq(graph.nodes[node_index].kind,
                           static_cast<unsigned char>(
                               DisclosureKind::array_element)));
      const auto& placement = placements[node_index];

      // The three-element disclosure's second top-level item is its object
      // path component. Its decoded string witness (not raw spelling) is the
      // authenticated component used by typed policy selection.
      BitW component_selected = logic_.bit(0);
      for (std::size_t source = 1; source < Sources; ++source) {
        const auto source_branch = logic_.land(
            object, logic_.veq(graph.nodes[node_index].source, source));
        for (std::size_t token = 0; token < TokenSlots; ++token) {
          BitW no_prior_pair = logic_.bit(1);
          BitW prior_xor = logic_.bit(0);
          for (std::size_t earlier = 0; earlier < token; ++earlier) {
            const auto comma = logic_.land(
                logic_.vlt(earlier, token_counts[source]),
                logic_.land(
                    logic_.veq(depths[source][earlier], 2),
                    logic_.veq(tokens[source][earlier].kind,
                               static_cast<unsigned char>(JsonLexeme::comma))));
            prior_xor = logic_.lor_exclusive(prior_xor, comma);
            for (std::size_t other = earlier + 1; other < token; ++other) {
              const auto other_comma = logic_.land(
                  logic_.vlt(other, token_counts[source]),
                  logic_.land(
                      logic_.veq(depths[source][other], 2),
                      logic_.veq(tokens[source][other].kind,
                                 static_cast<unsigned char>(
                                     JsonLexeme::comma))));
              no_prior_pair = logic_.land(
                  no_prior_pair,
                  logic_.lnot(logic_.land(comma, other_comma)));
            }
          }
          const auto candidate = logic_.land(
              source_branch,
              logic_.land(
                  logic_.veq(placement.component_token, token),
                  logic_.land(
                      logic_.vlt(token, token_counts[source]),
                      logic_.land(
                          logic_.veq(depths[source][token], 2),
                          logic_.land(
                              logic_.veq(tokens[source][token].kind,
                                         static_cast<unsigned char>(
                                             JsonLexeme::string)),
                              logic_.land(prior_xor, no_prior_pair))))));
          component_selected =
              logic_.lor_exclusive(component_selected, candidate);
        }
      }
      logic_.assert_implies(object, component_selected);
      logic_.assert_implies(array,
                            logic_.veq(placement.component_token, 0));
      logic_.assert_implies(object,
                            logic_.veq(placement.array_index, 0));

      for (std::size_t reference_index = 0; reference_index < Slots;
           ++reference_index) {
        const auto maps_reference = logic_.land(
            live, logic_.veq(graph.nodes[node_index].reference_index,
                             reference_index));
        for (std::size_t source = 0; source < Sources; ++source) {
          const auto source_branch = logic_.land(
              maps_reference,
              logic_.veq(graph.references[reference_index].source, source));
          BitW marker_selected = logic_.bit(0);
          BitW colon_selected = logic_.bit(0);
          BitW reference_selected = logic_.bit(0);
          BitW value_open_selected = logic_.bit(0);
          BitW object_open_selected = logic_.bit(0);
          BitW object_close_selected = logic_.bit(0);
          BitW parent_array_selected = logic_.bit(0);
          for (std::size_t token = 0; token < TokenSlots; ++token) {
            const auto active_token = logic_.vlt(token, token_counts[source]);
            const auto marker = logic_.land(
                source_branch,
                logic_.land(logic_.veq(placement.marker_token, token),
                            active_token));
            const auto colon = logic_.land(
                source_branch,
                logic_.land(logic_.veq(placement.colon_token, token),
                            active_token));
            const auto reference = logic_.land(
                source_branch,
                logic_.land(logic_.veq(placement.reference_token, token),
                            active_token));
            const auto value_open = logic_.land(
                logic_.land(source_branch, object),
                logic_.land(logic_.veq(placement.value_open_token, token),
                            active_token));
            const auto object_open = logic_.land(
                logic_.land(source_branch, array),
                logic_.land(logic_.veq(placement.object_open_token, token),
                            active_token));
            const auto object_close = logic_.land(
                logic_.land(source_branch, array),
                logic_.land(logic_.veq(placement.object_close_token, token),
                            active_token));
            const auto parent_array = logic_.land(
                logic_.land(source_branch, array),
                logic_.land(
                    logic_.veq(placement.parent_array_open_token, token),
                    active_token));
            marker_selected = logic_.lor_exclusive(marker_selected, marker);
            colon_selected = logic_.lor_exclusive(colon_selected, colon);
            reference_selected =
                logic_.lor_exclusive(reference_selected, reference);
            value_open_selected =
                logic_.lor_exclusive(value_open_selected, value_open);
            object_open_selected =
                logic_.lor_exclusive(object_open_selected, object_open);
            object_close_selected =
                logic_.lor_exclusive(object_close_selected, object_close);
            parent_array_selected =
                logic_.lor_exclusive(parent_array_selected, parent_array);
            logic_.assert_implies(
                marker,
                logic_.veq(tokens[source][token].kind,
                           static_cast<unsigned char>(JsonLexeme::string)));
            logic_.assert_implies(
                logic_.land(marker, object),
                decoded_equals(
                    strings[source][token],
                    std::array<unsigned char, 3>{'_', 's', 'd'}));
            logic_.assert_implies(
                logic_.land(marker, array),
                decoded_equals(
                    strings[source][token],
                    std::array<unsigned char, 3>{'.', '.', '.'}));
            BitW key_state = logic_.bit(0);
            for (std::size_t depth = 2; depth <= TokenSlots + 1; ++depth) {
              const auto expects_key = logic_.lor_exclusive(
                  logic_.veq(frames[source][token][depth - 1],
                             object_first_key_or_end),
                  logic_.veq(frames[source][token][depth - 1], object_key));
              key_state = logic_.lor_exclusive(
                  key_state,
                  logic_.land(logic_.veq(depths[source][token], depth),
                              expects_key));
            }
            logic_.assert_implies(marker, key_state);
            logic_.assert_implies(
                colon,
                logic_.veq(tokens[source][token].kind,
                           static_cast<unsigned char>(JsonLexeme::colon)));
            logic_.assert_implies(
                reference,
                logic_.land(
                    logic_.veq(tokens[source][token].kind,
                               static_cast<unsigned char>(JsonLexeme::string)),
                    logic_.land(
                        logic_.veq(tokens[source][token].begin,
                                   graph.references[reference_index].begin),
                        logic_.veq(tokens[source][token].end,
                                   graph.references[reference_index].end))));
            logic_.assert_implies(
                reference,
                logic_.veq(strings[source][token].unit_count, 43));
            for (std::size_t byte = 0; byte < 43; ++byte) {
              BitW same_ascii = logic_.bit(1);
              for (std::size_t bit = 0; bit < 8; ++bit)
                same_ascii = logic_.land(
                    same_ascii,
                    logic_.lnot(logic_.lxor(
                        strings[source][token].units[byte].codepoint[bit],
                        graph.references[reference_index].digest[byte][bit])));
              for (std::size_t bit = 8; bit < 21; ++bit)
                same_ascii = logic_.land(
                    same_ascii,
                    logic_.lnot(strings[source][token]
                                    .units[byte]
                                    .codepoint[bit]));
              logic_.assert_implies(reference, same_ascii);
            }
            logic_.assert_implies(
                value_open,
                logic_.veq(tokens[source][token].kind,
                           static_cast<unsigned char>(JsonLexeme::array_open)));
            logic_.assert_implies(
                object_open,
                logic_.veq(tokens[source][token].kind,
                           static_cast<unsigned char>(JsonLexeme::object_open)));
            logic_.assert_implies(
                object_close,
                logic_.veq(tokens[source][token].kind,
                           static_cast<unsigned char>(JsonLexeme::object_close)));
            logic_.assert_implies(
                parent_array,
                logic_.veq(tokens[source][token].kind,
                           static_cast<unsigned char>(JsonLexeme::array_open)));
          }
          logic_.assert_implies(source_branch, marker_selected);
          logic_.assert_implies(source_branch, colon_selected);
          logic_.assert_implies(source_branch, reference_selected);
          logic_.assert_implies(logic_.land(source_branch, object),
                                value_open_selected);
          logic_.assert_implies(logic_.land(source_branch, array),
                                object_open_selected);
          logic_.assert_implies(logic_.land(source_branch, array),
                                object_close_selected);
          logic_.assert_implies(logic_.land(source_branch, array),
                                parent_array_selected);
          assert_adjacent(source, placement.marker_token,
                          placement.colon_token, source_branch);
          assert_adjacent(source, placement.colon_token,
                          placement.value_open_token,
                          logic_.land(source_branch, object));
          assert_adjacent(source, placement.colon_token,
                          placement.reference_token,
                          logic_.land(source_branch, array));
          assert_adjacent(source, placement.object_open_token,
                          placement.marker_token,
                          logic_.land(source_branch, array));
          assert_adjacent(source, placement.reference_token,
                          placement.object_close_token,
                          logic_.land(source_branch, array));

          // Direct membership in the selected `_sd` array or exact placeholder
          // object is proved by the parser's constrained opener-id stack.
          BitW object_membership = logic_.bit(0);
          BitW array_membership = logic_.bit(0);
          for (std::size_t token = 0; token < TokenSlots; ++token) {
            const auto reference_token = logic_.land(
                source_branch,
                logic_.veq(placement.reference_token, token));
            const auto marker_token = logic_.land(
                source_branch, logic_.veq(placement.marker_token, token));
            for (std::size_t depth = 2; depth <= TokenSlots; ++depth) {
              const auto object_branch = logic_.land(
                  logic_.land(reference_token, object),
                  logic_.land(
                      logic_.veq(depths[source][token], depth + 1),
                      logic_.veq(container_ids[source][token][depth],
                                 logic_.vadd(placement.value_open_token, 1))));
              object_membership =
                  logic_.lor_exclusive(object_membership, object_branch);
              if (depth < 3) continue;
              const auto array_branch = logic_.land(
                  logic_.land(marker_token, array),
                  logic_.land(
                      logic_.veq(depths[source][token], depth),
                      logic_.land(
                          logic_.veq(container_ids[source][token][depth - 1],
                                     logic_.vadd(
                                         placement.object_open_token, 1)),
                          logic_.veq(container_ids[source][token][depth - 2],
                                     logic_.vadd(
                                         placement.parent_array_open_token,
                                         1)))));
              array_membership =
                  logic_.lor_exclusive(array_membership, array_branch);
            }
          }
          logic_.assert_implies(logic_.land(source_branch, object),
                                object_membership);
          logic_.assert_implies(logic_.land(source_branch, array),
                                array_membership);

          Index derived_index{};
          for (std::size_t bit = 0; bit < IndexBits; ++bit)
            derived_index[bit] = logic_.bit(0);
          for (std::size_t token = 0; token < TokenSlots; ++token) {
            BitW sibling_comma = logic_.bit(0);
            for (std::size_t depth = 3; depth <= TokenSlots; ++depth) {
              const auto candidate = logic_.land(
                  logic_.land(source_branch, array),
                  logic_.land(
                      logic_.vlt(token, placement.object_open_token),
                      logic_.land(
                          logic_.veq(tokens[source][token].kind,
                                     static_cast<unsigned char>(
                                         JsonLexeme::comma)),
                          logic_.land(
                              logic_.veq(depths[source][token], depth - 1),
                              logic_.veq(
                                  container_ids[source][token][depth - 2],
                                  logic_.vadd(
                                      placement.parent_array_open_token,
                                      1))))));
              sibling_comma =
                  logic_.lor_exclusive(sibling_comma, candidate);
            }
            Index increment{};
            increment[0] = sibling_comma;
            for (std::size_t bit = 1; bit < IndexBits; ++bit)
              increment[bit] = logic_.bit(0);
            derived_index = logic_.vadd(derived_index, increment);
          }
          logic_.assert_implies(logic_.land(source_branch, array),
                                logic_.veq(placement.array_index,
                                           derived_index));
        }
      }
      assert_inactive_placement(placement, logic_.lnot(live));
    }
  }

  template <std::size_t Sources, std::size_t TokenSlots,
            class StringWitness, class GrammarStack,
            class ContainerIdStack>
  void assert_reference_placements(
      const GraphInput& graph,
      const std::array<Placement, Slots>& placements,
      const PlacementParserTables<Sources, TokenSlots, StringWitness,
                                  GrammarStack, ContainerIdStack>& tables)
      const {
    assert_reference_placements(
        graph, placements, tables.tokens, tables.token_counts, tables.strings,
        tables.depths, tables.frames, tables.container_ids);
  }

  // Sound retained experimental entry point. Each source is first accepted by
  // the full bounded JSON relation, and the resulting *same wires* are consumed
  // by graph range/shape/placement checks. Callers must bind source zero to
  // the authenticated issuer JSON and source n+1 to disclosure n's
  // base64url-decoded JSON; allocating an independent parser table is not a
  // valid handoff. A single capacity keeps all source witness types uniform;
  // shorter disclosure texts use zero byte padding after active_length.
  template <std::size_t Capacity, std::size_t Sources,
            std::size_t TokenSlots, std::size_t JsonDepth>
  void assert_bounded_source_placements(
      const GraphInput& graph,
      const std::array<Placement, Slots>& placements,
      const std::array<BoundedJsonCircuitInput<
          LogicCircuit, Capacity, TokenSlots, IndexBits, JsonDepth>,
                       Sources>& sources) const {
    static_assert(Sources == Slots + 1);
    using JsonRelation = BoundedJsonTokenRelation<
        LogicCircuit, Capacity, TokenSlots, IndexBits, JsonDepth>;
    using Tables = PlacementParserTables<
        Sources, TokenSlots, typename JsonRelation::StringWitness,
        typename JsonRelation::GrammarStack,
        typename JsonRelation::ContainerIdStack>;
    Tables tables{};
    for (std::size_t source = 0; source < Sources; ++source) {
      const auto& input = sources[source];
      JsonRelation(logic_).assert_json(
          input.text, input.active_length, input.token_count, input.tokens,
          input.strings, input.numbers, input.depths, input.frames,
          input.container_ids);
      logic_.vassert_eq(graph.source_lengths[source], input.active_length);
      tables.token_counts[source] = input.token_count;
      tables.strings[source] = input.strings;
      tables.depths[source] = input.depths;
      tables.frames[source] = input.frames;
      tables.container_ids[source] = input.container_ids;
      for (std::size_t token = 0; token < TokenSlots; ++token) {
        tables.tokens[source][token].kind = input.tokens[token].kind;
        tables.tokens[source][token].begin = input.tokens[token].begin;
        tables.tokens[source][token].end = input.tokens[token].end;
      }
    }
    assert_token_ranges(graph, tables.tokens, tables.token_counts);
    for (std::size_t node = 0; node < Slots; ++node) {
      for (std::size_t source = 1; source < Sources; ++source) {
        const auto selected = logic_.land(
            logic_.vlt(node, graph.supplied_active),
            logic_.veq(graph.nodes[node].source, source));
        assert_disclosure_shape(graph.nodes[node], tables.token_counts[source],
                                tables.tokens[source], tables.depths[source],
                                selected);
      }
    }
    assert_reference_placements(graph, placements, tables);
  }

  // Production-sized heterogeneous variant: the authenticated issuer JSON
  // and decoded disclosure JSON use distinct bounded-parser capacities while
  // sharing token count/index width. DisclosureCapacity must accommodate a
  // complete 43-character nested digest string. The placement view uses the
  // issuer StringWitness type; disclosure string units above their smaller
  // capacity are constants, never fresh advice.
  template <std::size_t IssuerCapacity, std::size_t DisclosureCapacity,
            std::size_t TokenSlots, std::size_t IssuerDepth,
            std::size_t DisclosureDepth>
  void assert_heterogeneous_bounded_source_placements(
      const GraphInput& graph,
      const std::array<Placement, Slots>& placements,
      const BoundedJsonCircuitInput<LogicCircuit, IssuerCapacity, TokenSlots,
                                    IndexBits, IssuerDepth>& issuer,
      const std::array<BoundedJsonCircuitInput<
          LogicCircuit, DisclosureCapacity, TokenSlots, IndexBits,
          DisclosureDepth>,
                       Slots>& disclosures) const {
    static_assert(IndexBits >= 8,
                  "heterogeneous experimental sources require 8-bit indices");
    static_assert(IssuerCapacity >= DisclosureCapacity);
    static_assert(DisclosureCapacity >= 43);
    using IssuerJson = BoundedJsonTokenRelation<
        LogicCircuit, IssuerCapacity, TokenSlots, IndexBits, IssuerDepth>;
    using DisclosureJson = BoundedJsonTokenRelation<
        LogicCircuit, DisclosureCapacity, TokenSlots, IndexBits,
        DisclosureDepth>;
    using Tables = PlacementParserTables<
        Slots + 1, TokenSlots, typename IssuerJson::StringWitness,
        typename IssuerJson::GrammarStack,
        typename IssuerJson::ContainerIdStack>;
    Tables tables{};
    IssuerJson(logic_).assert_json(
        issuer.text, issuer.active_length, issuer.token_count, issuer.tokens,
        issuer.strings, issuer.numbers, issuer.depths, issuer.frames,
        issuer.container_ids);
    logic_.vassert_eq(graph.source_lengths[0], issuer.active_length);
    tables.token_counts[0] = issuer.token_count;
    tables.strings[0] = issuer.strings;
    tables.depths[0] = issuer.depths;
    tables.frames[0] = issuer.frames;
    tables.container_ids[0] = issuer.container_ids;
    for (std::size_t token = 0; token < TokenSlots; ++token) {
      tables.tokens[0][token].kind = issuer.tokens[token].kind;
      tables.tokens[0][token].begin = issuer.tokens[token].begin;
      tables.tokens[0][token].end = issuer.tokens[token].end;
    }
    for (std::size_t slot = 0; slot < Slots; ++slot) {
      const auto& input = disclosures[slot];
      const std::size_t source = slot + 1;
      DisclosureJson(logic_).assert_json(
          input.text, input.active_length, input.token_count, input.tokens,
          input.strings, input.numbers, input.depths, input.frames,
          input.container_ids);
      logic_.vassert_eq(graph.source_lengths[source], input.active_length);
      tables.token_counts[source] = input.token_count;
      tables.depths[source] = input.depths;
      tables.frames[source] = input.frames;
      tables.container_ids[source] = input.container_ids;
      for (std::size_t token = 0; token < TokenSlots; ++token) {
        tables.tokens[source][token].kind = input.tokens[token].kind;
        tables.tokens[source][token].begin = input.tokens[token].begin;
        tables.tokens[source][token].end = input.tokens[token].end;
        tables.strings[source][token].unit_count =
            input.strings[token].unit_count;
        for (std::size_t unit = 0; unit < IssuerCapacity; ++unit) {
          if (unit < DisclosureCapacity) {
            tables.strings[source][token].units[unit].begin =
                input.strings[token].units[unit].begin;
            tables.strings[source][token].units[unit].end =
                input.strings[token].units[unit].end;
            tables.strings[source][token].units[unit].codepoint =
                input.strings[token].units[unit].codepoint;
          } else {
            for (auto* range : {
                     &tables.strings[source][token].units[unit].begin,
                     &tables.strings[source][token].units[unit].end})
              for (auto& bit : *range) bit = logic_.bit(0);
            for (auto& bit :
                 tables.strings[source][token].units[unit].codepoint)
              bit = logic_.bit(0);
          }
        }
      }
    }
    assert_token_ranges(graph, tables.tokens, tables.token_counts);
    for (std::size_t node = 0; node < Slots; ++node) {
      for (std::size_t source = 1; source <= Slots; ++source) {
        const auto selected = logic_.land(
            logic_.vlt(node, graph.supplied_active),
            logic_.veq(graph.nodes[node].source, source));
        assert_disclosure_shape(graph.nodes[node], tables.token_counts[source],
                                tables.tokens[source], tables.depths[source],
                                selected);
      }
    }
    assert_reference_placements(graph, placements, tables);
  }

  template <std::size_t SelectedSlots>
  void assert_authenticated_selected_results(
      const GraphInput& graph,
      const std::array<Placement, Slots>& placements,
      const std::array<AuthenticatedSelectedResult, SelectedSlots>& selected,
      const Index& selected_active) const {
    logic_.assert1(logic_.vleq(selected_active, SelectedSlots));
    for (std::size_t output = 0; output < SelectedSlots; ++output) {
      const auto live = logic_.vlt(output, selected_active);
      BitW matched = logic_.bit(0);
      for (std::size_t node = 0; node < Slots; ++node) {
        const auto chosen = logic_.land(
            live, logic_.veq(selected[output].node_index, node));
        matched = logic_.lor_exclusive(matched, chosen);
        logic_.assert_implies(chosen,
                              logic_.vlt(node, graph.supplied_active));
        logic_.assert_implies(chosen,
                              logic_.veq(selected[output].kind,
                                         graph.nodes[node].kind));
        logic_.assert_implies(
            chosen,
            logic_.veq(selected[output].component_token,
                       placements[node].component_token));
        logic_.assert_implies(chosen,
                              logic_.veq(selected[output].array_index,
                                         placements[node].array_index));
        logic_.assert_implies(chosen,
                              logic_.veq(selected[output].source,
                                         graph.nodes[node].source));
        logic_.assert_implies(chosen,
                              logic_.veq(selected[output].value_begin,
                                         graph.nodes[node].value_begin));
        logic_.assert_implies(chosen,
                              logic_.veq(selected[output].value_end,
                                         graph.nodes[node].value_end));
      }
      logic_.assert_implies(live, matched);
    }
  }

  // Exact disclosure ASCII -> SHA-256 -> issuer digest base64url linkage. The
  // caller allocates one fixed bucket per slot; inactive slots may carry a
  // canonical dummy SHA witness but are never reachable from the active graph.
  template <std::size_t ShaBlocks, std::size_t DisclosureChars,
            class ShaWitness, class Digest>
  void assert_digest_link(
      const Node& node,
      const std::array<v8, DisclosureChars>& disclosure_ascii,
      const std::array<v8, 64 * ShaBlocks>& sha_input,
      const std::array<ShaWitness, ShaBlocks>& sha_witness,
      const Digest& digest_bits, std::uint8_t sha_block_count) const {
    assert_digest_link<ShaBlocks, DisclosureChars>(
        node, disclosure_ascii, sha_input, sha_witness, digest_bits,
        sha_block_count, logic_.bit(1));
  }

  // Variable-length experimental bucket. The same active length drives compact
  // base64url decoding and exact SHA padding. Inactive slots use the unique
  // canonical dummy segment `MA` (the valid JSON number `0`), rather than an
  // impossible all-zero digest. `decoded_json` is the byte array that must be
  // passed to the slot's BoundedJsonTokenRelation.
  template <std::size_t ShaBlocks, std::size_t DisclosureCapacity,
            class Length, class ShaWitness, class Digest>
  void assert_bounded_digest_link(
      const Node& node,
      const std::array<v8, DisclosureCapacity>& disclosure_ascii,
      const Length& active_length,
      std::array<v8, (DisclosureCapacity * 6) / 8>& decoded_json,
      const Length& decoded_length,
      const std::array<v8, 64 * ShaBlocks>& sha_input,
      const std::array<ShaWitness, ShaBlocks>& sha_witness,
      const Digest& digest_bits, const v8& sha_block_count,
      const BitW& live) const {
    static_assert(ShaBlocks > 0);
    static_assert(DisclosureCapacity + 9 <= 64 * ShaBlocks,
                  "SHA bucket cannot hold maximum disclosure and padding");
    logic_.assert_is_bit(live);
    logic_.assert_implies(logic_.lnot(live),
                          logic_.veq(active_length, 2));
    logic_.assert_implies(logic_.lnot(live),
                          logic_.veq(disclosure_ascii[0], 'M'));
    logic_.assert_implies(logic_.lnot(live),
                          logic_.veq(disclosure_ascii[1], 'A'));
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode_active(
        disclosure_ascii, decoded_json, active_length);
    for (std::size_t byte = 0; byte < DisclosureCapacity; ++byte)
      logic_.assert_implies(logic_.vlt(byte, active_length),
                            logic_.veq(sha_input[byte],
                                       disclosure_ascii[byte]));

    BitW selected_length = logic_.bit(0);
    for (std::size_t length = 2; length <= DisclosureCapacity; ++length) {
      if (length % 4 == 1) continue;
      const auto branch = logic_.veq(active_length, length);
      selected_length = logic_.lor_exclusive(selected_length, branch);
      logic_.assert_implies(branch,
                            logic_.veq(decoded_length, (length * 6) / 8));
      const std::size_t blocks = (length + 9 + 63) / 64;
      const std::size_t padded_end = blocks * 64;
      logic_.assert_implies(branch,
                            logic_.veq(sha_block_count, blocks));
      logic_.assert_implies(branch,
                            logic_.veq(sha_input[length], 0x80));
      for (std::size_t byte = length + 1; byte < padded_end - 8; ++byte)
        logic_.assert_implies(branch, logic_.veq(sha_input[byte], 0));
      const std::uint64_t bit_length = length * 8;
      for (std::size_t byte = 0; byte < 8; ++byte)
        logic_.assert_implies(
            branch,
            logic_.veq(sha_input[padded_end - 8 + byte],
                       static_cast<unsigned char>(
                           bit_length >> ((7 - byte) * 8))));
      for (std::size_t byte = padded_end; byte < 64 * ShaBlocks; ++byte)
        logic_.assert_implies(branch, logic_.veq(sha_input[byte], 0));
    }
    logic_.assert1(selected_length);
    Sha(logic_).assert_message_hash(ShaBlocks, sha_block_count,
                                    sha_input.data(), digest_bits,
                                    sha_witness.data());
    std::array<v8, 32> signed_digest{};
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(
        node.supplied_digest, signed_digest);
    for (std::size_t byte = 0; byte < signed_digest.size(); ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        logic_.assert_eq(signed_digest[byte][bit],
                         digest_bits[(31 - byte) * 8 + bit]);
  }

  // Fixed-slot variant. SHA constraints cannot be conditionally removed, so
  // inactive slots use one satisfiable canonical dummy preimage: `A` repeated
  // DisclosureChars times. Its digest remains unreachable because assert_graph
  // gates every reference/use by supplied_active.
  template <std::size_t ShaBlocks, std::size_t DisclosureChars,
            class ShaWitness, class Digest>
  void assert_digest_link(
      const Node& node,
      const std::array<v8, DisclosureChars>& disclosure_ascii,
      const std::array<v8, 64 * ShaBlocks>& sha_input,
      const std::array<ShaWitness, ShaBlocks>& sha_witness,
      const Digest& digest_bits, std::uint8_t sha_block_count,
      const BitW& live) const {
    static_assert(DisclosureChars + 9 <= 64 * ShaBlocks,
                  "SHA bucket cannot hold disclosure and padding");
    static_assert(DisclosureChars + 9 > 64 * (ShaBlocks - 1),
                  "SHA bucket count must be canonical");
    logic_.assert_is_bit(live);
    for (std::size_t byte = 0; byte < DisclosureChars; ++byte)
      logic_.assert_implies(logic_.lnot(live),
                            logic_.veq(disclosure_ascii[byte], 'A'));
    logic_.vassert_eq(sha_input[DisclosureChars], 0x80);
    for (std::size_t byte = DisclosureChars + 1;
         byte < 64 * ShaBlocks - 8; ++byte)
      logic_.vassert_eq(sha_input[byte], 0);
    constexpr std::uint64_t bit_length = DisclosureChars * 8;
    for (std::size_t byte = 0; byte < 8; ++byte)
      logic_.vassert_eq(
          sha_input[64 * ShaBlocks - 8 + byte],
          static_cast<unsigned char>(bit_length >> ((7 - byte) * 8)));
    using Relation =
        FlatDisclosureRelation<LogicCircuit, ShaBlocks, DisclosureChars>;
    typename Relation::Input input{disclosure_ascii, sha_input, sha_witness,
                                   digest_bits, node.supplied_digest,
                                   static_cast<std::uint8_t>(ShaBlocks)};
    (void)sha_block_count;
    Relation(logic_).assert_digest_match(input);
  }

  template <std::size_t DisclosureChars>
  void assert_disclosure_base64url(
      const std::array<v8, DisclosureChars>& disclosure_ascii,
      std::array<v8, (DisclosureChars * 6) / 8>& decoded_json) const {
    RestrictedBase64UrlRelation<LogicCircuit>(logic_).decode(disclosure_ascii,
                                                               decoded_json);
  }

  template <std::size_t SelectedSlots>
  void assert_selected_results(
      const GraphInput& graph,
      const std::array<SelectedResult, SelectedSlots>& selected,
      const Index& selected_active) const {
    logic_.assert1(logic_.vleq(selected_active, SelectedSlots));
    for (std::size_t output = 0; output < SelectedSlots; ++output) {
      const auto live = logic_.vlt(output, selected_active);
      BitW matched = logic_.bit(0);
      for (std::size_t node = 0; node < Slots; ++node) {
        const auto chosen = logic_.land(
            live, logic_.veq(selected[output].node_index, node));
        matched = logic_.lor_exclusive(matched, chosen);
        logic_.assert_implies(chosen,
                              logic_.vlt(node, graph.supplied_active));
        logic_.assert_implies(
            chosen,
            logic_.veq(selected[output].path_length,
                       graph.nodes[node].path_length));
        logic_.assert_implies(chosen,
                              logic_.veq(selected[output].kind,
                                         graph.nodes[node].kind));
        logic_.assert_implies(chosen,
                              logic_.veq(selected[output].source,
                                         graph.nodes[node].source));
        logic_.assert_implies(
            chosen, logic_.veq(selected[output].value_begin,
                               graph.nodes[node].value_begin));
        logic_.assert_implies(
            chosen, logic_.veq(selected[output].value_end,
                               graph.nodes[node].value_end));
        for (std::size_t byte = 0; byte < PathBytes; ++byte)
          logic_.assert_implies(
              chosen, logic_.veq(selected[output].path[byte],
                                 graph.nodes[node].path[byte]));
      }
      logic_.assert_implies(live, matched);
      for (std::size_t earlier = 0; earlier < output; ++earlier)
        logic_.assert_implies(
            logic_.land(live, logic_.vlt(earlier, selected_active)),
            logic_.lnot(logic_.veq(selected[output].node_index,
                                   selected[earlier].node_index)));
      assert_inactive_selection(selected[output], logic_.lnot(live));
    }
  }

  // Legacy bridge retained while the full-family advice layout migrates to
  // GraphInput. It enforces digest cardinality but is not a substitute for
  // assert_graph + token/shape/SHA/selected-result bindings.
  template <class LegacyIndex>
  void assert_one_to_one(
      const std::array<std::array<v8, 43>, Slots>& supplied,
      const std::array<std::array<v8, 43>, Slots>& references,
      const LegacyIndex& active) const {
    logic_.assert1(logic_.vleq(active, Slots));
    for (std::size_t slot = 0; slot < Slots; ++slot) {
      const auto live = logic_.vlt(slot, active);
      BitW matches = logic_.bit(0);
      for (std::size_t reference = 0; reference < Slots; ++reference) {
        matches = logic_.lor_exclusive(
            matches,
            logic_.land(logic_.vlt(reference, active),
                        same_digest(supplied[slot], references[reference])));
      }
      logic_.assert_implies(live, matches);
      for (std::size_t byte = 0; byte < 43; ++byte)
        logic_.assert_implies(logic_.lnot(live),
                              logic_.veq(supplied[slot][byte], 0));
      for (std::size_t later = slot + 1; later < Slots; ++later)
        logic_.assert_implies(
            logic_.land(live, logic_.vlt(later, active)),
            logic_.lnot(same_digest(supplied[slot], supplied[later])));
    }
  }

  template <class LegacyIndex>
  void assert_traversal_depth(
      const std::array<LegacyIndex, Slots>& depths,
      const LegacyIndex& active, std::size_t max_depth) const {
    for (std::size_t slot = 0; slot < Slots; ++slot) {
      const auto live = logic_.vlt(slot, active);
      logic_.assert_implies(live, logic_.vleq(depths[slot], max_depth));
      logic_.assert_implies(logic_.lnot(live),
                            logic_.veq(depths[slot], 0));
    }
  }

 private:
  BitW same_digest(const std::array<v8, 43>& left,
                   const std::array<v8, 43>& right) const {
    BitW same = logic_.bit(1);
    for (std::size_t byte = 0; byte < 43; ++byte)
      same = logic_.land(same, logic_.veq(left[byte], right[byte]));
    return same;
  }

  BitW same_path(const Node& left, const Node& right) const {
    BitW same = logic_.veq(left.path_length, right.path_length);
    for (std::size_t byte = 0; byte < PathBytes; ++byte)
      same = logic_.land(same, logic_.veq(left.path[byte], right.path[byte]));
    return same;
  }

  Index selected_source_length(
      const Index& source,
      const std::array<Index, Slots + 1>& source_lengths) const {
    Index result{};
    for (std::size_t bit = 0; bit < IndexBits; ++bit) {
      BitW selected = logic_.bit(0);
      for (std::size_t slot = 0; slot <= Slots; ++slot)
        selected = logic_.lor_exclusive(
            selected,
            logic_.land(logic_.veq(source, slot),
                        source_lengths[slot][bit]));
      result[bit] = selected;
    }
    return result;
  }

  void assert_path_padding(const std::array<v8, PathBytes>& path,
                           const Index& length, const BitW& live) const {
    logic_.assert_implies(live, logic_.vlt(0, length));
    if constexpr (PathBytes < (std::size_t{1} << IndexBits))
      logic_.assert_implies(live, logic_.vleq(length, PathBytes));
    logic_.assert_implies(live, logic_.veq(path[0], '/'));
    for (std::size_t byte = 0; byte < PathBytes; ++byte)
      logic_.assert_implies(logic_.lnot(logic_.land(live,
                                                   logic_.vlt(byte, length))),
                            logic_.veq(path[byte], 0));
  }

  void assert_inactive_node(const Node& node, const BitW& inactive) const {
    // supplied_digest is deliberately left to assert_digest_link's canonical
    // inactive dummy. Requiring zero here would make fixed SHA slots
    // unsatisfiable because no SHA-256 digest encodes as 43 zero bytes.
    for (const auto& byte : node.path)
      logic_.assert_implies(inactive, logic_.veq(byte, 0));
    logic_.assert_implies(inactive, logic_.veq(node.kind, 0));
    logic_.assert_implies(inactive, logic_.veq(node.arity, 0));
    for (const auto* field : {&node.source, &node.parent, &node.depth,
                              &node.reference_index,
                              &node.disclosure_begin, &node.disclosure_end,
                              &node.value_begin, &node.value_end,
                              &node.path_length})
      logic_.assert_implies(inactive, logic_.veq(*field, 0));
  }

  void assert_inactive_reference(const Reference& reference,
                                 const BitW& inactive) const {
    for (const auto& byte : reference.digest)
      logic_.assert_implies(inactive, logic_.veq(byte, 0));
    logic_.assert_implies(inactive, logic_.veq(reference.kind, 0));
    for (const auto* field : {&reference.source, &reference.begin,
                              &reference.end})
      logic_.assert_implies(inactive, logic_.veq(*field, 0));
  }

  void assert_inactive_selection(const SelectedResult& selected,
                                 const BitW& inactive) const {
    for (const auto& byte : selected.path)
      logic_.assert_implies(inactive, logic_.veq(byte, 0));
    logic_.assert_implies(inactive, logic_.veq(selected.kind, 0));
    for (const auto* field : {&selected.node_index, &selected.path_length,
                              &selected.source, &selected.value_begin,
                              &selected.value_end})
      logic_.assert_implies(inactive, logic_.veq(*field, 0));
  }

  void assert_inactive_placement(const Placement& placement,
                                 const BitW& inactive) const {
    for (const auto* field : {
             &placement.marker_token, &placement.colon_token,
             &placement.value_open_token, &placement.reference_token,
             &placement.object_open_token, &placement.object_close_token,
             &placement.parent_array_open_token, &placement.component_token,
             &placement.array_index})
      logic_.assert_implies(inactive, logic_.veq(*field, 0));
  }

  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
