#pragma once

#include <memory>

#include "circuits/compiler/compiler.h"
#include "ec/p256.h"
#include "sd_jwt_zk/bounded_json_circuit.h"
#include "sd_jwt_zk/compact_opening_bridge_relation.h"
#include "sd_jwt_zk/full_disclosure_relation.h"
#include "sd_jwt_zk/swiss_policy_relation.h"
#include "sd_jwt_zk/full_disclosure_family.h"
#include "sd_jwt_zk/full_disclosure_layout.h"
#include "sd_jwt_zk/flat_bearer_proof.h"

namespace sd_jwt_zk {
template <class Logic, std::size_t Slots>
struct FullDisclosureCircuitAdviceV1 {
  using Bit = typename Logic::BitW;
  using Byte = typename Logic::v8;
  std::array<std::array<Byte, 43>, Slots> supplied{}, references{};
  typename Logic::bitvec<6> active{};
  std::array<typename Logic::bitvec<6>, Slots> depths{};
  std::array<Byte, 3> vct_name{};
  std::array<Byte, 5> private_vct{}, requested_vct{};
  Bit equality_result{};
  std::array<Byte, 5> alg{};
  std::array<Byte, 9> typ{};
  std::array<Byte, 22> profile{};
  struct Registered { Bit top_level{}, is_string{}, present{}; };
  std::array<Registered, 7> registered_claims{};
  typename Logic::bitvec<5> nbf{}, exp{}, iat{}, now{};
  Bit time_result{}, iat_result{};
  std::array<Byte, 2> policy_path{}, other_policy_path{};
  typename Logic::bitvec<3> policy_kind{};
  Bit boolean_value{}, boolean_result{};
  typename Logic::bitvec<5> integer_value{}, integer_low{}, integer_high{};
  Bit integer_result{};
  typename Logic::bitvec<5> date_value{}, date_low{}, date_high{};
  Bit date_result{};
  std::array<Byte, 1> set_value{};
  std::array<std::array<Byte, 1>, 2> set_options{};
  Bit set_result{};
  std::array<Byte, 8> issuer_key{}, trust_key{};
  std::array<Byte, 16> trust_root{}, selected_trust_root{};
  std::array<Byte, 8> holder_key{}, kb_signer_key{};
  std::array<Byte, 16> presentation_hash{}, kb_sd_hash{}, challenge{}, kb_challenge{};
  using GraphRelation = FullDisclosureGraphRelation<Logic, Slots, 8, 64>;
  typename GraphRelation::GraphInput graph{};
  std::array<std::array<typename GraphRelation::RangeToken, 13>, Slots + 1>
      graph_tokens{};
  std::array<typename GraphRelation::Index, Slots + 1> graph_token_counts{};
  std::array<std::array<typename GraphRelation::Index, 14>, Slots + 1>
      graph_token_depths{};
  std::array<typename GraphRelation::SelectedResult, 1> graph_selected{};
  typename GraphRelation::Index graph_selected_active{};
  std::array<typename GraphRelation::Placement, Slots> graph_placements{};
  std::array<typename GraphRelation::AuthenticatedSelectedResult, 1>
      graph_authenticated_selected{};
  typename GraphRelation::Index graph_authenticated_selected_active{};
  using IssuerJson = BoundedJsonTokenRelation<Logic, 128, 13, 8, 13>;
  using DisclosureJson = BoundedJsonTokenRelation<Logic, 64, 13, 8, 13>;
  std::array<Byte,128> issuer_parser_text{};
  std::array<typename IssuerJson::StringWitness,13> issuer_parser_strings{};
  std::array<typename IssuerJson::GrammarStack,14> issuer_parser_frames{};
  std::array<typename IssuerJson::ContainerIdStack,14> issuer_parser_container_ids{};
  std::array<typename IssuerJson::Token,13> issuer_parser_tokens{};
  std::array<typename IssuerJson::NumberWitness,13> issuer_parser_numbers{};
  std::array<std::array<typename DisclosureJson::StringWitness,13>,Slots>
      disclosure_parser_strings{};
  std::array<std::array<typename DisclosureJson::GrammarStack,14>,Slots>
      disclosure_parser_frames{};
  std::array<std::array<typename DisclosureJson::ContainerIdStack,14>,Slots>
      disclosure_parser_container_ids{};
  std::array<std::array<typename DisclosureJson::Token,13>,Slots>
      disclosure_parser_tokens{};
  std::array<std::array<typename DisclosureJson::NumberWitness,13>,Slots>
      disclosure_parser_numbers{};
  using GraphSha = proofs::FlatSHA256Circuit<
      Logic, proofs::BitPlucker<Logic, 4>>;
  struct GraphDigestAdvice {
    std::array<Byte, 86> ascii{};
    typename GraphRelation::Index active_length{};
    std::array<Byte, 64> decoded_json{};
    typename GraphRelation::Index decoded_length{};
    std::array<Byte, 128> sha_input{};
    std::array<typename GraphSha::BlockWitness, 2> sha_witness{};
    typename Logic::v256 digest_bits{};
    Byte sha_block_count{};
  };
  std::array<GraphDigestAdvice, Slots> graph_digests{};
};

template <class Logic, std::size_t Slots, class Source>
void BindFullDisclosureAdviceV1Into(
    Logic& logic, Source& source,
    FullDisclosureCircuitAdviceV1<Logic, Slots>& result) {
  for (auto* set : {&result.supplied, &result.references})
    for (auto& digest : *set) for (auto& byte : digest) byte = source.byte();
  for (auto& bit : result.active) bit = source.bit();
  for (auto& depth : result.depths) for (auto& bit : depth) bit = source.bit();
  for (auto& byte : result.vct_name) byte = source.byte();
  for (auto& byte : result.private_vct) byte = source.byte();
  for (auto& byte : result.requested_vct) byte = source.byte();
  for (auto& byte : result.alg) byte = source.byte();
  for (auto& byte : result.typ) byte = source.byte();
  for (auto& byte : result.profile) byte = source.byte();
  for (auto& byte : result.policy_path) byte = source.byte();
  for (auto& byte : result.other_policy_path) byte = source.byte();
  result.equality_result = source.bit();
  for (auto& claim : result.registered_claims) {
    claim.top_level = source.bit(); claim.is_string = source.bit(); claim.present = source.bit();
  }
  for (auto* value : {&result.nbf, &result.exp, &result.iat, &result.now})
    for (auto& bit : *value) bit = source.bit();
  result.time_result = source.bit(); result.iat_result = source.bit();
  for (auto& bit : result.policy_kind) bit = source.bit();
  result.boolean_value = source.bit(); result.boolean_result = source.bit();
  for (auto* value : {&result.integer_value, &result.integer_low, &result.integer_high,
                      &result.date_value, &result.date_low, &result.date_high})
    for (auto& bit : *value) bit = source.bit();
  result.integer_result = source.bit(); result.date_result = source.bit();
  for (auto& byte : result.set_value) byte = source.byte();
  for (auto& option : result.set_options) for (auto& byte : option) byte = source.byte();
  result.set_result = source.bit();
  for (auto& byte : result.issuer_key) byte = source.byte();
  for (auto& byte : result.trust_key) byte = source.byte();
  for (auto& byte : result.trust_root) byte = source.byte();
  for (auto& byte : result.selected_trust_root) byte = source.byte();
  for (auto& byte : result.holder_key) byte = source.byte();
  for (auto& byte : result.kb_signer_key) byte = source.byte();
  for (auto& byte : result.presentation_hash) byte = source.byte();
  for (auto& byte : result.kb_sd_hash) byte = source.byte();
  for (auto& byte : result.challenge) byte = source.byte();
  for (auto& byte : result.kb_challenge) byte = source.byte();
  const auto index = [&]() {
    typename Logic::template bitvec<8> value{};
    for (auto& bit : value) bit = source.bit();
    return value;
  };
  for (auto& node : result.graph.nodes) {
    for (auto& byte : node.supplied_digest) byte = source.byte();
    node.kind = source.byte(); node.arity = source.byte();
    node.source = index(); node.parent = index(); node.depth = index();
    node.reference_index = index(); node.disclosure_begin = index();
    node.disclosure_end = index(); node.value_begin = index();
    node.value_end = index();
    for (auto& byte : node.path) byte = source.byte();
    node.path_length = index();
  }
  for (auto& reference : result.graph.references) {
    for (auto& byte : reference.digest) byte = source.byte();
    reference.kind = source.byte(); reference.source = index();
    reference.begin = index(); reference.end = index();
  }
  result.graph.supplied_active = index();
  result.graph.reference_active = index();
  for (auto& length : result.graph.source_lengths) length = index();
  for (auto& source_tokens : result.graph_tokens)
    for (auto& token : source_tokens) {
      token.kind = source.byte(); token.begin = index(); token.end = index();
    }
  for (auto& count : result.graph_token_counts) count = index();
  for (auto& source_depths : result.graph_token_depths)
    for (auto& depth : source_depths) depth = index();
  auto& selected = result.graph_selected[0];
  selected.node_index = index();
  for (auto& byte : selected.path) byte = source.byte();
  selected.path_length = index(); selected.kind = source.byte();
  selected.source = index(); selected.value_begin = index();
  selected.value_end = index(); result.graph_selected_active = index();
  for (auto& placement : result.graph_placements)
    for (auto* value : {&placement.marker_token, &placement.colon_token,
                        &placement.value_open_token, &placement.reference_token,
                        &placement.object_open_token, &placement.object_close_token,
                        &placement.parent_array_open_token, &placement.component_token,
                        &placement.array_index})
      *value = index();
  auto& authenticated = result.graph_authenticated_selected[0];
  authenticated.node_index = index(); authenticated.kind = source.byte();
  authenticated.component_token = index(); authenticated.array_index = index();
  authenticated.source = index(); authenticated.value_begin = index();
  authenticated.value_end = index();
  result.graph_authenticated_selected_active = index();
  for (auto& string : result.issuer_parser_strings) {
    string.unit_count = index();
    for (auto& unit : string.units) {
      unit.begin = index(); unit.end = index();
      for (auto& bit : unit.codepoint) bit = source.bit();
    }
  }
  for (auto& stack : result.issuer_parser_frames)
    for (auto& frame : stack) frame = source.byte();
  for (auto& stack : result.issuer_parser_container_ids)
    for (auto& id : stack) id = index();
  for (auto& byte : result.issuer_parser_text) byte = source.byte();
  for (auto& token : result.issuer_parser_tokens) {
    token.kind = source.byte(); token.begin = index(); token.end = index();
  }
  for (auto& number : result.issuer_parser_numbers) {
    number.negative = source.bit(); number.exponent_negative = source.bit();
    for (auto* value : {&number.digit_count, &number.fraction_count,
                        &number.significant_begin, &number.significant_end,
                        &number.significant_length}) *value = index();
    for (auto& value : number.digit_offsets) value = index();
    for (auto& value : number.significand) value = source.byte();
    for (auto& value : number.states) value = source.byte();
    for (auto& value : number.exponent_accumulator)
      for (auto& bit : value) bit = source.bit();
    for (auto& bit : number.scale) bit = source.bit();
  }
  for (auto& source_strings : result.disclosure_parser_strings)
    for (auto& string : source_strings) {
      string.unit_count = index();
      for (auto& unit : string.units) {
        unit.begin = index(); unit.end = index();
        for (auto& bit : unit.codepoint) bit = source.bit();
      }
    }
  for (auto& source_frames : result.disclosure_parser_frames)
    for (auto& stack : source_frames)
      for (auto& frame : stack) frame = source.byte();
  for (auto& source_ids : result.disclosure_parser_container_ids)
    for (auto& stack : source_ids)
      for (auto& id : stack) id = index();
  for (auto& source_tokens : result.disclosure_parser_tokens)
    for (auto& token : source_tokens) {
      token.kind = source.byte(); token.begin = index(); token.end = index();
    }
  for (auto& source_numbers : result.disclosure_parser_numbers)
    for (auto& number : source_numbers) {
      number.negative = source.bit(); number.exponent_negative = source.bit();
      for (auto* value : {&number.digit_count, &number.fraction_count,
                          &number.significant_begin, &number.significant_end,
                          &number.significant_length})
        *value = index();
      for (auto& value : number.digit_offsets) value = index();
      for (auto& value : number.significand) value = source.byte();
      for (auto& value : number.states) value = source.byte();
      for (auto& value : number.exponent_accumulator)
        for (auto& bit : value) bit = source.bit();
      for (auto& bit : number.scale) bit = source.bit();
    }
  for (auto& digest : result.graph_digests) {
    for (auto& byte : digest.ascii) byte = source.byte();
    digest.active_length = index();
    for (auto& byte : digest.decoded_json) byte = source.byte();
    digest.decoded_length = index();
    for (auto& byte : digest.sha_input) byte = source.byte();
    for (auto& witness : digest.sha_witness) {
      for (auto& value : witness.outw) value = source.packed();
      for (std::size_t i = 0; i < 64; ++i) {
        witness.oute[i] = source.packed(); witness.outa[i] = source.packed();
      }
      for (auto& value : witness.h1) value = source.packed();
    }
    for (auto& bit : digest.digest_bits) bit = source.bit();
    digest.sha_block_count = source.byte();
  }
}

// The full 32-disclosure compiler bucket has a large private advice layout.
// Keep the in-place binder available so the factory can heap-own that layout
// instead of materializing it in a compiler-stack frame.  Small evaluator
// fixtures retain this value-returning convenience wrapper.
template <class Logic, std::size_t Slots, class Source>
FullDisclosureCircuitAdviceV1<Logic, Slots> BindFullDisclosureAdviceV1(
    Logic& logic, Source& source) {
  FullDisclosureCircuitAdviceV1<Logic, Slots> result{};
  BindFullDisclosureAdviceV1Into(logic, source, result);
  return result;
}

template <Binding ExpectedBinding, Trust ExpectedTrust, class Logic, std::size_t Slots>
void AssertFullDisclosureAdviceV1(const Logic& logic,
                                  FullDisclosureCircuitAdviceV1<Logic, Slots>& advice,
                                  const std::array<typename Logic::v8, 128>* authenticated_payload = nullptr,
                                  const typename Logic::template bitvec<8>* authenticated_payload_length = nullptr) {
  typename FullDisclosureCircuitAdviceV1<Logic, Slots>::GraphRelation graph_relation(logic);
  graph_relation.assert_one_to_one(
      advice.supplied, advice.references, advice.active);
  graph_relation.assert_traversal_depth(advice.depths, advice.active, 2);
  graph_relation.assert_graph(advice.graph, 2, true);
  graph_relation.assert_selected_results(
      advice.graph, advice.graph_selected, advice.graph_selected_active);
  using IssuerInput = BoundedJsonCircuitInput<Logic,128,13,8,13>;
  using DisclosureInput = BoundedJsonCircuitInput<Logic,64,13,8,13>;
  // These parser witnesses are intentionally heap-owned: at production
  // capacities they exceed the evaluator's bounded stack when coexisting with
  // the complete graph advice.  The allocated wires and constraints are
  // otherwise identical to the former local aggregates.
  auto issuer_storage = std::make_unique<IssuerInput>();
  auto disclosures_storage = std::make_unique<std::array<DisclosureInput,Slots>>();
  auto& issuer = *issuer_storage;
  issuer.text = authenticated_payload == nullptr ? advice.issuer_parser_text
                                                  : *authenticated_payload;
  issuer.active_length = authenticated_payload_length == nullptr
                             ? advice.graph.source_lengths[0]
                             : *authenticated_payload_length;
  issuer.token_count = advice.graph_token_counts[0];
  issuer.tokens = advice.issuer_parser_tokens;
  issuer.strings = advice.issuer_parser_strings;
  issuer.numbers = advice.issuer_parser_numbers;
  issuer.depths = advice.graph_token_depths[0];
  issuer.frames = advice.issuer_parser_frames;
  issuer.container_ids = advice.issuer_parser_container_ids;
  auto& disclosures = *disclosures_storage;
  for (std::size_t slot = 0; slot < Slots; ++slot) {
    auto& parser = disclosures[slot];
    parser.text = advice.graph_digests[slot].decoded_json;
    parser.active_length = advice.graph_digests[slot].decoded_length;
    parser.token_count = advice.graph_token_counts[slot + 1];
    parser.tokens = advice.disclosure_parser_tokens[slot];
    parser.strings = advice.disclosure_parser_strings[slot];
    parser.numbers = advice.disclosure_parser_numbers[slot];
    parser.depths = advice.graph_token_depths[slot + 1];
    parser.frames = advice.disclosure_parser_frames[slot];
    parser.container_ids = advice.disclosure_parser_container_ids[slot];
  }
  graph_relation.template assert_heterogeneous_bounded_source_placements<128,64,13,13,13>(
      advice.graph, advice.graph_placements, issuer, disclosures);
  graph_relation.assert_authenticated_selected_results(
      advice.graph, advice.graph_placements, advice.graph_authenticated_selected,
      advice.graph_authenticated_selected_active);
  for (std::size_t slot = 0; slot < Slots; ++slot) {
    auto& digest = advice.graph_digests[slot];
    const auto live = logic.vlt(slot, advice.graph.supplied_active);
    graph_relation.template assert_bounded_digest_link<2, 86>(
        advice.graph.nodes[slot], digest.ascii, digest.active_length,
        digest.decoded_json,
        digest.decoded_length, digest.sha_input, digest.sha_witness,
        digest.digest_bits, digest.sha_block_count, live);
  }
  SwissPolicyRelation<Logic> policy(logic);
  policy.assert_top_level_vct(advice.vct_name);
  policy.assert_equality(advice.private_vct, advice.requested_vct, advice.equality_result);
  policy.assert_fixed_text(advice.alg, std::array<unsigned char, 5>{'E', 'S', '2', '5', '6'});
  policy.assert_fixed_text(advice.typ, std::array<unsigned char, 9>{'d','c','+','s','d','-','j','w','t'});
  policy.assert_fixed_text(advice.profile, std::array<unsigned char, 22>{'s','w','i','s','s','-','p','r','o','f','i','l','e','-','v','c',':','1','.','0','.','0'});
  for (const auto& claim : advice.registered_claims)
    policy.assert_disclosed_registered_claim(claim.top_level, claim.is_string, claim.present);
  policy.assert_time_window(advice.nbf, advice.exp, advice.now, advice.time_result);
  policy.assert_integer_range(advice.iat, logic.template vbit<5>(0), advice.now, advice.iat_result);
  policy.assert_distinct_paths(advice.policy_path, advice.other_policy_path);
  logic.assert1(logic.vleq(advice.policy_kind, 4));
  policy.assert_boolean(advice.boolean_result, advice.boolean_value);
  policy.assert_integer_range(advice.integer_value, advice.integer_low, advice.integer_high,
                              advice.integer_result);
  policy.assert_date_range(advice.date_value, advice.date_low, advice.date_high, advice.date_result);
  policy.assert_set_membership(advice.set_value, advice.set_options, advice.set_result);
  // These are relation inputs, rather than verifier-side family labels.  The
  // conditional blocks deliberately change both the input layout and the
  // constraint graph for each binding/trust specialization.
  static_assert(ExpectedTrust == Trust::exact_key,
                "issuer-registry trust is not part of this release");
  for (std::size_t i = 0; i < advice.issuer_key.size(); ++i)
    logic.vassert_eq(advice.issuer_key[i], advice.trust_key[i]);
  if constexpr (ExpectedBinding == Binding::holder_bound) {
    for (std::size_t i = 0; i < advice.holder_key.size(); ++i)
      logic.vassert_eq(advice.holder_key[i], advice.kb_signer_key[i]);
    for (std::size_t i = 0; i < advice.presentation_hash.size(); ++i) {
      logic.vassert_eq(advice.presentation_hash[i], advice.kb_sd_hash[i]);
      logic.vassert_eq(advice.challenge[i], advice.kb_challenge[i]);
    }
  }
}

// Representative opt-in compiler bucket for the versioned full family.  It
// uses the same composite bounded JSON relation as the production family;
// larger family buckets are selected by their distinct identities.
template <Binding ExpectedBinding, Trust ExpectedTrust,
          std::size_t JsonCapacity, std::size_t JsonTokens,
          std::size_t JsonIndexBits, std::size_t JsonDepth,
          std::size_t Slots>
inline std::unique_ptr<proofs::Circuit<proofs::Fp256Base>>
BuildFullDisclosureBucketCircuitV1(proofs::QuadCircuit<proofs::Fp256Base>* q) {
  using Field = proofs::Fp256Base;
  using Backend = proofs::CompilerBackend<Field>;
  using Logic = proofs::Logic<Field, Backend>;
  Backend backend(q); Logic logic(&backend, proofs::p256_base);
  struct FactorySource {
    Logic& logic;
    typename Logic::v8 byte() { return logic.template vinput<8>(); }
    typename Logic::BitW bit() { return logic.input(); }
    typename FullDisclosureCircuitAdviceV1<Logic, Slots>::GraphSha::packed_v32
    packed() {
      typename FullDisclosureCircuitAdviceV1<Logic, Slots>::GraphSha::packed_v32 value{};
      for (auto& element : value) element = logic.eltw_input();
      return value;
    }
  } source{logic};
  auto advice = std::make_unique<FullDisclosureCircuitAdviceV1<Logic, Slots>>();
  BindFullDisclosureAdviceV1Into(logic, source, *advice);
  // Source zero of the recursive graph is the exact decoded issuer payload
  // produced by the authenticated flat bearer relation, never parallel advice.
  std::array<typename Logic::v8, 128> authenticated_payload{};
  typename Logic::template bitvec<8> authenticated_payload_length{};
  // Retain the exact issuer relation's compact wire bundle for the disclosure
  // bridge; no independently allocated source-zero header/payload advice is
  // permitted in this factory path.
  FlatBearerCompactOpeningWireBundleV1<Logic> compact_opening{};
  std::array<typename Logic::EltW, 32> issuer_public_signing_digest{};
  AllocateFlatBearerRelationV1(q, logic, &advice->issuer_key,
                               &advice->references[0],
                               &authenticated_payload,
                               &authenticated_payload_length,
                               &issuer_public_signing_digest,
                               &compact_opening, false);
  CompactOpeningBridgeRelation<Logic, 102, 140, 5>(logic).assert_valid({
      compact_opening.header, compact_opening.header_length,
      compact_opening.payload, compact_opening.payload_length,
      compact_opening.sha_input, compact_opening.sha_witness,
      compact_opening.digest_bits, compact_opening.sha_block_count,
      issuer_public_signing_digest, compact_opening.decoded_payload,
      authenticated_payload_length});
  AssertFullDisclosureAdviceV1<ExpectedBinding, ExpectedTrust>(
      logic, *advice, &authenticated_payload, &authenticated_payload_length);
  return q->mkcircuit(1);
}
template <Binding ExpectedBinding = Binding::bearer,
          Trust ExpectedTrust = Trust::exact_key,
          std::size_t Slots = FullDisclosureSmallV1::kMaxDisclosures>
inline std::unique_ptr<proofs::Circuit<proofs::Fp256Base>>
BuildFullDisclosureCircuitV1(proofs::QuadCircuit<proofs::Fp256Base>* q) {
  return BuildFullDisclosureBucketCircuitV1<
      ExpectedBinding, ExpectedTrust, FullDisclosureSmallV1::kCapacity,
      FullDisclosureSmallV1::kMaxTokens, 5,
      FullDisclosureSmallV1::kMaxDepth, Slots>(q);
}
template <Binding ExpectedBinding = Binding::bearer,
          Trust ExpectedTrust = Trust::exact_key>
inline std::unique_ptr<proofs::Circuit<proofs::Fp256Base>>
BuildFullDisclosureMediumCircuitV1(
    proofs::QuadCircuit<proofs::Fp256Base>* q) {
  return BuildFullDisclosureBucketCircuitV1<
      ExpectedBinding, ExpectedTrust, FullDisclosureMediumV1::kCapacity,
      FullDisclosureMediumV1::kMaxTokens, 5,
      FullDisclosureMediumV1::kMaxDepth,
      FullDisclosureMediumV1::kMaxDisclosures>(q);
}
inline std::unique_ptr<proofs::Circuit<proofs::Fp256Base>>
BuildFullDisclosureRepresentativeCircuitV1(proofs::QuadCircuit<proofs::Fp256Base>* q) {
  return BuildFullDisclosureCircuitV1<Binding::bearer, Trust::exact_key, 2>(q);
}
// A separately named static capacity bucket for focused object+array graph
// evaluation. It does not widen or alter the full32 family.
template <Binding ExpectedBinding = Binding::bearer,
          Trust ExpectedTrust = Trust::exact_key>
inline std::unique_ptr<proofs::Circuit<proofs::Fp256Base>>
BuildFullDisclosureFocusedCircuitV1(
    proofs::QuadCircuit<proofs::Fp256Base>* q) {
  static_assert(FullDisclosureFocusedV1::kLiveDisclosures == 2);
  return BuildFullDisclosureCircuitV1<ExpectedBinding, ExpectedTrust,
                                      FullDisclosureFocusedV1::kLiveDisclosures>(q);
}

// This authenticated diagnostic circuit is a distinct, statically bounded
// family: one issuer payload produced by the flat bearer relation and one
// decoded disclosure source.  It deliberately retains the production
// source-zero handoff while avoiding any witness-controlled slot selection.
template <Binding ExpectedBinding = Binding::bearer,
          Trust ExpectedTrust = Trust::exact_key>
inline std::unique_ptr<proofs::Circuit<proofs::Fp256Base>>
BuildFullDisclosureAuthenticatedFocusedCircuitV1(
    proofs::QuadCircuit<proofs::Fp256Base>* q) {
  static_assert(FullDisclosureAuthenticatedFocusedV1::kLiveDisclosures == 1);
  return BuildFullDisclosureCircuitV1<
      ExpectedBinding, ExpectedTrust,
      FullDisclosureAuthenticatedFocusedV1::kLiveDisclosures>(q);
}
}  // namespace sd_jwt_zk
