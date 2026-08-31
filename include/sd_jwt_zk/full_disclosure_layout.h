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

#pragma once
#include <array>
#include <cstdint>
namespace sd_jwt_zk {
// Canonical private-advice order after bounded JSON input.  The compiler
// factory and the EvaluationBackend harness both bind these fields in this
// exact order through FullDisclosureCircuitAdviceV1.
struct RegisteredClaimAdviceV1 {
  std::uint8_t top_level{};
  std::uint8_t is_string{};
  std::uint8_t present{};
};
template<std::size_t PathBytes> struct FullDisclosureGraphNodeAdviceV1 {
  std::array<std::uint8_t,43> digest{};
  std::uint8_t kind{}, arity{}, source{}, parent{}, depth{}, reference_index{};
  std::uint8_t disclosure_begin{}, disclosure_end{}, value_begin{}, value_end{};
  std::array<std::uint8_t,PathBytes> path{};
  std::uint8_t path_length{};
};
struct FullDisclosureGraphReferenceAdviceV1 {
  std::array<std::uint8_t,43> digest{};
  std::uint8_t kind{}, source{}, begin{}, end{};
};
struct FullDisclosureRangeTokenAdviceV1 {
  std::uint8_t kind{}, begin{}, end{};
};
struct FullDisclosurePlacementAdviceV1 {
  std::uint8_t marker_token{}, colon_token{}, value_open_token{}, reference_token{};
  std::uint8_t object_open_token{}, object_close_token{}, parent_array_open_token{};
  std::uint8_t component_token{}, array_index{};
};
struct FullDisclosureAuthenticatedSelectedAdviceV1 {
  std::uint8_t node_index{}, kind{}, component_token{}, array_index{};
  std::uint8_t source{}, value_begin{}, value_end{};
};
struct FullDisclosurePlacementStringUnitAdviceV1 {
  std::uint8_t begin{}, end{}; std::uint32_t codepoint{};
};
template<std::size_t Capacity> struct FullDisclosurePlacementStringAdviceV1 {
  std::uint8_t unit_count{};
  std::array<FullDisclosurePlacementStringUnitAdviceV1,Capacity> units{};
};
template<std::size_t Capacity> struct FullDisclosurePlacementNumberAdviceV1 {
  std::uint8_t negative{}, exponent_negative{}, digit_count{}, fraction_count{};
  std::uint8_t significant_begin{}, significant_end{}, significant_length{};
  std::array<std::uint8_t,Capacity> digit_offsets{}, significand{};
  std::array<std::uint8_t,Capacity + 1> states{};
  std::array<std::array<std::uint8_t,Capacity * 4 + 2>,Capacity + 1>
      exponent_accumulator{};
  std::array<std::uint8_t,Capacity * 4 + 2> scale{};
};
template<std::size_t PathBytes> struct FullDisclosureSelectedAdviceV1 {
  std::uint8_t node_index{};
  std::array<std::uint8_t,PathBytes> path{};
  std::uint8_t path_length{}, kind{}, source{}, value_begin{}, value_end{};
};

template<std::size_t Slots> struct FullDisclosureAdviceV1 {
  std::array<std::array<std::uint8_t,43>,Slots> supplied{}, references{};
  std::uint8_t active{};
  std::array<std::uint8_t,Slots> depths{};
  std::array<std::uint8_t,3> vct_name{};
  std::array<std::uint8_t,5> private_vct{}, requested_vct{};
  std::uint8_t equality_result{};
  std::array<std::uint8_t,5> alg{};
  std::array<std::uint8_t,9> typ{};
  std::array<std::uint8_t,22> profile{};
  std::array<RegisteredClaimAdviceV1,7> registered_claims{};
  std::uint8_t nbf{}, exp{}, iat{}, now{};
  std::uint8_t time_result{}, iat_result{};
  std::array<std::uint8_t,2> policy_path{}, other_policy_path{};
  std::uint8_t policy_kind{};
  std::uint8_t boolean_value{}, boolean_result{};
  std::uint8_t integer_value{}, integer_low{}, integer_high{}, integer_result{};
  std::uint8_t date_value{}, date_low{}, date_high{}, date_result{};
  std::array<std::uint8_t,1> set_value{};
  std::array<std::array<std::uint8_t,1>,2> set_options{};
  std::uint8_t set_result{};
  std::array<std::uint8_t,8> issuer_key{}, exact_trust_key{};
  std::array<std::uint8_t,8> registry_authorized_key{};
  std::array<std::uint8_t,16> registry_root{}, registry_selected_root{};
  std::array<std::uint8_t,8> credential_holder_key{}, kb_signer_key{};
  std::array<std::uint8_t,16> presentation_hash{}, kb_sd_hash{};
  std::array<std::uint8_t,16> challenge{}, kb_challenge{};
  std::array<FullDisclosureGraphNodeAdviceV1<64>,Slots> graph_nodes{};
  std::array<FullDisclosureGraphReferenceAdviceV1,Slots> graph_references{};
  std::uint8_t graph_supplied_active{}, graph_reference_active{};
  std::array<std::uint8_t,Slots+1> graph_source_lengths{};
  std::array<std::array<FullDisclosureRangeTokenAdviceV1,13>,Slots+1> graph_tokens{};
  std::array<std::uint8_t,Slots+1> graph_token_counts{};
  std::array<std::array<std::uint8_t,14>,Slots+1> graph_token_depths{};
  FullDisclosureSelectedAdviceV1<64> graph_selected{};
  std::uint8_t graph_selected_active{};
  std::array<FullDisclosurePlacementAdviceV1,Slots> graph_placements{};
  FullDisclosureAuthenticatedSelectedAdviceV1 graph_authenticated_selected{};
  std::uint8_t graph_authenticated_selected_active{};
  // Source zero is the issuer-authenticated payload (128-byte bucket).
  // Disclosure sources are smaller 64-byte decoded JSON buckets.
  std::array<std::uint8_t,128> issuer_parser_text{};
  std::array<FullDisclosurePlacementStringAdviceV1<128>,13> issuer_parser_strings{};
  std::array<std::array<std::uint8_t,14>,14> issuer_parser_frames{};
  std::array<std::array<std::uint8_t,14>,14> issuer_parser_container_ids{};
  std::array<FullDisclosureRangeTokenAdviceV1,13> issuer_parser_tokens{};
  std::array<FullDisclosurePlacementNumberAdviceV1<128>,13> issuer_parser_numbers{};
  std::array<std::array<FullDisclosurePlacementStringAdviceV1<64>,13>,Slots>
      disclosure_parser_strings{};
  std::array<std::array<std::array<std::uint8_t,14>,14>,Slots>
      disclosure_parser_frames{};
  std::array<std::array<std::array<std::uint8_t,14>,14>,Slots>
      disclosure_parser_container_ids{};
  std::array<std::array<FullDisclosureRangeTokenAdviceV1,13>,Slots>
      disclosure_parser_tokens{};
  std::array<std::array<FullDisclosurePlacementNumberAdviceV1<64>,13>,Slots>
      disclosure_parser_numbers{};
};
}
