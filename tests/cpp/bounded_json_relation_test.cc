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

#include "sd_jwt_zk/bounded_json_relation.h"
#include "sd_jwt_zk/bounded_json.h"
#include "sd_jwt_zk/bounded_json_circuit.h"
#include "sd_jwt_zk/flat_disclosure_relation.h"
#include "sd_jwt_zk/full_disclosure_circuit.h"
#include "sd_jwt_zk/full_disclosure_relation.h"
#include "sd_jwt_zk/swiss_policy_relation.h"
#include "sd_jwt_zk/full_disclosure_family.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"

namespace {
using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Relation = sd_jwt_zk::BoundedJsonTokenRelation<Logic, 32, 8, 8>;
using StringRelation = sd_jwt_zk::BoundedJsonTokenRelation<Logic, 24, 2, 5>;
using NumberRelation = sd_jwt_zk::BoundedJsonTokenRelation<Logic, 24, 2, 5>;
using DuplicateRelation = sd_jwt_zk::BoundedJsonTokenRelation<Logic, 24, 10, 5>;
using ShallowRelation = sd_jwt_zk::BoundedJsonTokenRelation<Logic, 16, 8, 5, 1>;

struct PlainStringUnit {
  std::size_t begin;
  std::size_t end;
  std::uint32_t codepoint;
};

bool accepts_string(const std::string& input,
                    const std::vector<PlainStringUnit>& units,
                    bool dirty_padding = false) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, 24> text{};
  for (std::size_t i = 0; i < text.size(); ++i)
    text[i] = logic.template vbit<8>(
        i < input.size() ? static_cast<unsigned char>(input[i]) : 0);
  using Index = Logic::bitvec<5>;
  std::array<StringRelation::Token, 2> tokens{};
  for (std::size_t token = 0; token < tokens.size(); ++token) {
    tokens[token].kind = logic.template vbit<8>(
        token == 0 ? static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::string) : 0);
    logic.bits(5, tokens[token].begin.data(), 0);
    logic.bits(5, tokens[token].end.data(), token == 0 ? input.size() : 0);
  }
  Index length{}, count{};
  logic.bits(5, length.data(), input.size());
  logic.bits(5, count.data(), 1);
  std::array<StringRelation::StringWitness, 2> strings{};
  for (std::size_t token = 0; token < strings.size(); ++token) {
    logic.bits(5, strings[token].unit_count.data(), token == 0 ? units.size() : 0);
    for (std::size_t unit = 0; unit < strings[token].units.size(); ++unit) {
      const bool active = token == 0 && unit < units.size();
      const std::size_t begin = active ? units[unit].begin : 0;
      const std::size_t end = active ? units[unit].end : 0;
      const std::uint32_t codepoint = active ? units[unit].codepoint :
          (dirty_padding && token == 0 && unit == units.size() ? 1u : 0u);
      logic.bits(5, strings[token].units[unit].begin.data(), begin);
      logic.bits(5, strings[token].units[unit].end.data(), end);
      logic.bits(21, strings[token].units[unit].codepoint.data(), codepoint);
    }
  }
  StringRelation relation(logic);
  relation.assert_partition(text, length, count, tokens);
  relation.assert_string_lexemes(text, count, tokens, strings);
  return !backend.assertion_failed();
}

using BigBits = std::array<unsigned char, 98>;

BigBits add_bits(const BigBits& left, const BigBits& right) {
  BigBits out{};
  unsigned carry = 0;
  for (std::size_t bit = 0; bit < out.size(); ++bit) {
    const unsigned sum = left[bit] + right[bit] + carry;
    out[bit] = static_cast<unsigned char>(sum & 1u);
    carry = sum >> 1;
  }
  return out;
}

BigBits small_bits(std::size_t value) {
  BigBits out{};
  for (std::size_t bit = 0; bit < out.size() && bit < 8 * sizeof(value); ++bit)
    out[bit] = static_cast<unsigned char>((value >> bit) & 1u);
  return out;
}

BigBits negate_bits(BigBits value) {
  for (auto& bit : value) bit ^= 1u;
  return add_bits(value, small_bits(1));
}

BigBits multiply_ten(const BigBits& value) {
  BigBits twice{}, eight_times{};
  for (std::size_t bit = 1; bit < value.size(); ++bit) twice[bit] = value[bit - 1];
  for (std::size_t bit = 3; bit < value.size(); ++bit) eight_times[bit] = value[bit - 3];
  return add_bits(twice, eight_times);
}

BigBits add_signed_small(BigBits value, std::int64_t adjustment) {
  if (adjustment >= 0)
    return add_bits(value, small_bits(static_cast<std::size_t>(adjustment)));
  return add_bits(value,
                  negate_bits(small_bits(static_cast<std::size_t>(-adjustment))));
}

template <class Bits>
void set_big(const Logic& logic, Bits& bits, const BigBits& value) {
  for (std::size_t bit = 0; bit < bits.size(); ++bit)
    bits[bit] = logic.bit(value[bit]);
}

template <class NumberWitness>
void fill_number_witness(const Logic& logic, const std::string& input,
                         NumberWitness& witness, bool bad_scale = false,
                         bool bad_significand = false,
                         std::size_t source_begin = 0) {
  enum State : unsigned char { start = 1, minus = 2, zero = 3, integer = 4,
    dot = 5, fraction = 6, exponent = 7, exponent_sign = 8,
    exponent_digits = 9 };
  std::vector<unsigned char> states(witness.states.size(), 0);
  std::vector<BigBits> accum(witness.exponent_accumulator.size());
  std::vector<std::size_t> offsets;
  std::string coefficient;
  std::size_t fraction_count = 0;
  bool raw_negative = false, exponent_negative = false;
  states[source_begin] = start;
  for (std::size_t i = 0; i < input.size(); ++i) {
    const std::size_t source = source_begin + i;
    const unsigned char state = states[source];
    const unsigned char c = static_cast<unsigned char>(input[i]);
    const bool digit = c >= '0' && c <= '9';
    unsigned char next = 0;
    bool coefficient_digit = false, fraction_digit = false, exponent_digit = false;
    if (state == start && c == '-') { next = minus; raw_negative = true; }
    else if ((state == start || state == minus) && c == '0') { next = zero; coefficient_digit = true; }
    else if ((state == start || state == minus) && c >= '1' && c <= '9') { next = integer; coefficient_digit = true; }
    else if (state == zero && c == '.') next = dot;
    else if (state == zero && (c == 'e' || c == 'E')) next = exponent;
    else if (state == integer && digit) { next = integer; coefficient_digit = true; }
    else if (state == integer && c == '.') next = dot;
    else if (state == integer && (c == 'e' || c == 'E')) next = exponent;
    else if ((state == dot || state == fraction) && digit) { next = fraction; coefficient_digit = true; fraction_digit = true; }
    else if (state == fraction && (c == 'e' || c == 'E')) next = exponent;
    else if (state == exponent && (c == '+' || c == '-')) { next = exponent_sign; exponent_negative = c == '-'; }
    else if ((state == exponent || state == exponent_sign || state == exponent_digits) && digit) { next = exponent_digits; exponent_digit = true; }
    states[source + 1] = next;
    accum[source + 1] = accum[source];
    if (exponent_digit)
      accum[source + 1] = add_bits(multiply_ten(accum[source]), small_bits(c - '0'));
    if (coefficient_digit) { offsets.push_back(source); coefficient.push_back(static_cast<char>(c)); }
    if (fraction_digit) ++fraction_count;
  }
  const auto first = coefficient.find_first_not_of('0');
  std::size_t significant_begin = 0, significant_end = 0;
  std::string significand;
  BigBits scale{};
  bool semantic_negative = false;
  if (first != std::string::npos) {
    significant_begin = first;
    significant_end = coefficient.find_last_not_of('0') + 1;
    significand = coefficient.substr(significant_begin,
                                     significant_end - significant_begin);
    const BigBits& exponent_value = accum[source_begin + input.size()];
    scale = exponent_negative ? negate_bits(exponent_value) : exponent_value;
    scale = add_signed_small(
        scale, static_cast<std::int64_t>(coefficient.size() - significant_end) -
                   static_cast<std::int64_t>(fraction_count));
    semantic_negative = raw_negative;
  }
  if (bad_scale) scale = add_signed_small(scale, 1);
  if (bad_significand && !significand.empty()) significand[0] = '9';
  witness.negative = logic.bit(semantic_negative);
  witness.exponent_negative = logic.bit(exponent_negative);
  logic.bits(5, witness.digit_count.data(), coefficient.size());
  logic.bits(5, witness.fraction_count.data(), fraction_count);
  logic.bits(5, witness.significant_begin.data(), significant_begin);
  logic.bits(5, witness.significant_end.data(), significant_end);
  logic.bits(5, witness.significant_length.data(), significand.size());
  for (std::size_t i = 0; i < witness.digit_offsets.size(); ++i) {
    logic.bits(5, witness.digit_offsets[i].data(), i < offsets.size() ? offsets[i] : 0);
    witness.significand[i] = logic.template vbit<8>(
        i < significand.size() ? static_cast<unsigned char>(significand[i]) : 0);
  }
  for (std::size_t i = 0; i < witness.states.size(); ++i) {
    witness.states[i] = logic.template vbit<8>(i < states.size() ? states[i] : 0);
    set_big(logic, witness.exponent_accumulator[i],
            i < accum.size() ? accum[i] : BigBits{});
  }
  set_big(logic, witness.scale, scale);
}

template <class NumberWitness>
void zero_number_witness(const Logic& logic, NumberWitness& witness) {
  witness.negative = logic.bit(0);
  witness.exponent_negative = logic.bit(0);
  logic.bits(5, witness.digit_count.data(), 0);
  logic.bits(5, witness.fraction_count.data(), 0);
  logic.bits(5, witness.significant_begin.data(), 0);
  logic.bits(5, witness.significant_end.data(), 0);
  logic.bits(5, witness.significant_length.data(), 0);
  for (auto& offset : witness.digit_offsets) logic.bits(5, offset.data(), 0);
  for (auto& byte : witness.significand) byte = logic.template vbit<8>(0);
  for (auto& state : witness.states) state = logic.template vbit<8>(0);
  for (auto& accum : witness.exponent_accumulator)
    set_big(logic, accum, BigBits{});
  set_big(logic, witness.scale, BigBits{});
}

bool accepts_number(const std::string& input, bool bad_scale = false,
                    bool bad_significand = false,
                    bool permuted_offsets = false) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, 24> text{};
  for (std::size_t i = 0; i < text.size(); ++i)
    text[i] = logic.template vbit<8>(
        i < input.size() ? static_cast<unsigned char>(input[i]) : 0);
  using Index = Logic::bitvec<5>;
  std::array<NumberRelation::Token, 2> tokens{};
  for (std::size_t token = 0; token < tokens.size(); ++token) {
    tokens[token].kind = logic.template vbit<8>(
        token == 0 ? static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::number) : 0);
    logic.bits(5, tokens[token].begin.data(), 0);
    logic.bits(5, tokens[token].end.data(), token == 0 ? input.size() : 0);
  }
  Index length{}, count{};
  logic.bits(5, length.data(), input.size());
  logic.bits(5, count.data(), 1);
  std::array<NumberRelation::NumberWitness, 2> numbers{};
  fill_number_witness(logic, input, numbers[0], bad_scale, bad_significand);
  if (permuted_offsets)
    std::swap(numbers[0].digit_offsets[0], numbers[0].digit_offsets[1]);
  fill_number_witness(logic, "0", numbers[1]);
  // Slot one is inactive and must use canonical zero advice.
  zero_number_witness(logic, numbers[1]);
  NumberRelation relation(logic);
  relation.assert_partition(text, length, count, tokens);
  relation.assert_number_lexemes(text, count, tokens, numbers);
  return !backend.assertion_failed();
}

bool numbers_equal(const std::string& left, const std::string& right,
                   bool expected_equal) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  using Index = Logic::bitvec<5>;
  const auto make = [&](const std::string& input,
                        std::array<Logic::v8, 24>& text,
                        std::array<NumberRelation::Token, 2>& tokens,
                        std::array<NumberRelation::NumberWitness, 2>& numbers,
                        Index& count) {
    for (std::size_t i = 0; i < text.size(); ++i)
      text[i] = logic.template vbit<8>(i < input.size() ?
          static_cast<unsigned char>(input[i]) : 0);
    for (std::size_t token = 0; token < tokens.size(); ++token) {
      tokens[token].kind = logic.template vbit<8>(token == 0 ?
          static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::number) : 0);
      logic.bits(5, tokens[token].begin.data(), 0);
      logic.bits(5, tokens[token].end.data(), token == 0 ? input.size() : 0);
    }
    logic.bits(5, count.data(), 1);
    fill_number_witness(logic, input, numbers[0]);
    zero_number_witness(logic, numbers[1]);
  };
  std::array<Logic::v8, 24> left_text{}, right_text{};
  std::array<NumberRelation::Token, 2> left_tokens{}, right_tokens{};
  std::array<NumberRelation::NumberWitness, 2> left_numbers{}, right_numbers{};
  Index left_count{}, right_count{};
  make(left, left_text, left_tokens, left_numbers, left_count);
  make(right, right_text, right_tokens, right_numbers, right_count);
  NumberRelation relation(logic);
  relation.assert_number_lexemes(left_text, left_count, left_tokens, left_numbers);
  relation.assert_number_lexemes(right_text, right_count, right_tokens, right_numbers);
  const auto equal = relation.number_semantically_equal(left_numbers[0],
                                                        right_numbers[0]);
  logic.assert1(expected_equal ? equal : logic.lnot(equal));
  return !backend.assertion_failed();
}

bool accepts_object_keys(bool escaped_duplicate, bool forged_parent = false) {
  const std::string input = escaped_duplicate
      ? "{\"a\":0,\"\\u0061\":1}" : "{\"a\":0,\"b\":1}";
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, 24> text{};
  for (std::size_t i = 0; i < text.size(); ++i)
    text[i] = logic.template vbit<8>(i < input.size() ?
        static_cast<unsigned char>(input[i]) : 0);
  using Index = Logic::bitvec<5>;
  std::array<DuplicateRelation::Token, 10> tokens{};
  const std::array<unsigned char, 9> kinds{
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::object_open),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::string),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::colon),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::number),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::comma),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::string),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::colon),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::number),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::object_close)};
  const std::array<std::size_t, 9> duplicate_begins{0, 1, 4, 5, 6, 7, 15, 16, 17};
  const std::array<std::size_t, 9> duplicate_ends{1, 4, 5, 6, 7, 15, 16, 17, 18};
  const std::array<std::size_t, 9> distinct_begins{0, 1, 4, 5, 6, 7, 10, 11, 12};
  const std::array<std::size_t, 9> distinct_ends{1, 4, 5, 6, 7, 10, 11, 12, 13};
  for (std::size_t token = 0; token < tokens.size(); ++token) {
    tokens[token].kind = logic.template vbit<8>(token < kinds.size() ? kinds[token] : 0);
    logic.bits(5, tokens[token].begin.data(), token < kinds.size() ?
        (escaped_duplicate ? duplicate_begins[token] : distinct_begins[token]) : 0);
    logic.bits(5, tokens[token].end.data(), token < kinds.size() ?
        (escaped_duplicate ? duplicate_ends[token] : distinct_ends[token]) : 0);
  }
  Index length{}, count{};
  logic.bits(5, length.data(), input.size());
  logic.bits(5, count.data(), 9);
  std::array<DuplicateRelation::StringWitness, 10> strings{};
  for (std::size_t token = 0; token < strings.size(); ++token) {
    const bool key = token == 1 || token == 5;
    logic.bits(5, strings[token].unit_count.data(), key ? 1 : 0);
    for (std::size_t unit = 0; unit < strings[token].units.size(); ++unit) {
      std::size_t begin = 0, end = 0;
      std::uint32_t codepoint = 0;
      if (unit == 0 && token == 1) { begin = 2; end = 3; codepoint = 'a'; }
      if (unit == 0 && token == 5) {
        begin = 8; end = escaped_duplicate ? 14 : 9;
        codepoint = escaped_duplicate ? 'a' : 'b';
      }
      logic.bits(5, strings[token].units[unit].begin.data(), begin);
      logic.bits(5, strings[token].units[unit].end.data(), end);
      logic.bits(21, strings[token].units[unit].codepoint.data(), codepoint);
    }
  }
  std::array<Index, 11> depths{};
  const std::array<std::size_t, 10> depth_values{1, 2, 2, 2, 2, 2, 2, 2, 2, 1};
  std::array<DuplicateRelation::GrammarStack, 11> frames{};
  const std::array<unsigned char, 10> object_states{0, 3, 5, 6, 7, 4, 5, 6, 7, 0};
  std::array<DuplicateRelation::ContainerIdStack, 11> ids{};
  for (std::size_t step = 0; step < depths.size(); ++step) {
    logic.bits(5, depths[step].data(), step < depth_values.size() ? depth_values[step] : 0);
    for (std::size_t slot = 0; slot < frames[step].size(); ++slot) {
      unsigned char frame = 0;
      if (step < depth_values.size() && slot == 0) frame = step == 0 ? 1 : 2;
      if (step < object_states.size() && slot == 1) frame = object_states[step];
      frames[step][slot] = logic.template vbit<8>(frame);
      std::size_t id = step > 0 && step < 9 && slot == 1 ? 1 : 0;
      if (forged_parent && step == 5 && slot == 1) id = 2;
      logic.bits(5, ids[step][slot].data(), id);
    }
  }
  std::array<DuplicateRelation::NumberWitness, 10> numbers{};
  for (auto& number : numbers) zero_number_witness(logic, number);
  fill_number_witness(logic, "0", numbers[3], false, false, 5);
  fill_number_witness(logic, "1", numbers[7], false, false,
                      escaped_duplicate ? 16 : 11);
  DuplicateRelation relation(logic);
  relation.assert_json(text, length, count, tokens, strings, numbers,
                       depths, frames, ids);
  return !backend.assertion_failed();
}

bool accepts(std::string input, bool bad_literal = false, bool overlap = false,
             bool array_close = false, bool bad_state = false,
             std::size_t length_override = 0,
             std::size_t count_override = 0) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, 32> text{};
  for (std::size_t i = 0; i < text.size(); ++i)
    text[i] = logic.template vbit<8>(i < input.size() ? static_cast<unsigned char>(input[i]) : 0);
  if (bad_literal) text[5] = logic.template vbit<8>('x');
  using Index = Logic::bitvec<8>;
  std::array<Relation::Token, 8> tokens{};
  const std::array<unsigned char, 5> kinds{
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::object_open),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::string),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::colon),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::true_value),
      static_cast<unsigned char>(array_close ? sd_jwt_zk::JsonLexeme::array_close : sd_jwt_zk::JsonLexeme::object_close)};
  const std::array<std::size_t, 5> begins{0, 1, 4, overlap ? std::size_t{4} : std::size_t{5}, 9};
  const std::array<std::size_t, 5> ends{1, 4, 5, 9, 10};
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    tokens[i].kind = logic.template vbit<8>(i < kinds.size() ? kinds[i] : 0);
    logic.bits(8, tokens[i].begin.data(), i < begins.size() ? begins[i] : 0);
    logic.bits(8, tokens[i].end.data(), i < ends.size() ? ends[i] : 0);
  }
  Index length{}, count{};
  logic.bits(8, length.data(), length_override == 0 ? input.size() : length_override);
  logic.bits(8, count.data(), count_override == 0 ? 5 : count_override);
  Relation(logic).assert_partition(text, length, count, tokens);
  std::array<Index, 9> depths{};
  for (std::size_t i = 0; i < depths.size(); ++i)
    logic.bits(8, depths[i].data(), i == 0 ? 0 : i == 1 || i == 2 || i == 3 || i == 4 ? 1 : 0);
  std::array<Relation::Stack, 9> stacks{};
  for (std::size_t step = 0; step < stacks.size(); ++step) for (std::size_t slot = 0; slot < stacks[step].size(); ++slot)
    stacks[step][slot] = logic.template vbit<8>(slot == 0 && step >= 1 ? static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::object_open) : 0);
  Relation(logic).assert_balanced_structure(count, tokens, depths, stacks);
  std::array<Logic::v8, 9> states{};
  const std::array<unsigned char, 6> state_values{1, 2, 3, 4, 5, 8};
  for (std::size_t i = 0; i < states.size(); ++i)
    states[i] = logic.template vbit<8>(i < state_values.size() ? (bad_state && i == 2 ? 5 : state_values[i]) : 0);
  Relation(logic).assert_scalar_container_grammar(count, tokens, states);
  return !backend.assertion_failed();
}

bool rejects_shallow_depth() {
  const std::string input = "[[true]]";
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, 16> text{};
  for (std::size_t i = 0; i < text.size(); ++i)
    text[i] = logic.template vbit<8>(i < input.size() ?
        static_cast<unsigned char>(input[i]) : 0);
  using Index = Logic::bitvec<5>;
  std::array<ShallowRelation::Token, 8> tokens{};
  const std::array<unsigned char, 5> kinds{
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::array_open),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::array_open),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::true_value),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::array_close),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::array_close)};
  const std::array<std::size_t, 5> begins{0, 1, 2, 6, 7};
  const std::array<std::size_t, 5> ends{1, 2, 6, 7, 8};
  for (std::size_t token = 0; token < tokens.size(); ++token) {
    tokens[token].kind = logic.template vbit<8>(token < kinds.size() ? kinds[token] : 0);
    logic.bits(5, tokens[token].begin.data(), token < begins.size() ? begins[token] : 0);
    logic.bits(5, tokens[token].end.data(), token < ends.size() ? ends[token] : 0);
  }
  Index length{}, count{};
  logic.bits(5, length.data(), input.size());
  logic.bits(5, count.data(), 5);
  std::array<Index, 9> depths{};
  const std::array<std::size_t, 6> depth_values{1, 2, 3, 3, 2, 1};
  std::array<ShallowRelation::GrammarStack, 9> frames{};
  const std::array<std::array<unsigned char, 3>, 6> frame_values{{
      {{1, 0, 0}}, {{2, 8, 0}}, {{2, 10, 8}},
      {{2, 10, 10}}, {{2, 10, 0}}, {{2, 0, 0}}}};
  for (std::size_t step = 0; step < depths.size(); ++step) {
    logic.bits(5, depths[step].data(), step < depth_values.size() ? depth_values[step] : 0);
    for (std::size_t slot = 0; slot < frames[step].size(); ++slot)
      frames[step][slot] = logic.template vbit<8>(
          step < frame_values.size() && slot < 3 ? frame_values[step][slot] : 0);
  }
  ShallowRelation relation(logic);
  relation.assert_partition(text, length, count, tokens);
  relation.assert_nested_container_grammar(count, tokens, depths, frames);
  return backend.assertion_failed();
}

bool accepts_nested(bool forged_frame = false, bool trailing_comma = false) {
  const std::string input = trailing_comma ? "[true,]" : "[{\"a\":true}]";
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, 32> text{};
  for (std::size_t i = 0; i < text.size(); ++i)
    text[i] = logic.template vbit<8>(
        i < input.size() ? static_cast<unsigned char>(input[i]) : 0);
  using Index = Logic::bitvec<8>;
  std::array<Relation::Token, 8> tokens{};
  const std::array<unsigned char, 7> nested_kinds{
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::array_open),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::object_open),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::string),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::colon),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::true_value),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::object_close),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::array_close)};
  const std::array<std::size_t, 7> nested_begins{0, 1, 2, 5, 6, 10, 11};
  const std::array<std::size_t, 7> nested_ends{1, 2, 5, 6, 10, 11, 12};
  const std::array<unsigned char, 4> trailing_kinds{
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::array_open),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::true_value),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::comma),
      static_cast<unsigned char>(sd_jwt_zk::JsonLexeme::array_close)};
  const std::array<std::size_t, 4> trailing_begins{0, 1, 5, 6};
  const std::array<std::size_t, 4> trailing_ends{1, 5, 6, 7};
  const std::size_t count_value = trailing_comma ? 4 : 7;
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    tokens[i].kind = logic.template vbit<8>(
        i < count_value ? (trailing_comma ? trailing_kinds[i] : nested_kinds[i]) : 0);
    logic.bits(8, tokens[i].begin.data(),
               i < count_value ? (trailing_comma ? trailing_begins[i] : nested_begins[i]) : 0);
    logic.bits(8, tokens[i].end.data(),
               i < count_value ? (trailing_comma ? trailing_ends[i] : nested_ends[i]) : 0);
  }
  Index length{}, count{};
  logic.bits(8, length.data(), input.size());
  logic.bits(8, count.data(), count_value);
  Relation relation(logic);
  relation.assert_partition(text, length, count, tokens);

  std::array<Index, 9> depths{};
  std::array<Relation::GrammarStack, 9> frames{};
  const std::array<std::size_t, 8> nested_depths{1, 2, 3, 3, 3, 3, 2, 1};
  const std::array<std::array<unsigned char, 3>, 8> nested_frames{{
      {{1, 0, 0}}, {{2, 8, 0}}, {{2, 10, 3}}, {{2, 10, 5}},
      {{2, 10, 6}}, {{2, 10, 7}}, {{2, 10, 0}}, {{2, 0, 0}}}};
  const std::array<std::size_t, 5> trailing_depths{1, 2, 2, 2, 1};
  const std::array<std::array<unsigned char, 2>, 5> trailing_frames{{
      {{1, 0}}, {{2, 8}}, {{2, 10}}, {{2, 9}}, {{2, 0}}}};
  for (std::size_t step = 0; step < depths.size(); ++step) {
    const std::size_t depth = step <= count_value
        ? (trailing_comma ? trailing_depths[step] : nested_depths[step]) : 0;
    logic.bits(8, depths[step].data(), depth);
    for (std::size_t slot = 0; slot < frames[step].size(); ++slot) {
      unsigned char value = 0;
      if (step <= count_value) {
        if (trailing_comma && slot < 2) value = trailing_frames[step][slot];
        if (!trailing_comma && slot < 3) value = nested_frames[step][slot];
      }
      if (forged_frame && step == 4 && slot == 2) value = 7;
      frames[step][slot] = logic.template vbit<8>(value);
    }
  }
  relation.assert_nested_container_grammar(count, tokens, depths, frames);
  return !backend.assertion_failed();
}
bool compiles_combined_relation() {
  proofs::QuadCircuit<Field> quad(proofs::p256_base);
  const auto circuit =
      sd_jwt_zk::BuildBoundedJsonCircuit<8, 4, 4, 2>(&quad);
  return circuit->ninputs > 0 && circuit->nterms() > 0;
}
bool accepts_array_element_disclosure(bool malformed = false) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  using Disclosure = sd_jwt_zk::FlatDisclosureRelation<Logic, 1, 42>;
  std::array<Logic::v8, 9> json{};
  constexpr std::array<unsigned char, 9> bytes{'[', '"', 's', '"', ',', '"', 'x', '"', ']'};
  for (std::size_t index = 0; index < json.size(); ++index)
    json[index] = logic.template vbit<8>(malformed && index == 4 ? ':' : bytes[index]);
  Disclosure(logic).template assert_two_string_array<1, 1>(json);
  return !backend.assertion_failed();
}
bool accepts_disclosure_graph(bool duplicate = false, bool bad_depth = false, bool overactive = false) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  using Graph = sd_jwt_zk::FullDisclosureGraphRelation<Logic, 2>; using Index = Logic::bitvec<5>;
  std::array<std::array<Logic::v8,43>,2> supplied{}, references{};
  for (std::size_t slot=0;slot<2;++slot) for(std::size_t byte=0;byte<43;++byte) {
    const unsigned char value=slot==0?'a':(duplicate?'a':'b');
    supplied[slot][byte]=logic.template vbit<8>(value); references[slot][byte]=logic.template vbit<8>(value);
  }
  Index active{}; logic.bits(5,active.data(),overactive?3:2); std::array<Index,2> depths{};
  logic.bits(5,depths[0].data(),1); logic.bits(5,depths[1].data(),bad_depth?3:2);
  Graph relation(logic); relation.assert_one_to_one(supplied,references,active); relation.assert_traversal_depth(depths,active,2);
  return !backend.assertion_failed();
}
bool accepts_swiss_policy(bool mutation = false) {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  sd_jwt_zk::SwissPolicyRelation<Logic> policy(logic);
  const auto value = logic.bit(1); policy.assert_boolean(logic.bit(mutation ? 0 : 1), value);
  std::array<Logic::v8, 2> private_value{}, requested{};
  private_value[0]=logic.template vbit<8>('v'); private_value[1]=logic.template vbit<8>('c');
  requested[0]=logic.template vbit<8>('v'); requested[1]=logic.template vbit<8>(mutation?'x':'c');
  policy.assert_equality(private_value,requested,logic.bit(mutation?0:1));
  Logic::bitvec<5> age{}, low{}, high{};
  logic.bits(5,age.data(),mutation?21:18); logic.bits(5,low.data(),18); logic.bits(5,high.data(),20);
  policy.assert_integer_range(age,low,high,logic.bit(mutation?0:1));
  Logic::bitvec<5> nbf{}, exp{}, now{}; logic.bits(5,nbf.data(),10); logic.bits(5,exp.data(),20); logic.bits(5,now.data(),mutation?21:10); policy.assert_time_window(nbf,exp,now,logic.bit(mutation?0:1));
  Logic::bitvec<5> iat{}; logic.bits(5,iat.data(),mutation?11:10); policy.assert_integer_range(iat,logic.template vbit<5>(0),logic.template vbit<5>(10),logic.bit(mutation?0:1));
  Logic::bitvec<5> date{}; logic.bits(5,date.data(),mutation?9:10); policy.assert_date_range(date,logic.template vbit<5>(10),logic.template vbit<5>(12),logic.bit(mutation?0:1));
  std::array<std::array<Logic::v8,1>,2> options{}; options[0][0]=logic.template vbit<8>('a'); options[1][0]=logic.template vbit<8>('b');
  std::array<Logic::v8,1> selected{}; selected[0]=logic.template vbit<8>(mutation?'z':'a'); policy.assert_set_membership(selected,options,logic.bit(mutation?0:1));
  std::array<Logic::v8,2> alg{}; alg[0]=logic.template vbit<8>(mutation?'E':'E'); alg[1]=logic.template vbit<8>(mutation?'D':'S'); policy.assert_fixed_text(alg,std::array<unsigned char,2>{'E','S'});
  std::array<Logic::v8,2> profile{}; profile[0]=logic.template vbit<8>('v'); profile[1]=logic.template vbit<8>(mutation?'0':'1'); policy.assert_fixed_text(profile,std::array<unsigned char,2>{'v','1'});
  std::array<Logic::v8,3> vct{}; vct[0]=logic.template vbit<8>('v'); vct[1]=logic.template vbit<8>('c'); vct[2]=logic.template vbit<8>(mutation?'x':'t'); policy.assert_top_level_vct(vct);
  std::array<Logic::v8,1> path_a{}, path_b{}; path_a[0]=logic.template vbit<8>('a'); path_b[0]=logic.template vbit<8>(mutation?'a':'b'); policy.assert_distinct_paths(path_a,path_b);
  return !backend.assertion_failed();
}
bool rejects_type_confusion() {
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  sd_jwt_zk::SwissPolicyRelation<Logic> policy(logic);
  // A numeric/encoded claim cannot satisfy a Boolean predicate merely by
  // choosing a public Boolean result: the relation binds the result bit.
  policy.assert_boolean(logic.bit(1), logic.bit(0));
  return backend.assertion_failed();
}
bool rejects_cross_family_identity() {
  const auto bearer = sd_jwt_zk::full_disclosure_circuit_identity_v1(sd_jwt_zk::Binding::bearer, sd_jwt_zk::Trust::exact_key);
  const auto holder = sd_jwt_zk::full_disclosure_circuit_identity_v1(sd_jwt_zk::Binding::holder_bound, sd_jwt_zk::Trust::exact_key);
  return bearer.binding != holder.binding || bearer.trust != holder.trust;
}
bool rejects_one_over_bounds() {
  if (sd_jwt_zk::parse_bounded_json("[0]", {2, 1, 3})) return false;
  if (sd_jwt_zk::parse_bounded_json("[[0]]", {5, 1, 5})) return false;
  if (sd_jwt_zk::parse_bounded_json("[0]", {3, 1, 2})) return false;
  return true;
}
}  // namespace

int main() {
  if (!accepts("{\"a\":true}")) return 1;
  if (accepts("{\"a\":true}", true)) return 2;
  if (accepts("{\"a\":true}", false, true)) return 3;
  if (accepts("{\"a\":true]", false, false, true)) return 4;
  if (accepts("{\"a\":true}", false, false, false, true)) return 5;
  if (!accepts_nested()) return 6;
  if (accepts_nested(true)) return 7;
  if (accepts_nested(false, true)) return 8;
  if (!accepts_string("\"a\\n\\u00e9\\uD83D\\uDE03\"",
                      {{1, 2, 'a'}, {2, 4, '\n'}, {4, 10, 0xe9},
                       {10, 22, 0x1f603}})) return 9;
  if (!accepts_string(std::string("\"") + "\xc3\xa9\xf0\x9f\x98\x83" + "\"",
                      {{1, 3, 0xe9}, {3, 7, 0x1f603}})) return 10;
  if (accepts_string("\"\\x\"", {{1, 3, 'x'}})) return 11;
  if (accepts_string("\"\\uD800\"", {{1, 7, 0xd800}})) return 12;
  if (accepts_string("\"\\uDC00\"", {{1, 7, 0xdc00}})) return 13;
  if (accepts_string("\"\\uD800\\u0041\"", {{1, 13, 0x10041}})) return 14;
  if (accepts_string(std::string("\"") + "\xc0\x80" + "\"",
                     {{1, 3, 0}})) return 15;
  if (accepts_string(std::string("\"") + "\xed\xa0\x80" + "\"",
                     {{1, 4, 0xd800}})) return 16;
  if (accepts_string("\"a\"", {{1, 2, 'b'}})) return 17;
  if (accepts_string("\"a\"", {{1, 2, 'a'}}, true)) return 18;
  if (!accepts_number("-12.50e+1")) return 19;
  if (!accepts_number("1e18446744073709551616")) return 20;
  if (accepts_number("01")) return 21;
  if (accepts_number("1.")) return 22;
  if (accepts_number("1e+")) return 23;
  if (accepts_number("-12.50e+1", true)) return 24;
  if (accepts_number("-12.50e+1", false, true)) return 25;
  if (!numbers_equal("12.50e+1", "125", true)) return 26;
  if (!numbers_equal("-0.000e999", "0", true)) return 27;
  if (!numbers_equal("1e18446744073709551616",
                     "10e18446744073709551615", true)) return 28;
  if (!numbers_equal("125", "12.6e1", false)) return 29;
  if (!accepts_object_keys(false)) return 30;
  if (accepts_object_keys(true)) return 31;
  if (accepts_object_keys(true, true)) return 32;
  if (accepts("{\"a\":true}x")) return 33;
  if (accepts("{\"a\":true}", false, false, false, false, 33)) return 34;
  if (accepts("{\"a\":true}", false, false, false, false, 0, 9)) return 35;
  if (!rejects_shallow_depth()) return 36;
  if (!compiles_combined_relation()) return 37;
  if (accepts_number("12.5", false, false, true)) return 38;
  if (!accepts_array_element_disclosure()) return 39;
  if (accepts_array_element_disclosure(true)) return 40;
  if (!accepts_disclosure_graph()) return 42;
  if (accepts_disclosure_graph(true)) return 43;
  if (accepts_disclosure_graph(false,true)) return 44;
  if (accepts_disclosure_graph(false,false,true)) return 49;
  if (!accepts_swiss_policy()) return 45;
  if (!rejects_type_confusion()) return 50;
  if (accepts_swiss_policy(true)) return 46;
  if (!rejects_cross_family_identity()) return 47;
  if (!rejects_one_over_bounds()) return 48;
  return 0;
}
