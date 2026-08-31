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
#include <cstddef>
#include <cstdint>
#include <string>

namespace sd_jwt_zk {

// Token kinds are deliberately lexical.  The parser state/stack relation is
// layered above this component; this layer proves that its input bytes have a
// unique, gap-free partition before any JSON structure is interpreted.
enum class JsonLexeme : unsigned char {
  whitespace = 1, string = 2, number = 3, true_value = 4, false_value = 5,
  null_value = 6, object_open = 7, object_close = 8, array_open = 9,
  array_close = 10, comma = 11, colon = 12,
};

template <class LogicCircuit, std::size_t Capacity, std::size_t MaxTokens,
          std::size_t IndexBits, std::size_t MaxDepth = MaxTokens>
class BoundedJsonTokenRelation {
  static_assert(MaxDepth > 0 && MaxDepth <= MaxTokens);
  static_assert(IndexBits < 64 &&
                Capacity < (std::uint64_t{1} << IndexBits) &&
                MaxTokens < (std::uint64_t{1} << IndexBits));
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using Index = typename LogicCircuit::template bitvec<IndexBits>;
  using Codepoint = typename LogicCircuit::template bitvec<21>;
  static constexpr std::size_t ScaleBits = Capacity * 4 + 2;
  using Scale = typename LogicCircuit::template bitvec<ScaleBits>;

 public:
  struct Token { v8 kind; Index begin; Index end; };
  using Stack = std::array<v8, MaxTokens>;
  using GrammarStack = std::array<v8, MaxTokens + 1>;
  using ContainerIdStack = std::array<Index, MaxTokens + 1>;
  struct StringUnit { Index begin; Index end; Codepoint codepoint; };
  // Retained decoder value type; no candidate cache is currently wired into
  // the relation after the measured cache experiment was reverted.
  struct StringCandidate { BitW valid; Codepoint codepoint; };
  struct StringWitness {
    Index unit_count;
    std::array<StringUnit, Capacity> units;
  };
  struct NumberWitness {
    BitW negative;
    BitW exponent_negative;
    Index digit_count;
    Index fraction_count;
    Index significant_begin;
    Index significant_end;
    Index significant_length;
    std::array<Index, Capacity> digit_offsets;
    std::array<v8, Capacity> significand;
    std::array<v8, Capacity + 1> states;
    std::array<Scale, Capacity + 1> exponent_accumulator;
    Scale scale;
  };

  explicit BoundedJsonTokenRelation(const LogicCircuit& logic) : logic_(logic) {}

  void assert_partition(const std::array<v8, Capacity>& text,
                        const Index& active_length, const Index& token_count,
                        const std::array<Token, MaxTokens>& tokens) const {
    logic_.assert1(logic_.vleq(active_length, Capacity));
    logic_.assert1(logic_.vleq(token_count, MaxTokens));
    for (std::size_t token = 0; token < MaxTokens; ++token) {
      const BitW active = logic_.vlt(token, token_count);
      const BitW known = known_kind(tokens[token].kind);
      logic_.assert_implies(active, known);
      logic_.assert_implies(active, logic_.vlt(tokens[token].begin, tokens[token].end));
      logic_.assert_implies(active, logic_.vleq(tokens[token].end, active_length));
      logic_.assert_implies(logic_.lnot(active), logic_.veq(tokens[token].kind, 0));
      logic_.assert_implies(logic_.lnot(active), logic_.veq(tokens[token].begin, 0));
      logic_.assert_implies(logic_.lnot(active), logic_.veq(tokens[token].end, 0));
      if (token > 0) {
        logic_.assert_implies(active,
                              logic_.veq(tokens[token - 1].end,
                                         tokens[token].begin));
        const BitW adjacent_whitespace = logic_.land(
            logic_.veq(tokens[token - 1].kind,
                       static_cast<unsigned char>(JsonLexeme::whitespace)),
            logic_.veq(tokens[token].kind,
                       static_cast<unsigned char>(JsonLexeme::whitespace)));
        logic_.assert_implies(active, logic_.lnot(adjacent_whitespace));
      }
      assert_fixed(text, active, tokens[token], JsonLexeme::true_value, "true");
      assert_fixed(text, active, tokens[token], JsonLexeme::false_value, "false");
      assert_fixed(text, active, tokens[token], JsonLexeme::null_value, "null");
      assert_fixed(text, active, tokens[token], JsonLexeme::object_open, "{");
      assert_fixed(text, active, tokens[token], JsonLexeme::object_close, "}");
      assert_fixed(text, active, tokens[token], JsonLexeme::array_open, "[");
      assert_fixed(text, active, tokens[token], JsonLexeme::array_close, "]");
      assert_fixed(text, active, tokens[token], JsonLexeme::comma, ",");
      assert_fixed(text, active, tokens[token], JsonLexeme::colon, ":");
    }
    for (std::size_t byte = 0; byte < Capacity; ++byte) {
      const BitW input_active = logic_.vlt(byte, active_length);
      auto coverage = logic_.konst(0);
      for (std::size_t token = 0; token < MaxTokens; ++token) {
        const BitW member = logic_.land(logic_.vlt(token, token_count),
            logic_.land(logic_.vleq(tokens[token].begin, byte), logic_.vlt(byte, tokens[token].end)));
        coverage = logic_.add(coverage, logic_.eval(member));
        const BitW whitespace = logic_.land(member, logic_.veq(tokens[token].kind, static_cast<unsigned char>(JsonLexeme::whitespace)));
        logic_.assert_implies(whitespace, whitespace_byte(text[byte]));
      }
      // Exactly one token owns every active byte; inactive bytes are padding.
      logic_.assert_eq(coverage, logic_.eval(input_active));
      logic_.assert_implies(logic_.lnot(input_active), logic_.veq(text[byte], 0));
    }
  }

  // The stack is witness advice, but every transition is constrained from the
  // lexical token kind.  Consequently a closing brace cannot discharge an
  // array frame (or vice versa), and depth cannot be fabricated at a later
  // token.  Grammar states for object-key/value sequencing layer on top.
  void assert_balanced_structure(const Index& token_count,
                                 const std::array<Token, MaxTokens>& tokens,
                                 const std::array<Index, MaxTokens + 1>& depths,
                                 const std::array<Stack, MaxTokens + 1>& stacks) const {
    for (std::size_t token = 0; token < MaxTokens; ++token) {
      const BitW active = logic_.vlt(token, token_count);
      BitW selected_depth = logic_.bit(0);
      for (std::size_t depth = 0; depth <= MaxTokens; ++depth) {
        const BitW at_depth = logic_.land(active, logic_.veq(depths[token], depth));
        selected_depth = logic_.lor_exclusive(selected_depth, at_depth);
        const BitW object_open = logic_.land(at_depth, logic_.veq(tokens[token].kind, static_cast<unsigned char>(JsonLexeme::object_open)));
        const BitW array_open = logic_.land(at_depth, logic_.veq(tokens[token].kind, static_cast<unsigned char>(JsonLexeme::array_open)));
        const BitW object_close = logic_.land(at_depth, logic_.veq(tokens[token].kind, static_cast<unsigned char>(JsonLexeme::object_close)));
        const BitW array_close = logic_.land(at_depth, logic_.veq(tokens[token].kind, static_cast<unsigned char>(JsonLexeme::array_close)));
        const BitW opens = logic_.lor_exclusive(object_open, array_open);
        const BitW closes = logic_.lor_exclusive(object_close, array_close);
        const BitW other = logic_.land(at_depth, logic_.lnot(logic_.lor_exclusive(opens, closes)));
        if (depth == MaxTokens) {
          logic_.assert_implies(opens, logic_.bit(0));
        } else {
          logic_.assert_implies(opens, logic_.veq(depths[token + 1], depth + 1));
          for (std::size_t slot = 0; slot < MaxTokens; ++slot) {
            if (slot == depth) {
              logic_.assert_implies(object_open, logic_.veq(stacks[token + 1][slot], static_cast<unsigned char>(JsonLexeme::object_open)));
              logic_.assert_implies(array_open, logic_.veq(stacks[token + 1][slot], static_cast<unsigned char>(JsonLexeme::array_open)));
            } else {
              logic_.assert_implies(opens, logic_.veq(stacks[token + 1][slot], stacks[token][slot]));
            }
          }
        }
        if (depth == 0) {
          logic_.assert_implies(closes, logic_.bit(0));
        } else {
          logic_.assert_implies(closes, logic_.veq(depths[token + 1], depth - 1));
          logic_.assert_implies(object_close, logic_.veq(stacks[token][depth - 1], static_cast<unsigned char>(JsonLexeme::object_open)));
          logic_.assert_implies(array_close, logic_.veq(stacks[token][depth - 1], static_cast<unsigned char>(JsonLexeme::array_open)));
          for (std::size_t slot = 0; slot < MaxTokens; ++slot)
            logic_.assert_implies(closes, logic_.veq(stacks[token + 1][slot], stacks[token][slot]));
        }
        logic_.assert_implies(other, logic_.veq(depths[token + 1], depth));
        for (std::size_t slot = 0; slot < MaxTokens; ++slot)
          logic_.assert_implies(other, logic_.veq(stacks[token + 1][slot], stacks[token][slot]));
      }
      logic_.assert_implies(active, selected_depth);
    }
    for (std::size_t count = 0; count <= MaxTokens; ++count)
      logic_.assert_implies(logic_.veq(token_count, count), logic_.veq(depths[count], 0));
  }

  // First grammar layer for a root object or array whose values are lexical
  // scalars. Nested containers are handled by the stack grammar layer above;
  // keeping this transition table separate makes every accepted token/state
  // edge explicit and auditable.
  void assert_scalar_container_grammar(const Index& token_count,
      const std::array<Token, MaxTokens>& tokens,
      const std::array<v8, MaxTokens + 1>& states) const {
    constexpr unsigned start = 1, object_key_or_end = 2, object_colon = 3,
        object_value = 4, object_comma_or_end = 5, array_value_or_end = 6,
        array_comma_or_end = 7, done = 8;
    for (std::size_t token = 0; token < MaxTokens; ++token) {
      const BitW active = logic_.vlt(token, token_count);
      BitW selected = logic_.bit(0);
      for (unsigned state = start; state <= done; ++state) {
        for (unsigned kind = static_cast<unsigned>(JsonLexeme::whitespace);
             kind <= static_cast<unsigned>(JsonLexeme::colon); ++kind) {
          unsigned next = 0;
          const bool scalar = kind == static_cast<unsigned>(JsonLexeme::string) || kind == static_cast<unsigned>(JsonLexeme::number) || kind == static_cast<unsigned>(JsonLexeme::true_value) || kind == static_cast<unsigned>(JsonLexeme::false_value) || kind == static_cast<unsigned>(JsonLexeme::null_value);
          if (kind == static_cast<unsigned>(JsonLexeme::whitespace)) next = state;
          else if (state == start && kind == static_cast<unsigned>(JsonLexeme::object_open)) next = object_key_or_end;
          else if (state == start && kind == static_cast<unsigned>(JsonLexeme::array_open)) next = array_value_or_end;
          else if (state == object_key_or_end && kind == static_cast<unsigned>(JsonLexeme::object_close)) next = done;
          else if (state == object_key_or_end && kind == static_cast<unsigned>(JsonLexeme::string)) next = object_colon;
          else if (state == object_colon && kind == static_cast<unsigned>(JsonLexeme::colon)) next = object_value;
          else if (state == object_value && scalar) next = object_comma_or_end;
          else if (state == object_comma_or_end && kind == static_cast<unsigned>(JsonLexeme::object_close)) next = done;
          else if (state == object_comma_or_end && kind == static_cast<unsigned>(JsonLexeme::comma)) next = object_key_or_end;
          else if (state == array_value_or_end && kind == static_cast<unsigned>(JsonLexeme::array_close)) next = done;
          else if (state == array_value_or_end && scalar) next = array_comma_or_end;
          else if (state == array_comma_or_end && kind == static_cast<unsigned>(JsonLexeme::array_close)) next = done;
          else if (state == array_comma_or_end && kind == static_cast<unsigned>(JsonLexeme::comma)) next = array_value_or_end;
          if (next == 0) continue;
          const BitW edge = logic_.land(active, logic_.land(logic_.veq(states[token], state), logic_.veq(tokens[token].kind, kind)));
          selected = logic_.lor_exclusive(selected, edge);
          logic_.assert_implies(edge, logic_.veq(states[token + 1], next));
        }
      }
      logic_.assert_implies(active, selected);
    }
    for (std::size_t count = 0; count <= MaxTokens; ++count)
      logic_.assert_implies(logic_.veq(token_count, count), logic_.veq(states[count], done));
  }

  // Deterministic pushdown grammar for arbitrary nesting.  The root frame is
  // never popped.  Opening a child first advances its parent to the
  // after-value state, then pushes a typed child state.  Separate first-entry
  // and post-comma states ensure that `[1,]` and `{"a":1,}` are rejected.
  void assert_nested_container_grammar(
      const Index& token_count, const std::array<Token, MaxTokens>& tokens,
      const std::array<Index, MaxTokens + 1>& depths,
      const std::array<GrammarStack, MaxTokens + 1>& frames) const {
    constexpr unsigned root_value = 1, root_done = 2,
        object_first_key_or_end = 3, object_key = 4, object_colon = 5,
        object_value = 6, object_comma_or_end = 7,
        array_first_value_or_end = 8, array_value = 9,
        array_comma_or_end = 10;
    logic_.vassert_eq(depths[0], 1);
    logic_.vassert_eq(frames[0][0], root_value);
    for (std::size_t slot = 1; slot <= MaxTokens; ++slot)
      logic_.vassert_eq(frames[0][slot], 0);

    for (std::size_t token = 0; token < MaxTokens; ++token) {
      const BitW active = logic_.vlt(token, token_count);
      BitW selected = logic_.bit(0);
      for (std::size_t depth = 1; depth <= MaxTokens + 1; ++depth) {
        const BitW at_depth = logic_.land(active, logic_.veq(depths[token], depth));
        if (depth > MaxDepth + 1) {
          logic_.assert_implies(at_depth, logic_.bit(0));
          continue;
        }
        for (unsigned state = root_value; state <= array_comma_or_end; ++state) {
          for (unsigned kind = static_cast<unsigned>(JsonLexeme::whitespace);
               kind <= static_cast<unsigned>(JsonLexeme::colon); ++kind) {
            const BitW edge = logic_.land(
                at_depth,
                logic_.land(logic_.veq(frames[token][depth - 1], state),
                            logic_.veq(tokens[token].kind, kind)));
            const bool scalar = kind == static_cast<unsigned>(JsonLexeme::string) ||
                kind == static_cast<unsigned>(JsonLexeme::number) ||
                kind == static_cast<unsigned>(JsonLexeme::true_value) ||
                kind == static_cast<unsigned>(JsonLexeme::false_value) ||
                kind == static_cast<unsigned>(JsonLexeme::null_value);
            const bool expects_value = state == root_value || state == object_value ||
                state == array_first_value_or_end || state == array_value;
            const unsigned after_value = state == root_value ? root_done :
                (state == object_value ? object_comma_or_end : array_comma_or_end);
            bool valid = false, push = false, pop = false;
            std::size_t next_depth = depth;
            unsigned next_state = state;
            if (kind == static_cast<unsigned>(JsonLexeme::whitespace)) {
              valid = true;
            } else if ((state == object_first_key_or_end || state == object_key) &&
                       kind == static_cast<unsigned>(JsonLexeme::string)) {
              valid = true; next_state = object_colon;
            } else if (state == object_colon &&
                       kind == static_cast<unsigned>(JsonLexeme::colon)) {
              valid = true; next_state = object_value;
            } else if (state == object_comma_or_end &&
                       kind == static_cast<unsigned>(JsonLexeme::comma)) {
              valid = true; next_state = object_key;
            } else if (state == array_comma_or_end &&
                       kind == static_cast<unsigned>(JsonLexeme::comma)) {
              valid = true; next_state = array_value;
            } else if (expects_value && scalar) {
              valid = true; next_state = after_value;
            } else if (expects_value &&
                       (kind == static_cast<unsigned>(JsonLexeme::object_open) ||
                        kind == static_cast<unsigned>(JsonLexeme::array_open))) {
              valid = depth <= MaxDepth;
              push = valid; next_depth = depth + 1; next_state = after_value;
            } else if (depth > 1 &&
                       kind == static_cast<unsigned>(JsonLexeme::object_close) &&
                       (state == object_first_key_or_end || state == object_comma_or_end)) {
              valid = true; pop = true; next_depth = depth - 1;
            } else if (depth > 1 &&
                       kind == static_cast<unsigned>(JsonLexeme::array_close) &&
                       (state == array_first_value_or_end || state == array_comma_or_end)) {
              valid = true; pop = true; next_depth = depth - 1;
            }
            if (!valid) continue;
            selected = logic_.lor_exclusive(selected, edge);
            logic_.assert_implies(edge, logic_.veq(depths[token + 1], next_depth));
            for (std::size_t slot = 0; slot <= MaxTokens; ++slot) {
              if (push && slot == depth - 1) {
                logic_.assert_implies(edge,
                    logic_.veq(frames[token + 1][slot], next_state));
              } else if (push && slot == depth) {
                const unsigned child = kind == static_cast<unsigned>(JsonLexeme::object_open)
                    ? object_first_key_or_end : array_first_value_or_end;
                logic_.assert_implies(edge, logic_.veq(frames[token + 1][slot], child));
              } else if (pop && slot == depth - 1) {
                logic_.assert_implies(edge, logic_.veq(frames[token + 1][slot], 0));
              } else if (!push && !pop && slot == depth - 1) {
                logic_.assert_implies(edge,
                    logic_.veq(frames[token + 1][slot], next_state));
              } else {
                logic_.assert_implies(edge,
                    logic_.veq(frames[token + 1][slot], frames[token][slot]));
              }
            }
          }
        }
      }
      logic_.assert_implies(active, selected);
    }
    for (std::size_t count = 0; count <= MaxTokens; ++count) {
      const BitW final = logic_.veq(token_count, count);
      logic_.assert_implies(final, logic_.veq(depths[count], 1));
      logic_.assert_implies(final, logic_.veq(frames[count][0], root_done));
      for (std::size_t slot = 1; slot <= MaxTokens; ++slot)
        logic_.assert_implies(final, logic_.veq(frames[count][slot], 0));
      for (std::size_t step = count + 1; step <= MaxTokens; ++step) {
        logic_.assert_implies(final, logic_.veq(depths[step], 0));
        for (std::size_t slot = 0; slot <= MaxTokens; ++slot)
          logic_.assert_implies(final, logic_.veq(frames[step][slot], 0));
      }
    }
  }

  // Constrain each string token to a decoded Unicode-scalar table.  The unit
  // source ranges exactly partition the bytes between the quotes; hence an
  // escape, continuation byte, or surrogate half cannot be hidden in an
  // unconstrained gap.  Non-string token slots have canonical zero advice.
  void assert_string_lexemes(
      const std::array<v8, Capacity>& text, const Index& token_count,
      const std::array<Token, MaxTokens>& tokens,
      const std::array<StringWitness, MaxTokens>& strings) const {
    for (std::size_t token = 0; token < MaxTokens; ++token) {
      const BitW active = logic_.land(
          logic_.vlt(token, token_count),
          logic_.veq(tokens[token].kind,
                     static_cast<unsigned char>(JsonLexeme::string)));
      assert_string(text, active, tokens[token], strings[token]);
    }
  }

  // Bind each live grammar frame to the token that opened it, then reject two
  // key strings with the same decoded scalar sequence in the same object.
  // Comparing decoded codepoints catches aliases such as `"a"` and
  // `"\u0061"`; comparing opener ids (not merely depth) keeps sibling objects
  // independent.
  void assert_unique_object_keys(
      const Index& token_count, const std::array<Token, MaxTokens>& tokens,
      const std::array<StringWitness, MaxTokens>& strings,
      const std::array<Index, MaxTokens + 1>& depths,
      const std::array<GrammarStack, MaxTokens + 1>& frames,
      const std::array<ContainerIdStack, MaxTokens + 1>& container_ids) const {
    assert_container_ids(token_count, tokens, depths, container_ids);
    for (std::size_t left = 0; left < MaxTokens; ++left) {
      const BitW left_key = object_key_at(left, token_count, tokens, depths, frames);
      for (std::size_t right = left + 1; right < MaxTokens; ++right) {
        const BitW both_keys = logic_.land(
            left_key, object_key_at(right, token_count, tokens, depths, frames));
        const BitW duplicate = logic_.land(
            both_keys,
            logic_.land(same_parent(left, right, depths, container_ids),
                        same_decoded_string(strings[left], strings[right])));
        logic_.assert1(logic_.lnot(duplicate));
      }
    }
  }

  void assert_number_lexemes(
      const std::array<v8, Capacity>& text, const Index& token_count,
      const std::array<Token, MaxTokens>& tokens,
      const std::array<NumberWitness, MaxTokens>& numbers) const {
    for (std::size_t token = 0; token < MaxTokens; ++token) {
      const BitW active = logic_.land(
          logic_.vlt(token, token_count),
          logic_.veq(tokens[token].kind,
                     static_cast<unsigned char>(JsonLexeme::number)));
      assert_number(text, active, tokens[token], numbers[token]);
    }
  }

  BitW number_semantically_equal(const NumberWitness& left,
                                 const NumberWitness& right) const {
    BitW same = logic_.land(
        logic_.lnot(logic_.lxor(left.negative, right.negative)),
        logic_.land(logic_.veq(left.scale, right.scale),
                    logic_.veq(left.significant_length,
                               right.significant_length)));
    for (std::size_t digit = 0; digit < Capacity; ++digit) {
      const BitW compared = logic_.lor(
          logic_.lnot(logic_.vlt(digit, left.significant_length)),
          logic_.veq(left.significand[digit], right.significand[digit]));
      same = logic_.land(same, compared);
    }
    return same;
  }

  // Primary entry point: callers cannot accidentally constrain token ranges
  // while omitting scalar, grammar, or duplicate-key semantics.
  void assert_json(
      const std::array<v8, Capacity>& text, const Index& active_length,
      const Index& token_count, const std::array<Token, MaxTokens>& tokens,
      const std::array<StringWitness, MaxTokens>& strings,
      const std::array<NumberWitness, MaxTokens>& numbers,
      const std::array<Index, MaxTokens + 1>& depths,
      const std::array<GrammarStack, MaxTokens + 1>& frames,
      const std::array<ContainerIdStack, MaxTokens + 1>& container_ids) const {
    assert_partition(text, active_length, token_count, tokens);
    assert_string_lexemes(text, token_count, tokens, strings);
    assert_number_lexemes(text, token_count, tokens, numbers);
    assert_nested_container_grammar(token_count, tokens, depths, frames);
    assert_unique_object_keys(token_count, tokens, strings, depths, frames,
                              container_ids);
  }

 private:
  enum NumberState : unsigned char {
    number_start = 1, number_minus = 2, number_zero = 3,
    number_integer = 4, number_dot = 5, number_fraction = 6,
    number_exponent = 7, number_exponent_sign = 8,
    number_exponent_digits = 9,
  };
  void assert_container_ids(
      const Index& token_count, const std::array<Token, MaxTokens>& tokens,
      const std::array<Index, MaxTokens + 1>& depths,
      const std::array<ContainerIdStack, MaxTokens + 1>& ids) const {
    for (std::size_t slot = 0; slot <= MaxTokens; ++slot)
      logic_.vassert_eq(ids[0][slot], 0);
    for (std::size_t token = 0; token < MaxTokens; ++token) {
      const BitW active = logic_.vlt(token, token_count);
      const BitW opens = logic_.land(
          active, logic_.lor(
              logic_.veq(tokens[token].kind,
                         static_cast<unsigned char>(JsonLexeme::object_open)),
              logic_.veq(tokens[token].kind,
                         static_cast<unsigned char>(JsonLexeme::array_open))));
      const BitW closes = logic_.land(
          active, logic_.lor(
              logic_.veq(tokens[token].kind,
                         static_cast<unsigned char>(JsonLexeme::object_close)),
              logic_.veq(tokens[token].kind,
                         static_cast<unsigned char>(JsonLexeme::array_close))));
      for (std::size_t depth = 1; depth <= MaxTokens + 1; ++depth) {
        const BitW at_depth = logic_.land(active, logic_.veq(depths[token], depth));
        for (std::size_t slot = 0; slot <= MaxTokens; ++slot) {
          if (slot == depth) {
            logic_.assert_implies(logic_.land(at_depth, opens),
                                  logic_.veq(ids[token + 1][slot], token + 1));
          } else if (slot == depth - 1) {
            logic_.assert_implies(logic_.land(at_depth, closes),
                                  logic_.veq(ids[token + 1][slot], 0));
          }
          const BitW changed = logic_.lor(
              logic_.land(opens, logic_.bit(slot == depth)),
              logic_.land(closes, logic_.bit(slot == depth - 1)));
          logic_.assert_implies(logic_.land(at_depth, logic_.lnot(changed)),
                                logic_.veq(ids[token + 1][slot], ids[token][slot]));
        }
      }
    }
    for (std::size_t count = 0; count <= MaxTokens; ++count) {
      const BitW final = logic_.veq(token_count, count);
      for (std::size_t slot = 0; slot <= MaxTokens; ++slot)
        logic_.assert_implies(final, logic_.veq(ids[count][slot], 0));
      for (std::size_t step = count + 1; step <= MaxTokens; ++step)
        for (std::size_t slot = 0; slot <= MaxTokens; ++slot)
          logic_.assert_implies(final, logic_.veq(ids[step][slot], 0));
    }
  }

  BitW object_key_at(
      std::size_t token, const Index& token_count,
      const std::array<Token, MaxTokens>& tokens,
      const std::array<Index, MaxTokens + 1>& depths,
      const std::array<GrammarStack, MaxTokens + 1>& frames) const {
    constexpr unsigned object_first_key_or_end = 3, object_key = 4;
    BitW key_state = logic_.bit(0);
    for (std::size_t depth = 2; depth <= MaxTokens + 1; ++depth) {
      const BitW at_depth = logic_.veq(depths[token], depth);
      const BitW expects_key = logic_.lor_exclusive(
          logic_.veq(frames[token][depth - 1], object_first_key_or_end),
          logic_.veq(frames[token][depth - 1], object_key));
      key_state = logic_.lor_exclusive(
          key_state, logic_.land(at_depth, expects_key));
    }
    return logic_.land(
        logic_.vlt(token, token_count),
        logic_.land(
            logic_.veq(tokens[token].kind,
                       static_cast<unsigned char>(JsonLexeme::string)),
            key_state));
  }

  BitW same_parent(
      std::size_t left, std::size_t right,
      const std::array<Index, MaxTokens + 1>& depths,
      const std::array<ContainerIdStack, MaxTokens + 1>& ids) const {
    BitW same = logic_.bit(0);
    for (std::size_t left_depth = 2; left_depth <= MaxTokens + 1; ++left_depth) {
      for (std::size_t right_depth = 2; right_depth <= MaxTokens + 1; ++right_depth) {
        const BitW branch = logic_.land(
            logic_.land(logic_.veq(depths[left], left_depth),
                        logic_.veq(depths[right], right_depth)),
            logic_.veq(ids[left][left_depth - 1],
                       ids[right][right_depth - 1]));
        same = logic_.lor_exclusive(same, branch);
      }
    }
    return same;
  }

  BitW same_decoded_string(const StringWitness& left,
                           const StringWitness& right) const {
    BitW same = logic_.veq(left.unit_count, right.unit_count);
    for (std::size_t unit = 0; unit < Capacity; ++unit) {
      const BitW active = logic_.vlt(unit, left.unit_count);
      same = logic_.land(
          same, logic_.lor(logic_.lnot(active),
                           logic_.veq(left.units[unit].codepoint,
                                      right.units[unit].codepoint)));
    }
    return same;
  }

  void assert_number(const std::array<v8, Capacity>& text, const BitW& active,
                     const Token& token, const NumberWitness& witness) const {
    logic_.assert_is_bit(witness.negative);
    logic_.assert_is_bit(witness.exponent_negative);
    logic_.assert_implies(active, logic_.vlt(0, witness.digit_count));
    logic_.assert_implies(active, logic_.vleq(witness.digit_count, Capacity));
    logic_.assert_implies(active, logic_.vleq(witness.fraction_count,
                                              witness.digit_count));
    for (std::size_t begin = 0; begin < Capacity; ++begin) {
      const BitW branch = logic_.land(active, logic_.veq(token.begin, begin));
      logic_.assert_implies(branch,
                            logic_.veq(witness.states[begin], number_start));
      logic_.assert_implies(branch,
                            logic_.veq(witness.exponent_accumulator[begin],
                                       scale_constant(false)));
    }

    auto coefficient_total = logic_.konst(0);
    auto fraction_total = logic_.konst(0);
    BitW raw_negative = logic_.bit(0);
    BitW raw_exponent_negative = logic_.bit(0);
    for (std::size_t byte = 0; byte < Capacity; ++byte) {
      const BitW inside = logic_.land(
          active, logic_.land(logic_.vleq(token.begin, byte),
                              logic_.vlt(byte, token.end)));
      const v8& state = witness.states[byte];
      const BitW digit = decimal_digit(text[byte]);
      const BitW nonzero = logic_.land(digit,
                                       logic_.lnot(logic_.veq(text[byte], '0')));
      const BitW zero = logic_.veq(text[byte], '0');
      const BitW minus = logic_.veq(text[byte], '-');
      const BitW plus = logic_.veq(text[byte], '+');
      const BitW dot = logic_.veq(text[byte], '.');
      const BitW exponent_mark = logic_.lor_exclusive(
          logic_.veq(text[byte], 'e'), logic_.veq(text[byte], 'E'));
      BitW selected = logic_.bit(0);
      BitW coefficient = logic_.bit(0);
      BitW fraction = logic_.bit(0);
      BitW exponent_digit = logic_.bit(0);
      const auto edge = [&](unsigned from, const BitW& symbol,
                            unsigned to) {
        const BitW branch = logic_.land(
            inside, logic_.land(logic_.veq(state, from), symbol));
        selected = logic_.lor_exclusive(selected, branch);
        logic_.assert_implies(branch,
                              logic_.veq(witness.states[byte + 1], to));
        return branch;
      };
      const BitW start_minus = edge(number_start, minus, number_minus);
      const BitW start_zero = edge(number_start, zero, number_zero);
      const BitW start_nonzero = edge(number_start, nonzero, number_integer);
      const BitW minus_zero = edge(number_minus, zero, number_zero);
      const BitW minus_nonzero = edge(number_minus, nonzero, number_integer);
      edge(number_zero, dot, number_dot);
      edge(number_zero, exponent_mark, number_exponent);
      const BitW integer_digit = edge(number_integer, digit, number_integer);
      edge(number_integer, dot, number_dot);
      edge(number_integer, exponent_mark, number_exponent);
      const BitW first_fraction = edge(number_dot, digit, number_fraction);
      const BitW later_fraction = edge(number_fraction, digit, number_fraction);
      edge(number_fraction, exponent_mark, number_exponent);
      const BitW exponent_minus = edge(number_exponent, minus,
                                       number_exponent_sign);
      edge(number_exponent, plus, number_exponent_sign);
      const BitW first_exponent_digit = edge(number_exponent, digit,
                                             number_exponent_digits);
      const BitW signed_exponent_digit = edge(number_exponent_sign, digit,
                                              number_exponent_digits);
      const BitW later_exponent_digit = edge(number_exponent_digits, digit,
                                             number_exponent_digits);
      coefficient = logic_.lor(
          logic_.lor(logic_.lor(start_zero, start_nonzero),
                     logic_.lor(minus_zero, minus_nonzero)),
          logic_.lor(integer_digit,
                     logic_.lor(first_fraction, later_fraction)));
      fraction = logic_.lor(first_fraction, later_fraction);
      exponent_digit = logic_.lor(first_exponent_digit,
          logic_.lor(signed_exponent_digit, later_exponent_digit));
      logic_.assert_implies(inside, selected);

      Scale digit_value{};
      for (std::size_t bit = 0; bit < ScaleBits; ++bit)
        digit_value[bit] = bit < 4 ? text[byte][bit] : logic_.bit(0);
      const Scale times_ten = logic_.vadd(
          logic_.vshl(witness.exponent_accumulator[byte], 3),
          logic_.vshl(witness.exponent_accumulator[byte], 1));
      logic_.assert_implies(
          exponent_digit,
          logic_.veq(witness.exponent_accumulator[byte + 1],
                     logic_.vadd(times_ten, digit_value)));
      logic_.assert_implies(
          logic_.land(inside, logic_.lnot(exponent_digit)),
          logic_.veq(witness.exponent_accumulator[byte + 1],
                     witness.exponent_accumulator[byte]));

      coefficient_total = logic_.add(coefficient_total, logic_.eval(coefficient));
      fraction_total = logic_.add(fraction_total, logic_.eval(fraction));
      raw_negative = logic_.lor_exclusive(raw_negative, start_minus);
      raw_exponent_negative = logic_.lor_exclusive(raw_exponent_negative,
                                                    exponent_minus);

      auto offset_coverage = logic_.konst(0);
      for (std::size_t offset = 0; offset < Capacity; ++offset) {
        const BitW offset_active = logic_.land(
            active, logic_.vlt(offset, witness.digit_count));
        const BitW owns = logic_.land(
            offset_active, logic_.veq(witness.digit_offsets[offset], byte));
        offset_coverage = logic_.add(offset_coverage, logic_.eval(owns));
      }
      logic_.assert_eq(offset_coverage, logic_.eval(coefficient));
    }
    logic_.assert_eq(coefficient_total, logic_.as_scalar(witness.digit_count));
    logic_.assert_eq(fraction_total, logic_.as_scalar(witness.fraction_count));
    logic_.assert_eq(witness.exponent_negative, raw_exponent_negative);
    for (std::size_t digit = 1; digit < Capacity; ++digit) {
      const BitW active_offset = logic_.land(
          active, logic_.vlt(digit, witness.digit_count));
      logic_.assert_implies(active_offset,
                            logic_.vlt(witness.digit_offsets[digit - 1],
                                       witness.digit_offsets[digit]));
    }

    BitW accepted_end = logic_.bit(0);
    Scale exponent_magnitude{};
    for (std::size_t bit = 0; bit < ScaleBits; ++bit)
      exponent_magnitude[bit] = logic_.bit(0);
    for (std::size_t end = 1; end <= Capacity; ++end) {
      const BitW at_end = logic_.land(active, logic_.veq(token.end, end));
      const BitW accepted_state = logic_.lor(
          logic_.lor(logic_.veq(witness.states[end], number_zero),
                     logic_.veq(witness.states[end], number_integer)),
          logic_.lor(logic_.veq(witness.states[end], number_fraction),
                     logic_.veq(witness.states[end], number_exponent_digits)));
      accepted_end = logic_.lor_exclusive(
          accepted_end, logic_.land(at_end, accepted_state));
      for (std::size_t bit = 0; bit < ScaleBits; ++bit)
        exponent_magnitude[bit] = logic_.lor_exclusive(
            exponent_magnitude[bit],
            logic_.land(at_end, witness.exponent_accumulator[end][bit]));
    }
    logic_.assert_implies(active, accepted_end);
    Scale signed_exponent{};
    const Scale negated_exponent = logic_.vadd(
        logic_.vnot(exponent_magnitude), scale_constant(true));
    logic_.vmux(witness.exponent_negative, signed_exponent,
                negated_exponent, exponent_magnitude);
    assert_number_normal_form(text, active, raw_negative, witness,
                              signed_exponent);
    assert_number_padding(active, token, witness);
  }

  void assert_number_normal_form(const std::array<v8, Capacity>& text,
                                 const BitW& active,
                                 const BitW& raw_negative,
                                 const NumberWitness& witness,
                                 const Scale& signed_exponent) const {
    BitW all_zero = logic_.bit(1);
    for (std::size_t digit = 0; digit < Capacity; ++digit) {
      const BitW digit_active = logic_.land(
          active, logic_.vlt(digit, witness.digit_count));
      const BitW is_zero = byte_at_offset_equals(
          text, witness.digit_offsets[digit], '0');
      all_zero = logic_.land(
          all_zero, logic_.lor(logic_.lnot(digit_active), is_zero));
    }
    const BitW zero = logic_.land(active, all_zero);
    const BitW nonzero = logic_.land(active, logic_.lnot(all_zero));
    logic_.assert_implies(zero, logic_.veq(witness.significant_begin, 0));
    logic_.assert_implies(zero, logic_.veq(witness.significant_end, 0));
    logic_.assert_implies(zero, logic_.veq(witness.significant_length, 0));
    logic_.assert_implies(zero, logic_.lnot(witness.negative));
    logic_.assert_implies(zero,
                          logic_.veq(witness.scale, scale_constant(false)));
    logic_.assert_implies(nonzero,
                          logic_.lnot(logic_.lxor(witness.negative,
                                                 raw_negative)));
    logic_.assert_implies(nonzero,
                          logic_.vlt(witness.significant_begin,
                                     witness.significant_end));
    logic_.assert_implies(active,
                          logic_.vleq(witness.significant_end,
                                      witness.digit_count));
    const Index significant_length = index_sub(
        witness.significant_end, witness.significant_begin);
    logic_.assert_implies(nonzero,
                          logic_.veq(witness.significant_length,
                                     significant_length));

    for (std::size_t digit = 0; digit < Capacity; ++digit) {
      const BitW active_digit = logic_.land(
          nonzero, logic_.vlt(digit, witness.digit_count));
      const BitW before = logic_.vlt(digit, witness.significant_begin);
      const BitW after = logic_.lnot(logic_.vlt(digit, witness.significant_end));
      logic_.assert_implies(
          logic_.land(active_digit, logic_.lor(before, after)),
          byte_at_offset_equals(text, witness.digit_offsets[digit], '0'));
      for (std::size_t begin = 0; begin < Capacity; ++begin) {
        const BitW begins = logic_.land(
            nonzero, logic_.veq(witness.significant_begin, begin));
        if (digit == begin)
          logic_.assert_implies(
              begins, byte_at_offset_is_nonzero_digit(
                          text, witness.digit_offsets[digit]));
      }
      for (std::size_t end = 1; end <= Capacity; ++end) {
        if (digit == end - 1) {
          const BitW ends = logic_.land(
              nonzero, logic_.veq(witness.significant_end, end));
          logic_.assert_implies(
              ends, byte_at_offset_is_nonzero_digit(
                        text, witness.digit_offsets[digit]));
        }
      }
    }

    for (std::size_t begin = 0; begin < Capacity; ++begin) {
      const BitW branch = logic_.land(
          nonzero, logic_.veq(witness.significant_begin, begin));
      for (std::size_t out = 0; out < Capacity; ++out) {
        if (begin + out < Capacity) {
          for (std::size_t byte = 0; byte < Capacity; ++byte) {
            const BitW selected = logic_.land(
                branch,
                logic_.land(logic_.vlt(out, witness.significant_length),
                            logic_.veq(witness.digit_offsets[begin + out], byte)));
            logic_.assert_implies(selected,
                                  logic_.veq(witness.significand[out], text[byte]));
          }
        }
      }
    }
    const Index trailing = index_sub(witness.digit_count,
                                     witness.significant_end);
    const Scale scale = logic_.vadd(
        logic_.vadd(signed_exponent, extend_index(trailing)),
        negate_scale(extend_index(witness.fraction_count)));
    logic_.assert_implies(nonzero, logic_.veq(witness.scale, scale));
  }

  void assert_number_padding(const BitW& active, const Token& token,
                             const NumberWitness& witness) const {
    const BitW inactive = logic_.lnot(active);
    logic_.assert_implies(inactive, logic_.lnot(witness.negative));
    logic_.assert_implies(inactive, logic_.lnot(witness.exponent_negative));
    logic_.assert_implies(inactive, logic_.veq(witness.digit_count, 0));
    logic_.assert_implies(inactive, logic_.veq(witness.fraction_count, 0));
    logic_.assert_implies(inactive, logic_.veq(witness.significant_begin, 0));
    logic_.assert_implies(inactive, logic_.veq(witness.significant_end, 0));
    logic_.assert_implies(inactive, logic_.veq(witness.significant_length, 0));
    logic_.assert_implies(inactive,
                          logic_.veq(witness.scale, scale_constant(false)));
    for (std::size_t digit = 0; digit < Capacity; ++digit) {
      logic_.assert_implies(
          logic_.lor(inactive,
                     logic_.lnot(logic_.vlt(digit, witness.digit_count))),
          logic_.veq(witness.digit_offsets[digit], 0));
      logic_.assert_implies(
          logic_.lor(inactive,
                     logic_.lnot(logic_.vlt(digit, witness.significant_length))),
          logic_.veq(witness.significand[digit], 0));
    }
    for (std::size_t byte = 0; byte <= Capacity; ++byte) {
      BitW used = logic_.bit(0);
      if (byte < Capacity) {
        used = logic_.land(active,
            logic_.land(logic_.vleq(token.begin, byte),
                        logic_.lnot(logic_.vlt(token.end, byte))));
      } else {
        used = logic_.land(active, logic_.veq(token.end, byte));
      }
      logic_.assert_implies(logic_.lnot(used),
                            logic_.veq(witness.states[byte], 0));
      logic_.assert_implies(logic_.lnot(used),
                            logic_.veq(witness.exponent_accumulator[byte],
                                       scale_constant(false)));
    }
  }

  BitW decimal_digit(const v8& byte) const {
    return logic_.land(logic_.lnot(logic_.vlt(byte, '0')),
                       logic_.vleq(byte, '9'));
  }

  BitW byte_at_offset_equals(const std::array<v8, Capacity>& text,
                             const Index& offset, unsigned char value) const {
    BitW selected = logic_.bit(0);
    for (std::size_t byte = 0; byte < Capacity; ++byte)
      selected = logic_.lor_exclusive(
          selected, logic_.land(logic_.veq(offset, byte),
                                logic_.veq(text[byte], value)));
    return selected;
  }

  BitW byte_at_offset_is_nonzero_digit(
      const std::array<v8, Capacity>& text, const Index& offset) const {
    BitW selected = logic_.bit(0);
    for (unsigned char value = '1'; value <= '9'; ++value)
      selected = logic_.lor_exclusive(
          selected, byte_at_offset_equals(text, offset, value));
    return selected;
  }

  Index index_sub(const Index& left, const Index& right) const {
    return logic_.vadd(left, logic_.vadd(logic_.vnot(right), 1));
  }

  Scale extend_index(const Index& value) const {
    Scale result{};
    for (std::size_t bit = 0; bit < ScaleBits; ++bit)
      result[bit] = bit < IndexBits ? value[bit] : logic_.bit(0);
    return result;
  }

  Scale negate_scale(const Scale& value) const {
    return logic_.vadd(logic_.vnot(value), scale_constant(true));
  }

  Scale scale_constant(bool one) const {
    Scale result{};
    for (std::size_t bit = 0; bit < ScaleBits; ++bit)
      result[bit] = logic_.bit(one && bit == 0);
    return result;
  }

  void assert_string(const std::array<v8, Capacity>& text, const BitW& active,
                     const Token& token, const StringWitness& witness) const {
    logic_.assert_implies(active, logic_.vleq(witness.unit_count, Capacity));
    BitW opening = logic_.bit(0), closing = logic_.bit(0);
    for (std::size_t begin = 0; begin < Capacity; ++begin) {
      const BitW branch = logic_.land(active, logic_.veq(token.begin, begin));
      opening = logic_.lor_exclusive(opening, branch);
      logic_.assert_implies(branch, logic_.veq(text[begin], '"'));
    }
    for (std::size_t end = 1; end <= Capacity; ++end) {
      const BitW branch = logic_.land(active, logic_.veq(token.end, end));
      closing = logic_.lor_exclusive(closing, branch);
      logic_.assert_implies(branch, logic_.veq(text[end - 1], '"'));
    }
    logic_.assert_implies(active, logic_.land(opening, closing));

    for (std::size_t unit = 0; unit < Capacity; ++unit) {
      const BitW unit_active = logic_.land(active, logic_.vlt(unit, witness.unit_count));
      const BitW padding = logic_.lnot(unit_active);
      logic_.assert_implies(padding, logic_.veq(witness.units[unit].begin, 0));
      logic_.assert_implies(padding, logic_.veq(witness.units[unit].end, 0));
      logic_.assert_implies(padding, logic_.veq(witness.units[unit].codepoint, 0));
      logic_.assert_implies(unit_active,
                            logic_.vlt(witness.units[unit].begin,
                                       witness.units[unit].end));
      if (unit == 0) {
        logic_.assert_implies(unit_active,
                              logic_.veq(witness.units[unit].begin,
                                         logic_.vadd(token.begin, 1)));
      } else {
        logic_.assert_implies(unit_active,
                              logic_.veq(witness.units[unit].begin,
                                         witness.units[unit - 1].end));
      }
      assert_string_unit(text, unit_active, witness.units[unit]);
    }
    for (std::size_t count = 0; count <= Capacity; ++count) {
      const BitW branch = logic_.land(active, logic_.veq(witness.unit_count, count));
      if (count == 0) {
        logic_.assert_implies(branch,
                              logic_.veq(token.end, logic_.vadd(token.begin, 2)));
      } else {
        for (std::size_t end = 1; end <= Capacity; ++end) {
          const BitW ending = logic_.land(branch, logic_.veq(token.end, end));
          logic_.assert_implies(ending,
                                logic_.veq(witness.units[count - 1].end, end - 1));
        }
      }
    }
    logic_.assert_implies(logic_.lnot(active), logic_.veq(witness.unit_count, 0));
  }

  void assert_string_unit(const std::array<v8, Capacity>& text,
                          const BitW& active, const StringUnit& unit) const {
    BitW selected = logic_.bit(0);
    for (std::size_t begin = 0; begin < Capacity; ++begin) {
      for (const std::size_t width : {std::size_t{1}, std::size_t{2},
                                      std::size_t{3}, std::size_t{4},
                                      std::size_t{6}, std::size_t{12}}) {
        if (begin + width > Capacity) continue;
        const BitW branch = logic_.land(
            active, logic_.land(logic_.veq(unit.begin, begin),
                                logic_.veq(unit.end, begin + width)));
        selected = logic_.lor_exclusive(selected, branch);
        if (width == 1) assert_ascii_unit(text[begin], branch, unit.codepoint);
        if (width == 2) assert_two_byte_unit(text, begin, branch, unit.codepoint,
                                              utf8_two_candidate(text, begin));
        if (width == 3 || width == 4) assert_utf8_unit(text, begin, width, branch, unit.codepoint);
        if (width == 6) assert_unicode_escape(text, begin, branch, unit.codepoint);
        if (width == 12) assert_surrogate_escape(text, begin, branch, unit.codepoint);
      }
    }
    logic_.assert_implies(active, selected);
  }

  StringCandidate ascii_candidate(const v8& byte) const {
    StringCandidate result{logic_.land(
        logic_.land(logic_.lnot(logic_.vlt(byte, 0x20)), logic_.vlt(byte, 0x80)),
        logic_.land(logic_.lnot(logic_.veq(byte, '"')),
                    logic_.lnot(logic_.veq(byte, '\\')))), {}};
    for (std::size_t bit = 0; bit < 21; ++bit)
      result.codepoint[bit] = bit < 8 ? byte[bit] : logic_.bit(0);
    return result;
  }

  void assert_ascii_unit(const v8& byte, const BitW& active,
                         const Codepoint& codepoint) const {
    const StringCandidate candidate = ascii_candidate(byte);
    logic_.assert_implies(active, candidate.valid);
    logic_.assert_implies(active, logic_.veq(codepoint, candidate.codepoint));
  }

  StringCandidate utf8_two_candidate(const std::array<v8, Capacity>& text,
                                     std::size_t begin) const {
    StringCandidate result{logic_.land(
        logic_.land(logic_.lnot(logic_.vlt(text[begin], 0xc2)),
                    logic_.vleq(text[begin], 0xdf)), continuation(text[begin + 1])), {}};
    for (std::size_t bit = 0; bit < 21; ++bit)
      result.codepoint[bit] = bit < 6 ? text[begin + 1][bit] :
          (bit < 11 ? text[begin][bit - 6] : logic_.bit(0));
    return result;
  }

  void assert_two_byte_unit(const std::array<v8, Capacity>& text,
                            std::size_t begin, const BitW& active,
                            const Codepoint& codepoint,
                            const StringCandidate& candidate) const {
    const BitW escaped = logic_.veq(text[begin], '\\');
    const BitW utf8 = candidate.valid;
    logic_.assert_implies(active, logic_.lor(escaped, utf8));
    const BitW utf8_branch = logic_.land(active, utf8);
    logic_.assert_implies(utf8_branch, logic_.veq(codepoint, candidate.codepoint));

    BitW escape_selected = logic_.bit(0);
    struct Escape { unsigned char raw; unsigned char decoded; };
    for (const Escape escape : std::array<Escape, 8>{{
             {'"', '"'}, {'\\', '\\'}, {'/', '/'}, {'b', '\b'},
             {'f', '\f'}, {'n', '\n'}, {'r', '\r'}, {'t', '\t'}}}) {
      const BitW branch = logic_.land(
          active, logic_.land(escaped, logic_.veq(text[begin + 1], escape.raw)));
      escape_selected = logic_.lor_exclusive(escape_selected, branch);
      logic_.assert_implies(branch, logic_.veq(codepoint, escape.decoded));
    }
    logic_.assert_implies(logic_.land(active, escaped), escape_selected);
  }

  struct HexResult { BitW known; v8 value; };
  HexResult hex_value(const v8& byte) const {
    HexResult result{logic_.bit(0), {}};
    for (std::size_t bit = 0; bit < 8; ++bit) result.value[bit] = logic_.bit(0);
    for (unsigned value = 0; value < 16; ++value) {
      const unsigned char lower = value < 10
          ? static_cast<unsigned char>('0' + value)
          : static_cast<unsigned char>('a' + value - 10);
      BitW match = logic_.veq(byte, lower);
      result.known = logic_.lor_exclusive(result.known, match);
      if (value >= 10) {
        const BitW upper = logic_.veq(
            byte, static_cast<unsigned char>('A' + value - 10));
        result.known = logic_.lor_exclusive(result.known, upper);
        match = logic_.lor_exclusive(match, upper);
      }
      for (std::size_t bit = 0; bit < 4; ++bit)
        if (((value >> bit) & 1u) != 0)
          result.value[bit] = logic_.lor_exclusive(result.value[bit], match);
    }
    return result;
  }

  Codepoint unicode_code_unit(const std::array<v8, Capacity>& text,
                              std::size_t begin, const BitW& active) const {
    Codepoint result{};
    for (std::size_t bit = 0; bit < 21; ++bit) result[bit] = logic_.bit(0);
    for (std::size_t nibble = 0; nibble < 4; ++nibble) {
      const HexResult hex = hex_value(text[begin + nibble]);
      logic_.assert_implies(active, hex.known);
      const std::size_t shift = (3 - nibble) * 4;
      for (std::size_t bit = 0; bit < 4; ++bit)
        result[shift + bit] = hex.value[bit];
    }
    return result;
  }

  void assert_unicode_escape(const std::array<v8, Capacity>& text,
                             std::size_t begin, const BitW& active,
                             const Codepoint& codepoint) const {
    logic_.assert_implies(active, logic_.veq(text[begin], '\\'));
    logic_.assert_implies(active, logic_.veq(text[begin + 1], 'u'));
    const Codepoint decoded = unicode_code_unit(text, begin + 2, active);
    logic_.assert_implies(active,
        logic_.lor(logic_.vlt(decoded, 0xd800), logic_.vlt(0xdfff, decoded)));
    logic_.assert_implies(active, logic_.veq(codepoint, decoded));
  }

  StringCandidate escape_candidate(const std::array<v8, Capacity>& text,
                                   std::size_t begin) const {
    BitW hex_known = logic_.bit(1);
    for (std::size_t nibble = 0; nibble < 4; ++nibble)
      hex_known = logic_.land(hex_known, hex_value(text[begin + 2 + nibble]).known);
    Codepoint decoded = unicode_code_unit(text, begin + 2, logic_.bit(0));
    const BitW valid = logic_.land(
        logic_.land(logic_.veq(text[begin], '\\'), logic_.veq(text[begin + 1], 'u')),
        logic_.land(hex_known,
            logic_.lor(logic_.vlt(decoded, 0xd800), logic_.vlt(0xdfff, decoded))));
    return StringCandidate{std::move(valid), std::move(decoded)};
  }

  StringCandidate surrogate_candidate(const std::array<v8, Capacity>& text,
                                     std::size_t begin) const {
    Codepoint high = unicode_code_unit(text, begin + 2, logic_.bit(0));
    Codepoint low = unicode_code_unit(text, begin + 8, logic_.bit(0));
    BitW hex_known = logic_.bit(1);
    for (std::size_t n = 0; n < 4; ++n) { hex_known = logic_.land(hex_known, hex_value(text[begin + 2 + n]).known); hex_known = logic_.land(hex_known, hex_value(text[begin + 8 + n]).known); }
    Codepoint high_offset{}, low_offset{};
    for (std::size_t bit = 0; bit < 21; ++bit) { high_offset[bit] = bit < 10 ? high[bit] : logic_.bit(0); low_offset[bit] = bit < 10 ? low[bit] : logic_.bit(0); }
    Codepoint decoded = logic_.vadd(logic_.vadd(logic_.vshl(high_offset, 10), low_offset), 0x10000);
    const BitW valid = logic_.land(hex_known, logic_.land(logic_.land(logic_.veq(text[begin], '\\'), logic_.veq(text[begin + 1], 'u')), logic_.land(logic_.land(logic_.veq(text[begin + 6], '\\'), logic_.veq(text[begin + 7], 'u')), logic_.land(logic_.land(logic_.lnot(logic_.vlt(high, 0xd800)), logic_.vleq(high, 0xdbff)), logic_.land(logic_.lnot(logic_.vlt(low, 0xdc00)), logic_.vleq(low, 0xdfff))))));
    return StringCandidate{std::move(valid), std::move(decoded)};
  }

  void assert_surrogate_escape(const std::array<v8, Capacity>& text,
                               std::size_t begin, const BitW& active,
                               const Codepoint& codepoint) const {
    logic_.assert_implies(active, logic_.veq(text[begin], '\\'));
    logic_.assert_implies(active, logic_.veq(text[begin + 1], 'u'));
    logic_.assert_implies(active, logic_.veq(text[begin + 6], '\\'));
    logic_.assert_implies(active, logic_.veq(text[begin + 7], 'u'));
    const Codepoint high = unicode_code_unit(text, begin + 2, active);
    const Codepoint low = unicode_code_unit(text, begin + 8, active);
    logic_.assert_implies(active,
        logic_.land(logic_.lnot(logic_.vlt(high, 0xd800)), logic_.vleq(high, 0xdbff)));
    logic_.assert_implies(active,
        logic_.land(logic_.lnot(logic_.vlt(low, 0xdc00)), logic_.vleq(low, 0xdfff)));
    Codepoint high_offset{}, low_offset{};
    for (std::size_t bit = 0; bit < 21; ++bit) {
      high_offset[bit] = bit < 10 ? high[bit] : logic_.bit(0);
      low_offset[bit] = bit < 10 ? low[bit] : logic_.bit(0);
    }
    const Codepoint decoded = logic_.vadd(
        logic_.vadd(logic_.vshl(high_offset, 10), low_offset), 0x10000);
    logic_.assert_implies(active, logic_.veq(codepoint, decoded));
  }

  StringCandidate utf8_candidate(const std::array<v8, Capacity>& text,
                                 std::size_t begin, std::size_t width) const {
    Codepoint decoded{};
    for (std::size_t bit = 0; bit < 21; ++bit) decoded[bit] = logic_.bit(0);
    const v8& first = text[begin];
    BitW valid = logic_.bit(0);
    if (width == 3) {
      const v8& second = text[begin + 1];
      const v8& third = text[begin + 2];
      const BitW generic_first = logic_.lor(
          logic_.land(logic_.lnot(logic_.vlt(first, 0xe1)), logic_.vleq(first, 0xec)),
          logic_.land(logic_.lnot(logic_.vlt(first, 0xee)), logic_.vleq(first, 0xef)));
      const BitW generic = logic_.land(generic_first, continuation(second));
      const BitW e0 = logic_.land(logic_.veq(first, 0xe0),
          logic_.land(logic_.lnot(logic_.vlt(second, 0xa0)), logic_.vleq(second, 0xbf)));
      const BitW ed = logic_.land(logic_.veq(first, 0xed),
          logic_.land(logic_.lnot(logic_.vlt(second, 0x80)), logic_.vleq(second, 0x9f)));
      valid = logic_.land(logic_.lor(logic_.lor(generic, e0), ed),
                          continuation(third));
      for (std::size_t bit = 0; bit < 6; ++bit) decoded[bit] = third[bit];
      for (std::size_t bit = 0; bit < 6; ++bit) decoded[6 + bit] = second[bit];
      for (std::size_t bit = 0; bit < 4; ++bit) decoded[12 + bit] = first[bit];
    } else {
      const v8& second = text[begin + 1];
      const v8& third = text[begin + 2];
      const v8& fourth = text[begin + 3];
      const BitW generic = logic_.land(
          logic_.land(logic_.lnot(logic_.vlt(first, 0xf1)), logic_.vleq(first, 0xf3)),
          continuation(second));
      const BitW f0 = logic_.land(logic_.veq(first, 0xf0),
          logic_.land(logic_.lnot(logic_.vlt(second, 0x90)), logic_.vleq(second, 0xbf)));
      const BitW f4 = logic_.land(logic_.veq(first, 0xf4),
          logic_.land(logic_.lnot(logic_.vlt(second, 0x80)), logic_.vleq(second, 0x8f)));
      valid = logic_.land(logic_.lor(logic_.lor(generic, f0), f4),
          logic_.land(continuation(third), continuation(fourth)));
      for (std::size_t bit = 0; bit < 6; ++bit) decoded[bit] = fourth[bit];
      for (std::size_t bit = 0; bit < 6; ++bit) decoded[6 + bit] = third[bit];
      for (std::size_t bit = 0; bit < 6; ++bit) decoded[12 + bit] = second[bit];
      for (std::size_t bit = 0; bit < 3; ++bit) decoded[18 + bit] = first[bit];
    }
    return StringCandidate{std::move(valid), std::move(decoded)};
  }

  void assert_utf8_unit(const std::array<v8, Capacity>& text,
                        std::size_t begin, std::size_t width,
                        const BitW& active, const Codepoint& codepoint) const {
    const StringCandidate candidate = utf8_candidate(text, begin, width);
    logic_.assert_implies(active, candidate.valid);
    logic_.assert_implies(active, logic_.veq(codepoint, candidate.codepoint));
  }

  BitW continuation(const v8& byte) const {
    return logic_.land(logic_.lnot(logic_.vlt(byte, 0x80)),
                       logic_.vleq(byte, 0xbf));
  }

  BitW known_kind(const v8& kind) const {
    BitW selected = logic_.bit(0);
    for (unsigned char value = static_cast<unsigned char>(JsonLexeme::whitespace);
         value <= static_cast<unsigned char>(JsonLexeme::colon); ++value)
      selected = logic_.lor_exclusive(selected, logic_.veq(kind, value));
    return selected;
  }
  BitW whitespace_byte(const v8& value) const {
    BitW selected = logic_.bit(0);
    for (const unsigned char allowed : {' ', '\t', '\r', '\n'})
      selected = logic_.lor_exclusive(selected, logic_.veq(value, allowed));
    return selected;
  }
  void assert_fixed(const std::array<v8, Capacity>& text, const BitW& token_active,
                    const Token& token, JsonLexeme type, const char* literal) const {
    const std::size_t length = std::char_traits<char>::length(literal);
    BitW selected = logic_.bit(0);
    for (std::size_t begin = 0; begin + length <= Capacity; ++begin) {
      const BitW branch = logic_.land(token_active,
          logic_.land(logic_.veq(token.kind, static_cast<unsigned char>(type)), logic_.veq(token.begin, begin)));
      selected = logic_.lor_exclusive(selected, branch);
      logic_.assert_implies(branch, logic_.veq(token.end, begin + length));
      for (std::size_t offset = 0; offset < length; ++offset)
        logic_.assert_implies(branch, logic_.veq(text[begin + offset], static_cast<unsigned char>(literal[offset])));
    }
    const BitW is_type = logic_.land(token_active, logic_.veq(token.kind, static_cast<unsigned char>(type)));
    logic_.assert_implies(is_type, selected);
  }
  const LogicCircuit& logic_;
};

}  // namespace sd_jwt_zk
