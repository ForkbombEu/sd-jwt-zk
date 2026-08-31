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
#include <memory>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "sd_jwt_zk/bounded_json_relation.h"

namespace sd_jwt_zk {

// The complete private-advice layout consumed by the bounded JSON circuit.
// Keeping allocation next to the production factory prevents a caller from
// accidentally compiling only the lexical partition while omitting string,
// number, grammar, or duplicate-key constraints.
template <class LogicCircuit, std::size_t Capacity, std::size_t MaxTokens,
          std::size_t IndexBits, std::size_t MaxDepth = MaxTokens>
struct BoundedJsonCircuitInput {
  using Relation = BoundedJsonTokenRelation<LogicCircuit, Capacity, MaxTokens,
                                            IndexBits, MaxDepth>;
  using Index = typename LogicCircuit::template bitvec<IndexBits>;

  std::array<typename LogicCircuit::v8, Capacity> text{};
  Index active_length{};
  Index token_count{};
  std::array<typename Relation::Token, MaxTokens> tokens{};
  std::array<typename Relation::StringWitness, MaxTokens> strings{};
  std::array<typename Relation::NumberWitness, MaxTokens> numbers{};
  std::array<Index, MaxTokens + 1> depths{};
  std::array<typename Relation::GrammarStack, MaxTokens + 1> frames{};
  std::array<typename Relation::ContainerIdStack, MaxTokens + 1> container_ids{};

  void input(LogicCircuit& logic) {
    const auto bits_input = [&](auto& bits) {
      for (auto& bit : bits) bit = logic.input();
    };
    for (auto& byte : text) bits_input(byte);
    bits_input(active_length);
    bits_input(token_count);
    for (auto& token : tokens) {
      bits_input(token.kind);
      bits_input(token.begin);
      bits_input(token.end);
    }
    for (auto& string : strings) {
      bits_input(string.unit_count);
      for (auto& unit : string.units) {
        bits_input(unit.begin);
        bits_input(unit.end);
        bits_input(unit.codepoint);
      }
    }
    for (auto& number : numbers) {
      number.negative = logic.input();
      number.exponent_negative = logic.input();
      bits_input(number.digit_count);
      bits_input(number.fraction_count);
      bits_input(number.significant_begin);
      bits_input(number.significant_end);
      bits_input(number.significant_length);
      for (auto& offset : number.digit_offsets) bits_input(offset);
      for (auto& byte : number.significand) bits_input(byte);
      for (auto& state : number.states) bits_input(state);
      for (auto& accumulator : number.exponent_accumulator)
        bits_input(accumulator);
      bits_input(number.scale);
    }
    for (auto& depth : depths) bits_input(depth);
    for (auto& stack : frames)
      for (auto& frame : stack) bits_input(frame);
    for (auto& stack : container_ids)
      for (auto& id : stack) bits_input(id);
  }
};

// Compile one explicitly bucketed bounded-JSON family. Capacity, token count,
// index width, and depth are template parameters and therefore part of the
// circuit shape. Callers must give each chosen tuple its own circuit identity.
template <std::size_t Capacity, std::size_t MaxTokens, std::size_t IndexBits,
          std::size_t MaxDepth = MaxTokens>
std::unique_ptr<proofs::Circuit<proofs::Fp256Base>> BuildBoundedJsonCircuit(
    proofs::QuadCircuit<proofs::Fp256Base>* q) {
  using Field = proofs::Fp256Base;
  using Backend = proofs::CompilerBackend<Field>;
  using Logic = proofs::Logic<Field, Backend>;
  using Relation = BoundedJsonTokenRelation<Logic, Capacity, MaxTokens,
                                            IndexBits, MaxDepth>;
  Backend backend(q);
  Logic logic(&backend, proofs::p256_base);
  BoundedJsonCircuitInput<Logic, Capacity, MaxTokens, IndexBits, MaxDepth>
      advice{};
  advice.input(logic);
  Relation(logic).assert_json(advice.text, advice.active_length,
                              advice.token_count, advice.tokens,
                              advice.strings, advice.numbers, advice.depths,
                              advice.frames, advice.container_ids);
  return q->mkcircuit(1);
}

}  // namespace sd_jwt_zk
