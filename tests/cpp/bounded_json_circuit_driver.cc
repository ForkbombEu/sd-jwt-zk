#include "sd_jwt_zk/bounded_json.h"
#include "sd_jwt_zk/bounded_json_relation.h"

#include <array>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"

namespace {
using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Relation = sd_jwt_zk::BoundedJsonTokenRelation<Logic, 16, 8, 5, 2>;

int hex(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}
bool decode_hex(const char* encoded, std::string& output) {
  const std::string_view input(encoded);
  if (input.size() % 2 != 0) return false;
  for (std::size_t index = 0; index < input.size(); index += 2) {
    const int high = hex(input[index]), low = hex(input[index + 1]);
    if (high < 0 || low < 0) return false;
    output.push_back(static_cast<char>((high << 4) | low));
  }
  return true;
}
bool scalar(unsigned char kind) {
  return kind == 2 || kind == 4 || kind == 5 || kind == 6;
}

// Build complete, non-fixture-specific advice for the small ASCII/no-number
// family. This exercises assert_json (not merely the lexical partition) for
// root arrays/objects, nested containers, strings, booleans and null.
bool run(const std::string& input, const std::vector<sd_jwt_zk::JsonToken>& native) {
  if (input.size() > 16 || native.empty() || native.size() > 8) return false;
  for (const auto& token : native) if (token.kind == 3) return false;
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<Logic::v8, 16> text{};
  for (std::size_t i = 0; i < text.size(); ++i)
    text[i] = logic.template vbit<8>(i < input.size() ? static_cast<unsigned char>(input[i]) : 0);
  std::array<Relation::Token, 8> tokens{};
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    const bool active = i < native.size();
    tokens[i].kind = logic.template vbit<8>(active ? native[i].kind : 0);
    logic.bits(5, tokens[i].begin.data(), active ? native[i].begin : 0);
    logic.bits(5, tokens[i].end.data(), active ? native[i].end : 0);
  }
  Logic::bitvec<5> length{}, count{};
  logic.bits(5, length.data(), input.size()); logic.bits(5, count.data(), native.size());
  std::array<Relation::StringWitness, 8> strings{};
  for (std::size_t token = 0; token < strings.size(); ++token) {
    std::size_t units = 0;
    if (token < native.size() && native[token].kind == 2) {
      if (native[token].end < native[token].begin + 2) return false;
      units = native[token].end - native[token].begin - 2;
      for (std::size_t unit = 0; unit < units; ++unit) {
        const unsigned char byte = input[native[token].begin + 1 + unit];
        if (byte < 0x20 || byte >= 0x80 || byte == '"' || byte == '\\') return false;
      }
    }
    logic.bits(5, strings[token].unit_count.data(), units);
    for (std::size_t unit = 0; unit < strings[token].units.size(); ++unit) {
      const bool active = unit < units;
      const std::size_t begin = active ? native[token].begin + 1 + unit : 0;
      logic.bits(5, strings[token].units[unit].begin.data(), begin);
      logic.bits(5, strings[token].units[unit].end.data(), active ? begin + 1 : 0);
      logic.bits(21, strings[token].units[unit].codepoint.data(), active ? static_cast<unsigned char>(input[begin]) : 0);
    }
  }
  std::array<Relation::NumberWitness, 8> numbers{};
  for (auto& number : numbers) {
    number.negative = logic.bit(0); number.exponent_negative = logic.bit(0);
    logic.bits(5, number.digit_count.data(), 0); logic.bits(5, number.fraction_count.data(), 0);
    logic.bits(5, number.significant_begin.data(), 0); logic.bits(5, number.significant_end.data(), 0); logic.bits(5, number.significant_length.data(), 0);
    for (auto& x : number.digit_offsets) logic.bits(5, x.data(), 0);
    for (auto& x : number.significand) x = logic.template vbit<8>(0);
    for (auto& x : number.states) x = logic.template vbit<8>(0);
    for (auto& x : number.exponent_accumulator) for (auto& bit : x) bit = logic.bit(0);
    for (auto& bit : number.scale) bit = logic.bit(0);
  }
  std::array<std::array<unsigned char, 9>, 9> frame_values{};
  std::array<std::array<std::size_t, 9>, 9> id_values{};
  std::array<std::size_t, 9> depth_values{};
  std::vector<unsigned char> frames{1}; std::vector<std::size_t> ids{0};
  depth_values[0] = 1; frame_values[0][0] = 1;
  for (std::size_t step = 0; step < native.size(); ++step) {
    const unsigned char kind = native[step].kind; const std::size_t depth = frames.size();
    if (depth > 3) return false;
    unsigned char& state = frames.back(); bool valid = kind == 1;
    if (!valid && (state == 1 || state == 6 || state == 8 || state == 9) && scalar(kind)) { state = state == 1 ? 2 : state == 6 ? 7 : 10; valid = true; }
    else if (!valid && (state == 1 || state == 6 || state == 8 || state == 9) && (kind == 7 || kind == 9)) {
      if (depth == 3) return false; state = state == 1 ? 2 : state == 6 ? 7 : 10; frames.push_back(kind == 7 ? 3 : 8); ids.push_back(step + 1); valid = true;
    } else if (!valid && (state == 3 || state == 4) && kind == 2) { state = 5; valid = true; }
    else if (!valid && state == 5 && kind == 12) { state = 6; valid = true; }
    else if (!valid && state == 7 && kind == 11) { state = 4; valid = true; }
    else if (!valid && state == 10 && kind == 11) { state = 9; valid = true; }
    else if (!valid && depth > 1 && (((state == 3 || state == 7) && kind == 8) || ((state == 8 || state == 10) && kind == 10))) { frames.pop_back(); ids.pop_back(); valid = true; }
    if (!valid) return false;
    depth_values[step + 1] = frames.size();
    for (std::size_t slot = 0; slot < frames.size(); ++slot) { frame_values[step + 1][slot] = frames[slot]; id_values[step + 1][slot] = ids[slot]; }
  }
  if (frames.size() != 1 || frames[0] != 2) return false;
  std::array<Logic::bitvec<5>, 9> depths{}; std::array<Relation::GrammarStack, 9> grammar{}; std::array<Relation::ContainerIdStack, 9> ids_advice{};
  for (std::size_t step = 0; step < depths.size(); ++step) {
    logic.bits(5, depths[step].data(), depth_values[step]);
    for (std::size_t slot = 0; slot < grammar[step].size(); ++slot) { grammar[step][slot] = logic.template vbit<8>(frame_values[step][slot]); logic.bits(5, ids_advice[step][slot].data(), id_values[step][slot]); }
  }
  Relation(logic).assert_json(text, length, count, tokens, strings, numbers, depths, grammar, ids_advice);
  return !backend.assertion_failed();
}
}  // namespace
int main(int argc, char** argv) {
  std::string input;
  if (argc != 2 || !decode_hex(argv[1], input)) return 64;
  const auto native = sd_jwt_zk::tokenize_bounded_json(input, {16, 2, 8});
  const bool circuit = native && run(input, *native.value);
  std::cout << "{\"native\":" << (native ? "true" : "false") << ",\"circuit\":" << (circuit ? "true" : "false") << "}\n";
}
