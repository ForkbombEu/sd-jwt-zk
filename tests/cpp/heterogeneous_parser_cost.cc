#include <iostream>
#include <memory>
#include <string_view>

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "sd_jwt_zk/bounded_json_circuit.h"

namespace {
using Field = proofs::Fp256Base;
using Backend = proofs::CompilerBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
enum class RelationSlice { full, strings, numbers };

template <std::size_t Capacity, std::size_t MaxTokens, std::size_t IndexBits,
          std::size_t MaxDepth, RelationSlice Slice = RelationSlice::full>
void add_parser(Logic& logic) {
  using Advice = sd_jwt_zk::BoundedJsonCircuitInput<
      Logic, Capacity, MaxTokens, IndexBits, MaxDepth>;
  using Relation = sd_jwt_zk::BoundedJsonTokenRelation<
      Logic, Capacity, MaxTokens, IndexBits, MaxDepth>;
  // Capacity-128 number witnesses are deliberately heap owned: this tool
  // measures relation construction, not stack availability.
  auto advice = std::make_unique<Advice>();
  advice->input(logic);
  Relation relation(logic);
  if constexpr (Slice == RelationSlice::full) {
    relation.assert_json(advice->text, advice->active_length,
                         advice->token_count, advice->tokens, advice->strings,
                         advice->numbers, advice->depths, advice->frames,
                         advice->container_ids);
  } else if constexpr (Slice == RelationSlice::strings) {
    relation.assert_string_lexemes(advice->text, advice->token_count,
                                   advice->tokens, advice->strings);
  } else {
    relation.assert_number_lexemes(advice->text, advice->token_count,
                                   advice->tokens, advice->numbers);
  }
}

std::size_t compile(std::size_t issuer_capacity, std::size_t disclosures) {
  proofs::QuadCircuit<Field> quad(proofs::p256_base);
  Backend backend(&quad);
  Logic logic(&backend, proofs::p256_base);
  if (issuer_capacity == 128)
    add_parser<128, 13, 8, 13>(logic);
  else
    // 105 is the authenticated issuer-payload size of the current fixture;
    // this is a separate circuit bucket, not a witness-dependent shortcut.
    add_parser<105, 13, 7, 13>(logic);
  for (std::size_t slot = 0; slot < disclosures; ++slot)
    add_parser<64, 13, 8, 13>(logic);
  return quad.mkcircuit(1)->nterms();
}

template <RelationSlice Slice>
std::size_t compile_issuer105_slice() {
  proofs::QuadCircuit<Field> quad(proofs::p256_base);
  Backend backend(&quad); Logic logic(&backend, proofs::p256_base);
  add_parser<105, 13, 7, 13, Slice>(logic);
  return quad.mkcircuit(1)->nterms();
}
}  // namespace

int main(int argc, char** argv) {
  const std::string_view lane = argc == 2 ? argv[1] : "issuer128";
  if (lane == "issuer128") {
    std::cout << "issuer128_terms=" << compile(128, 0) << '\n';
    return 0;
  }
  if (lane == "issuer105") {
    std::cout << "issuer105_terms=" << compile(105, 0) << '\n';
    return 0;
  }
  if (lane == "issuer105-strings") {
    std::cout << "issuer105_string_terms="
              << compile_issuer105_slice<RelationSlice::strings>() << '\n';
    return 0;
  }
  if (lane == "issuer105-numbers") {
    std::cout << "issuer105_number_terms="
              << compile_issuer105_slice<RelationSlice::numbers>() << '\n';
    return 0;
  }
  if (lane == "disclosure64") {
    // A disclosure parser is independently composable: the heterogeneous
    // factory only adds its own input/relation, so this is its exact marginal
    // parser term count (graph/digest relations are measured elsewhere).
    proofs::QuadCircuit<Field> quad(proofs::p256_base);
    Backend backend(&quad); Logic logic(&backend, proofs::p256_base);
    add_parser<64, 13, 8, 13>(logic);
    std::cout << "disclosure64_terms=" << quad.mkcircuit(1)->nterms() << '\n';
    return 0;
  }
  return 64;
}
