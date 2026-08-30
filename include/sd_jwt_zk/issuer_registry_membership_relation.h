#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace sd_jwt_zk {

// Fixed-depth SHA-256 issuer registry membership. It is deliberately
// project-owned experimental compatibility code pending migration to the
// planned upstream Longfellow Merkle gadget; it is not the desired final
// release primitive.
template <class LogicCircuit, std::size_t Depth>
class IssuerRegistryMembershipRelation {
  using v8 = typename LogicCircuit::v8;
  using v256 = typename LogicCircuit::v256;
  using BitW = typename LogicCircuit::BitW;
  template <std::size_t N>
  using bitvec = typename LogicCircuit::template bitvec<N>;
  using Sha = proofs::FlatSHA256Circuit<LogicCircuit,
                                        proofs::BitPlucker<LogicCircuit, 4>>;

 public:
  struct Hash3 { const std::array<v8, 192>& message;
                 const std::array<typename Sha::BlockWitness, 3>& witness;
                 const v256& digest; };
  struct Hash2 { const std::array<v8, 128>& message;
                 const std::array<typename Sha::BlockWitness, 2>& witness;
                 const v256& digest; };
  struct Input {
    const std::array<v8, 32>& issuer_x;
    const std::array<v8, 32>& issuer_y;
    const v256& vct_digest;
    const std::array<v8, 8>& not_before;
    const std::array<v8, 8>& not_after;
    const bitvec<64>& not_before_bits;
    const bitvec<64>& not_after_bits;
    const bitvec<64>& private_epoch;
    const bitvec<Depth>& leaf_index;
    const Hash3& leaf;
    const std::array<std::array<v8, 32>, Depth>& siblings;
    const std::array<BitW, Depth>& sibling_is_left;
    const std::array<Hash2, Depth>& nodes;
    const std::array<v8, 32>& public_root;
    const bitvec<64>& public_epoch;
    const bitvec<64>& public_valid_from;
    const bitvec<64>& public_valid_until;
    const bitvec<8>& public_depth;
  };

  explicit IssuerRegistryMembershipRelation(const LogicCircuit& logic) : logic_(logic) {}

  void assert_valid(const Input& in) const {
    // The public registry metadata is circuit input, not merely transcript
    // decoration.  Epoch and fixed family depth are equality-gated, and the
    // complete public verification window must fall within the private leaf's
    // authorization interval.
    logic_.assert1(logic_.veq(in.private_epoch, in.public_epoch));
    logic_.assert1(logic_.veq(in.public_depth, Depth));
    logic_.assert1(logic_.vleq(in.public_valid_from,
                               in.public_valid_until));
    logic_.assert1(logic_.vleq(in.not_before_bits,
                               in.public_valid_from));
    logic_.assert1(logic_.vleq(in.public_valid_until,
                               in.not_after_bits));
    bind_u64_bytes(in.not_before, in.not_before_bits);
    bind_u64_bytes(in.not_after, in.not_after_bits);
    constexpr char kLeaf[] = "SDJWT-ZK/issuer-registry/v1/leaf";
    bind_literal(in.leaf.message, 0, kLeaf);
    for (std::size_t i = 0; i < 32; ++i) {
      logic_.vassert_eq(in.leaf.message[sizeof(kLeaf) - 1 + i], in.issuer_x[i]);
      logic_.vassert_eq(in.leaf.message[sizeof(kLeaf) - 1 + 32 + i], in.issuer_y[i]);
      bind_digest_byte(in.leaf.message[sizeof(kLeaf) - 1 + 64 + i], in.vct_digest, i);
    }
    for (std::size_t i = 0; i < 8; ++i) {
      logic_.vassert_eq(in.leaf.message[sizeof(kLeaf) - 1 + 96 + i], in.not_before[i]);
      logic_.vassert_eq(in.leaf.message[sizeof(kLeaf) - 1 + 104 + i], in.not_after[i]);
    }
    Sha(logic_).assert_message_hash(3, logic_.template vbit<8>(3),
                                    in.leaf.message.data(), in.leaf.digest,
                                    in.leaf.witness.data());
    const v256* current = &in.leaf.digest;
    constexpr char kNode[] = "SDJWT-ZK/issuer-registry/v1/node";
    for (std::size_t level = 0; level < Depth; ++level) {
      logic_.assert_is_bit(in.sibling_is_left[level]);
      logic_.assert_eq(in.sibling_is_left[level], in.leaf_index[level]);
      bind_literal(in.nodes[level].message, 0, kNode);
      for (std::size_t byte = 0; byte < 32; ++byte) for (std::size_t bit = 0; bit < 8; ++bit) {
        const auto current_bit = (*current)[(31 - byte) * 8 + bit];
        const auto sibling_bit = in.siblings[level][byte][bit];
        logic_.assert_eq(in.nodes[level].message[sizeof(kNode) - 1 + byte][bit],
                         logic_.mux(in.sibling_is_left[level], sibling_bit, current_bit));
        logic_.assert_eq(in.nodes[level].message[sizeof(kNode) - 1 + 32 + byte][bit],
                         logic_.mux(in.sibling_is_left[level], current_bit, sibling_bit));
      }
      Sha(logic_).assert_message_hash(2, logic_.template vbit<8>(2),
                                      in.nodes[level].message.data(),
                                      in.nodes[level].digest,
                                      in.nodes[level].witness.data());
      current = &in.nodes[level].digest;
    }
    for (std::size_t byte = 0; byte < 32; ++byte)
      bind_digest_byte(in.public_root[byte], *current, byte);
  }

 private:
  template <std::size_t N>
  void bind_literal(const std::array<v8, N>& message, std::size_t offset,
                    const char* text) const {
    for (std::size_t i = 0; text[i] != '\0'; ++i)
      logic_.vassert_eq(message[offset + i], static_cast<std::uint8_t>(text[i]));
  }
  void bind_digest_byte(const v8& byte, const v256& digest,
                        std::size_t index) const {
    for (std::size_t bit = 0; bit < 8; ++bit)
      logic_.assert_eq(byte[bit], digest[(31 - index) * 8 + bit]);
  }
  void bind_u64_bytes(const std::array<v8, 8>& bytes,
                      const bitvec<64>& value) const {
    for (std::size_t byte = 0; byte < 8; ++byte)
      for (std::size_t bit = 0; bit < 8; ++bit)
        logic_.assert_eq(bytes[7 - byte][bit], value[byte * 8 + bit]);
  }
  const LogicCircuit& logic_;
};

template <class Logic, std::size_t Depth>
void AllocateAndAssertIssuerRegistryMembership(
    Logic& logic, const std::array<typename Logic::v8, 32>& issuer_x,
    const std::array<typename Logic::v8, 32>& issuer_y,
    const typename Logic::v256& vct_digest,
    const std::array<typename Logic::v8, 32>& root,
    const typename Logic::template bitvec<64>& epoch,
    const typename Logic::template bitvec<64>& valid_from,
    const typename Logic::template bitvec<64>& valid_until,
    const typename Logic::template bitvec<8>& depth) {
  using Relation = IssuerRegistryMembershipRelation<Logic, Depth>;
  using Sha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;
  const auto not_before_bits = logic.template vinput<64>();
  const auto not_after_bits = logic.template vinput<64>();
  const auto private_epoch = logic.template vinput<64>();
  const auto leaf_index = logic.template vinput<Depth>();
  std::array<typename Logic::v8, 8> not_before{}, not_after{};
  for (auto* value : {&not_before, &not_after})
    for (auto& byte : *value) byte = logic.template vinput<8>();
  std::array<typename Logic::v8, 192> leaf_message{};
  for (auto& byte : leaf_message) byte = logic.template vinput<8>();
  std::array<typename Sha::BlockWitness, 3> leaf_witness{};
  for (auto& block : leaf_witness) block.input(logic);
  typename Logic::v256 leaf_digest{};
  for (auto& bit : leaf_digest) bit = logic.input();
  std::array<std::array<typename Logic::v8, 32>, Depth> siblings{};
  for (auto& sibling : siblings)
    for (auto& byte : sibling) byte = logic.template vinput<8>();
  std::array<typename Logic::BitW, Depth> directions{};
  for (std::size_t i = 0; i < Depth; ++i) directions[i] = leaf_index[i];
  std::array<std::array<typename Logic::v8, 128>, Depth> node_messages{};
  std::array<std::array<typename Sha::BlockWitness, 2>, Depth> node_witnesses{};
  std::array<typename Logic::v256, Depth> node_digests{};
  for (std::size_t level = 0; level < Depth; ++level) {
    for (auto& byte : node_messages[level]) byte = logic.template vinput<8>();
    for (auto& block : node_witnesses[level]) block.input(logic);
    for (auto& bit : node_digests[level]) bit = logic.input();
  }
  typename Relation::Hash3 leaf{leaf_message, leaf_witness, leaf_digest};
  std::array<typename Relation::Hash2, Depth> nodes{
      typename Relation::Hash2{node_messages[0], node_witnesses[0], node_digests[0]},
      typename Relation::Hash2{node_messages[1], node_witnesses[1], node_digests[1]}};
  Relation(logic).assert_valid(typename Relation::Input{
      issuer_x, issuer_y, vct_digest, not_before, not_after, not_before_bits,
      not_after_bits, private_epoch, leaf_index, leaf, siblings, directions,
      nodes, root, epoch, valid_from, valid_until, depth});
}

}  // namespace sd_jwt_zk
