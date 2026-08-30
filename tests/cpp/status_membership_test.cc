#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"
#include "merkle/merkle_tree.h"
#include "sd_jwt_zk/status_membership.h"

namespace {
void require(bool value, const char* message) {
  if (!value) { std::cerr << message << '\n'; std::exit(1); }
}

using EvalBackend = proofs::EvaluationBackend<proofs::Fp256Base>;
using EvalLogic = proofs::Logic<proofs::Fp256Base, EvalBackend>;
using EvalRelation = sd_jwt_zk::StatusMembershipCircuitV1<EvalLogic, 2>;

void assign_digest(const EvalLogic& logic, EvalLogic::v256& output,
                   const proofs::Digest& digest) {
  for (std::size_t byte = 0; byte < proofs::Digest::kLength; ++byte)
    logic.bits(8, &output[(31 - byte) * 8], digest.data[byte]);
}

void assign_block(const EvalLogic& logic, EvalRelation::ShaBlockWitness& output,
                  const proofs::FlatSHA256Witness::BlockWitness& input) {
  proofs::BitPluckerEncoder<proofs::Fp256Base, 4> encoder(proofs::p256_base);
  for (std::size_t i = 0; i < 48; ++i) {
    const auto packed = encoder.mkpacked_v32(input.outw[i]);
    for (std::size_t j = 0; j < packed.size(); ++j)
      output.outw[i][j] = logic.konst(packed[j]);
  }
  for (std::size_t i = 0; i < 64; ++i) {
    const auto packed_e = encoder.mkpacked_v32(input.oute[i]);
    const auto packed_a = encoder.mkpacked_v32(input.outa[i]);
    for (std::size_t j = 0; j < packed_e.size(); ++j) {
      output.oute[i][j] = logic.konst(packed_e[j]);
      output.outa[i][j] = logic.konst(packed_a[j]);
    }
  }
  for (std::size_t i = 0; i < 8; ++i) {
    const auto packed = encoder.mkpacked_v32(input.h1[i]);
    for (std::size_t j = 0; j < packed.size(); ++j)
      output.h1[i][j] = logic.konst(packed[j]);
  }
}

void evaluate_relation(
    const proofs::FixedDepthSha256MerklePath<2>& path) {
  EvalBackend backend(proofs::p256_base, false);
  EvalLogic logic(&backend, proofs::p256_base);
  EvalRelation::Input input{};
  assign_digest(logic, input.leaf_digest, path.leaf);
  assign_digest(logic, input.expected_root, path.root);
  proofs::Digest current = path.leaf;
  for (std::size_t level = 0; level < 2; ++level) {
    assign_digest(logic, input.siblings[level], path.siblings[level]);
    input.direction_bits[level] = logic.bit(path.direction_bits[level]);
    input.index_bits[level] = logic.bit(path.direction_bits[level]);
    const auto& sibling = path.siblings[level];
    const bool sibling_left = path.direction_bits[level] != 0;
    const auto& left = sibling_left ? sibling : current;
    const auto& right = sibling_left ? current : sibling;
    std::array<std::uint8_t, 64> message{};
    std::copy(left.data, left.data + proofs::Digest::kLength, message.begin());
    std::copy(right.data, right.data + proofs::Digest::kLength,
              message.begin() + proofs::Digest::kLength);
    std::uint8_t blocks = 0;
    std::array<std::uint8_t, 128> padded{};
    std::array<proofs::FlatSHA256Witness::BlockWitness, 2> witness{};
    proofs::FlatSHA256Witness::transform_and_witness_message(
        message.size(), message.data(), 2, blocks, padded.data(),
        witness.data());
    require(blocks == 2, "status SHA uses two blocks");
    assign_block(logic, input.sha_witness[2 * level], witness[0]);
    assign_block(logic, input.sha_witness[2 * level + 1], witness[1]);
    current = proofs::Digest::hash2(left, right);
  }
  EvalRelation(logic).assert_member(input);
  require(!backend.assertion_failed(), "production status relation evaluates");
}
}

int main() {
  std::array<std::uint8_t, 32> issuer{}; issuer[0] = 7;
  const auto valid = sd_jwt_zk::status_leaf_v1(
      issuer, 4, 9, sd_jwt_zk::CredentialStatusV1::valid);
  const auto revoked = sd_jwt_zk::status_leaf_v1(
      issuer, 4, 10, sd_jwt_zk::CredentialStatusV1::revoked);
  proofs::MerkleTree tree(4);
  tree.set_leaf(0, revoked); tree.set_leaf(1, valid);
  tree.set_leaf(2, revoked); tree.set_leaf(3, revoked);
  const auto root = tree.build_tree();
  std::vector<proofs::Digest> proof;
  const std::size_t index = 1;
  tree.generate_compressed_proof(proof, &index, 1);
  sd_jwt_zk::StatusSnapshotPublicV1 snapshot{issuer, root, 4, 10, 20};
  require(sd_jwt_zk::accepts_status_snapshot_v1(snapshot, issuer, 4, 15),
          "current issuer snapshot accepts");
  require(!sd_jwt_zk::accepts_status_snapshot_v1(snapshot, issuer, 5, 15),
          "epoch substitution rejects");
  require(!sd_jwt_zk::accepts_status_snapshot_v1(snapshot, issuer, 4, 9),
          "stale snapshot rejects");
  require(!sd_jwt_zk::accepts_status_snapshot_v1(snapshot, issuer, 4, 21),
          "future snapshot rejects");
  const auto path = sd_jwt_zk::status_membership_path_v1<2>(snapshot, valid, index, proof);
  require(path.root == snapshot.root, "installed adapter preserves root");
  evaluate_relation(path);
  auto wrong_root = snapshot; wrong_root.root.data[0] ^= 1;
  try { (void)sd_jwt_zk::status_membership_path_v1<2>(wrong_root, valid, index, proof); std::exit(1); }
  catch (const std::invalid_argument&) {}
  auto wrong_proof = proof; wrong_proof[0].data[0] ^= 1;
  try { (void)sd_jwt_zk::status_membership_path_v1<2>(snapshot, valid, index, wrong_proof); std::exit(1); }
  catch (const std::invalid_argument&) {}
  try { (void)sd_jwt_zk::status_membership_path_v1<2>(snapshot, valid, 0, proof); std::exit(1); }
  catch (const std::invalid_argument&) {}
}
