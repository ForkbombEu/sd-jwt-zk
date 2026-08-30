#include <array>
#include <cstdlib>
#include <vector>

#include "merkle/merkle_tree.h"
#include "sd_jwt_zk/status_membership.h"

namespace {
void require(bool value) {
  if (!value) std::exit(1);
}
}

int main() {
  std::array<std::uint8_t, 32> issuer{};
  issuer[0] = 7;
  std::array<std::uint8_t, 32> binding{};
  binding[0] = 9;
  constexpr std::uint64_t kEpoch = 4;
  constexpr std::uint64_t kCredential = 11;
  const auto valid = sd_jwt_zk::status_leaf_v1(
      issuer, kEpoch, kCredential,
      sd_jwt_zk::CredentialStatusV1::valid);
  const auto revoked = sd_jwt_zk::status_leaf_v1(
      issuer, kEpoch, kCredential,
      sd_jwt_zk::CredentialStatusV1::revoked);
  proofs::MerkleTree tree(4);
  tree.set_leaf(0, revoked);
  tree.set_leaf(1, valid);
  tree.set_leaf(2, revoked);
  tree.set_leaf(3, revoked);
  const auto root = tree.build_tree();
  const std::size_t index = 1;
  std::vector<proofs::Digest> compressed;
  tree.generate_compressed_proof(compressed, &index, 1);
  const sd_jwt_zk::StatusSnapshotPublicV1 snapshot{
      issuer, root, kEpoch, 10, 20};

  auto proof = sd_jwt_zk::prove_status_membership_v1(
      snapshot, kCredential, index, compressed, binding);
  require(static_cast<bool>(proof));
  auto verified = sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch, kCredential, 15, binding);
  require(verified && *verified.value);

  auto wrong_root = snapshot;
  wrong_root.root.data[0] ^= 1;
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, wrong_root, issuer, kEpoch, kCredential, 15, binding));
  auto wrong_issuer = issuer;
  wrong_issuer[0] ^= 1;
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, wrong_issuer, kEpoch, kCredential, 15, binding));
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch + 1, kCredential, 15, binding));
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch, kCredential + 1, 15, binding));
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch, kCredential, 9, binding));
  auto wrong_binding = binding;
  wrong_binding[0] ^= 1;
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch, kCredential, 15,
      wrong_binding));

  proofs::MerkleTree revoked_tree(4);
  for (std::size_t i = 0; i < 4; ++i) revoked_tree.set_leaf(i, revoked);
  auto revoked_root = revoked_tree.build_tree();
  std::vector<proofs::Digest> revoked_proof;
  revoked_tree.generate_compressed_proof(revoked_proof, &index, 1);
  const sd_jwt_zk::StatusSnapshotPublicV1 revoked_snapshot{
      issuer, revoked_root, kEpoch, 10, 20};
  require(!sd_jwt_zk::prove_status_membership_v1(
      revoked_snapshot, kCredential, index, revoked_proof, binding));
}
