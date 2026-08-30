#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "merkle/merkle_tree.h"
#include "sd_jwt_zk/status_membership.h"

namespace {
void require(bool value, const char* message) {
  if (!value) { std::cerr << message << '\n'; std::exit(1); }
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
  auto wrong_root = snapshot; wrong_root.root.data[0] ^= 1;
  try { (void)sd_jwt_zk::status_membership_path_v1<2>(wrong_root, valid, index, proof); std::exit(1); }
  catch (const std::invalid_argument&) {}
  auto wrong_proof = proof; wrong_proof[0].data[0] ^= 1;
  try { (void)sd_jwt_zk::status_membership_path_v1<2>(snapshot, valid, index, wrong_proof); std::exit(1); }
  catch (const std::invalid_argument&) {}
  try { (void)sd_jwt_zk::status_membership_path_v1<2>(snapshot, valid, 0, proof); std::exit(1); }
  catch (const std::invalid_argument&) {}
}
