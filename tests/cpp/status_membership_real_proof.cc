#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "sd_jwt_zk/status_membership.h"

namespace {
void require(bool value, const char* label = "require") {
  if (!value) {
    std::cerr << label << '\n';
    std::exit(1);
  }
}
}

int main() {
  std::array<std::uint8_t, 32> issuer{};
  issuer[0] = 7;
  std::array<std::uint8_t, 32> binding{};
  binding[0] = 9;
  constexpr std::uint64_t kEpoch = 4;
  std::array<std::uint8_t, 32> credential_binding{};
  credential_binding.back() = 11;
  // The builder rejects duplicate bindings, so use four distinct bindings.
  std::vector<sd_jwt_zk::LocalStatusEntryV1> bounded_entries;
  for (std::uint8_t value = 0; value < 4; ++value) {
    sd_jwt_zk::LocalStatusEntryV1 entry;
    entry.credential_binding[value] = value + 1;
    entry.status = value == 1 ? sd_jwt_zk::CredentialStatusV1::valid
                              : sd_jwt_zk::CredentialStatusV1::revoked;
    bounded_entries.push_back(entry);
  }
  credential_binding = bounded_entries[1].credential_binding;
  auto local = sd_jwt_zk::build_local_status_snapshot_v1(
      issuer, kEpoch, 10, 20, bounded_entries);
  require(static_cast<bool>(local));
  const auto snapshot = local.value->public_part;
  const std::size_t index = 1;
  auto compressed = sd_jwt_zk::local_status_path_v1(*local.value, index);
  require(static_cast<bool>(compressed));
  // The public circuit layout exposes precisely the verifier-selected root;
  // a credential leaf, index, and compressed path never enter inspection.
  require(sd_jwt_zk::status_membership_merkle_public_input_width_v1() == 256,
          "public Merkle root width");
  require(sd_jwt_zk::status_membership_public_input_width_v1() == 768,
          "total public status statement width");

  auto proof = sd_jwt_zk::prove_status_membership_v1(
      snapshot, credential_binding, index, *compressed.value, binding);
  require(static_cast<bool>(proof), "status prover");
  auto verified = sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch, 15, binding);
  require(verified && *verified.value);
  auto repeated = sd_jwt_zk::prove_status_membership_v1(
      snapshot, credential_binding, index, *compressed.value, binding);
  require(repeated && repeated.value->proof != proof.value->proof);

  auto wrong_root = snapshot;
  wrong_root.root.data[0] ^= 1;
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, wrong_root, issuer, kEpoch, 15, binding));
  auto wrong_issuer = issuer;
  wrong_issuer[0] ^= 1;
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, wrong_issuer, kEpoch, 15, binding));
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch + 1, 15, binding));
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch, 9, binding));
  auto wrong_binding = binding;
  wrong_binding[0] ^= 1;
  require(!sd_jwt_zk::verify_status_membership_v1(
      *proof.value, snapshot, issuer, kEpoch, 15, wrong_binding));

  auto revoked_entries = bounded_entries;
  revoked_entries[1].status = sd_jwt_zk::CredentialStatusV1::revoked;
  auto revoked_local = sd_jwt_zk::build_local_status_snapshot_v1(
      issuer, kEpoch, 10, 20, revoked_entries);
  require(static_cast<bool>(revoked_local));
  auto revoked_proof = sd_jwt_zk::local_status_path_v1(*revoked_local.value, index);
  require(static_cast<bool>(revoked_proof));
  const auto revoked_snapshot = revoked_local.value->public_part;
  require(!sd_jwt_zk::prove_status_membership_v1(
      revoked_snapshot, credential_binding, index, *revoked_proof.value, binding));
}
