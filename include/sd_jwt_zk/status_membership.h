#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "circuits/merkle/fixed_depth_sha256_merkle_membership.h"
#include "sd_jwt_zk/api.h"

namespace sd_jwt_zk {

// Application policy lives here; tree construction, proof verification, path
// ordering, SHA witnesses, and root equality are owned by LongfellowZK.
enum class CredentialStatusV1 : std::uint8_t { valid = 1, revoked = 2 };

struct StatusSnapshotPublicV1 {
  std::array<std::uint8_t, 32> issuer{};
  proofs::Digest root{};
  std::uint64_t epoch{};
  std::uint64_t valid_from{};
  std::uint64_t valid_until{};
};

inline constexpr std::size_t kStatusMembershipDepthV1 = 2;

// A status proof is a second, presentation-bound proof component.  The
// snapshot is deliberately absent: verification always receives the trusted
// snapshot out of band, so proof bytes cannot select their own trust root.
struct StatusMembershipProofV1 { Bytes proof; };

struct StatusMembershipWitnessV1 {
  std::size_t private_index{};
  std::vector<proofs::Digest> compressed_proof;
};

struct StatusPolicyV1 {
  StatusSnapshotPublicV1 snapshot;
  std::array<std::uint8_t, 32> credential_binding{};
};

std::array<std::uint8_t, 32> status_issuer_v1(const P256Key& issuer_key);
Bytes encode_status_policy_v1(const StatusPolicyV1& policy);
Result<StatusPolicyV1> decode_status_policy_v1(const Bytes& encoded);
std::array<std::uint8_t, 32> status_credential_binding_v1(
    const std::array<std::uint8_t, 32>& credential_digest);

inline proofs::Digest status_leaf_v1(
    const std::array<std::uint8_t, 32>& issuer, std::uint64_t epoch,
    const std::array<std::uint8_t, 32>& credential_binding,
    CredentialStatusV1 status) {
  if (status != CredentialStatusV1::valid && status != CredentialStatusV1::revoked)
    throw std::invalid_argument("unknown credential status");
  std::string material{"sd-jwt-zk/status-leaf/v1"};
  material.append(reinterpret_cast<const char*>(issuer.data()), issuer.size());
  for (const auto value : {epoch})
    for (int shift = 56; shift >= 0; shift -= 8)
      material.push_back(static_cast<char>(value >> shift));
  material.append(reinterpret_cast<const char*>(credential_binding.data()),
                  credential_binding.size());
  material.push_back(static_cast<char>(status));
  const auto digest = sha256_ascii(material);
  proofs::Digest result{};
  for (std::size_t i = 0; i < result.kLength; ++i) result.data[i] = digest[i];
  return result;
}

inline bool accepts_status_snapshot_v1(
    const StatusSnapshotPublicV1& snapshot,
    const std::array<std::uint8_t, 32>& expected_issuer,
    std::uint64_t expected_epoch, std::uint64_t now) {
  return snapshot.issuer == expected_issuer && snapshot.epoch == expected_epoch &&
         snapshot.valid_from <= snapshot.valid_until &&
         now >= snapshot.valid_from && now <= snapshot.valid_until;
}

template <std::size_t Depth>
inline proofs::FixedDepthSha256MerklePath<Depth> status_membership_path_v1(
    const StatusSnapshotPublicV1& snapshot, const proofs::Digest& leaf,
    std::size_t private_index, const std::vector<proofs::Digest>& compressed_proof) {
  // The upstream adapter host-verifies the supplied single-leaf proof before
  // copying it into private circuit witness form and rejects bad root/index/path.
  return proofs::FixedDepthSha256MerklePathAdapter<Depth>::from_single_leaf(
      std::size_t{1} << Depth, snapshot.root, leaf, private_index,
      compressed_proof);
}

template <class Logic, std::size_t Depth>
using StatusMembershipCircuitV1 =
    proofs::FixedDepthSha256MerkleMembership<Logic, Depth>;

Result<StatusMembershipProofV1> prove_status_membership_v1(
    const StatusSnapshotPublicV1& snapshot,
    const std::array<std::uint8_t, 32>& credential_binding,
    std::size_t private_index,
    const std::vector<proofs::Digest>& compressed_proof,
    const std::array<std::uint8_t, 32>& presentation_binding,
    const Limits& limits = {});

Result<bool> verify_status_membership_v1(
    const StatusMembershipProofV1& proof,
    const StatusSnapshotPublicV1& trusted_snapshot,
    const std::array<std::uint8_t, 32>& expected_issuer,
    std::uint64_t expected_epoch,
    const std::array<std::uint8_t, 32>& credential_binding,
    std::uint64_t now,
    const std::array<std::uint8_t, 32>& presentation_binding,
    const Limits& limits = {});

}  // namespace sd_jwt_zk
