#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "sd_jwt_zk/api.h"

namespace sd_jwt_zk {

// Authorization records contain issuer policy only.  They deliberately do
// not contain an issuer JWS, disclosure, holder key, or credential subject.
struct IssuerAuthorizationRecordV1 {
  P256Key issuer_key;
  std::string vct;
  std::uint64_t not_before{};
  std::uint64_t not_after{};
};

struct IssuerRegistryPathV1 {
  IssuerAuthorizationRecordV1 record;
  std::uint64_t epoch{};
  std::uint32_t index{};
  std::vector<std::array<std::uint8_t, 32>> siblings;
  std::vector<bool> sibling_is_left;
};

struct IssuerRegistryV1 {
  std::uint64_t epoch{};
  std::uint64_t valid_from{};
  std::uint64_t valid_until{};
  std::uint8_t depth{};
  std::array<std::uint8_t, 32> root{};
  std::vector<IssuerRegistryPathV1> paths;
};

// This is the complete public registry commitment carried in Request::trust_public
// by a registry family.  It contains no issuer key, type, leaf index, or path.
struct RegistryTrustContextV1 {
  std::array<std::uint8_t, 32> root{};
  std::uint64_t epoch{};
  std::uint64_t valid_from{};
  std::uint64_t valid_until{};
  std::uint8_t depth{};
};

Result<Bytes> encode_registry_trust_context_v1(
    const RegistryTrustContextV1& context);
Result<RegistryTrustContextV1> decode_registry_trust_context_v1(
    const Bytes& encoded);
RegistryTrustContextV1 registry_trust_context_v1(const IssuerRegistryV1& registry);

// Builds a fixed-depth registry with deterministic record sorting.  Depth is
// constrained to keep host-side allocations bounded; empty registries have a
// deterministic root but no membership paths.
Result<IssuerRegistryV1> build_issuer_registry_v1(
    std::vector<IssuerAuthorizationRecordV1> records, std::uint8_t depth,
    std::uint64_t epoch, std::uint64_t valid_from, std::uint64_t valid_until,
    const Limits& limits = {});

// Recomputes a path and enforces that index direction bits, depth, and the
// registry epoch all agree.  The caller supplies local root policy; this
// function never treats a proof-supplied registry as authoritative.
bool issuer_registry_path_matches_v1(const IssuerRegistryV1& registry,
                                     const IssuerRegistryPathV1& path);

std::array<std::uint8_t, 32> issuer_registry_leaf_v1(
    const IssuerAuthorizationRecordV1& record);

}  // namespace sd_jwt_zk
