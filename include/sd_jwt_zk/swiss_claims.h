#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sd_jwt_zk/bounded_json.h"

namespace sd_jwt_zk {
enum class SwissPolicyKind : std::uint8_t {
  reveal,
  equality,
  integer_range,
  date_range,
  boolean_value,
  set_membership,
};
struct SwissTypedPolicy {
  std::string path;
  SwissPolicyKind kind{};
  std::string value;
  std::string upper;
  std::vector<std::string> set;
};
// These are verifier-supplied public values.  Claim values remain private to
// the relation/witness; validation returns only accept or reject.
struct SwissTimePolicy {
  std::uint64_t now{};
  bool require_expiry{};
  bool require_issued_at{};
};

// Validates only bounded compact Swiss credential-format semantics. Trust,
// metadata, rendering and schema retrieval deliberately remain external policy.
Result<bool> validate_swiss_compact_claims(std::string_view protected_header,
                                           std::string_view payload,
                                           const SwissTimePolicy& time_policy,
                                           const std::vector<SwissTypedPolicy>& policies,
                                           const JsonLimits& limits = {});
}  // namespace sd_jwt_zk
