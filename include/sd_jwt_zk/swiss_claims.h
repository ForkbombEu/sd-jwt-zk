/*
 * Copyright (C) 2026 by The Forkbomb Company
 * designed, written and maintained by Denis Roio
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
