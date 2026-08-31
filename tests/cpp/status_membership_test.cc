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

#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "sd_jwt_zk/status_membership.h"

namespace {
void require(bool value, const char* message) {
  if (!value) { std::cerr << message << '\n'; std::exit(1); }
}

sd_jwt_zk::LocalStatusEntryV1 entry(std::uint8_t binding,
                                    sd_jwt_zk::CredentialStatusV1 status) {
  sd_jwt_zk::LocalStatusEntryV1 result;
  result.credential_binding[0] = binding;
  result.status = status;
  return result;
}
}  // namespace

int main() {
  std::array<std::uint8_t, 32> issuer{};
  issuer[0] = 7;
  const std::vector<sd_jwt_zk::LocalStatusEntryV1> entries{
      entry(1, sd_jwt_zk::CredentialStatusV1::revoked),
      entry(2, sd_jwt_zk::CredentialStatusV1::valid),
      entry(3, sd_jwt_zk::CredentialStatusV1::revoked),
      entry(4, sd_jwt_zk::CredentialStatusV1::revoked),
  };
  auto snapshot = sd_jwt_zk::build_local_status_snapshot_v1(
      issuer, 4, 10, 20, entries);
  require(static_cast<bool>(snapshot), "bounded local snapshot builds");
  auto rebuilt = sd_jwt_zk::build_local_status_snapshot_v1(
      issuer, 4, 10, 20, entries);
  require(rebuilt && rebuilt.value->public_part.root == snapshot.value->public_part.root,
          "local snapshot root deterministically rebuilds");
  require(sd_jwt_zk::accepts_status_snapshot_v1(
              snapshot.value->public_part, issuer, 4, 15),
          "current local snapshot accepts");
  require(!sd_jwt_zk::accepts_status_snapshot_v1(
              snapshot.value->public_part, issuer, 5, 15),
          "epoch substitution rejects");
  require(!sd_jwt_zk::accepts_status_snapshot_v1(
              snapshot.value->public_part, issuer, 4, 9),
          "stale local snapshot rejects");
  require(!sd_jwt_zk::accepts_status_snapshot_v1(
              snapshot.value->public_part, issuer, 4, 21),
          "future local snapshot rejects");

  auto path = sd_jwt_zk::local_status_path_v1(*snapshot.value, 1);
  require(path && path.value->size() == sd_jwt_zk::kStatusMembershipDepthV1,
          "Longfellow generates one fixed-depth compressed path");
  const auto adapted = sd_jwt_zk::status_membership_path_v1<2>(
      snapshot.value->public_part, snapshot.value->leaves[1], 1, *path.value);
  require(adapted.root == snapshot.value->public_part.root,
          "Longfellow adapter host-verifies root before witness adaptation");
  auto altered = *path.value;
  altered[0].data[0] ^= 1;
  try {
    (void)sd_jwt_zk::status_membership_path_v1<2>(
        snapshot.value->public_part, snapshot.value->leaves[1], 1, altered);
    std::exit(1);
  } catch (const std::invalid_argument&) {}
  require(!sd_jwt_zk::local_status_path_v1(*snapshot.value, 4),
          "out-of-range private index rejects");

  auto duplicate = entries;
  duplicate[3].credential_binding = duplicate[0].credential_binding;
  require(!sd_jwt_zk::build_local_status_snapshot_v1(issuer, 4, 10, 20, duplicate),
          "duplicate credential bindings reject");
  require(!sd_jwt_zk::build_local_status_snapshot_v1(issuer, 4, 21, 20, entries),
          "malformed validity window rejects");
  auto short_entries = entries;
  short_entries.pop_back();
  require(!sd_jwt_zk::build_local_status_snapshot_v1(issuer, 4, 10, 20, short_entries),
          "wrong fixed capacity rejects");
}
