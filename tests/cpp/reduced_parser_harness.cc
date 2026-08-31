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

#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/bounded_json.h"
#include "sd_jwt_zk/status_membership.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

namespace {

using sd_jwt_zk::Bytes;

template <class Decode>
std::size_t mutate_bytes(const Bytes& seed, Decode&& decode) {
  std::size_t cases{};
  for (std::size_t index = 0; index < seed.size(); ++index) {
    Bytes changed = seed;
    changed[index] ^= static_cast<std::uint8_t>(1U << (index % 8));
    (void)decode(changed);
    ++cases;
  }
  for (std::size_t length = 0; length < seed.size(); ++length) {
    (void)decode(Bytes(seed.begin(), seed.begin() + static_cast<std::ptrdiff_t>(length)));
    ++cases;
  }
  return cases;
}

}  // namespace

int main() {
  using namespace sd_jwt_zk;
  const CircuitIdentity identity{Binding::bearer, Trust::exact_key, 2, {},
                                 "gf2_128", 2, 3};
  const Request request{identity, "https://verifier.example\x1flogin", "nonce-1",
                        1, 2, {1}, {1}, {2}, {}};
  const auto request_bytes = encode_request(request);
  const auto envelope_bytes = encode_envelope({request, {1, 2, 3}});
  if (!request_bytes || !envelope_bytes) return 1;

  std::size_t cases{};
  cases += mutate_bytes(*request_bytes.value,
                        [](const Bytes& bytes) { return decode_request(bytes); });
  cases += mutate_bytes(*envelope_bytes.value,
                        [](const Bytes& bytes) { return decode_envelope(bytes); });

  StatusSnapshotPublicV1 snapshot{};
  snapshot.epoch = 7;
  snapshot.valid_from = 1;
  snapshot.valid_until = 2;
  const Bytes status = encode_status_policy_v1({snapshot});
  cases += mutate_bytes(status,
                        [](const Bytes& bytes) { return decode_status_policy_v1(bytes); });

  const std::string compact = "eyJhIjoxfQ.eyJiIjoyfQ.AA";
  for (std::size_t index = 0; index < compact.size(); ++index) {
    auto changed = compact;
    changed[index] = static_cast<char>(static_cast<unsigned char>(changed[index]) ^ 0x80U);
    (void)split_compact_jws(changed);
    (void)base64url_decode(changed);
    ++cases;
  }

  const std::string json = "{\"root\":[\"scalar\",7]}";
  for (std::size_t index = 0; index < json.size(); ++index) {
    auto changed = json;
    changed[index] = '!';
    (void)parse_bounded_json(changed);
    ++cases;
  }

  const std::string presentation = compact + "~WyJzYWx0IiwibmFtZSIsImFsaWNlIl0"
                                      "~WyJzYWx0IiwxLCJyb2xlIiwidXNlciJd~";
  if (!build_native_witness(presentation)) return 2;
  for (std::size_t index = 0; index < presentation.size(); ++index) {
    auto changed = presentation;
    changed[index] = static_cast<char>(static_cast<unsigned char>(changed[index]) ^ 1U);
    (void)build_native_witness(changed);
    ++cases;
  }

  Limits tight{};
  tight.max_input = presentation.size() - 1;
  if (build_native_witness(presentation, tight)) return 3;
  if (build_native_witness(compact + "~AA~")) return 4;
  if (build_native_witness(compact + "~AA~AA~AA~")) return 5;

  std::cout << "reduced-parser-cases=" << cases
            << " boundaries=request,envelope,proof-preparser,compact-jws,base64url,"
               "bounded-json,two-slot-disclosures,local-status\n";
  return 0;
}
