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

#include <array>
#include <cstddef>
#include <cstdint>

#include "sd_jwt_zk/api.h"

namespace sd_jwt_zk {
// EXPERIMENTAL/DEFERRED SUPPORT ONLY: these retained full-family identities
// exist for historical diagnostics. They are not the supported L6 proof gate,
// do not provide Swiss-profile conformance, and never widen flat V1 identities.
// Their capacities are public circuit-selection inputs and active lengths pad.
struct FullDisclosureFamilyV1 {
  static constexpr std::uint32_t kCapacity = 4096;
  static constexpr std::uint32_t kMaxTokens = 256;
  static constexpr std::uint32_t kMaxDepth = 8;
  static constexpr std::uint32_t kMaxDisclosures = 32;
};
struct FullDisclosureSmallV1 {
  static constexpr std::uint32_t kCapacity = 16;
  static constexpr std::uint32_t kMaxTokens = 8;
  static constexpr std::uint32_t kMaxDepth = 3;
  static constexpr std::uint32_t kMaxDisclosures = 32;
};
struct FullDisclosureMediumV1 {
  static constexpr std::uint32_t kCapacity = 24;
  static constexpr std::uint32_t kMaxTokens = 12;
  static constexpr std::uint32_t kMaxDepth = 5;
  static constexpr std::uint32_t kMaxDisclosures = 32;
};
// Explicit opt-in diagnostic family. Its two disclosure sources are a public
// circuit-capacity choice, never a witness-controlled fast path.
struct FullDisclosureFocusedV1 {
  static constexpr std::uint32_t kIssuerCapacity = 128;
  static constexpr std::uint32_t kDisclosureCapacity = 64;
  static constexpr std::uint32_t kMaxTokens = 13;
  static constexpr std::uint32_t kMaxDepth = 13;
  static constexpr std::uint32_t kLiveDisclosures = 2;
};
// A deliberately separate authenticated experimental diagnostic bucket. It
// retains the flat-bearer payload handoff, but fixes the disclosure graph to
// exactly one supplied disclosure.  It is not a substitute for the 32-slot
// family and its identity prevents a witness-controlled capacity downgrade.
struct FullDisclosureAuthenticatedFocusedV1 {
  static constexpr std::uint32_t kIssuerCapacity = 128;
  static constexpr std::uint32_t kDisclosureCapacity = 64;
  static constexpr std::uint32_t kMaxTokens = 13;
  static constexpr std::uint32_t kMaxDepth = 13;
  static constexpr std::uint32_t kLiveDisclosures = 1;
};
struct FullDisclosureWitnessLayoutV1 {
  std::uint32_t active_payload_bytes{};
  std::uint32_t active_disclosures{};
  std::array<std::uint32_t, FullDisclosureFamilyV1::kMaxDisclosures> disclosure_lengths{};
};
CircuitIdentity full_disclosure_circuit_identity_v1(Binding binding, Trust trust);
CircuitIdentity full_disclosure_authenticated_focused_circuit_identity_v1(
    Binding binding, Trust trust);
}  // namespace sd_jwt_zk
