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

#include <string_view>

#include "sd_jwt_zk/flat_bearer_proof.h"
#include "sd_jwt_zk/holder_kb_witness.h"

namespace sd_jwt_zk {

struct HolderCredentialWitnessV1 {
  FlatBearerWitness credential;
  std::string compact_issuer;
  std::array<std::uint8_t, 32> presentation_digest{};
};

struct HolderCredentialPublicInputsV1 {
  std::array<proofs::GF2_128<>::Elt, 6> bridge_tags{};
  proofs::GF2_128<>::Elt bridge_challenge{};
  bool policy_result{};
  bool status_required{};
  std::array<std::uint8_t, 32> status_context{};
  std::array<std::uint8_t, 32> status_commitment{};
};


Result<HolderCredentialWitnessV1> holder_credential_witness_from_presentation_v1(
    std::string_view presentation, const P256Key& issuer_key,
    const Limits& limits = {});

bool FillHolderCredentialDenseWitnessV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderDenseLayoutV1& layout,
    const HolderCredentialPublicInputsV1& public_inputs,
    const HolderCredentialWitnessV1& witness,
    const HolderKbBridgeWriterV1& bridge_writer);

// Fills only the verifier-visible prefix of BuildHolderCredentialCircuitV1.
// This is the canonical public-wire encoder used by the production pair
// verifier; it deliberately has no access to credential witness material.
bool FillHolderCredentialPublicInputsV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderCredentialPublicInputsV1& public_inputs,
    const P256Key& issuer_key);


}  // namespace sd_jwt_zk
