#pragma once

#include <string_view>

#include "sd_jwt_zk/flat_bearer_proof.h"
#include "sd_jwt_zk/holder_kb_witness.h"
#include "sd_jwt_zk/issuer_registry.h"

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
};

struct HolderRegistryCredentialWitnessV1 {
  HolderCredentialWitnessV1 credential;
  IssuerRegistryPathV1 authorization;
};

struct HolderRegistryCredentialPublicInputsV1 {
  HolderCredentialPublicInputsV1 holder;
  RegistryTrustContextV1 trust;
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

Result<HolderRegistryCredentialWitnessV1>
holder_registry_credential_witness_from_presentation_v1(
    std::string_view presentation, const IssuerRegistryPathV1& authorization,
    const Limits& limits = {});
bool FillHolderRegistryCredentialDenseWitnessV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderDenseLayoutV1& registry_layout,
    const HolderDenseLayoutV1& exact_layout,
    const HolderRegistryCredentialPublicInputsV1& public_inputs,
    const HolderRegistryCredentialWitnessV1& witness,
    const HolderKbBridgeWriterV1& bridge_writer);
bool FillHolderRegistryCredentialPublicInputsV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderRegistryCredentialPublicInputsV1& public_inputs);

}  // namespace sd_jwt_zk
