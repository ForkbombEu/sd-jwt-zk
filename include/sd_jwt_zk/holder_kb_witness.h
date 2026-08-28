#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "arrays/dense.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/holder_dense_layout.h"

namespace sd_jwt_zk {

using HolderKbFieldV1 = proofs::Fp256Base;

// Host values needed by the bounded KB component.  Construction parses and
// validates the compact KB-JWT once; the Dense encoder below is the only
// production definition of its private wire order.
struct HolderKbWitnessV1 {
  CompactJws compact;
  P256Key holder_key;
  P256Signature signature;
  RestrictedKbJwtPayload claims;
  std::array<std::uint8_t, 32> signing_digest{};
};

struct HolderKbPublicInputsV1 {
  std::array<proofs::GF2_128<>::Elt, 6> bridge_tags{};
  proofs::GF2_128<>::Elt bridge_challenge{};
  std::string audience;
  std::string nonce;
  std::uint64_t time_min{};
  std::uint64_t time_max{};
};

// These are the three values shared with the credential component.  The
// presentation hash field and its MAC bytes are derived from the exact
// sd_hash wires filled by FillHolderKbDenseWitnessV1, never reparsed by a
// diagnostic or proof harness.
struct HolderKbBridgeValuesV1 {
  std::array<HolderKbFieldV1::Elt, 3> fields{};
  std::array<std::array<std::uint8_t, 32>, 3> messages{};
};

using HolderKbBridgeWriterV1 = std::function<bool(
    proofs::DenseFiller<HolderKbFieldV1>&,
    const HolderKbBridgeValuesV1&)>;

Result<HolderKbWitnessV1> holder_kb_witness_from_compact_jwt_v1(
    std::string_view compact_jwt, std::string_view holder_x,
    std::string_view holder_y, const Limits& limits = {});

// Canonical host counterpart of HolderBridgeMacRelation::bind_digest.
HolderKbFieldV1::Elt holder_bridge_digest_field_v1(
    const std::array<std::uint8_t, 32>& digest);

// Fills public request/bridge values and the complete private KB relation in
// the exact order declared by BuildHolderKbCircuitV1.  The callback owns only
// bridge MAC advice and is invoked at the named bridge-advice boundary.
bool FillHolderKbDenseWitnessV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderDenseLayoutV1& layout,
    const HolderKbPublicInputsV1& public_inputs,
    const HolderKbWitnessV1& witness,
    const HolderKbBridgeWriterV1& bridge_writer);

// Fills only the verifier-visible prefix of BuildHolderKbCircuitV1.
bool FillHolderKbPublicInputsV1(
    proofs::Dense<HolderKbFieldV1>& inputs,
    const HolderKbPublicInputsV1& public_inputs);

}  // namespace sd_jwt_zk
