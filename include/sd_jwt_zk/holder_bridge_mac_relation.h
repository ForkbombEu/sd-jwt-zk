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
#include <stdexcept>

#include "circuits/logic/bit_plucker.h"
#include "circuits/mac/mac_circuit.h"
#include "ec/p256.h"

namespace sd_jwt_zk {

// The P-256 half of the ordered holder bridge.  The caller makes tags and av
// public before switching the QuadCircuit to private inputs, then allocates
// the three witness values and these MAC witnesses privately.  `av` is only
// derived after both proof commitments have been absorbed by the shared
// transcript; see holder_two_proof_mac_bridge.cc for that protocol.
template <class LogicCircuit>
class HolderBridgeMacRelation {
 public:
  using Field = typename LogicCircuit::Field;
  using EltW = typename LogicCircuit::EltW;
  using v128 = typename LogicCircuit::v128;
  using v256 = typename LogicCircuit::v256;
  using Mac = proofs::MAC<LogicCircuit, proofs::BitPlucker<LogicCircuit, 2>>;
  static constexpr std::size_t kValues = 3;
  static constexpr std::size_t kTags = kValues * 2;
  // BitPlucker<2> allocates 64 packed slots for each a_p half and 128
  // packed slots for the 256-bit message, hence 256 per bridge value.
  static constexpr std::size_t kWitnessSlotsPerValue = 256;

  struct Witness {
    std::array<typename Mac::Witness, kValues> mac{};
    void input(const LogicCircuit& logic) {
      for (auto& value : mac) value.input(logic);
    }
  };

  explicit HolderBridgeMacRelation(const LogicCircuit& logic) : logic_(logic) {}

  // Binds a SHA-256 bit digest to one canonical P-256-field message.  The
  // relation rejects the negligible set of 256-bit strings outside the P-256
  // base-field range rather than silently reducing them, which would weaken
  // the cross-proof equality statement.
  EltW bind_digest(const v256& digest) const {
    const auto message = logic_.eltw_input();
    EltW packed = logic_.konst(logic_.zero());
    typename Field::Elt two = logic_.one();
    for (std::size_t i = 0; i < digest.size(); ++i) {
      packed = logic_.axpy(packed, two, logic_.eval(digest[i]));
      logic_.f_.add(two, two);
    }
    logic_.assert_eq(message, packed);
    return message;
  }

  void assert_valid(const std::array<v128, kTags>& tags, const v128& av,
                    const EltW& holder_x, const EltW& holder_y,
                    const EltW& presentation_hash,
                    const Witness& witness,
                    std::size_t value_count = kValues) const {
    if (value_count > kValues) throw std::invalid_argument("bridge value count");
    const std::array<EltW, kValues> values{holder_x, holder_y,
                                             presentation_hash};
    const typename Field::N bound(proofs::Fp256Reduce::kModulus);
    Mac mac(logic_);
    for (std::size_t i = 0; i < value_count; ++i)
      mac.verify_mac(values[i], &tags[i * 2], av, witness.mac[i], bound);
  }

 private:
  const LogicCircuit& logic_;
};
}  // namespace sd_jwt_zk
