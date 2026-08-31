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

#include "sd_jwt_zk/holder_presentation_circuit.h"

#include <iostream>

int main() {
  proofs::QuadCircuit<sd_jwt_zk::HolderPresentationField> quad(proofs::p256_base);
  const auto circuit = sd_jwt_zk::BuildHolderPresentationCircuitV1(&quad);
  if (!circuit || circuit->ninputs == 0 || circuit->npub_in !=
      sd_jwt_zk::kHolderPresentationPublicInputsV1 || quad.nquad_terms_ == 0)
    return 1;
  std::cout << "public-inputs=" << circuit->npub_in << '\n'
            << "total-inputs=" << circuit->ninputs << '\n'
            << "quad-terms=" << quad.nquad_terms_ << '\n';
  return 0;
}
