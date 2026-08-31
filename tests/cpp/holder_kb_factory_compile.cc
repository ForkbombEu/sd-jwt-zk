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

#include <chrono>
#include <iostream>

#include "ec/p256.h"
#include "sd_jwt_zk/holder_kb_circuit.h"

int main() {
  const auto start = std::chrono::steady_clock::now();
  proofs::QuadCircuit<sd_jwt_zk::HolderCredentialField> quad(proofs::p256_base);
  sd_jwt_zk::HolderDenseLayoutV1 layout;
  const auto circuit = sd_jwt_zk::BuildHolderKbCircuitV1(&quad, &layout);
  const auto done = std::chrono::steady_clock::now();
  if (!circuit || circuit->ninputs == 0 || circuit->npub_in == 0) return 1;
  if (layout.public_inputs != circuit->npub_in || layout.total_inputs != circuit->ninputs ||
      layout.ranges.size() != 3 || layout.ranges.front().first != circuit->npub_in ||
      layout.ranges[0].first + layout.ranges[0].count != layout.ranges[1].first ||
      layout.ranges[1].first + layout.ranges[1].count != layout.ranges[2].first ||
      layout.ranges[2].first + layout.ranges[2].count != layout.total_inputs)
    return 1;
  std::cout << "inputs=" << circuit->ninputs << " public=" << circuit->npub_in
            << " terms=" << circuit->nterms() << " compile-ms="
            << std::chrono::duration_cast<std::chrono::milliseconds>(done-start).count()
            << '\n';
}
