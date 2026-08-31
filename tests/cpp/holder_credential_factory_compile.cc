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
#include <stdexcept>

#include "ec/p256.h"
#include "sd_jwt_zk/holder_credential_circuit.h"
#include "sd_jwt_zk/holder_kb_circuit.h"

int main() {
  const auto start = std::chrono::steady_clock::now();
  proofs::QuadCircuit<sd_jwt_zk::HolderCredentialField> quad(proofs::p256_base);
  sd_jwt_zk::HolderDenseLayoutV1 layout;
  const auto circuit = sd_jwt_zk::BuildHolderCredentialCircuitV1(&quad, &layout);
  const auto done = std::chrono::steady_clock::now();
  if (!circuit || circuit->ninputs == 0 || circuit->npub_in == 0)
    throw std::runtime_error("credential factory did not compile");
  if (layout.public_inputs != circuit->npub_in || layout.total_inputs != circuit->ninputs ||
      layout.ranges.size() != 5 || layout.ranges.front().first != circuit->npub_in)
    throw std::runtime_error("credential dense layout did not track factory inputs");
  for (std::size_t i = 1; i < layout.ranges.size(); ++i)
    if (layout.ranges[i - 1].first + layout.ranges[i - 1].count !=
        layout.ranges[i].first)
      throw std::runtime_error("credential dense layout range gap");
  if (layout.ranges.back().first + layout.ranges.back().count !=
      layout.total_inputs)
    throw std::runtime_error("credential dense layout final range mismatch");
  std::cout << "inputs=" << circuit->ninputs << " public=" << circuit->npub_in
            << " terms=" << circuit->nterms() << " compile-ms="
            << std::chrono::duration_cast<std::chrono::milliseconds>(done-start).count()
            << '\n';
}
