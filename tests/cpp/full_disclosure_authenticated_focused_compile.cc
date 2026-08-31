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

#include <cstring>
#include <iostream>

#include "ec/p256.h"
#include "sd_jwt_zk/full_disclosure_circuit.h"
#include "sd_jwt_zk/full_disclosure_family.h"

template <sd_jwt_zk::Binding Binding, sd_jwt_zk::Trust Trust>
int compile() {
  proofs::QuadCircuit<proofs::Fp256Base> q(proofs::p256_base);
  auto circuit =
      sd_jwt_zk::BuildFullDisclosureAuthenticatedFocusedCircuitV1<Binding,
                                                                    Trust>(&q);
  const auto identity =
      sd_jwt_zk::full_disclosure_authenticated_focused_circuit_identity_v1(
          Binding, Trust);
  if (circuit->nterms() == 0 || identity.capacity != 128) return 1;
  std::cout << "terms=" << circuit->nterms() << " inputs=" << circuit->ninputs
            << " focused_capacity=" << identity.capacity << '\n';
  return 0;
}

int main(int argc, char** argv) {
  const char* lane = argc > 1 ? argv[1] : "bearer-exact";
  if (std::strcmp(lane, "bearer-exact") == 0)
    return compile<sd_jwt_zk::Binding::bearer, sd_jwt_zk::Trust::exact_key>();
  if (std::strcmp(lane, "holder-exact") == 0)
    return compile<sd_jwt_zk::Binding::holder_bound,
                   sd_jwt_zk::Trust::exact_key>();
  return 2;
}
