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
