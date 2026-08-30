#include "sd_jwt_zk/full_disclosure_circuit.h"
#include "ec/p256.h"
#include <cstring>
#include <iomanip>
#include <iostream>

template <sd_jwt_zk::Binding Binding, sd_jwt_zk::Trust Trust>
int compile(bool medium) {
  proofs::QuadCircuit<proofs::Fp256Base> q(proofs::p256_base);
  auto c = medium
      ? sd_jwt_zk::BuildFullDisclosureMediumCircuitV1<Binding, Trust>(&q)
      : sd_jwt_zk::BuildFullDisclosureCircuitV1<Binding, Trust, 32>(&q);
  std::cout << "terms=" << c->nterms() << " inputs=" << c->ninputs
            << " circuit_id=";
  for (std::size_t i = 0; i < 32; ++i)
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<unsigned>(c->id[i]);
  std::cout << '\n';
  return c->nterms() > 0 ? 0 : 1;
}

int main(int argc, char** argv) {
  const char* const lane = argc > 1 ? argv[1] : "bearer-exact";
  const bool medium = argc > 2 && std::strcmp(argv[2], "medium") == 0;
  if (std::strcmp(lane, "bearer-exact") == 0)
    return compile<sd_jwt_zk::Binding::bearer, sd_jwt_zk::Trust::exact_key>(medium);
  if (std::strcmp(lane, "holder-exact") == 0)
    return compile<sd_jwt_zk::Binding::holder_bound, sd_jwt_zk::Trust::exact_key>(medium);
  return 2;
}
