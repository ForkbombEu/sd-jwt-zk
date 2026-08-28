#include "sd_jwt_zk/flat_bearer_proof.h"
#include <iostream>

int main() {
  proofs::QuadCircuit<sd_jwt_zk::FlatBearerField> quad(proofs::p256_base);
  const auto circuit = sd_jwt_zk::BuildFlatBearerCircuitV1(&quad);
  if (!circuit) return 1;
  std::cout << "public-inputs=" << circuit->npub_in << '\n'
            << "total-inputs=" << circuit->ninputs << '\n'
            << "quad-terms=" << quad.nquad_terms_ << '\n';
  return circuit->npub_in == sd_jwt_zk::kFlatBearerPublicInputsV1 &&
                 circuit->ninputs == sd_jwt_zk::kFlatBearerDenseInputsV1
             ? 0
             : 1;
}
