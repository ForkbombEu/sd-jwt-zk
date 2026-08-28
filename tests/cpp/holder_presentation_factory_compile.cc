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
