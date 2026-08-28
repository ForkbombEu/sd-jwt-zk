#include "sd_jwt_zk/registry_bearer_proof.h"
int main() {
  proofs::QuadCircuit<sd_jwt_zk::FlatBearerField> quad(proofs::p256_base);
  sd_jwt_zk::RegistryBearerDenseLayoutV1 layout;
  const auto circuit = sd_jwt_zk::BuildRegistryBearerCircuitV1(&quad, &layout);
  return circuit && layout.public_inputs == circuit->npub_in &&
                 layout.total_inputs == circuit->ninputs &&
                 layout.membership_first > layout.public_inputs
             ? 0
             : 1;
}
