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
      layout.ranges.size() != 3 || layout.ranges.front().first != circuit->npub_in ||
      layout.ranges[0].first + layout.ranges[0].count != layout.ranges[1].first ||
      layout.ranges[1].first + layout.ranges[1].count != layout.ranges[2].first ||
      layout.ranges[2].first + layout.ranges[2].count != layout.total_inputs)
    throw std::runtime_error("credential dense layout did not track factory inputs");
  std::cout << "inputs=" << circuit->ninputs << " public=" << circuit->npub_in
            << " terms=" << circuit->nterms() << " compile-ms="
            << std::chrono::duration_cast<std::chrono::milliseconds>(done-start).count()
            << '\n';
}
