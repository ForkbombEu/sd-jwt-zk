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
      layout.ranges.size() != 2 || layout.ranges.front().first != circuit->npub_in ||
      layout.ranges[0].first + layout.ranges[0].count != layout.ranges[1].first ||
      layout.ranges[1].first + layout.ranges[1].count != layout.total_inputs)
    return 1;
  std::cout << "inputs=" << circuit->ninputs << " public=" << circuit->npub_in
            << " terms=" << circuit->nterms() << " compile-ms="
            << std::chrono::duration_cast<std::chrono::milliseconds>(done-start).count()
            << '\n';
}
