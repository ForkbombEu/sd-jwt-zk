#pragma once

#include <memory>

#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/holder_credential_witness.h"
#include "sd_jwt_zk/holder_kb_witness.h"

namespace sd_jwt_zk {

// Frozen identities for the first bounded two-proof holder family.  The
// request identity is the credential component identity; the envelope carries
// the distinct KB identity alongside it.
CircuitIdentity holder_bound_credential_circuit_identity_v1();
CircuitIdentity holder_bound_kb_circuit_identity_v1();
Bytes holder_bound_policy_v1();
Bytes holder_bound_true_policy_result_v1();
HolderBoundVerifierPolicyV1 holder_bound_verifier_policy_v1(Request request);

struct HolderBoundCircuitMetricsV1 {
  std::size_t credential_public_inputs{};
  std::size_t credential_private_inputs{};
  std::size_t credential_terms{};
  std::size_t kb_public_inputs{};
  std::size_t kb_private_inputs{};
  std::size_t kb_terms{};
};
HolderBoundCircuitMetricsV1 holder_bound_circuit_metrics_v1();

// Concrete installed-library adapter for the ordered callback protocol in
// api.h.  It owns the real circuits, Dense witnesses, commitments and
// component transcript forks; callers never reproduce bridge wire order.
class HolderBoundCircuitProverV1 final : public HolderBoundProofProverV1 {
 public:
  HolderBoundCircuitProverV1(
      const HolderBoundVerifierPolicyV1& policy,
      const HolderCredentialWitnessV1& credential,
      const HolderKbWitnessV1& kb);
  ~HolderBoundCircuitProverV1() override;
  HolderBoundCircuitProverV1(HolderBoundCircuitProverV1&&) noexcept;
  HolderBoundCircuitProverV1& operator=(HolderBoundCircuitProverV1&&) noexcept;
  HolderBoundCircuitProverV1(const HolderBoundCircuitProverV1&) = delete;
  HolderBoundCircuitProverV1& operator=(const HolderBoundCircuitProverV1&) =
      delete;

  Result<Bytes> commit(HolderComponent component,
                       const CircuitIdentity& identity,
                       const Request& request) override;
  Result<Bytes> bridge_public(
      const Request& request, const CircuitIdentity& credential_identity,
      const CircuitIdentity& kb_identity,
      const Bytes& credential_commitment,
      const Bytes& kb_commitment) override;
  Result<Bytes> prove(HolderComponent component,
                      const CircuitIdentity& identity,
                      const Request& request,
                      const Bytes& credential_commitment,
                      const Bytes& kb_commitment,
                      const Bytes& bridge_public) override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class HolderBoundCircuitVerifierV1 final : public HolderBoundProofVerifierV1 {
 public:
  bool verify(HolderComponent component, const CircuitIdentity& identity,
              const Request& request,
              const Bytes& credential_commitment,
              const Bytes& kb_commitment,
              const Bytes& bridge_public, const Bytes& proof) override;
};

Result<HolderBoundEnvelope> prove_holder_bound_v1(
    const HolderBoundVerifierPolicyV1& policy,
    const HolderCredentialWitnessV1& credential,
    const HolderKbWitnessV1& kb, const Limits& limits = {});
Result<HolderBoundEnvelope> prove_holder_bound_v1(
    const HolderBoundVerifierPolicyV1& policy,
    const HolderCredentialWitnessV1& credential,
    const HolderKbWitnessV1& kb,
    const StatusMembershipWitnessV1& status_witness,
    const Limits& limits = {});
Result<bool> verify_holder_bound_v1(
    const HolderBoundEnvelope& envelope,
    const HolderBoundVerifierPolicyV1& expected, std::uint64_t now,
    HolderBoundReplayStoreV1& replay_store, const Limits& limits = {});

}  // namespace sd_jwt_zk
