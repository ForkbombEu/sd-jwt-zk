#include "sd_jwt_zk/holder_bound_proof.h"

#include <algorithm>
#include <array>
#include <exception>
#include <utility>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sd_jwt_zk/holder_credential_circuit.h"
#include "sd_jwt_zk/holder_kb_circuit.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace sd_jwt_zk {
namespace {

constexpr std::size_t kRate = 4;
constexpr std::size_t kQueries = 32;
using Field = HolderCredentialField;
using Field2 = proofs::Fp2<Field>;
using Fft = proofs::FFTExtConvolutionFactory<Field, Field2>;
using ReedSolomon = proofs::ReedSolomonFactory<Field, Fft>;
using GF = proofs::GF2_128<>;

struct RuntimeV1 {
  Field2 extension{proofs::p256_base};
  Field2::Elt omega;
  Fft fft;
  ReedSolomon reed_solomon;
  std::unique_ptr<proofs::Circuit<Field>> credential_circuit;
  std::unique_ptr<proofs::Circuit<Field>> kb_circuit;
  HolderDenseLayoutV1 credential_layout;
  HolderDenseLayoutV1 kb_layout;

  RuntimeV1()
      : omega(extension.of_string(
            "112649224146410281873500457609690258373018840430489408729223714171582664680802",
            "84087994358540907695740461427818660560182168997182378749313018254450460212908")),
        fft(proofs::p256_base, extension, omega, 1ull << 31),
        reed_solomon(fft, proofs::p256_base) {
    proofs::QuadCircuit<Field> credential_quad(proofs::p256_base);
    credential_circuit = BuildHolderCredentialCircuitV1(
        &credential_quad, &credential_layout);
    proofs::QuadCircuit<Field> kb_quad(proofs::p256_base);
    kb_circuit = BuildHolderKbCircuitV1(&kb_quad, &kb_layout);
  }
};

RuntimeV1& runtime_v1() {
  static RuntimeV1 runtime;
  return runtime;
}

bool identity_equal(const CircuitIdentity& left,
                    const CircuitIdentity& right) {
  return left.binding == right.binding && left.trust == right.trust &&
         left.capacity == right.capacity &&
         left.circuit_digest == right.circuit_digest &&
         left.field == right.field && left.ligero_rate == right.ligero_rate &&
         left.query_count == right.query_count;
}

bool request_equal(const Request& left, const Request& right) {
  const auto encoded_left = encode_request(left);
  const auto encoded_right = encode_request(right);
  return encoded_left && encoded_right &&
         *encoded_left.value == *encoded_right.value;
}

std::optional<P256Key> request_issuer_key(const Request& request) {
  if (request.trust_public.size() != 64) return std::nullopt;
  P256Key key{};
  std::copy_n(request.trust_public.begin(), 32, key.x.begin());
  std::copy_n(request.trust_public.begin() + 32, 32, key.y.begin());
  return key;
}

void append_u32(Bytes& output, std::size_t value);

bool valid_policy(const HolderBoundVerifierPolicyV1& policy) {
  const auto issuer_key = request_issuer_key(policy.request);
  const bool exact = identity_equal(
                         policy.credential_identity,
                         holder_bound_credential_circuit_identity_v1()) &&
                     identity_equal(policy.kb_identity,
                                    holder_bound_kb_circuit_identity_v1()) &&
                     issuer_key.has_value();
  const auto status = policy.request.status_public.empty()
                          ? Result<StatusPolicyV1>::fail(
                                ErrorCode::unsupported, "status absent")
                          : decode_status_policy_v1(policy.request.status_public);
  const bool valid_status = policy.request.status_public.empty() ||
                            (status && issuer_key &&
                             status.value->snapshot.issuer ==
                                 status_issuer_v1(*issuer_key));
  return exact &&
         identity_equal(policy.request.identity,
                        policy.credential_identity) &&
         !policy.request.audience.empty() && !policy.request.nonce.empty() &&
         policy.request.policy == holder_bound_policy_v1() &&
         policy.request.policy_result == holder_bound_true_policy_result_v1() &&
         valid_status &&
         static_cast<bool>(encode_request(policy.request));
}

void append_u32(Bytes& output, std::size_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 24));
  output.push_back(static_cast<std::uint8_t>(value >> 16));
  output.push_back(static_cast<std::uint8_t>(value >> 8));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_field(Bytes& output, const Bytes& value) {
  append_u32(output, value.size());
  output.insert(output.end(), value.begin(), value.end());
}

Bytes pair_manifest(const HolderBoundVerifierPolicyV1& policy) {
  static constexpr char kDomain[] = "sd-jwt-zk/holder-pair/v1";
  static constexpr char kSchema[] =
      "credential-before-kb;bridge=gf2-128-mac(x,y,sd_hash);forks=v1";
  const auto credential = encode_identity(policy.credential_identity);
  const auto kb = encode_identity(policy.kb_identity);
  const auto request = encode_request(policy.request);
  if (!credential || !kb || !request) return {};
  Bytes manifest(kDomain, kDomain + sizeof(kDomain) - 1);
  append_field(manifest, Bytes(kSchema, kSchema + sizeof(kSchema) - 1));
  append_field(manifest, *credential.value);
  append_field(manifest, *kb.value);
  append_field(manifest, *request.value);
  return manifest;
}

void fork_component(proofs::Transcript& transcript,
                    HolderComponent component) {
  static constexpr char kCredential[] =
      "sd-jwt-zk/holder-pair/v1/proof/credential";
  static constexpr char kKb[] = "sd-jwt-zk/holder-pair/v1/proof/kb";
  if (component == HolderComponent::credential)
    transcript.write(reinterpret_cast<const std::uint8_t*>(kCredential),
                     sizeof(kCredential) - 1);
  else
    transcript.write(reinterpret_cast<const std::uint8_t*>(kKb),
                     sizeof(kKb) - 1);
}

Bytes commitment_bytes(const proofs::ZkProof<Field>& proof) {
  return Bytes(proof.com.root.data,
               proof.com.root.data + proofs::Digest::kLength);
}

bool set_commitment(proofs::ZkProof<Field>& proof, const Bytes& bytes) {
  if (bytes.size() != proofs::Digest::kLength) return false;
  std::copy(bytes.begin(), bytes.end(), proof.com.root.data);
  return true;
}

struct BridgeState {
  std::array<std::array<GF::Elt, 2>, 3> randomness{};
  HolderKbBridgeValuesV1 values{};
  bool captured{};

  HolderKbBridgeWriterV1 writer() {
    return [this](proofs::DenseFiller<Field>& filler,
                  const HolderKbBridgeValuesV1& incoming) {
      if (!captured) {
        values = incoming;
        captured = true;
      } else if (values.fields != incoming.fields ||
                 values.messages != incoming.messages) {
        return false;
      }
      GF gf;
      for (std::size_t i = 0; i < randomness.size(); ++i) {
        proofs::MacWitness<Field> witness(proofs::p256_base, gf);
        witness.compute_witness(randomness[i].data(),
                                values.messages[i].data());
        witness.fill_witness(filler);
      }
      return true;
    };
  }

  std::array<GF::Elt, 6> tags(const GF::Elt& challenge) const {
    std::array<GF::Elt, 6> output{};
    proofs::MACReference<GF> mac;
    for (std::size_t i = 0; i < randomness.size(); ++i)
      mac.compute(&output[i * 2], challenge, randomness[i].data(),
                  const_cast<std::uint8_t*>(values.messages[i].data()));
    return output;
  }
};

bool decode_bridge(const Bytes& bytes,
                   std::array<GF::Elt, 6>* tags,
                   GF::Elt* challenge) {
  if (bytes.size() != 7 * GF::kBytes) return false;
  GF gf;
  for (std::size_t i = 0; i < tags->size(); ++i) {
    const auto value = gf.of_bytes_field(bytes.data() + i * GF::kBytes);
    if (!value) return false;
    (*tags)[i] = *value;
  }
  const auto value = gf.of_bytes_field(bytes.data() + 6 * GF::kBytes);
  if (!value) return false;
  *challenge = *value;
  return true;
}

Bytes encode_bridge(const std::array<GF::Elt, 6>& tags,
                    const GF::Elt& challenge) {
  Bytes output(7 * GF::kBytes);
  GF gf;
  for (std::size_t i = 0; i < tags.size(); ++i)
    gf.to_bytes_field(output.data() + i * GF::kBytes, tags[i]);
  gf.to_bytes_field(output.data() + 6 * GF::kBytes, challenge);
  return output;
}

}  // namespace

CircuitIdentity holder_bound_credential_circuit_identity_v1() {
  CircuitIdentity identity{Binding::holder_bound, Trust::exact_key, 514, {},
                           "p256-base", kRate, kQueries};
  const auto& circuit = *runtime_v1().credential_circuit;
  std::copy_n(circuit.id, identity.circuit_digest.size(),
              identity.circuit_digest.begin());
  return identity;
}

CircuitIdentity holder_bound_kb_circuit_identity_v1() {
  CircuitIdentity identity{Binding::holder_bound, Trust::exact_key, 216, {},
                           "p256-base", kRate, kQueries};
  const auto& circuit = *runtime_v1().kb_circuit;
  std::copy_n(circuit.id, identity.circuit_digest.size(),
              identity.circuit_digest.begin());
  return identity;
}


Bytes holder_bound_policy_v1() {
  static constexpr char kPolicy[] = "age_over:eq:true";
  return Bytes(kPolicy, kPolicy + sizeof(kPolicy) - 1);
}

Bytes holder_bound_true_policy_result_v1() { return Bytes{1}; }

HolderBoundVerifierPolicyV1 holder_bound_verifier_policy_v1(Request request) {
  const auto credential = holder_bound_credential_circuit_identity_v1();
  const auto kb = holder_bound_kb_circuit_identity_v1();
  request.identity = credential;
  return HolderBoundVerifierPolicyV1{std::move(request), credential, kb};
}


HolderBoundCircuitMetricsV1 holder_bound_circuit_metrics_v1() {
  const auto& runtime = runtime_v1();
  return HolderBoundCircuitMetricsV1{
      runtime.credential_circuit->npub_in,
      runtime.credential_circuit->ninputs -
          runtime.credential_circuit->npub_in,
      runtime.credential_circuit->nterms(), runtime.kb_circuit->npub_in,
      runtime.kb_circuit->ninputs - runtime.kb_circuit->npub_in,
      runtime.kb_circuit->nterms()};
}


struct HolderBoundCircuitProverV1::Impl {
  HolderBoundVerifierPolicyV1 policy;
  HolderCredentialWitnessV1 credential_witness;
  HolderKbWitnessV1 kb_witness;
  RuntimeV1& runtime;
  proofs::Circuit<Field>* credential_circuit{};
  HolderDenseLayoutV1* credential_layout{};
  proofs::Dense<Field> credential_dense;
  proofs::Dense<Field> kb_dense;
  HolderCredentialPublicInputsV1 credential_public{};
  HolderKbPublicInputsV1 kb_public{};
  BridgeState bridge;
  proofs::SecureRandomEngine random;
  std::unique_ptr<proofs::ZkProof<Field>> credential_proof;
  std::unique_ptr<proofs::ZkProof<Field>> kb_proof;
  std::unique_ptr<proofs::ZkProver<Field, ReedSolomon>> credential_prover;
  std::unique_ptr<proofs::ZkProver<Field, ReedSolomon>> kb_prover;
  std::unique_ptr<proofs::Transcript> shared_transcript;
  Bytes credential_commitment;
  Bytes kb_commitment;
  Bytes bridge_bytes;
  int phase{};
  bool valid{};
  const char* invalid_reason{"uninitialized holder prover"};

  Impl(const HolderBoundVerifierPolicyV1& policy_in,
       const HolderCredentialWitnessV1& credential_in,
       const HolderKbWitnessV1& kb_in)
      : policy(policy_in),
        credential_witness(credential_in),
        kb_witness(kb_in),
        runtime(runtime_v1()),
        credential_circuit(runtime.credential_circuit.get()),
        credential_layout(&runtime.credential_layout),
        credential_dense(1, credential_circuit->ninputs),
        kb_dense(1, runtime.kb_circuit->ninputs) {
    try {
      if (!valid_policy(policy)) { invalid_reason = "invalid holder policy"; return; }
      const auto issuer = request_issuer_key(policy.request);
      const auto sd_hash = base64url_decode(kb_witness.claims.sd_hash, 64);
      if ((!issuer || issuer->x != credential_witness.credential.issuer_key.x ||
            issuer->y != credential_witness.credential.issuer_key.y) ||
          !credential_witness.credential.payload.holder_key ||
          credential_witness.credential.payload.holder_key->x !=
              kb_witness.holder_key.x ||
          credential_witness.credential.payload.holder_key->y !=
              kb_witness.holder_key.y ||
          !sd_hash || sd_hash.value->size() != 32 ||
          !std::equal(sd_hash.value->begin(), sd_hash.value->end(),
                      credential_witness.presentation_digest.begin()))
        { invalid_reason = "holder witness binding failed"; return; }
      proofs::MACReference<GF> mac;
      for (auto& randomness : bridge.randomness)
        mac.sample(randomness.data(), randomness.size(), &random);
      credential_public.policy_result = true;
      kb_public.audience = policy.request.audience;
      kb_public.nonce = policy.request.nonce;
      kb_public.time_min = policy.request.time_min;
      kb_public.time_max = policy.request.time_max;
      const bool credential_filled = FillHolderCredentialDenseWitnessV1(
          credential_dense, *credential_layout, credential_public,
          credential_witness, bridge.writer());
      if (!credential_filled) {
        invalid_reason = "holder credential dense witness failed";
        return;
      }
      if (!FillHolderKbDenseWitnessV1(kb_dense, runtime.kb_layout, kb_public,
                                      kb_witness, bridge.writer())) {
        invalid_reason = "holder KB dense witness failed";
        return;
      }
      if (!bridge.captured) {
        invalid_reason = "holder bridge capture failed";
        return;
      }
      credential_proof = std::make_unique<proofs::ZkProof<Field>>(
          *credential_circuit, kRate, kQueries);
      kb_proof = std::make_unique<proofs::ZkProof<Field>>(
          *runtime.kb_circuit, kRate, kQueries);
      credential_prover =
          std::make_unique<proofs::ZkProver<Field, ReedSolomon>>(
              *credential_circuit, proofs::p256_base,
              runtime.reed_solomon);
      kb_prover = std::make_unique<proofs::ZkProver<Field, ReedSolomon>>(
          *runtime.kb_circuit, proofs::p256_base, runtime.reed_solomon);
      const auto manifest = pair_manifest(policy);
      if (manifest.empty()) { invalid_reason = "holder manifest failed"; return; }
      shared_transcript = std::make_unique<proofs::Transcript>(
          manifest.data(), manifest.size());
      valid = true;
      invalid_reason = "";
    } catch (const std::exception&) {
      valid = false;
    }
  }
};

HolderBoundCircuitProverV1::HolderBoundCircuitProverV1(
    const HolderBoundVerifierPolicyV1& policy,
    const HolderCredentialWitnessV1& credential,
    const HolderKbWitnessV1& kb)
    : impl_(std::make_unique<Impl>(policy, credential, kb)) {}

HolderBoundCircuitProverV1::~HolderBoundCircuitProverV1() = default;
HolderBoundCircuitProverV1::HolderBoundCircuitProverV1(
    HolderBoundCircuitProverV1&&) noexcept = default;
HolderBoundCircuitProverV1& HolderBoundCircuitProverV1::operator=(
    HolderBoundCircuitProverV1&&) noexcept = default;

Result<Bytes> HolderBoundCircuitProverV1::commit(
    HolderComponent component, const CircuitIdentity& identity,
    const Request& request) {
  if (!impl_ || !impl_->valid || !request_equal(request, impl_->policy.request))
    return Result<Bytes>::fail(ErrorCode::malformed,
                               impl_ && !impl_->valid ? impl_->invalid_reason
                                                     : "invalid holder circuit prover state");
  if (component == HolderComponent::credential && impl_->phase == 0 &&
      identity_equal(identity, impl_->policy.credential_identity)) {
    impl_->credential_prover->commit(*impl_->credential_proof,
                                     impl_->credential_dense,
                                     *impl_->shared_transcript, impl_->random);
    impl_->credential_commitment = commitment_bytes(*impl_->credential_proof);
    impl_->phase = 1;
    return Result<Bytes>::ok(impl_->credential_commitment);
  }
  if (component == HolderComponent::kb && impl_->phase == 1 &&
      identity_equal(identity, impl_->policy.kb_identity)) {
    impl_->kb_prover->commit(*impl_->kb_proof, impl_->kb_dense,
                             *impl_->shared_transcript, impl_->random);
    impl_->kb_commitment = commitment_bytes(*impl_->kb_proof);
    impl_->phase = 2;
    return Result<Bytes>::ok(impl_->kb_commitment);
  }
  return Result<Bytes>::fail(ErrorCode::malformed,
                             "holder commitments are out of order");
}

Result<Bytes> HolderBoundCircuitProverV1::bridge_public(
    const Request& request, const CircuitIdentity& credential_identity,
    const CircuitIdentity& kb_identity,
    const Bytes& credential_commitment, const Bytes& kb_commitment) {
  if (!impl_ || !impl_->valid || impl_->phase != 2 ||
      !request_equal(request, impl_->policy.request) ||
      !identity_equal(credential_identity, impl_->policy.credential_identity) ||
      !identity_equal(kb_identity, impl_->policy.kb_identity) ||
      credential_commitment != impl_->credential_commitment ||
      kb_commitment != impl_->kb_commitment)
    return Result<Bytes>::fail(ErrorCode::malformed,
                               "invalid holder bridge inputs");
  std::array<std::uint8_t, GF::kBytes> challenge_bytes{};
  impl_->shared_transcript->bytes(challenge_bytes.data(),
                                  challenge_bytes.size());
  GF gf;
  const auto challenge = gf.of_bytes_field(challenge_bytes.data());
  if (!challenge)
    return Result<Bytes>::fail(ErrorCode::malformed,
                               "invalid holder bridge challenge");
  const auto tags = impl_->bridge.tags(*challenge);
  impl_->credential_public.bridge_tags = tags;
  impl_->credential_public.bridge_challenge = *challenge;
  impl_->kb_public.bridge_tags = tags;
  impl_->kb_public.bridge_challenge = *challenge;
  const bool credential_filled = FillHolderCredentialDenseWitnessV1(
      impl_->credential_dense, *impl_->credential_layout,
      impl_->credential_public, impl_->credential_witness,
      impl_->bridge.writer());
  if (!credential_filled ||
      !FillHolderKbDenseWitnessV1(
          impl_->kb_dense, impl_->runtime.kb_layout, impl_->kb_public,
          impl_->kb_witness, impl_->bridge.writer()))
    return Result<Bytes>::fail(ErrorCode::malformed,
                               "holder bridge witness refill failed");
  impl_->bridge_bytes = encode_bridge(tags, *challenge);
  impl_->phase = 3;
  return Result<Bytes>::ok(impl_->bridge_bytes);
}

Result<Bytes> HolderBoundCircuitProverV1::prove(
    HolderComponent component, const CircuitIdentity& identity,
    const Request& request, const Bytes& credential_commitment,
    const Bytes& kb_commitment, const Bytes& bridge_public) {
  if (!impl_ || !impl_->valid || !request_equal(request, impl_->policy.request) ||
      credential_commitment != impl_->credential_commitment ||
      kb_commitment != impl_->kb_commitment ||
      bridge_public != impl_->bridge_bytes)
    return Result<Bytes>::fail(ErrorCode::malformed,
                               "invalid holder proof inputs");
  try {
    Bytes proof_bytes;
    auto transcript = impl_->shared_transcript->clone();
    fork_component(transcript, component);
    if (component == HolderComponent::credential && impl_->phase == 3 &&
        identity_equal(identity, impl_->policy.credential_identity) &&
        impl_->credential_prover->prove(*impl_->credential_proof,
                                        impl_->credential_dense, transcript)) {
      impl_->credential_proof->write(proof_bytes, proofs::p256_base);
      impl_->phase = 4;
      return Result<Bytes>::ok(std::move(proof_bytes));
    }
    if (component == HolderComponent::kb && impl_->phase == 4 &&
        identity_equal(identity, impl_->policy.kb_identity) &&
        impl_->kb_prover->prove(*impl_->kb_proof, impl_->kb_dense,
                                transcript)) {
      impl_->kb_proof->write(proof_bytes, proofs::p256_base);
      impl_->phase = 5;
      return Result<Bytes>::ok(std::move(proof_bytes));
    }
  } catch (const std::exception&) {
  }
  return Result<Bytes>::fail(ErrorCode::malformed,
                             "holder component proof failed");
}

bool HolderBoundCircuitVerifierV1::verify(
    HolderComponent component, const CircuitIdentity& identity,
    const Request& request, const Bytes& credential_commitment,
    const Bytes& kb_commitment, const Bytes& bridge_public,
    const Bytes& proof_bytes) {
  try {
    const HolderBoundVerifierPolicyV1 policy{
        request,
        holder_bound_credential_circuit_identity_v1(),
        holder_bound_kb_circuit_identity_v1()};
    if (component != HolderComponent::credential &&
        component != HolderComponent::kb)
      return false;
    if (!valid_policy(policy) ||
        !identity_equal(identity,
                        component == HolderComponent::credential
                            ? policy.credential_identity
                            : policy.kb_identity) ||
        credential_commitment.size() != proofs::Digest::kLength ||
        kb_commitment.size() != proofs::Digest::kLength)
      return false;
    auto& runtime = runtime_v1();
    auto* credential_circuit = runtime.credential_circuit.get();
    const auto& circuit = component == HolderComponent::credential
                              ? *credential_circuit
                              : *runtime.kb_circuit;
    proofs::ZkProof<Field> proof(circuit, kRate, kQueries);
    proofs::ReadBuffer reader(proof_bytes);
    if (!proof.read(reader, proofs::p256_base) || reader.remaining() != 0 ||
        commitment_bytes(proof) !=
            (component == HolderComponent::credential
                 ? credential_commitment
                 : kb_commitment))
      return false;

    const auto manifest = pair_manifest(policy);
    if (manifest.empty()) return false;
    proofs::Transcript shared(manifest.data(), manifest.size());
    proofs::ZkProof<Field> credential_commitment_proof(
        *credential_circuit, kRate, kQueries);
    proofs::ZkProof<Field> kb_commitment_proof(*runtime.kb_circuit, kRate,
                                               kQueries);
    if (!set_commitment(credential_commitment_proof, credential_commitment) ||
        !set_commitment(kb_commitment_proof, kb_commitment))
      return false;
    proofs::ZkVerifier<Field, ReedSolomon> credential_verifier(
        *credential_circuit, runtime.reed_solomon, kRate, kQueries,
        proofs::p256_base);
    proofs::ZkVerifier<Field, ReedSolomon> kb_verifier(
        *runtime.kb_circuit, runtime.reed_solomon, kRate, kQueries,
        proofs::p256_base);
    credential_verifier.recv_commitment(credential_commitment_proof, shared);
    kb_verifier.recv_commitment(kb_commitment_proof, shared);
    std::array<std::uint8_t, GF::kBytes> expected_challenge{};
    shared.bytes(expected_challenge.data(), expected_challenge.size());
    if (bridge_public.size() != 7 * GF::kBytes ||
        !std::equal(expected_challenge.begin(), expected_challenge.end(),
                    bridge_public.end() - static_cast<long>(GF::kBytes)))
      return false;

    std::array<GF::Elt, 6> tags{};
    GF::Elt challenge{};
    if (!decode_bridge(bridge_public, &tags, &challenge)) return false;
    auto transcript = shared.clone();
    fork_component(transcript, component);
    if (component == HolderComponent::credential) {
      HolderCredentialPublicInputsV1 inputs{tags, challenge, true};
      proofs::Dense<Field> dense(1, credential_circuit->npub_in);
      const auto issuer_key = request_issuer_key(request);
      return issuer_key &&
             FillHolderCredentialPublicInputsV1(dense, inputs, *issuer_key) &&
             credential_verifier.verify(proof, dense, transcript);
    }
    HolderKbPublicInputsV1 inputs{tags, challenge, request.audience,
                                  request.nonce, request.time_min,
                                  request.time_max};
    proofs::Dense<Field> dense(1, runtime.kb_circuit->npub_in);
    return FillHolderKbPublicInputsV1(dense, inputs) &&
           kb_verifier.verify(proof, dense, transcript);
  } catch (const std::exception&) {
    return false;
  }
}

Result<HolderBoundEnvelope> prove_holder_bound_impl_v1(
    const HolderBoundVerifierPolicyV1& policy,
    const HolderCredentialWitnessV1& credential,
    const HolderKbWitnessV1& kb,
    const StatusMembershipWitnessV1* status_witness, const Limits& limits) {
  if (!valid_policy(policy) ||
      policy.credential_identity.trust != Trust::exact_key)
    return Result<HolderBoundEnvelope>::fail(
        ErrorCode::unsupported, "unsupported holder-bound V1 policy");
  auto presentation_policy = policy;
  presentation_policy.request.status_public.clear();
  HolderBoundCircuitProverV1 prover(presentation_policy, credential, kb);
  auto envelope = prove_holder_bound_envelope_v1(presentation_policy, prover,
                                                  limits);
  if (!envelope) return envelope;
  envelope.value->request = policy.request;
  if (!policy.request.status_public.empty()) {
    if (!status_witness)
      return Result<HolderBoundEnvelope>::fail(ErrorCode::malformed,
                                                "status witness is required");
    const auto status_policy = decode_status_policy_v1(policy.request.status_public);
    if (!status_policy)
      return Result<HolderBoundEnvelope>::fail(status_policy.error->code,
                                                status_policy.error->message);
    const auto binding = transcript_seed(policy.request);
    auto status = prove_status_membership_v1(
        status_policy.value->snapshot, status_policy.value->credential_id,
        status_witness->private_index, status_witness->compressed_proof,
        binding, limits);
    if (!status)
      return Result<HolderBoundEnvelope>::fail(status.error->code,
                                                status.error->message);
    envelope.value->status_proof = std::move(status.value->proof);
  } else if (status_witness) {
    return Result<HolderBoundEnvelope>::fail(ErrorCode::malformed,
                                              "unexpected status witness");
  }
  return envelope;
}

Result<HolderBoundEnvelope> prove_holder_bound_v1(
    const HolderBoundVerifierPolicyV1& policy,
    const HolderCredentialWitnessV1& credential,
    const HolderKbWitnessV1& kb, const Limits& limits) {
  return prove_holder_bound_impl_v1(policy, credential, kb, nullptr, limits);
}

Result<HolderBoundEnvelope> prove_holder_bound_v1(
    const HolderBoundVerifierPolicyV1& policy,
    const HolderCredentialWitnessV1& credential,
    const HolderKbWitnessV1& kb,
    const StatusMembershipWitnessV1& status_witness, const Limits& limits) {
  return prove_holder_bound_impl_v1(policy, credential, kb, &status_witness,
                                    limits);
}

Result<bool> verify_holder_bound_v1(
    const HolderBoundEnvelope& envelope,
    const HolderBoundVerifierPolicyV1& expected, std::uint64_t now,
    HolderBoundReplayStoreV1& replay_store, const Limits& limits) {
  if (!valid_policy(expected) ||
      expected.credential_identity.trust != Trust::exact_key)
    return Result<bool>::fail(ErrorCode::unsupported,
                              "unsupported holder-bound V1 policy");
  if (!expected.request.status_public.empty()) {
    const auto status_policy = decode_status_policy_v1(expected.request.status_public);
    const auto issuer_key = request_issuer_key(expected.request);
    if (!status_policy || !issuer_key)
      return Result<bool>::fail(ErrorCode::malformed, "invalid status policy");
    const auto binding = transcript_seed(expected.request);
    const auto status = verify_status_membership_v1(
        StatusMembershipProofV1{envelope.status_proof},
        status_policy.value->snapshot, status_issuer_v1(*issuer_key),
        status_policy.value->snapshot.epoch, status_policy.value->credential_id,
        now, binding, limits);
    if (!status)
      return Result<bool>::fail(status.error->code, status.error->message);
  }
  HolderBoundCircuitVerifierV1 verifier;
  auto presentation = envelope;
  auto presentation_expected = expected;
  presentation.request.status_public.clear();
  presentation.status_proof.clear();
  presentation_expected.request.status_public.clear();
  return verify_holder_bound_envelope_v1(presentation, presentation_expected,
                                         now, verifier,
                                         replay_store, limits);
}

}  // namespace sd_jwt_zk
