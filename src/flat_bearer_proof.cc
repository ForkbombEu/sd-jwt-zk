#include "sd_jwt_zk/flat_bearer_proof.h"

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

#include <algorithm>
#include <exception>

namespace sd_jwt_zk {
namespace {

constexpr std::size_t kRate = 4;
constexpr std::size_t kQueries = 128;
using Field = FlatBearerField;
using Field2 = proofs::Fp2<Field>;
using FftFactory = proofs::FFTExtConvolutionFactory<Field, Field2>;
using ReedSolomon = proofs::ReedSolomonFactory<Field, FftFactory>;

struct RuntimeV1 {
  Field2 extension{proofs::p256_base};
  Field2::Elt omega;
  FftFactory fft;
  ReedSolomon reed_solomon;
  std::unique_ptr<proofs::Circuit<Field>> circuit;

  RuntimeV1()
      : omega(extension.of_string(
            "112649224146410281873500457609690258373018840430489408729223714171582664680802",
            "84087994358540907695740461427818660560182168997182378749313018254450460212908")),
        fft(proofs::p256_base, extension, omega, 1ull << 31),
        reed_solomon(fft, proofs::p256_base) {
    proofs::QuadCircuit<Field> quad(proofs::p256_base);
    circuit = BuildFlatBearerCircuitV1(&quad);
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

bool request_equal(const Request& left, const Request& right,
                   const Limits& limits) {
  const auto encoded_left = encode_request(left, limits);
  const auto encoded_right = encode_request(right, limits);
  return encoded_left && encoded_right &&
         *encoded_left.value == *encoded_right.value;
}

bool policy_result(const Request& request, bool* result) {
  if (request.policy_result.size() != 1 || request.policy_result[0] > 1)
    return false;
  *result = request.policy_result[0] == 1;
  return true;
}

std::optional<P256Key> request_issuer_key(const Request& request) {
  if (request.trust_public.size() != 64) return std::nullopt;
  P256Key key{};
  std::copy_n(request.trust_public.begin(), 32, key.x.begin());
  std::copy_n(request.trust_public.begin() + 32, 32, key.y.begin());
  return key;
}

Result<bool> validate_request(const Request& request, const Limits& limits) {
  if (!encode_request(request, limits))
    return Result<bool>::fail(ErrorCode::malformed,
                              "request is not canonically encodable");
  if (request.audience.empty() || request.nonce.empty())
    return Result<bool>::fail(ErrorCode::malformed,
                              "audience and nonce are required");
  if (!identity_equal(request.identity, flat_bearer_circuit_identity_v1()))
    return Result<bool>::fail(ErrorCode::unsupported,
                              "unsupported flat bearer circuit identity");
  if (request.policy != flat_bearer_policy_v1())
    return Result<bool>::fail(ErrorCode::unsupported,
                              "unsupported flat bearer policy");
  bool ignored = false;
  if (!policy_result(request, &ignored))
    return Result<bool>::fail(ErrorCode::malformed,
                              "policy result must be one Boolean byte");
  if (!request_issuer_key(request))
    return Result<bool>::fail(ErrorCode::malformed,
                              "exact-key trust must contain P-256 x and y");
  if (!request.status_public.empty())
    return Result<bool>::fail(ErrorCode::unsupported,
                              "status is not supported by the V1 family");
  return Result<bool>::ok(true);
}

}  // namespace

CircuitIdentity flat_bearer_circuit_identity_v1() {
  CircuitIdentity identity{Binding::bearer, Trust::exact_key, 140, {},
                           "p256-base", kRate, kQueries};
  const auto& circuit = *runtime_v1().circuit;
  std::copy_n(circuit.id, identity.circuit_digest.size(),
              identity.circuit_digest.begin());
  return identity;
}

Bytes flat_bearer_policy_v1() {
  constexpr char policy[] = "age_over:eq:true";
  return Bytes(policy, policy + sizeof(policy) - 1);
}

Bytes flat_bearer_true_policy_result_v1() { return Bytes{1}; }

Bytes flat_bearer_exact_key_trust_v1(const P256Key& issuer_key) {
  Bytes trust;
  trust.reserve(64);
  trust.insert(trust.end(), issuer_key.x.begin(), issuer_key.x.end());
  trust.insert(trust.end(), issuer_key.y.begin(), issuer_key.y.end());
  return trust;
}

Result<Envelope> prove_flat_bearer_v1(const Request& request,
                                     const FlatBearerWitness& witness,
                                     const Limits& limits) {
  const auto valid = validate_request(request, limits);
  if (!valid)
    return Result<Envelope>::fail(valid.error->code, valid.error->message);
  const auto request_key = request_issuer_key(request);
  if (!request_key || request_key->x != witness.issuer_key.x ||
      request_key->y != witness.issuer_key.y)
    return Result<Envelope>::fail(ErrorCode::malformed,
                                  "request issuer key does not match witness");
  bool result = false;
  if (!policy_result(request, &result))
    return Result<Envelope>::fail(ErrorCode::malformed,
                                  "invalid policy result");
  const auto statement = transcript_seed(request);
  try {
    auto& runtime = runtime_v1();
    proofs::Dense<Field> inputs(1, runtime.circuit->ninputs);
    if (!FillFlatBearerDenseWitnessV1(inputs, statement, result, witness))
      return Result<Envelope>::fail(ErrorCode::malformed,
                                    "dense witness encoding failed");
    proofs::ZkProof<Field> proof(*runtime.circuit, kRate, kQueries);
    proofs::ZkProver<Field, ReedSolomon> prover(
        *runtime.circuit, proofs::p256_base, runtime.reed_solomon);
    proofs::Transcript transcript(statement.data(), statement.size());
    proofs::SecureRandomEngine random;
    prover.commit(proof, inputs, transcript, random);
    if (!prover.prove(proof, inputs, transcript))
      return Result<Envelope>::fail(ErrorCode::malformed,
                                    "witness does not satisfy circuit");
    Bytes proof_bytes;
    proof.write(proof_bytes, proofs::p256_base);
    if (proof_bytes.empty() || proof_bytes.size() > limits.max_proof)
      return Result<Envelope>::fail(ErrorCode::limit,
                                    "proof exceeds configured bound");
    return Result<Envelope>::ok(Envelope{request, std::move(proof_bytes)});
  } catch (const std::exception&) {
    return Result<Envelope>::fail(ErrorCode::malformed,
                                  "proof construction failed");
  }
}

Result<bool> verify_flat_bearer_v1(const Envelope& envelope,
                                  const Request& expected_request,
                                  std::uint64_t now,
                                  FlatBearerReplayStoreV1& replay_store,
                                  const Limits& limits) {
  const auto valid = validate_request(expected_request, limits);
  if (!valid) return valid;
  if (!request_equal(envelope.request, expected_request, limits))
    return Result<bool>::fail(ErrorCode::malformed,
                              "proof request does not match verifier request");
  if (now < expected_request.time_min || now > expected_request.time_max)
    return Result<bool>::fail(ErrorCode::malformed,
                              "request validity window does not contain now");
  if (envelope.proof.empty() || envelope.proof.size() > limits.max_proof)
    return Result<bool>::fail(ErrorCode::limit, "invalid proof size");
  bool result = false;
  if (!policy_result(expected_request, &result))
    return Result<bool>::fail(ErrorCode::malformed, "invalid policy result");
  const auto issuer_key = request_issuer_key(expected_request);
  if (!issuer_key)
    return Result<bool>::fail(ErrorCode::malformed, "invalid issuer key");
  const auto statement = transcript_seed(expected_request);
  try {
    auto& runtime = runtime_v1();
    proofs::ReadBuffer reader(envelope.proof);
    proofs::ZkProof<Field> proof(*runtime.circuit, kRate, kQueries);
    if (!proof.read(reader, proofs::p256_base) || reader.remaining() != 0)
      return Result<bool>::fail(ErrorCode::noncanonical,
                                "malformed or trailing proof bytes");
    proofs::Dense<Field> public_inputs(1, runtime.circuit->npub_in);
    if (!FillFlatBearerPublicInputsV1(public_inputs, statement, result,
                                      *issuer_key))
      return Result<bool>::fail(ErrorCode::malformed,
                                "public input encoding failed");
    proofs::Transcript transcript(statement.data(), statement.size());
    proofs::ZkVerifier<Field, ReedSolomon> verifier(
        *runtime.circuit, runtime.reed_solomon, kRate, kQueries,
        proofs::p256_base);
    verifier.recv_commitment(proof, transcript);
    if (!verifier.verify(proof, public_inputs, transcript))
      return Result<bool>::fail(ErrorCode::malformed,
                                "proof verification failed");
    if (!replay_store.consume(expected_request.audience,
                              expected_request.nonce,
                              expected_request.time_max))
      return Result<bool>::fail(ErrorCode::malformed,
                                "nonce has already been consumed");
    return Result<bool>::ok(true);
  } catch (const std::exception&) {
    return Result<bool>::fail(ErrorCode::malformed,
                              "proof verification failed");
  }
}

}  // namespace sd_jwt_zk
