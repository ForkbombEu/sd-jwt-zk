#include "sd_jwt_zk/registry_bearer_proof.h"

#include <algorithm>
#include <exception>
#include <string_view>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace sd_jwt_zk {
namespace {

constexpr std::size_t kRate = 4;
constexpr std::size_t kQueries = 32;
constexpr std::size_t kExactPublicInputs = kFlatBearerPublicInputsV1;
constexpr std::string_view kLeafTag = "SDJWT-ZK/issuer-registry/v1/leaf";
constexpr std::string_view kNodeTag = "SDJWT-ZK/issuer-registry/v1/node";
using Field = FlatBearerField;
using Field2 = proofs::Fp2<Field>;
using Fft = proofs::FFTExtConvolutionFactory<Field, Field2>;
using ReedSolomon = proofs::ReedSolomonFactory<Field, Fft>;

void append_u64(Bytes& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8)
    out.push_back(static_cast<std::uint8_t>(value >> shift));
}

void fill_v8(proofs::DenseFiller<Field>& filler, std::uint8_t value) {
  filler.push_back(value, 8, proofs::p256_base);
}

proofs::Fp256Nat to_nat(const std::array<std::uint8_t, 32>& bytes) {
  std::array<std::uint8_t, 32> little{};
  for (std::size_t i = 0; i < little.size(); ++i)
    little[i] = bytes[little.size() - 1 - i];
  return proofs::Fp256Nat::of_bytes(little.data());
}

template <std::size_t Blocks>
bool fill_sha(proofs::DenseFiller<Field>& filler, const Bytes& message,
              std::array<std::uint8_t, 64 * Blocks>* padded,
              std::array<proofs::FlatSHA256Witness::BlockWitness, Blocks>*
                  advice,
              std::array<std::uint8_t, 32>* digest) {
  std::uint8_t block_count{};
  proofs::FlatSHA256Witness::transform_and_witness_message(
      message.size(), message.data(), Blocks, block_count, padded->data(),
      advice->data());
  if (block_count != Blocks) return false;
  *digest = sha256_ascii(std::string_view(
      reinterpret_cast<const char*>(message.data()), message.size()));
  for (const auto byte : *padded) fill_v8(filler, byte);
  proofs::BitPluckerEncoder<Field, 4> encoder(proofs::p256_base);
  for (const auto& block : *advice) {
    for (std::size_t i = 0; i < 48; ++i)
      filler.push_back(encoder.mkpacked_v32(block.outw[i]));
    for (std::size_t i = 0; i < 64; ++i) {
      filler.push_back(encoder.mkpacked_v32(block.oute[i]));
      filler.push_back(encoder.mkpacked_v32(block.outa[i]));
    }
    for (std::size_t i = 0; i < 8; ++i)
      filler.push_back(encoder.mkpacked_v32(block.h1[i]));
  }
  const auto digest_nat = to_nat(*digest);
  for (std::size_t bit = 0; bit < 256; ++bit)
    filler.push_back(proofs::p256_base.of_scalar(digest_nat.bit(bit)));
  return true;
}

bool same_identity(const CircuitIdentity& left, const CircuitIdentity& right) {
  return left.binding == right.binding && left.trust == right.trust &&
         left.capacity == right.capacity &&
         left.circuit_digest == right.circuit_digest &&
         left.field == right.field && left.ligero_rate == right.ligero_rate &&
         left.query_count == right.query_count;
}

bool same_request(const Request& left, const Request& right,
                  const Limits& limits) {
  const auto a = encode_request(left, limits);
  const auto b = encode_request(right, limits);
  return a && b && *a.value == *b.value;
}

Result<RegistryTrustContextV1> validate_request(const Request& request,
                                                const Limits& limits) {
  if (!encode_request(request, limits) || request.audience.empty() ||
      request.nonce.empty() || request.time_min > request.time_max)
    return Result<RegistryTrustContextV1>::fail(
        ErrorCode::malformed, "invalid registry bearer request");
  if (!same_identity(request.identity, registry_bearer_circuit_identity_v1()) ||
      request.policy != flat_bearer_policy_v1() ||
      request.policy_result != flat_bearer_true_policy_result_v1() ||
      !request.status_public.empty())
    return Result<RegistryTrustContextV1>::fail(
        ErrorCode::unsupported, "unsupported registry bearer family");
  const auto trust = decode_registry_trust_context_v1(request.trust_public);
  if (!trust || trust.value->depth != kIssuerRegistryDepthV1)
    return Result<RegistryTrustContextV1>::fail(
        ErrorCode::malformed, "wrong registry trust depth");
  return trust;
}

struct Runtime {
  Field2 extension{proofs::p256_base};
  Field2::Elt omega;
  Fft fft;
  ReedSolomon reed_solomon;
  RegistryBearerDenseLayoutV1 layout;
  std::unique_ptr<proofs::Circuit<Field>> circuit;
  Runtime()
      : omega(extension.of_string(
            "112649224146410281873500457609690258373018840430489408729223714171582664680802",
            "84087994358540907695740461427818660560182168997182378749313018254450460212908")),
        fft(proofs::p256_base, extension, omega, 1ull << 31),
        reed_solomon(fft, proofs::p256_base) {
    proofs::QuadCircuit<Field> quad(proofs::p256_base);
    circuit = BuildRegistryBearerCircuitV1(&quad, &layout);
  }
};

Runtime& runtime() {
  static Runtime value;
  return value;
}

}  // namespace

Result<RegistryBearerWitnessV1> registry_bearer_witness_from_presentation_v1(
    std::string_view presentation, const IssuerRegistryPathV1& authorization,
    const Limits& limits) {
  if (authorization.siblings.size() != kIssuerRegistryDepthV1 ||
      authorization.sibling_is_left.size() != kIssuerRegistryDepthV1 ||
      authorization.record.vct.empty())
    return Result<RegistryBearerWitnessV1>::fail(
        ErrorCode::malformed, "invalid fixed-depth issuer authorization");
  auto credential = flat_bearer_witness_from_presentation(
      presentation, authorization.record.issuer_key, limits);
  if (!credential) return Result<RegistryBearerWitnessV1>::fail(
      credential.error->code, credential.error->message);
  if (credential.value->payload.vct != authorization.record.vct)
    return Result<RegistryBearerWitnessV1>::fail(
        ErrorCode::malformed, "credential type is not registry-authorized");
  return Result<RegistryBearerWitnessV1>::ok(
      RegistryBearerWitnessV1{std::move(*credential.value), authorization});
}

bool AppendIssuerRegistryMembershipAdviceV1(
    proofs::DenseFiller<Field>& filler, const RegistryTrustContextV1& trust,
    const IssuerRegistryPathV1& path) {
  IssuerRegistryV1 registry{trust.epoch, trust.valid_from, trust.valid_until,
                            trust.depth, trust.root, {}};
  if (trust.depth != kIssuerRegistryDepthV1 ||
      !issuer_registry_path_matches_v1(registry, path))
    return false;
  filler.push_back(path.record.not_before, 64, proofs::p256_base);
  filler.push_back(path.record.not_after, 64, proofs::p256_base);
  filler.push_back(path.epoch, 64, proofs::p256_base);
  filler.push_back(path.index, kIssuerRegistryDepthV1, proofs::p256_base);
  for (const auto value : {path.record.not_before, path.record.not_after})
    for (int shift = 56; shift >= 0; shift -= 8)
      fill_v8(filler, static_cast<std::uint8_t>(value >> shift));
  Bytes leaf(kLeafTag.begin(), kLeafTag.end());
  leaf.insert(leaf.end(), path.record.issuer_key.x.begin(),
              path.record.issuer_key.x.end());
  leaf.insert(leaf.end(), path.record.issuer_key.y.begin(),
              path.record.issuer_key.y.end());
  const auto vct_digest = sha256_ascii(path.record.vct);
  leaf.insert(leaf.end(), vct_digest.begin(), vct_digest.end());
  append_u64(leaf, path.record.not_before);
  append_u64(leaf, path.record.not_after);
  std::array<std::uint8_t, 192> leaf_padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 3> leaf_advice{};
  std::array<std::uint8_t, 32> current{};
  if (!fill_sha(filler, leaf, &leaf_padded, &leaf_advice, &current))
    return false;
  for (const auto& sibling : path.siblings)
    for (const auto byte : sibling) fill_v8(filler, byte);
  for (std::size_t level = 0; level < kIssuerRegistryDepthV1; ++level) {
    Bytes node(kNodeTag.begin(), kNodeTag.end());
    const auto& sibling = path.siblings[level];
    if (path.sibling_is_left[level]) {
      node.insert(node.end(), sibling.begin(), sibling.end());
      node.insert(node.end(), current.begin(), current.end());
    } else {
      node.insert(node.end(), current.begin(), current.end());
      node.insert(node.end(), sibling.begin(), sibling.end());
    }
    std::array<std::uint8_t, 128> node_padded{};
    std::array<proofs::FlatSHA256Witness::BlockWitness, 2> node_advice{};
    std::array<std::uint8_t, 32> parent{};
    if (!fill_sha(filler, node, &node_padded, &node_advice, &parent))
      return false;
    current = parent;
  }
  return current == trust.root;
}

bool FillRegistryBearerPublicInputsV1(
    proofs::Dense<Field>& inputs,
    const std::array<std::uint8_t, 32>& statement, bool policy_result,
    const RegistryTrustContextV1& trust) {
  if (inputs.n0_ != 1 || trust.depth != kIssuerRegistryDepthV1 ||
      trust.valid_from > trust.valid_until)
    return false;
  proofs::DenseFiller<Field> filler(inputs);
  filler.push_back(proofs::p256_base.one());
  for (const auto byte : statement)
    filler.push_back(proofs::p256_base.of_scalar(byte));
  filler.push_back(proofs::p256_base.of_scalar(policy_result));
  for (const auto byte : trust.root) fill_v8(filler, byte);
  filler.push_back(trust.epoch, 64, proofs::p256_base);
  filler.push_back(trust.valid_from, 64, proofs::p256_base);
  filler.push_back(trust.valid_until, 64, proofs::p256_base);
  filler.push_back(trust.depth, 8, proofs::p256_base);
  return filler.size() == inputs.n1_;
}

bool FillRegistryBearerDenseWitnessV1(
    proofs::Dense<Field>& inputs, const RegistryBearerDenseLayoutV1& layout,
    const std::array<std::uint8_t, 32>& statement, bool policy_result,
    const RegistryTrustContextV1& trust,
    const RegistryBearerWitnessV1& witness) {
  if (inputs.n0_ != 1 || inputs.n1_ != layout.total_inputs ||
      layout.public_inputs >= layout.membership_first ||
      witness.authorization.record.issuer_key.x != witness.credential.issuer_key.x ||
      witness.authorization.record.issuer_key.y != witness.credential.issuer_key.y ||
      witness.authorization.record.vct != witness.credential.payload.vct ||
      witness.authorization.epoch != trust.epoch ||
      witness.authorization.siblings.size() != kIssuerRegistryDepthV1 ||
      witness.authorization.sibling_is_left.size() != kIssuerRegistryDepthV1)
    return false;
  IssuerRegistryV1 registry{trust.epoch, trust.valid_from, trust.valid_until,
                            trust.depth, trust.root, {}};
  if (!issuer_registry_path_matches_v1(registry, witness.authorization))
    return false;

  proofs::Dense<Field> exact(1, kFlatBearerDenseInputsV1);
  if (!FillFlatBearerDenseWitnessV1(exact, statement, policy_result,
                                    witness.credential))
    return false;
  proofs::DenseFiller<Field> filler(inputs);
  filler.push_back(proofs::p256_base.one());
  for (const auto byte : statement)
    filler.push_back(proofs::p256_base.of_scalar(byte));
  filler.push_back(proofs::p256_base.of_scalar(policy_result));
  for (const auto byte : trust.root) fill_v8(filler, byte);
  filler.push_back(trust.epoch, 64, proofs::p256_base);
  filler.push_back(trust.valid_from, 64, proofs::p256_base);
  filler.push_back(trust.valid_until, 64, proofs::p256_base);
  filler.push_back(trust.depth, 8, proofs::p256_base);
  if (filler.size() != layout.public_inputs) return false;

  // Exact factory public x/y become private here; its remaining private suffix
  // is byte-for-byte the shared issuer/disclosure advice order.
  filler.push_back(exact.v_[34]);
  filler.push_back(exact.v_[35]);
  for (std::size_t i = kExactPublicInputs; i < exact.v_.size(); ++i)
    filler.push_back(exact.v_[i]);
  if (filler.size() != layout.membership_first) return false;

  const auto& path = witness.authorization;
  filler.push_back(path.record.not_before, 64, proofs::p256_base);
  filler.push_back(path.record.not_after, 64, proofs::p256_base);
  filler.push_back(path.epoch, 64, proofs::p256_base);
  filler.push_back(path.index, kIssuerRegistryDepthV1, proofs::p256_base);
  for (const auto value : {path.record.not_before, path.record.not_after})
    for (int shift = 56; shift >= 0; shift -= 8)
      fill_v8(filler, static_cast<std::uint8_t>(value >> shift));

  Bytes leaf(kLeafTag.begin(), kLeafTag.end());
  leaf.insert(leaf.end(), path.record.issuer_key.x.begin(),
              path.record.issuer_key.x.end());
  leaf.insert(leaf.end(), path.record.issuer_key.y.begin(),
              path.record.issuer_key.y.end());
  const auto vct_digest = sha256_ascii(path.record.vct);
  leaf.insert(leaf.end(), vct_digest.begin(), vct_digest.end());
  append_u64(leaf, path.record.not_before);
  append_u64(leaf, path.record.not_after);
  std::array<std::uint8_t, 192> leaf_padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 3> leaf_advice{};
  std::array<std::uint8_t, 32> current{};
  if (!fill_sha(filler, leaf, &leaf_padded, &leaf_advice, &current))
    return false;

  for (const auto& sibling : path.siblings)
    for (const auto byte : sibling) fill_v8(filler, byte);
  for (std::size_t level = 0; level < kIssuerRegistryDepthV1; ++level) {
    Bytes node(kNodeTag.begin(), kNodeTag.end());
    const auto& sibling = path.siblings[level];
    if (path.sibling_is_left[level]) {
      node.insert(node.end(), sibling.begin(), sibling.end());
      node.insert(node.end(), current.begin(), current.end());
    } else {
      node.insert(node.end(), current.begin(), current.end());
      node.insert(node.end(), sibling.begin(), sibling.end());
    }
    std::array<std::uint8_t, 128> node_padded{};
    std::array<proofs::FlatSHA256Witness::BlockWitness, 2> node_advice{};
    std::array<std::uint8_t, 32> parent{};
    if (!fill_sha(filler, node, &node_padded, &node_advice, &parent))
      return false;
    current = parent;
  }
  return current == trust.root && filler.size() == layout.total_inputs;
}

CircuitIdentity registry_bearer_circuit_identity_v1() {
  CircuitIdentity identity{Binding::bearer, Trust::registry, 140, {},
                           "p256-base", kRate, kQueries};
  const auto& circuit = *runtime().circuit;
  std::copy_n(circuit.id, identity.circuit_digest.size(),
              identity.circuit_digest.begin());
  return identity;
}

Result<Envelope> prove_registry_bearer_v1(
    const Request& request, const RegistryBearerWitnessV1& witness,
    const Limits& limits) {
  const auto trust = validate_request(request, limits);
  if (!trust) return Result<Envelope>::fail(trust.error->code,
                                             trust.error->message);
  const auto statement = transcript_seed(request);
  try {
    auto& rt = runtime();
    proofs::Dense<Field> inputs(1, rt.circuit->ninputs);
    if (!FillRegistryBearerDenseWitnessV1(inputs, rt.layout, statement, true,
                                          *trust.value, witness))
      return Result<Envelope>::fail(ErrorCode::malformed,
                                    "registry dense witness encoding failed");
    proofs::ZkProof<Field> proof(*rt.circuit, kRate, kQueries);
    proofs::ZkProver<Field, ReedSolomon> prover(
        *rt.circuit, proofs::p256_base, rt.reed_solomon);
    proofs::Transcript transcript(statement.data(), statement.size());
    proofs::SecureRandomEngine random;
    prover.commit(proof, inputs, transcript, random);
    if (!prover.prove(proof, inputs, transcript))
      return Result<Envelope>::fail(ErrorCode::malformed,
                                    "registry witness does not satisfy circuit");
    Bytes bytes;
    proof.write(bytes, proofs::p256_base);
    if (bytes.empty() || bytes.size() > limits.max_proof)
      return Result<Envelope>::fail(ErrorCode::limit,
                                    "registry proof exceeds configured bound");
    return Result<Envelope>::ok(Envelope{request, std::move(bytes)});
  } catch (const std::exception&) {
    return Result<Envelope>::fail(ErrorCode::malformed,
                                  "registry proof construction failed");
  }
}

Result<bool> verify_registry_bearer_v1(
    const Envelope& envelope, const Request& expected_request,
    std::uint64_t now, FlatBearerReplayStoreV1& replay_store,
    const Limits& limits) {
  const auto trust = validate_request(expected_request, limits);
  if (!trust) return Result<bool>::fail(trust.error->code,
                                        trust.error->message);
  if (!same_request(envelope.request, expected_request, limits) ||
      now < expected_request.time_min || now > expected_request.time_max ||
      now < trust.value->valid_from || now > trust.value->valid_until ||
      envelope.proof.empty() || envelope.proof.size() > limits.max_proof)
    return Result<bool>::fail(ErrorCode::malformed,
                              "registry request or validity window mismatch");
  const auto statement = transcript_seed(expected_request);
  try {
    auto& rt = runtime();
    proofs::ReadBuffer reader(envelope.proof);
    proofs::ZkProof<Field> proof(*rt.circuit, kRate, kQueries);
    if (!proof.read(reader, proofs::p256_base) || reader.remaining() != 0)
      return Result<bool>::fail(ErrorCode::noncanonical,
                                "malformed registry proof bytes");
    proofs::Dense<Field> public_inputs(1, rt.circuit->npub_in);
    if (!FillRegistryBearerPublicInputsV1(public_inputs, statement, true,
                                          *trust.value))
      return Result<bool>::fail(ErrorCode::malformed,
                                "registry public input encoding failed");
    proofs::Transcript transcript(statement.data(), statement.size());
    proofs::ZkVerifier<Field, ReedSolomon> verifier(
        *rt.circuit, rt.reed_solomon, kRate, kQueries, proofs::p256_base);
    verifier.recv_commitment(proof, transcript);
    if (!verifier.verify(proof, public_inputs, transcript))
      return Result<bool>::fail(ErrorCode::malformed,
                                "registry proof verification failed");
    if (!replay_store.consume(expected_request.audience,
                              expected_request.nonce,
                              expected_request.time_max))
      return Result<bool>::fail(ErrorCode::malformed,
                                "nonce has already been consumed");
    return Result<bool>::ok(true);
  } catch (const std::exception&) {
    return Result<bool>::fail(ErrorCode::malformed,
                              "registry proof verification failed");
  }
}

}  // namespace sd_jwt_zk
