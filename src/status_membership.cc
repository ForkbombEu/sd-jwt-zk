#include "sd_jwt_zk/status_membership.h"

#include <algorithm>
#include <exception>
#include <memory>
#include <string>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace sd_jwt_zk {
namespace {

constexpr std::size_t kRate = 4;
constexpr std::size_t kQueries = 128;
using Field = proofs::Fp256Base;
using Backend = proofs::CompilerBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Relation = StatusMembershipCircuitV1<Logic, kStatusMembershipDepthV1>;
using Field2 = proofs::Fp2<Field>;
using FftFactory = proofs::FFTExtConvolutionFactory<Field, Field2>;
using ReedSolomon = proofs::ReedSolomonFactory<Field, FftFactory>;

std::unique_ptr<proofs::Circuit<Field>> build_circuit() {
  proofs::QuadCircuit<Field> quad(proofs::p256_base);
  const Backend backend(&quad);
  const Logic logic(&backend, proofs::p256_base);
  Relation relation(logic);
  Relation::Input input{};
  input.leaf_digest = logic.template vinput<256>();
  input.expected_root = logic.template vinput<256>();
  quad.private_input();
  for (auto& sibling : input.siblings)
    sibling = logic.template vinput<256>();
  for (auto& direction : input.direction_bits) direction = logic.input();
  input.index_bits = logic.template vinput<kStatusMembershipDepthV1>();
  for (auto& witness : input.sha_witness) witness.input(logic);
  relation.assert_member(input);
  return quad.mkcircuit(1);
}

struct Runtime {
  Field2 extension{proofs::p256_base};
  Field2::Elt omega;
  FftFactory fft;
  ReedSolomon reed_solomon;
  std::unique_ptr<proofs::Circuit<Field>> circuit;

  Runtime()
      : omega(extension.of_string(
            "112649224146410281873500457609690258373018840430489408729223714171582664680802",
            "84087994358540907695740461427818660560182168997182378749313018254450460212908")),
        fft(proofs::p256_base, extension, omega, 1ull << 31),
        reed_solomon(fft, proofs::p256_base),
        circuit(build_circuit()) {}
};

Runtime& runtime() {
  static Runtime value;
  return value;
}

void append_u64(std::string& output, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8)
    output.push_back(static_cast<char>((value >> shift) & 0xffu));
}

std::uint64_t read_u64(const Bytes& input, std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | input[offset + i];
  return value;
}

std::array<std::uint8_t, 32> statement_digest(
    const StatusSnapshotPublicV1& snapshot, std::uint64_t credential_id,
    const std::array<std::uint8_t, 32>& presentation_binding) {
  std::string material{"sd-jwt-zk/status-membership-proof/v1"};
  material.append(reinterpret_cast<const char*>(presentation_binding.data()),
                  presentation_binding.size());
  material.append(reinterpret_cast<const char*>(snapshot.issuer.data()),
                  snapshot.issuer.size());
  material.append(reinterpret_cast<const char*>(snapshot.root.data),
                  proofs::Digest::kLength);
  append_u64(material, snapshot.epoch);
  append_u64(material, snapshot.valid_from);
  append_u64(material, snapshot.valid_until);
  append_u64(material, credential_id);
  return sha256_ascii(material);
}

void fill_digest(proofs::DenseFiller<Field>& filler,
                 const proofs::Digest& digest) {
  for (std::size_t byte = 0; byte < proofs::Digest::kLength; ++byte)
    for (std::size_t bit = 0; bit < 8; ++bit)
      filler.push_back((digest.data[31 - byte] >> bit) & 1u, 1,
                       proofs::p256_base);
}

bool fill_public(proofs::Dense<Field>& output, const proofs::Digest& leaf,
                 const proofs::Digest& root) {
  proofs::DenseFiller<Field> filler(output);
  filler.push_back(proofs::p256_base.one());
  fill_digest(filler, leaf);
  fill_digest(filler, root);
  return filler.size() == output.n1_;
}

bool fill_witness(proofs::Dense<Field>& output,
                  const proofs::FixedDepthSha256MerklePath<
                      kStatusMembershipDepthV1>& path) {
  if (output.n0_ != 1) return false;
  proofs::Dense<Field> canonical(1, output.n1_);
  proofs::DenseFiller<Field> canonical_filler(canonical);
  canonical_filler.push_back(proofs::p256_base.one());
  Relation::Witness<Field> witness(path);
  witness.fill_witness(canonical_filler, proofs::p256_base);
  if (canonical_filler.size() != canonical.n1_) return false;

  constexpr std::size_t kDigestBits = 256;
  constexpr std::size_t kSiblingBits =
      kStatusMembershipDepthV1 * kDigestBits;
  constexpr std::size_t kDirectionBits = kStatusMembershipDepthV1;
  const std::size_t leaf_begin = 1;
  const std::size_t siblings_begin = leaf_begin + kDigestBits;
  const std::size_t directions_begin = siblings_begin + kSiblingBits;
  const std::size_t index_begin = directions_begin + kDirectionBits;
  const std::size_t root_begin = index_begin + kDirectionBits;
  const std::size_t sha_begin = root_begin + kDigestBits;

  std::size_t out = 0;
  output.v_[out++] = canonical.v_[0];
  for (std::size_t i = 0; i < kDigestBits; ++i)
    output.v_[out++] = canonical.v_[leaf_begin + i];
  for (std::size_t i = 0; i < kDigestBits; ++i)
    output.v_[out++] = canonical.v_[root_begin + i];
  for (std::size_t i = siblings_begin; i < root_begin; ++i)
    output.v_[out++] = canonical.v_[i];
  for (std::size_t i = sha_begin; i < canonical.n1_; ++i)
    output.v_[out++] = canonical.v_[i];
  return out == output.n1_;
}

}  // namespace

std::array<std::uint8_t, 32> status_issuer_v1(const P256Key& issuer_key) {
  std::string material{"sd-jwt-zk/status-issuer/v1"};
  material.append(reinterpret_cast<const char*>(issuer_key.x.data()),
                  issuer_key.x.size());
  material.append(reinterpret_cast<const char*>(issuer_key.y.data()),
                  issuer_key.y.size());
  return sha256_ascii(material);
}

Bytes encode_status_policy_v1(const StatusPolicyV1& policy) {
  Bytes output;
  output.reserve(96);
  output.insert(output.end(), policy.snapshot.issuer.begin(),
                policy.snapshot.issuer.end());
  output.insert(output.end(), policy.snapshot.root.data,
                policy.snapshot.root.data + proofs::Digest::kLength);
  for (const auto value : {policy.snapshot.epoch, policy.snapshot.valid_from,
                           policy.snapshot.valid_until, policy.credential_id})
    for (int shift = 56; shift >= 0; shift -= 8)
      output.push_back(static_cast<std::uint8_t>(value >> shift));
  return output;
}

Result<StatusPolicyV1> decode_status_policy_v1(const Bytes& encoded) {
  if (encoded.size() != 96)
    return Result<StatusPolicyV1>::fail(ErrorCode::noncanonical,
                                        "invalid status policy encoding");
  StatusPolicyV1 policy;
  std::copy_n(encoded.begin(), 32, policy.snapshot.issuer.begin());
  std::copy_n(encoded.begin() + 32, 32, policy.snapshot.root.data);
  policy.snapshot.epoch = read_u64(encoded, 64);
  policy.snapshot.valid_from = read_u64(encoded, 72);
  policy.snapshot.valid_until = read_u64(encoded, 80);
  policy.credential_id = read_u64(encoded, 88);
  if (policy.snapshot.valid_from > policy.snapshot.valid_until)
    return Result<StatusPolicyV1>::fail(ErrorCode::malformed,
                                        "invalid status policy interval");
  return Result<StatusPolicyV1>::ok(std::move(policy));
}

std::uint64_t status_credential_id_v1(
    const std::array<std::uint8_t, 32>& credential_digest) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | credential_digest[i];
  return value;
}

Result<StatusMembershipProofV1> prove_status_membership_v1(
    const StatusSnapshotPublicV1& snapshot, std::uint64_t credential_id,
    std::size_t private_index,
    const std::vector<proofs::Digest>& compressed_proof,
    const std::array<std::uint8_t, 32>& presentation_binding,
    const Limits& limits) {
  try {
    const auto leaf = status_leaf_v1(snapshot.issuer, snapshot.epoch,
                                     credential_id,
                                     CredentialStatusV1::valid);
    const auto path = status_membership_path_v1<kStatusMembershipDepthV1>(
        snapshot, leaf, private_index, compressed_proof);
    auto& state = runtime();
    proofs::Dense<Field> inputs(1, state.circuit->ninputs);
    if (!fill_witness(inputs, path))
      return Result<StatusMembershipProofV1>::fail(
          ErrorCode::malformed, "status witness encoding failed");
    const auto statement =
        statement_digest(snapshot, credential_id, presentation_binding);
    proofs::ZkProof<Field> proof(*state.circuit, kRate, kQueries);
    proofs::ZkProver<Field, ReedSolomon> prover(
        *state.circuit, proofs::p256_base, state.reed_solomon);
    proofs::Transcript transcript(statement.data(), statement.size());
    proofs::SecureRandomEngine random;
    prover.commit(proof, inputs, transcript, random);
    if (!prover.prove(proof, inputs, transcript))
      return Result<StatusMembershipProofV1>::fail(
          ErrorCode::malformed, "status witness does not satisfy circuit");
    Bytes encoded;
    proof.write(encoded, proofs::p256_base);
    if (encoded.empty() || encoded.size() > limits.max_proof)
      return Result<StatusMembershipProofV1>::fail(
          ErrorCode::limit, "status proof exceeds configured bound");
    return Result<StatusMembershipProofV1>::ok(
        StatusMembershipProofV1{std::move(encoded)});
  } catch (const std::exception&) {
    return Result<StatusMembershipProofV1>::fail(
        ErrorCode::malformed, "status proof construction failed");
  }
}

Result<bool> verify_status_membership_v1(
    const StatusMembershipProofV1& proof,
    const StatusSnapshotPublicV1& trusted_snapshot,
    const std::array<std::uint8_t, 32>& expected_issuer,
    std::uint64_t expected_epoch, std::uint64_t credential_id,
    std::uint64_t now,
    const std::array<std::uint8_t, 32>& presentation_binding,
    const Limits& limits) {
  if (!accepts_status_snapshot_v1(trusted_snapshot, expected_issuer,
                                  expected_epoch, now))
    return Result<bool>::fail(ErrorCode::malformed,
                              "status snapshot is not trusted and current");
  if (proof.proof.empty() || proof.proof.size() > limits.max_proof)
    return Result<bool>::fail(ErrorCode::limit, "invalid status proof size");
  try {
    const auto leaf = status_leaf_v1(expected_issuer, expected_epoch,
                                     credential_id,
                                     CredentialStatusV1::valid);
    const auto statement = statement_digest(trusted_snapshot, credential_id,
                                            presentation_binding);
    auto& state = runtime();
    proofs::ReadBuffer reader(proof.proof);
    proofs::ZkProof<Field> decoded(*state.circuit, kRate, kQueries);
    if (!decoded.read(reader, proofs::p256_base) || reader.remaining() != 0)
      return Result<bool>::fail(ErrorCode::noncanonical,
                                "malformed or trailing status proof bytes");
    proofs::Dense<Field> public_inputs(1, state.circuit->npub_in);
    if (!fill_public(public_inputs, leaf, trusted_snapshot.root))
      return Result<bool>::fail(ErrorCode::malformed,
                                "status public input encoding failed");
    proofs::Transcript transcript(statement.data(), statement.size());
    proofs::ZkVerifier<Field, ReedSolomon> verifier(
        *state.circuit, state.reed_solomon, kRate, kQueries,
        proofs::p256_base);
    verifier.recv_commitment(decoded, transcript);
    if (!verifier.verify(decoded, public_inputs, transcript))
      return Result<bool>::fail(ErrorCode::malformed,
                                "status proof verification failed");
    return Result<bool>::ok(true);
  } catch (const std::exception&) {
    return Result<bool>::fail(ErrorCode::malformed,
                              "status proof verification failed");
  }
}

}  // namespace sd_jwt_zk
