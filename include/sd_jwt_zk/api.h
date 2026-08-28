#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sd_jwt_zk {

enum class ErrorCode { malformed, limit, noncanonical, unsupported, utf8, secret };
struct Error { ErrorCode code; std::string message; };
template<class T> struct Result {
  std::optional<T> value; std::optional<Error> error;
  explicit operator bool() const { return value.has_value(); }
  static Result ok(T item) { return {std::move(item), std::nullopt}; }
  static Result fail(ErrorCode code, std::string message) { return {std::nullopt, Error{code, std::move(message)}}; }
};

using Bytes = std::vector<std::uint8_t>;
struct Limits { std::size_t max_input = 65536; std::size_t max_field = 4096; std::size_t max_proof = 1048576; };
enum class Binding : std::uint8_t { bearer = 1, holder_bound = 2 };
enum class Trust : std::uint8_t { exact_key = 1, registry = 2 };
struct CircuitIdentity { Binding binding; Trust trust; std::uint32_t capacity; std::array<std::uint8_t, 32> circuit_digest{}; std::string field; std::uint16_t ligero_rate{}; std::uint16_t query_count{}; };
struct Request { CircuitIdentity identity; std::string audience; std::string nonce; std::uint64_t time_min{}; std::uint64_t time_max{}; Bytes policy; Bytes policy_result; Bytes trust_public; Bytes status_public; };
struct Envelope { Request request; Bytes proof; };

// Holder evidence is intentionally a different wire format from Envelope.
// Its fixed component order is credential then KB; callers cannot pass an
// arbitrary vector and accidentally accept a bearer proof as holder evidence.
struct HolderBoundEnvelope {
  Request request;
  CircuitIdentity credential_identity;
  CircuitIdentity kb_identity;
  Bytes credential_commitment;
  Bytes kb_commitment;
  // Six GF(2^128) tags followed by the verifier challenge a_v.  These are
  // public only after both commitments have been absorbed into the ordered
  // transcript; their exact encoding stays component-independent here.
  Bytes bridge_public;
  Bytes credential_proof;
  Bytes kb_proof;
};

// Verification is deliberately an ordered operation.  Implementations receive
// the component role rather than an unlabelled proof vector, preventing a KB
// proof from being dispatched through the credential verifier.
enum class HolderComponent : std::uint8_t { credential = 1, kb = 2 };
class HolderBoundProofVerifierV1 {
 public:
  virtual ~HolderBoundProofVerifierV1() = default;
  virtual bool verify(HolderComponent component, const CircuitIdentity& identity,
                      const Request& request,
                      const Bytes& credential_commitment,
                      const Bytes& kb_commitment,
                      const Bytes& bridge_public, const Bytes& proof) = 0;
};
// The orchestrator below calls both commit methods before bridge_public(),
// then proves credential followed by KB.  Implementations may fork proof
// transcripts internally, but every fork receives the complete ordered
// commitment set and canonical request.
class HolderBoundProofProverV1 {
 public:
  virtual ~HolderBoundProofProverV1() = default;
  virtual Result<Bytes> commit(HolderComponent component,
                               const CircuitIdentity& identity,
                               const Request& request) = 0;
  virtual Result<Bytes> bridge_public(
      const Request& request, const CircuitIdentity& credential_identity,
      const CircuitIdentity& kb_identity,
      const Bytes& credential_commitment,
      const Bytes& kb_commitment) = 0;
  virtual Result<Bytes> prove(
      HolderComponent component, const CircuitIdentity& identity,
      const Request& request, const Bytes& credential_commitment,
      const Bytes& kb_commitment, const Bytes& bridge_public) = 0;
};
class HolderBoundReplayStoreV1 {
 public:
  virtual ~HolderBoundReplayStoreV1() = default;
  virtual bool consume(std::string_view audience, std::string_view nonce,
                       std::uint64_t expires_at) = 0;
};
struct HolderBoundVerifierPolicyV1 {
  Request request;
  CircuitIdentity credential_identity;
  CircuitIdentity kb_identity;
};

Result<Bytes> encode_identity(const CircuitIdentity& value, const Limits& limits = {});
Result<CircuitIdentity> decode_identity(const Bytes& input, const Limits& limits = {});
Result<Bytes> encode_request(const Request& value, const Limits& limits = {});
Result<Request> decode_request(const Bytes& input, const Limits& limits = {});
Result<Bytes> encode_envelope(const Envelope& value, const Limits& limits = {});
Result<Envelope> decode_envelope(const Bytes& input, const Limits& limits = {});
Result<Bytes> encode_holder_bound_envelope(const HolderBoundEnvelope& value,
                                           const Limits& limits = {});
Result<HolderBoundEnvelope> decode_holder_bound_envelope(
    const Bytes& input, const Limits& limits = {});
Result<HolderBoundEnvelope> prove_holder_bound_envelope_v1(
    const HolderBoundVerifierPolicyV1& request,
    HolderBoundProofProverV1& proof_prover, const Limits& limits = {});
Result<bool> verify_holder_bound_envelope_v1(
    const HolderBoundEnvelope& envelope,
    const HolderBoundVerifierPolicyV1& expected,
    std::uint64_t now, HolderBoundProofVerifierV1& proof_verifier,
    HolderBoundReplayStoreV1& replay_store, const Limits& limits = {});
std::array<std::uint8_t, 32> transcript_seed(const Request& request);

struct CompactJws { std::string protected_header; std::string payload; std::string signature; };
struct P256Signature { std::array<std::uint8_t, 32> r, s; };
struct P256Key { std::array<std::uint8_t, 32> x, y; };
Result<CompactJws> split_compact_jws(std::string_view input, const Limits& limits = {});
Result<Bytes> base64url_decode(std::string_view input, std::size_t limit = 65536);
std::string base64url_encode(const Bytes& input);
Result<P256Signature> decode_es256_signature(std::string_view input);
bool es256_signature_is_low_s(const P256Signature& signature);
Result<P256Key> decode_p256_jwk(std::string_view x, std::string_view y);
// Validates the complete affine P-256 public point, not just its byte shape.
// Callers must still keep a holder key private when it is credential-bound.
bool p256_key_is_valid(const P256Key& key);
bool verify_es256_signature(const P256Key& key, std::string_view signing_input,
                            const P256Signature& signature);
std::array<std::uint8_t, 32> sha256_ascii(std::string_view input);
class SecretBytes { public: explicit SecretBytes(Bytes bytes = {}); ~SecretBytes(); SecretBytes(SecretBytes&&) noexcept; SecretBytes& operator=(SecretBytes&&) noexcept; SecretBytes(const SecretBytes&) = delete; SecretBytes& operator=(const SecretBytes&) = delete; const Bytes& view() const; private: Bytes bytes_; };
struct NativeWitness { CompactJws issuer; std::vector<std::string> disclosures; std::optional<CompactJws> kb_jwt; };
Result<NativeWitness> build_native_witness(std::string_view presentation, const Limits& limits = {});
bool native_parsing_is_not_proof_verification();

struct RestrictedIssuerPayload {
  std::string digest;
  std::string issuer;
  std::string vct;
  bool explicit_sha256{};
  // Absent for bearer credentials.  Holder-bound callers require this member.
  std::optional<P256Key> holder_key;
};
Result<RestrictedIssuerPayload> parse_restricted_issuer_payload(
    std::string_view json, const Limits& limits = {});

struct RestrictedKbJwtPayload {
  std::string audience;
  std::string nonce;
  std::uint64_t issued_at{};
  std::string sd_hash;
};
Result<RestrictedKbJwtPayload> parse_restricted_kb_jwt_payload(
    std::string_view json, const Limits& limits = {});

} // namespace sd_jwt_zk
