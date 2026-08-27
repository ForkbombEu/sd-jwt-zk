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

Result<Bytes> encode_identity(const CircuitIdentity& value, const Limits& limits = {});
Result<CircuitIdentity> decode_identity(const Bytes& input, const Limits& limits = {});
Result<Bytes> encode_request(const Request& value, const Limits& limits = {});
Result<Request> decode_request(const Bytes& input, const Limits& limits = {});
Result<Bytes> encode_envelope(const Envelope& value, const Limits& limits = {});
Result<Envelope> decode_envelope(const Bytes& input, const Limits& limits = {});
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
std::array<std::uint8_t, 32> sha256_ascii(std::string_view input);
class SecretBytes { public: explicit SecretBytes(Bytes bytes = {}); ~SecretBytes(); SecretBytes(SecretBytes&&) noexcept; SecretBytes& operator=(SecretBytes&&) noexcept; SecretBytes(const SecretBytes&) = delete; SecretBytes& operator=(const SecretBytes&) = delete; const Bytes& view() const; private: Bytes bytes_; };
struct NativeWitness { CompactJws issuer; std::vector<std::string> disclosures; std::optional<CompactJws> kb_jwt; };
Result<NativeWitness> build_native_witness(std::string_view presentation, const Limits& limits = {});
bool native_parsing_is_not_proof_verification();
} // namespace sd_jwt_zk
