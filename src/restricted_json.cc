#include "sd_jwt_zk/api.h"

#include <algorithm>
#include <charconv>

namespace sd_jwt_zk {
namespace {
bool safe_string(std::string_view value) {
  return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) {
    return c >= 0x21 && c <= 0x7e && c != '"' && c != '\\';
  });
}
bool b64url(std::string_view value) {
  return std::all_of(value.begin(), value.end(), [](char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
  });
}
bool consume(std::string_view input, std::size_t& at, std::string_view literal) {
  if (input.substr(at, literal.size()) != literal) return false;
  at += literal.size();
  return true;
}
bool quoted(std::string_view input, std::size_t& at, std::string& out, std::size_t max) {
  if (at >= input.size() || input[at++] != '"') return false;
  const auto end = input.find('"', at);
  if (end == std::string_view::npos || end - at > max) return false;
  out.assign(input.substr(at, end - at));
  at = end + 1;
  return safe_string(out);
}
}  // namespace

Result<RestrictedIssuerPayload> parse_restricted_issuer_payload(
    std::string_view json, const Limits& limits) {
  if (json.empty() || json.size() > limits.max_field) {
    return Result<RestrictedIssuerPayload>::fail(ErrorCode::limit, "restricted payload limit");
  }
  std::size_t at = 0;
  RestrictedIssuerPayload result;
  // The V1 grammar deliberately has exactly one member order.  This makes
  // byte ranges unique and rejects whitespace, escapes, duplicate keys,
  // nested objects and hidden trailing content before circuit construction.
  if (!consume(json, at, "{\"_sd\":[") || !quoted(json, at, result.digest, 43) ||
      result.digest.size() != 43 || !b64url(result.digest) ||
      !consume(json, at, "],\"iss\":" ) || !quoted(json, at, result.issuer, limits.max_field) ||
      !consume(json, at, ",\"vct\":" ) || !quoted(json, at, result.vct, limits.max_field)) {
    return Result<RestrictedIssuerPayload>::fail(ErrorCode::malformed, "restricted payload grammar");
  }
  if (consume(json, at, ",\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":")) {
    std::string x, y;
    if (!quoted(json, at, x, 43) || x.size() != 43 ||
        !consume(json, at, ",\"y\":" ) || !quoted(json, at, y, 43) ||
        y.size() != 43 || !consume(json, at, "}}")) {
      return Result<RestrictedIssuerPayload>::fail(ErrorCode::malformed, "restricted cnf jwk grammar");
    }
    auto key = decode_p256_jwk(x, y);
    if (!key || !p256_key_is_valid(*key.value))
      return Result<RestrictedIssuerPayload>::fail(ErrorCode::malformed, "invalid cnf P-256 key");
    result.holder_key = *key.value;
  }
  if (consume(json, at, ",\"_sd_alg\":\"sha-256\"")) result.explicit_sha256 = true;
  if (!consume(json, at, "}") || at != json.size()) {
    return Result<RestrictedIssuerPayload>::fail(ErrorCode::malformed, "restricted payload trailing or algorithm");
  }
  return Result<RestrictedIssuerPayload>::ok(std::move(result));
}

Result<RestrictedKbJwtPayload> parse_restricted_kb_jwt_payload(
    std::string_view json, const Limits& limits) {
  if (json.empty() || json.size() > limits.max_field)
    return Result<RestrictedKbJwtPayload>::fail(ErrorCode::limit, "restricted KB-JWT payload limit");
  RestrictedKbJwtPayload result;
  std::size_t at = 0;
  if (!consume(json, at, "{\"aud\":" ) ||
      !quoted(json, at, result.audience, limits.max_field) ||
      !consume(json, at, ",\"nonce\":" ) ||
      !quoted(json, at, result.nonce, limits.max_field) ||
      !consume(json, at, ",\"iat\":"))
    return Result<RestrictedKbJwtPayload>::fail(ErrorCode::malformed, "restricted KB-JWT payload grammar");
  const auto number_start = at;
  while (at < json.size() && json[at] >= '0' && json[at] <= '9') ++at;
  if (at == number_start || (at - number_start > 1 && json[number_start] == '0') ||
      std::from_chars(json.data() + number_start, json.data() + at, result.issued_at).ec != std::errc{} ||
      !consume(json, at, ",\"sd_hash\":" ) ||
      !quoted(json, at, result.sd_hash, 43) || result.sd_hash.size() != 43 ||
      !b64url(result.sd_hash) || !consume(json, at, "}") || at != json.size())
    return Result<RestrictedKbJwtPayload>::fail(ErrorCode::malformed, "restricted KB-JWT payload grammar");
  return Result<RestrictedKbJwtPayload>::ok(std::move(result));
}
}  // namespace sd_jwt_zk
