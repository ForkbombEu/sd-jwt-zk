#include "sd_jwt_zk/api.h"

#include <stdexcept>
#include <string>

namespace {
void require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
}  // namespace

int main() {
  try {
    constexpr char kIssuerX[] = "mghCtkDvYlhoIJv3V9ntUSzKasQTW2-ieOZCkmyat6Q";
    constexpr char kIssuerY[] = "WZmOD4TDO1MqiMdF-bLKRzqFOsZ4l-lrOBo5vNcVTAQ";
    constexpr char kIssuer[] =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ."
        "eyJfc2QiOlsiRUtEMklOR1JlWkZtQXQ3LXZBbmNlY2VkUVRvb3gzNTlGR1hZR2dZUUJMOCJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJkR1dlTzhURGpONm9DdkhKQ3VRX2gxaWEtc2dvV3dZWXVjVGVzeHlTc2hnIiwieSI6IjdJdzZfQVJGVWF0aTFwemVWdzdYQUVIVkwxcVpMVldkNGkxMzJUNGVibm8ifX19."
        "zC41XCiPUiMI38m0IrKCHoC0XmOW6I0N0Sx5QEUKKmTXNbvW0DxK_4zXPqai0K1-vi0MwVzUl835id3-znLG0w";
    constexpr char kDisclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
    constexpr char kKbJwt[] =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9."
        "eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUiLCJub25jZSI6ImNoYWxsZW5nZS0wMDAxIiwiaWF0IjoxNzc3MzM0NDAwLCJzZF9oYXNoIjoiNERvQ0R1X21JR0xaUGJ3aGhqVGlzWFgteWp0eUZ5em50TjcwV0dvYncyZyJ9."
        "cFheyMPYhStqIfLtdZQS4yWByMqI-9YUGUakJafMh7gFVvMPy0lXS3l8QCDP_IBATxcl8lWylqzc9seGMvQTwA";
    const auto issuer_key = sd_jwt_zk::decode_p256_jwk(kIssuerX, kIssuerY);
    const auto issuer = sd_jwt_zk::split_compact_jws(kIssuer);
    const auto kb = sd_jwt_zk::split_compact_jws(kKbJwt);
    require(issuer_key && issuer && kb, "integrated fixture syntax rejected");
    const auto issuer_payload = sd_jwt_zk::base64url_decode(issuer.value->payload);
    const auto issuer_signature = sd_jwt_zk::decode_es256_signature(issuer.value->signature);
    require(issuer_payload && issuer_signature, "issuer fixture encoding rejected");
    const auto credential = sd_jwt_zk::parse_restricted_issuer_payload(
        std::string_view(reinterpret_cast<const char*>(issuer_payload.value->data()),
                         issuer_payload.value->size()));
    require(credential && credential.value->holder_key,
            "issuer fixture did not authenticate canonical cnf");
    const std::string issuer_signing = issuer.value->protected_header + "." + issuer.value->payload;
    require(sd_jwt_zk::verify_es256_signature(*issuer_key.value, issuer_signing,
                                               *issuer_signature.value),
            "issuer signature rejected");
    const auto kb_payload = sd_jwt_zk::base64url_decode(kb.value->payload);
    const auto kb_signature = sd_jwt_zk::decode_es256_signature(kb.value->signature);
    require(kb_payload && kb_signature, "KB fixture encoding rejected");
    const auto kb_claims = sd_jwt_zk::parse_restricted_kb_jwt_payload(
        std::string_view(reinterpret_cast<const char*>(kb_payload.value->data()),
                         kb_payload.value->size()));
    require(static_cast<bool>(kb_claims), "KB payload rejected");
    const std::string presentation = std::string(kIssuer) + "~" + kDisclosure + "~";
    const auto presentation_hash = sd_jwt_zk::sha256_ascii(presentation);
    require(kb_claims.value->sd_hash == sd_jwt_zk::base64url_encode(
                sd_jwt_zk::Bytes(presentation_hash.begin(), presentation_hash.end())),
            "KB sd_hash does not bind exact presentation");
    const std::string kb_signing = kb.value->protected_header + "." + kb.value->payload;
    require(sd_jwt_zk::verify_es256_signature(*credential.value->holder_key,
                                               kb_signing, *kb_signature.value),
            "KB signature not bound to issuer cnf");
    auto substituted = *credential.value->holder_key;
    substituted.x[0] ^= 1;
    require(!sd_jwt_zk::verify_es256_signature(substituted, kb_signing,
                                                *kb_signature.value),
            "substituted holder key accepted KB signature");
    auto issuer_mutated = std::string(kIssuer);
    // This byte belongs to the base64url-encoded issuer payload (and thus to
    // the authenticated cnf-containing issuer JWS), while preserving compact
    // syntax so the signature check is the rejecting condition.
    issuer_mutated[120] = issuer_mutated[120] == 'A' ? 'B' : 'A';
    const auto altered = sd_jwt_zk::split_compact_jws(issuer_mutated);
    require(static_cast<bool>(altered), "mutated issuer syntax unexpectedly invalid");
    const auto altered_sig = sd_jwt_zk::decode_es256_signature(altered.value->signature);
    require(altered_sig && !sd_jwt_zk::verify_es256_signature(
                *issuer_key.value,
                altered.value->protected_header + "." + altered.value->payload,
                *altered_sig.value), "mutated cnf remained issuer-authenticated");
    return 0;
  } catch (const std::exception&) {
    return 1;
  }
}
