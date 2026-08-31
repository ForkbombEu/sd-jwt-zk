/*
 * Copyright (C) 2026 by The Forkbomb Company
 * designed, written and maintained by Denis Roio
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sd_jwt_zk/api.h"
#include "nested_es256_fixture.h"

#include <stdexcept>
#include <string>

namespace {
void require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
}  // namespace

int main() {
  try {
    constexpr char kDisclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
    constexpr char kArrayDisclosure[] = "WyJhcnJheTAwMSIsIml0ZW0iXQ";
    constexpr char kHeader[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
    constexpr char kKbHeader[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9";
    constexpr char kHolderScalar[] = "6f1d2c3b4a59687766554433221100ffeeddccbbaa9988776655443322110099";
    auto digest_text=[](std::string_view d){auto h=sd_jwt_zk::sha256_ascii(d);return sd_jwt_zk::base64url_encode({h.begin(),h.end()});};
    sd_jwt_zk::P256Key holder_key{};std::array<unsigned char,64> raw{};
    require(sd_jwt_zk::test::sign_nested_fixture_es256("holder",raw,&holder_key,kHolderScalar),"holder key fixture failed");
    const auto x=sd_jwt_zk::base64url_encode({holder_key.x.begin(),holder_key.x.end()});
    const auto y=sd_jwt_zk::base64url_encode({holder_key.y.begin(),holder_key.y.end()});
    const std::string payload_json="{\"_sd\":[\""+digest_text(kDisclosure)+"\"],\"items\":[{\"...\":\""+digest_text(kArrayDisclosure)+"\"}],\"iss\":\"https://issuer.example\",\"vct\":\"example\",\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""+x+"\",\"y\":\""+y+"\"}}}";
    const auto payload=sd_jwt_zk::base64url_encode({payload_json.begin(),payload_json.end()});
    const std::string issuer_signing=std::string(kHeader)+"."+payload;
    sd_jwt_zk::P256Key issuer_public{};require(sd_jwt_zk::test::sign_nested_fixture_es256(issuer_signing,raw,&issuer_public),"issuer signing failed");
    const std::string issuer_compact=issuer_signing+"."+sd_jwt_zk::base64url_encode({raw.begin(),raw.end()});
    const std::string presentation=issuer_compact+"~"+kDisclosure+"~"+kArrayDisclosure+"~";
    const auto presentation_hash=sd_jwt_zk::sha256_ascii(presentation);
    const std::string kb_json="{\"aud\":\"https://verifier.example\",\"nonce\":\"challenge-0001\",\"iat\":1777334400,\"sd_hash\":\""+sd_jwt_zk::base64url_encode({presentation_hash.begin(),presentation_hash.end()})+"\"}";
    const std::string kb_signing=std::string(kKbHeader)+"."+sd_jwt_zk::base64url_encode({kb_json.begin(),kb_json.end()});
    require(sd_jwt_zk::test::sign_nested_fixture_es256(kb_signing,raw,nullptr,kHolderScalar),"KB signing failed");
    const std::string kb_compact=kb_signing+"."+sd_jwt_zk::base64url_encode({raw.begin(),raw.end()});
    const auto issuer_key = sd_jwt_zk::Result<sd_jwt_zk::P256Key>::ok(issuer_public);
    const auto issuer = sd_jwt_zk::split_compact_jws(issuer_compact);
    const auto kb = sd_jwt_zk::split_compact_jws(kb_compact);
    require(issuer_key && issuer && kb, "integrated fixture syntax rejected");
    const auto issuer_payload = sd_jwt_zk::base64url_decode(issuer.value->payload);
    const auto issuer_signature = sd_jwt_zk::decode_es256_signature(issuer.value->signature);
    require(issuer_payload && issuer_signature, "issuer fixture encoding rejected");
    const auto credential = sd_jwt_zk::parse_restricted_issuer_payload(
        std::string_view(reinterpret_cast<const char*>(issuer_payload.value->data()),
                         issuer_payload.value->size()));
    require(credential && credential.value->holder_key,
            "issuer fixture did not authenticate canonical cnf");
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
    require(kb_claims.value->sd_hash == sd_jwt_zk::base64url_encode(
                sd_jwt_zk::Bytes(presentation_hash.begin(), presentation_hash.end())),
            "KB sd_hash does not bind exact presentation");
    require(sd_jwt_zk::verify_es256_signature(*credential.value->holder_key,
                                               kb_signing, *kb_signature.value),
            "KB signature not bound to issuer cnf");
    auto substituted = *credential.value->holder_key;
    substituted.x[0] ^= 1;
    require(!sd_jwt_zk::verify_es256_signature(substituted, kb_signing,
                                                *kb_signature.value),
            "substituted holder key accepted KB signature");
    auto issuer_mutated = issuer_compact;
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
