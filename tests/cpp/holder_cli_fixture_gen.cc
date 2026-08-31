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

#include <array>
#include <fstream>
#include <string>

#include "nested_es256_fixture.h"
#include "sd_jwt_zk/holder_bound_proof.h"

namespace {
void hex_key(const std::string& path, const sd_jwt_zk::P256Key& key) {
  std::ofstream out(path); constexpr char hex[] = "0123456789abcdef";
  for (const auto byte : key.x) out << hex[byte >> 4] << hex[byte & 15];
  for (const auto byte : key.y) out << hex[byte >> 4] << hex[byte & 15];
}
}

int main(int argc, char** argv) {
  if (argc < 2 || argc > 3) return 2;
  const std::string nonce = argc == 3 ? argv[2] : "challenge-0001";
  if (nonce.size() != 14) return 2;
  constexpr char object[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
  constexpr char array[] = "WyJhcnJheTAwMSIsIml0ZW0iXQ";
  constexpr char issuer_header[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
  constexpr char kb_header[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9";
  constexpr char holder_scalar[] = "6f1d2c3b4a59687766554433221100ffeeddccbbaa9988776655443322110099";
  auto digest=[](std::string_view value){auto h=sd_jwt_zk::sha256_ascii(value);return sd_jwt_zk::base64url_encode({h.begin(),h.end()});};
  std::array<unsigned char,64> raw{}; sd_jwt_zk::P256Key holder{};
  if (!sd_jwt_zk::test::sign_nested_fixture_es256("holder", raw, &holder, holder_scalar)) return 2;
  const auto x=sd_jwt_zk::base64url_encode({holder.x.begin(),holder.x.end()});
  const auto y=sd_jwt_zk::base64url_encode({holder.y.begin(),holder.y.end()});
  const std::string payload_json="{\"_sd\":[\""+digest(object)+"\"],\"items\":[{\"...\":\""+digest(array)+"\"}],\"iss\":\"https://issuer.example\",\"vct\":\"example\",\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""+x+"\",\"y\":\""+y+"\"}}}";
  const auto payload=sd_jwt_zk::base64url_encode({payload_json.begin(),payload_json.end()});
  const std::string issuer_signing=std::string(issuer_header)+"."+payload;
  sd_jwt_zk::P256Key issuer{};
  if (!sd_jwt_zk::test::sign_nested_fixture_es256(issuer_signing,raw,&issuer)) return 2;
  const std::string compact=issuer_signing+"."+sd_jwt_zk::base64url_encode({raw.begin(),raw.end()});
  const std::string credential=compact+"~"+object+"~"+array+"~";
  const auto hash=sd_jwt_zk::sha256_ascii(credential);
  const std::string kb_json="{\"aud\":\"https://verifier.example\",\"nonce\":\""+nonce+"\",\"iat\":1777334400,\"sd_hash\":\""+sd_jwt_zk::base64url_encode({hash.begin(),hash.end()})+"\"}";
  const std::string kb_signing=std::string(kb_header)+"."+sd_jwt_zk::base64url_encode({kb_json.begin(),kb_json.end()});
  if (!sd_jwt_zk::test::sign_nested_fixture_es256(kb_signing,raw,nullptr,holder_scalar)) return 2;
  const std::string presentation=credential+kb_signing+"."+sd_jwt_zk::base64url_encode({raw.begin(),raw.end()});
  sd_jwt_zk::Request request{}; request.audience="https://verifier.example"; request.nonce=nonce;
  request.time_min=1777334300; request.time_max=1777334500; request.policy=sd_jwt_zk::holder_bound_policy_v1();
  request.policy_result=sd_jwt_zk::holder_bound_true_policy_result_v1();
  request.trust_public.insert(request.trust_public.end(),issuer.x.begin(),issuer.x.end());
  request.trust_public.insert(request.trust_public.end(),issuer.y.begin(),issuer.y.end());
  const auto policy=sd_jwt_zk::holder_bound_verifier_policy_v1(request); request=policy.request;
  const auto encoded=sd_jwt_zk::encode_request(request); if(!encoded)return 2;
  const std::string dir=argv[1]; hex_key(dir+"/issuer.hex",issuer);
  std::ofstream(dir+"/presentation")<<presentation;
  std::ofstream challenge(dir+"/challenge",std::ios::binary);challenge.write(reinterpret_cast<const char*>(encoded.value->data()),encoded.value->size());
  return 0;
}
