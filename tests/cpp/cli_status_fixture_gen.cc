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

#include <fstream>
#include <string>
#include <vector>

#include "sd_jwt_zk/flat_bearer_proof.h"
#include "nested_es256_fixture.h"

namespace {
constexpr char kHeader[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";
constexpr char kDisclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsInRydWUiXQ";
constexpr char kArrayDisclosure[] = "WyJhcnJheTAwMSIsIml0ZW0iXQ";
void write(const std::string& path, const std::vector<std::uint8_t>& bytes) { std::ofstream out(path, std::ios::binary); out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
}
int main(int argc, char** argv) {
  if (argc != 2) return 2;
  const std::string dir = argv[1];
  auto digest=[](std::string_view d){auto h=sd_jwt_zk::sha256_ascii(d);return sd_jwt_zk::base64url_encode({h.begin(),h.end()});};
  const std::string json="{\"_sd\":[\""+digest(kDisclosure)+"\"],\"items\":[{\"...\":\""+digest(kArrayDisclosure)+"\"}],\"iss\":\"https://issuer.example\",\"vct\":\"example\"}";
  const auto payload=sd_jwt_zk::base64url_encode({json.begin(),json.end()});
  const std::string signing=std::string(kHeader)+"."+payload;
  std::array<unsigned char,64> raw{};sd_jwt_zk::P256Key public_key{};
  if(!sd_jwt_zk::test::sign_nested_fixture_es256(signing,raw,&public_key))return 2;
  const auto key=sd_jwt_zk::Result<sd_jwt_zk::P256Key>::ok(public_key);
  const std::string presentation = signing+"."+sd_jwt_zk::base64url_encode({raw.begin(),raw.end()})+"~"+kDisclosure+"~"+kArrayDisclosure+"~";
  const auto witness = sd_jwt_zk::flat_bearer_witness_from_presentation(presentation, *key.value); if (!witness) return 2;
  const auto binding = sd_jwt_zk::status_credential_binding_v1(witness.value->signing_digest);
  std::vector<sd_jwt_zk::LocalStatusEntryV1> entries(4);
  for (std::size_t i=0;i<4;++i) { entries[i].credential_binding[0]=static_cast<std::uint8_t>(i+1); entries[i].status=sd_jwt_zk::CredentialStatusV1::revoked; }
  entries[1].credential_binding=binding; entries[1].status=sd_jwt_zk::CredentialStatusV1::valid;
  const auto issuer = sd_jwt_zk::status_issuer_v1(*key.value);
  const auto snapshot = sd_jwt_zk::build_local_status_snapshot_v1(issuer, 3, 100, 200, entries); if (!snapshot) return 2;
  const auto path = sd_jwt_zk::local_status_path_v1(*snapshot.value, 1); if (!path) return 2;
  std::ofstream key_out(dir+"/issuer.hex");
  const char* hex="0123456789abcdef"; for (auto byte: key.value->x) key_out<<hex[byte>>4]<<hex[byte&15]; for (auto byte: key.value->y) key_out<<hex[byte>>4]<<hex[byte&15];
  std::ofstream presentation_out(dir+"/presentation"); presentation_out<<presentation;
  std::ofstream nonce_out(dir+"/nonce"); nonce_out<<"cli-status-nonce";
  write(dir+"/status-policy", sd_jwt_zk::encode_status_policy_v1({snapshot.value->public_part}));
  std::vector<std::uint8_t> private_path{'S','P','W','1',1};
  for (const auto& sibling:*path.value) private_path.insert(private_path.end(), sibling.data, sibling.data+sibling.kLength);
  write(dir+"/status-witness", private_path);
  return 0;
}
