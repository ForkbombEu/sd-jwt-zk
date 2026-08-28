#include "sd_jwt_zk/holder_issuer_jws_relation.h"
#include "sd_jwt_zk/flat_bearer_proof.h"

#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {
using Field = proofs::Fp256Base;
using Backend = proofs::CompilerBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Relation = sd_jwt_zk::HolderIssuerJwsRelation<Logic, 10, 102, 472, 384>;
using Base = sd_jwt_zk::IssuerJwsRelation<Logic, 10, 102, 472, 384, 9>;
using Sha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;
using Ecdsa = proofs::VerifyCircuit<Logic, Field, proofs::P256>;

void compile_bridge() {
  const auto start = std::chrono::steady_clock::now();
  proofs::QuadCircuit<Field> quad(proofs::p256_base);
  Backend backend(&quad);
  Logic logic(&backend, proofs::p256_base);
  std::array<Logic::v8, 640> sha_input{};
  for (auto& byte : sha_input) byte = logic.template vinput<8>();
  std::array<Sha::BlockWitness, 10> sha_witness{};
  for (auto& block : sha_witness) block.input(logic);
  Logic::v256 digest_bits{};
  for (auto& bit : digest_bits) bit = logic.input();
  std::array<Logic::v8, 102> header_b64{};
  std::array<Logic::v8, 76> header_decoded{};
  std::array<Logic::v8, 472> payload_b64{};
  std::array<Logic::v8, 354> payload_decoded{};
  std::array<Logic::v8, 384> payload_padded{};
  for (auto& byte : header_b64) byte = logic.template vinput<8>();
  for (auto& byte : header_decoded) byte = logic.template vinput<8>();
  for (auto& byte : payload_b64) byte = logic.template vinput<8>();
  for (auto& byte : payload_decoded) byte = logic.template vinput<8>();
  for (auto& byte : payload_padded) byte = logic.template vinput<8>();
  typename Logic::template bitvec<9> header_length{}, payload_length{}, issuer_length{},
      vct_length{}, decoded_length{};
  for (auto* index : {&header_length, &payload_length, &issuer_length,
                      &vct_length, &decoded_length})
    for (auto& bit : *index) bit = logic.input();
  const auto explicit_sha = logic.input();
  const auto issuer_x = logic.eltw_input();
  const auto issuer_y = logic.eltw_input();
  const auto holder_x = logic.eltw_input();
  const auto holder_y = logic.eltw_input();
  std::array<Logic::v8, 86> signature_b64{};
  for (auto& byte : signature_b64) byte = logic.template vinput<8>();
  std::array<Logic::v8, 662> compact{};
  for (auto& byte : compact) byte = logic.template vinput<8>();
  typename Logic::template bitvec<9> compact_length{};
  for (auto& bit : compact_length) bit = logic.input();
  const auto digest = logic.eltw_input();
  Ecdsa::Witness ecdsa{};
  ecdsa.input(logic);
  typename Base::Input input{sha_input, sha_witness, digest_bits, header_b64,
      header_decoded, payload_b64, payload_decoded, header_length,
      payload_length, payload_padded, issuer_length, vct_length,
      decoded_length, explicit_sha, issuer_x, issuer_y, digest, ecdsa, 10};
  Base base(logic);
  base.assert_sha(input);
  const auto sha = std::chrono::steady_clock::now();
  std::cerr << "holder-issuer/sha-ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(sha - start).count() << '\n';
  base.assert_compact_binding(input);
  base.decode_payload_bucket(input.payload_b64, input.payload_b64_length, input.payload_decoded);
  base.assert_padded_payload(input.payload_decoded, input.payload_padded);
  base.assert_header(input, input.header_decoded);
  const auto issuer_shape = std::chrono::steady_clock::now();
  std::cerr << "holder-issuer/shared-json-ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(issuer_shape - sha).count() << '\n';
  Relation relation(logic);
  relation.assert_cnf_binding(input, holder_x, holder_y);
  relation.assert_full_compact_binding(input, signature_b64, compact,
                                       compact_length);
  const auto cnf = std::chrono::steady_clock::now();
  std::cerr << "holder-issuer/cnf-ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(cnf - issuer_shape).count() << '\n';
  const auto signature_r = logic.eltw_input();
  const auto signature_s = logic.eltw_input();
  sd_jwt_zk::CompactEs256SignatureRelation<Logic>(logic).assert_decode(
      signature_b64, signature_r, signature_s);
  base.assert_ecdsa_bound(input, signature_r, signature_s);
  const auto asserted = std::chrono::steady_clock::now();
  std::cerr << "holder-issuer/ecdsa-ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(asserted - cnf).count()
            << " inputs=" << quad.ninput_ << '\n';
  const auto circuit = quad.mkcircuit(1);
  const auto compiled = std::chrono::steady_clock::now();
  std::cerr << "holder-issuer/mkcircuit-ms="
            << std::chrono::duration_cast<std::chrono::milliseconds>(compiled - asserted).count()
            << " inputs=" << circuit->ninputs << " terms=" << quad.nquad_terms_ << '\n';
  if (circuit->ninputs == 0 || circuit->npub_in != 0)
    throw std::runtime_error("holder issuer bridge did not compile");
}

void compile_bearer_baseline() {
  const auto start = std::chrono::steady_clock::now();
  proofs::QuadCircuit<Field> quad(proofs::p256_base);
  const auto circuit = sd_jwt_zk::BuildFlatBearerCircuitV1(&quad);
  const auto done = std::chrono::steady_clock::now();
  std::cerr << "flat-bearer/mkcircuit-ms="
            << std::chrono::duration_cast<std::chrono::milliseconds>(done - start).count()
            << " inputs=" << circuit->ninputs << " terms=" << quad.nquad_terms_ << '\n';
}
}  // namespace

int main() {
  try {
    if (std::getenv("SD_JWT_ZK_MEASURE_BEARER") != nullptr)
      compile_bearer_baseline();
    compile_bridge();
    return 0;
  } catch (const std::exception&) {
    return 1;
  }
}
