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
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/resource.h>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mac/mac_circuit.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "sd_jwt_zk/holder_bridge_mac_relation.h"

namespace {
using Field = proofs::Fp256Base;
using Field2 = proofs::Fp2<Field>;
using FftFactory = proofs::FFTExtConvolutionFactory<Field, Field2>;
using ReedSolomon = proofs::ReedSolomonFactory<Field, FftFactory>;
using GF = proofs::GF2_128<>;
using GfElt = GF::Elt;
constexpr std::size_t kValues = 3;
constexpr std::size_t kTags = kValues * 2;
constexpr std::size_t kRate = 4;
constexpr std::size_t kQueries = 32;
constexpr std::uint64_t kCredentialDomain = 0x43524544454e5449ULL;
constexpr std::uint64_t kKbDomain = 0x4b422d4a57542d31ULL;
static_assert(sd_jwt_zk::HolderBridgeMacRelation<
                  proofs::Logic<Field, proofs::CompilerBackend<Field>>>::kTags == kTags);

struct CircuitRuntime {
  Field2 extension{proofs::p256_base};
  Field2::Elt omega;
  FftFactory fft;
  ReedSolomon rs;
  std::unique_ptr<proofs::Circuit<Field>> credential;
  std::unique_ptr<proofs::Circuit<Field>> kb;
  std::size_t credential_terms{};
  std::size_t kb_terms{};

  CircuitRuntime()
      : omega(extension.of_string(
            "112649224146410281873500457609690258373018840430489408729223714171582664680802",
            "84087994358540907695740461427818660560182168997182378749313018254450460212908")),
        fft(proofs::p256_base, extension, omega, 1ull << 31),
        rs(fft, proofs::p256_base), credential(build(kCredentialDomain,
        &credential_terms)), kb(build(kKbDomain, &kb_terms)) {}

  static std::unique_ptr<proofs::Circuit<Field>> build(std::uint64_t domain,
                                                        std::size_t* terms) {
    using Backend = proofs::CompilerBackend<Field>;
    using Logic = proofs::Logic<Field, Backend>;
    using Mac = proofs::MAC<Logic, proofs::BitPlucker<Logic, 2>>;
    proofs::QuadCircuit<Field> q(proofs::p256_base);
    Backend backend(&q);
    Logic logic(&backend, proofs::p256_base);
    const auto component_domain = logic.eltw_input();
    std::array<Logic::v128, kTags> tags{};
    for (auto& tag : tags) tag = logic.vinput<128>();
    const auto av = logic.vinput<128>();
    q.private_input();
    std::array<Logic::EltW, kValues> values{};
    std::array<Mac::Witness, kValues> witnesses{};
    for (std::size_t i = 0; i < kValues; ++i) {
      values[i] = logic.eltw_input();
      witnesses[i].input(logic);
    }
    logic.assert_eq(component_domain,
                    logic.konst(Field::Elt(Field::N(domain))));
    Mac mac(logic);
    const Field::N bound(proofs::Fp256Reduce::kModulus);
    for (std::size_t i = 0; i < kValues; ++i)
      mac.verify_mac(values[i], &tags[i * 2], av, witnesses[i], bound);
    auto circuit = q.mkcircuit(1);
    *terms = circuit->nterms();
    return circuit;
  }
};

CircuitRuntime& runtime() {
  static CircuitRuntime value;
  return value;
}

struct WitnessState {
  std::array<std::array<std::uint8_t, 32>, kValues> bytes{};
  std::array<Field::Elt, kValues> values{};
  std::array<std::array<GfElt, 2>, kValues> ap{};
};

struct BridgePair {
  std::array<GfElt, kTags> tags{};
  GfElt av{};
  proofs::ZkProof<Field> credential;
  proofs::ZkProof<Field> kb;
  std::vector<std::uint8_t> manifest;

  explicit BridgePair(const CircuitRuntime& r)
      : credential(*r.credential, kRate, kQueries), kb(*r.kb, kRate, kQueries) {}
};

std::vector<std::uint8_t> manifest(const CircuitRuntime& r) {
  static constexpr char kPrefix[] = "sd-jwt-zk/holder-bridge/v1";
  std::vector<std::uint8_t> out(kPrefix, kPrefix + sizeof(kPrefix) - 1);
  out.insert(out.end(), r.credential->id, r.credential->id + 32);
  out.insert(out.end(), r.kb->id, r.kb->id + 32);
  static constexpr char kRequest[] = "aud=bridge.example;nonce=bridge-nonce;schema=xyh";
  out.insert(out.end(), kRequest, kRequest + sizeof(kRequest) - 1);
  return out;
}

WitnessState make_witness(proofs::SecureRandomEngine& rng) {
  WitnessState state;
  proofs::MACReference<GF> mac;
  for (std::size_t i = 0; i < kValues; ++i) {
    rng.bytes(state.bytes[i].data(), state.bytes[i].size());
    // Keep every 256-bit message in the MAC circuit's canonical field range.
    state.bytes[i][0] = 0;
    state.values[i] = proofs::p256_base.of_bytes_field(state.bytes[i].data()).value();
    mac.sample(state.ap[i].data(), state.ap[i].size(), &rng);
  }
  return state;
}

void fill_gf(const GfElt& value, proofs::DenseFiller<Field>& filler) {
  proofs::fill_gf2k<GF, Field>(value, filler, proofs::p256_base);
}

void fill_public(proofs::Dense<Field>& dense, std::uint64_t domain,
                 const std::array<GfElt, kTags>& tags, const GfElt& av) {
  proofs::DenseFiller<Field> filler(dense);
  filler.push_back(proofs::p256_base.one());
  filler.push_back(Field::Elt(Field::N(domain)));
  for (const auto& tag : tags) fill_gf(tag, filler);
  fill_gf(av, filler);
}

void fill_full(proofs::Dense<Field>& dense, const proofs::Circuit<Field>& circuit,
               std::uint64_t domain, const WitnessState& state,
               const std::array<GfElt, kTags>& tags, const GfElt& av) {
  proofs::DenseFiller<Field> filler(dense);
  filler.push_back(proofs::p256_base.one());
  filler.push_back(Field::Elt(Field::N(domain)));
  for (const auto& tag : tags) fill_gf(tag, filler);
  fill_gf(av, filler);
  GF gf;
  for (std::size_t i = 0; i < kValues; ++i) {
    filler.push_back(state.values[i]);
    proofs::MacWitness<Field> witness(proofs::p256_base, gf);
    witness.compute_witness(state.ap[i].data(), state.bytes[i].data());
    witness.fill_witness(filler);
  }
  if (filler.size() != circuit.ninputs) throw std::runtime_error("dense layout mismatch");
}

std::array<GfElt, kTags> macs_for(const WitnessState& state, const GfElt& av) {
  std::array<GfElt, kTags> tags{};
  proofs::MACReference<GF> mac;
  for (std::size_t i = 0; i < kValues; ++i)
    mac.compute(&tags[i * 2], av, state.ap[i].data(),
                const_cast<std::uint8_t*>(state.bytes[i].data()));
  return tags;
}

BridgePair prove_pair(const WitnessState& credential_state,
                      const WitnessState& kb_state) {
  auto& r = runtime();
  BridgePair pair(r);
  pair.manifest = manifest(r);
  proofs::SecureRandomEngine rng;
  std::array<GfElt, kTags> zero_tags{};
  GF gf;
  proofs::Dense<Field> credential_dense(1, r.credential->ninputs);
  proofs::Dense<Field> kb_dense(1, r.kb->ninputs);
  fill_full(credential_dense, *r.credential, kCredentialDomain,
            credential_state, zero_tags, gf.zero());
  fill_full(kb_dense, *r.kb, kKbDomain, kb_state, zero_tags, gf.zero());
  proofs::Transcript transcript(pair.manifest.data(), pair.manifest.size());
  proofs::ZkProver<Field, ReedSolomon> credential_prover(*r.credential,
                                                           proofs::p256_base, r.rs);
  proofs::ZkProver<Field, ReedSolomon> kb_prover(*r.kb, proofs::p256_base, r.rs);
  credential_prover.commit(pair.credential, credential_dense, transcript, rng);
  kb_prover.commit(pair.kb, kb_dense, transcript, rng);
  std::array<std::uint8_t, GF::kBytes> av_bytes{};
  transcript.bytes(av_bytes.data(), av_bytes.size());
  pair.av = gf.of_bytes_field(av_bytes.data()).value();
  pair.tags = macs_for(credential_state, pair.av);
  // The state is deliberately shared: a mixed hidden x/y/hash cannot satisfy
  // both components under the tags produced after both commitments.
  const auto kb_tags = macs_for(kb_state, pair.av);
  if (kb_tags != pair.tags) throw std::runtime_error("bridge witnesses differ");
  fill_public(credential_dense, kCredentialDomain, pair.tags, pair.av);
  fill_public(kb_dense, kKbDomain, pair.tags, pair.av);
  if (!credential_prover.prove(pair.credential, credential_dense, transcript) ||
      !kb_prover.prove(pair.kb, kb_dense, transcript))
    throw std::runtime_error("bridge proof failed");
  return pair;
}

bool verify_components(const BridgePair& pair, const proofs::ZkProof<Field>& credential,
                       const proofs::ZkProof<Field>& kb, bool reverse = false) {
  auto& r = runtime();
  if (pair.manifest != manifest(r)) return false;
  proofs::Dense<Field> credential_public(1, r.credential->npub_in);
  proofs::Dense<Field> kb_public(1, r.kb->npub_in);
  fill_public(credential_public, kCredentialDomain, pair.tags, pair.av);
  fill_public(kb_public, kKbDomain, pair.tags, pair.av);
  proofs::Transcript transcript(pair.manifest.data(), pair.manifest.size());
  proofs::ZkVerifier<Field, ReedSolomon> credential_verifier(
      *r.credential, r.rs, kRate, kQueries, proofs::p256_base);
  proofs::ZkVerifier<Field, ReedSolomon> kb_verifier(*r.kb, r.rs, kRate,
                                                      kQueries, proofs::p256_base);
  if (reverse) {
    credential_verifier.recv_commitment(kb, transcript);
    kb_verifier.recv_commitment(credential, transcript);
  } else {
    credential_verifier.recv_commitment(credential, transcript);
    kb_verifier.recv_commitment(kb, transcript);
  }
  GF gf;
  std::array<std::uint8_t, GF::kBytes> av_bytes{};
  transcript.bytes(av_bytes.data(), av_bytes.size());
  if (gf.of_bytes_field(av_bytes.data()).value() != pair.av) return false;
  return credential_verifier.verify(credential, credential_public, transcript) &&
         kb_verifier.verify(kb, kb_public, transcript);
}

bool verify_pair(const BridgePair& pair, bool reverse = false) {
  return verify_components(pair, pair.credential, pair.kb, reverse);
}

std::vector<std::uint8_t> serialized_proofs(const BridgePair& pair) {
  std::vector<std::uint8_t> out;
  pair.credential.write(out, proofs::p256_base);
  pair.kb.write(out, proofs::p256_base);
  return out;
}
}  // namespace

int main() {
  try {
    const auto construction_start = std::chrono::steady_clock::now();
    auto& r = runtime();
    const auto constructed = std::chrono::steady_clock::now();
    proofs::SecureRandomEngine rng;
    const auto shared = make_witness(rng);
    const auto prove_start = std::chrono::steady_clock::now();
    auto pair = prove_pair(shared, shared);
    const auto proved = std::chrono::steady_clock::now();
    if (!verify_pair(pair)) throw std::runtime_error("positive bridge rejected");
    const auto verified = std::chrono::steady_clock::now();
    bool mixed_witness_rejected = false;
    try {
      (void)prove_pair(make_witness(rng), make_witness(rng));
    } catch (const std::exception&) {
      mixed_witness_rejected = true;
    }
    const auto repeated = prove_pair(shared, shared);
    const auto second_witness = make_witness(rng);
    const auto second = prove_pair(second_witness, second_witness);
    GF gf;
    auto changed_tag = pair; changed_tag.tags[0] = gf.addf(changed_tag.tags[0], gf.one());
    auto changed_av = pair; changed_av.av = gf.addf(changed_av.av, gf.one());
    auto changed_manifest = pair; changed_manifest.manifest.back() ^= 1;
    auto changed_circuit_id = pair;
    constexpr std::size_t kManifestPrefix = sizeof("sd-jwt-zk/holder-bridge/v1") - 1;
    changed_circuit_id.manifest[kManifestPrefix] ^= 1;
    if (!mixed_witness_rejected || !verify_pair(repeated) ||
        serialized_proofs(pair) == serialized_proofs(repeated) ||
        verify_components(pair, pair.credential, second.kb) ||
        verify_pair(changed_tag) || verify_pair(changed_av) ||
        verify_pair(changed_manifest) || verify_pair(changed_circuit_id) ||
        verify_pair(pair, true))
      throw std::runtime_error("bridge substitution accepted");
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    std::cout << "credential-inputs=" << r.credential->ninputs
              << " credential-terms=" << r.credential_terms
              << " kb-inputs=" << r.kb->ninputs
              << " kb-terms=" << r.kb_terms
              << " proof-bytes=" << serialized_proofs(pair).size()
              << " construct-ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(constructed-construction_start).count()
              << " prove-ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(proved-prove_start).count()
              << " verify-ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(verified-proved).count()
              << " peak-rss-kb=" << usage.ru_maxrss
              << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
