#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "ec/p256.h"
#include "sd_jwt_zk/compact_opening_bridge_relation.h"
#include "sd_jwt_zk/api.h"
using Field=proofs::Fp256Base; using Backend=proofs::EvaluationBackend<Field>; using Logic=proofs::Logic<Field,Backend>;
using Bridge=sd_jwt_zk::CompactOpeningBridgeRelation<Logic,4,8>;
using Sha=proofs::FlatSHA256Circuit<Logic,proofs::BitPlucker<Logic,4>>;
bool accepts(bool wrong_digest,bool splice) {
  const Field f; Backend backend(f,false); Logic l(&backend,f);
  const char* h="e30"; const char* p="bnVsbA"; std::array<Logic::v8,4> hb{}; std::array<Logic::v8,8> pb{}; std::array<Logic::v8,Bridge::kDecoded> dec{}; Logic::bitvec<8> hl{},pl{},dl{};
  l.bits(8,hl.data(),3);l.bits(8,pl.data(),6);l.bits(8,dl.data(),4);
  for(size_t i=0;i<hb.size();++i)hb[i]=l.template vbit<8>(i<3?h[i]:0);
  for(size_t i=0;i<pb.size();++i)pb[i]=l.template vbit<8>(i<6?(splice&&i==1?'A':p[i]):0);
  std::string msg=std::string(h)+"."+(splice?std::string("bAVsbA"):p); std::array<unsigned char,64> padded{};std::array<proofs::FlatSHA256Witness::BlockWitness,1> raw{};unsigned char blocks{};proofs::FlatSHA256Witness::transform_and_witness_message(msg.size(),reinterpret_cast<const unsigned char*>(msg.data()),1,blocks,padded.data(),raw.data());
  std::array<Logic::v8,64> pad{};for(size_t i=0;i<64;++i)pad[i]=l.template vbit<8>(padded[i]); proofs::BitPluckerEncoder<Field,4> enc(proofs::p256_base); std::array<Sha::BlockWitness,1> w{}; for(size_t i=0;i<48;++i)w[0].outw[i]=l.konst(enc.mkpacked_v32(raw[0].outw[i]));for(size_t i=0;i<64;++i){w[0].oute[i]=l.konst(enc.mkpacked_v32(raw[0].oute[i]));w[0].outa[i]=l.konst(enc.mkpacked_v32(raw[0].outa[i]));}for(size_t i=0;i<8;++i)w[0].h1[i]=l.konst(enc.mkpacked_v32(raw[0].h1[i]));
  auto hash=sd_jwt_zk::sha256_ascii(std::string(h)+"."+p); Logic::v256 bits{};std::array<Logic::EltW,32> pub{};for(size_t b=0;b<32;++b){for(size_t bit=0;bit<8;++bit)bits[(31-b)*8+bit]=l.bit((hash[b]>>bit)&1);pub[b]=l.konst(wrong_digest&&b==0?hash[b]^1:hash[b]);}for(size_t i=0;i<dec.size();++i)dec[i]=l.template vbit<8>(i<4?"null"[i]:0);
  const Bridge::Input input{hb,hl,pb,pl,pad,w,bits,l.template vbit<8>(1),pub,dec,dl};
  Bridge(l).assert_valid(input);return !backend.assertion_failed(); }
int main(){
  const bool valid=accepts(false,false), bad_digest=!accepts(true,false), splice=!accepts(false,true);
  std::cout << "valid=" << valid << " wrong_digest_rejected=" << bad_digest
            << " header_payload_splice_rejected=" << splice << '\n';
  return valid&&bad_digest&&splice?0:1;
}
