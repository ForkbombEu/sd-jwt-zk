#include "sd_jwt_zk/kb_jwt_relation.h"
#include "sd_jwt_zk/api.h"

#include <array>

#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"

namespace {
using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Relation = sd_jwt_zk::KbJwsRelation<Logic, 4, 40, 176, 24, 14>;
using Sha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;
using Ecdsa = proofs::VerifyCircuit<Logic, Field, proofs::P256>;

proofs::Fp256Nat nat(const std::array<std::uint8_t, 32>& in) {
  std::array<std::uint8_t, 32> little{};
  for (std::size_t i = 0; i < little.size(); ++i) little[i] = in[31 - i];
  return proofs::Fp256Nat::of_bytes(little.data());
}

bool accepts(bool wrong_holder_key, bool wrong_signature, bool wrong_presentation = false) {
  constexpr char header[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9";
  constexpr char header_json[] = "{\"alg\":\"ES256\",\"typ\":\"kb+jwt\"}";
  constexpr char payload[] = "eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUiLCJub25jZSI6ImNoYWxsZW5nZS0wMDAxIiwiaWF0IjoxNzc3MzM0NDAwLCJzZF9oYXNoIjoiRkY3THRhUGtZdXJzd2xob1ZBSk1vSnZTS0FXdjViMUYxQkswaDRQVVN6ayJ9";
  constexpr char payload_json[] = "{\"aud\":\"https://verifier.example\",\"nonce\":\"challenge-0001\",\"iat\":1777334400,\"sd_hash\":\"FF7LtaPkYurswlhoVAJMoJvSKAWv5b1F1BK0h4PUSzk\"}";
  constexpr char signature[] = "wZm5Q5D-b9stytMg-PFLi62qN4XzYBazkc3fwa5JJcY7k9Ta_YvTWGoQ8KrFKLbyviGJRJsCnN2SNqwiazTlbg";
  constexpr char x[] = "uNJkR8N_mIF4OiHzsbGdAoPFN9cyGZHN2rTeZS1L_p8";
  constexpr char y[] = "6p64Zi-F2FKs9RFB8V-EFWC7jrDk8jDP-17zIGy4JXA";
  static_assert(sizeof(header)-1 == 40 && sizeof(payload)-1 == 176 && sizeof(payload_json)-1 == 132);
  const auto key = sd_jwt_zk::decode_p256_jwk(x, y); auto sig = sd_jwt_zk::decode_es256_signature(signature);
  if (!key || !sig) return false;
  if (wrong_signature) sig.value->r[0] ^= 1;
  const std::string signing = std::string(header) + "." + payload;
  const auto digest = sd_jwt_zk::sha256_ascii(signing); const auto dn = nat(digest);
  const auto px = proofs::p256_base.to_montgomery(nat(key.value->x));
  const auto py = proofs::p256_base.to_montgomery(nat(key.value->y));
  proofs::VerifyWitness3<proofs::P256, proofs::Fp256Scalar> ew(proofs::p256_scalar, proofs::p256);
  if (!ew.compute_witness(px, py, dn, nat(sig.value->r), nat(sig.value->s))) return false;
  const Field field; Backend backend(field, false); Logic logic(&backend, field);
  std::array<std::uint8_t, 256> padded{}; std::array<proofs::FlatSHA256Witness::BlockWitness,4> raw{}; std::uint8_t blocks=0;
  proofs::FlatSHA256Witness::transform_and_witness_message(signing.size(), reinterpret_cast<const std::uint8_t*>(signing.data()),4,blocks,padded.data(),raw.data());
  if (blocks != 4) return false;
  std::array<Logic::v8,256> sha_in{}; for(std::size_t i=0;i<256;++i) sha_in[i]=logic.template vbit<8>(padded[i]);
  proofs::BitPluckerEncoder<Field,4> encoder(proofs::p256_base); std::array<Sha::BlockWitness,4> sw{};
  for(std::size_t b=0;b<4;++b){for(std::size_t i=0;i<48;++i)sw[b].outw[i]=logic.konst(encoder.mkpacked_v32(raw[b].outw[i]));for(std::size_t i=0;i<64;++i){sw[b].oute[i]=logic.konst(encoder.mkpacked_v32(raw[b].oute[i]));sw[b].outa[i]=logic.konst(encoder.mkpacked_v32(raw[b].outa[i]));}for(std::size_t i=0;i<8;++i)sw[b].h1[i]=logic.konst(encoder.mkpacked_v32(raw[b].h1[i]));}
  Logic::v256 bits{};for(std::size_t i=0;i<256;++i)bits[i]=logic.bit(dn.bit(i));
  std::array<Logic::v8,40> h{};std::array<Logic::v8,30> hd{};std::array<Logic::v8,176> p{};std::array<Logic::v8,86> sb{};std::array<Logic::v8,132> pd{};for(std::size_t i=0;i<h.size();++i)h[i]=logic.template vbit<8>(header[i]);for(std::size_t i=0;i<hd.size();++i)hd[i]=logic.template vbit<8>(header_json[i]);for(std::size_t i=0;i<p.size();++i)p[i]=logic.template vbit<8>(payload[i]);for(std::size_t i=0;i<sb.size();++i)sb[i]=logic.template vbit<8>(signature[i]);for(std::size_t i=0;i<pd.size();++i)pd[i]=logic.template vbit<8>(payload_json[i]);
  std::array<Logic::v8,24> aud{};constexpr char a[]="https://verifier.example";for(std::size_t i=0;i<aud.size();++i)aud[i]=logic.template vbit<8>(a[i]);std::array<Logic::v8,14> nonce{};constexpr char n[]="challenge-0001";for(std::size_t i=0;i<nonce.size();++i)nonce[i]=logic.template vbit<8>(n[i]);std::array<Logic::v8,10> lo{},hi{};constexpr char l[]="1777334300", u[]="1777334500";for(std::size_t i=0;i<10;++i){lo[i]=logic.template vbit<8>(l[i]);hi[i]=logic.template vbit<8>(u[i]);}std::array<Logic::v8,43> hash{};constexpr char sh[]="FF7LtaPkYurswlhoVAJMoJvSKAWv5b1F1BK0h4PUSzk";for(std::size_t i=0;i<43;++i)hash[i]=logic.template vbit<8>(sh[i]);
  Logic::bitvec<8> hl{},pl{},al{},nl{};logic.bits(8,hl.data(),40);logic.bits(8,pl.data(),176);logic.bits(8,al.data(),24);logic.bits(8,nl.data(),14);
  Ecdsa::Witness w{};w.rx=logic.konst(ew.rx_);w.ry=logic.konst(ew.ry_);w.rx_inv=logic.konst(ew.rx_inv_);w.s_inv=logic.konst(ew.s_inv_);w.pk_inv=logic.konst(ew.pk_inv_);for(std::size_t i=0;i<8;++i)w.pre[i]=logic.konst(ew.pre_[i]);for(std::size_t i=0;i<proofs::P256::kBits;++i){w.bi[i]=logic.konst(ew.bi_[i]);if(i+1<proofs::P256::kBits){w.int_x[i]=logic.konst(ew.int_x_[i]);w.int_y[i]=logic.konst(ew.int_y_[i]);w.int_z[i]=logic.konst(ew.int_z_[i]);}}
  auto holder_x=logic.konst(wrong_holder_key ? py : px);
  auto holder_y=logic.konst(py);
  auto signature_r=logic.konst(proofs::p256_base.to_montgomery(nat(sig.value->r)));
  auto signature_s=logic.konst(proofs::p256_base.to_montgomery(nat(sig.value->s)));
  auto digest_field=logic.konst(proofs::p256_base.to_montgomery(dn));
  Relation::Input input{sha_in,sw,bits,h,hd,p,sb,pd,hl,pl,aud,al,nonce,nl,lo,hi,hash,holder_x,holder_y,signature_r,signature_s,digest_field,w,blocks};
  Relation relation(logic);
  relation.assert_valid(input);
  constexpr char issuer[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ.eyJfc2QiOlsickxFZ2lmWmdPaGdVVUxiT0xlTVZrc1oyQVVJeDF6Z1NzT0pSenFMYWJuVSJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSIsIl9zZF9hbGciOiJzaGEtMjU2In0.RS6qxwyHcY1UIV7JU60XommQaDyhl1NTMyE-EESB6-ViM6WjVNJC56lUFwZLW82dtNMbySOKZBphd8jfRAICBQ";
  constexpr char disclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsdHJ1ZV0";
  constexpr std::size_t pb = 7;
  const std::string presentation = std::string(issuer) + "~" + disclosure + "~";
  std::array<std::uint8_t,64*pb> pp{}; std::array<proofs::FlatSHA256Witness::BlockWitness,pb> praw{}; std::uint8_t pblocks=0;
  proofs::FlatSHA256Witness::transform_and_witness_message(presentation.size(),reinterpret_cast<const std::uint8_t*>(presentation.data()),pb,pblocks,pp.data(),praw.data()); if(pblocks!=pb)return false;
  std::array<Logic::v8,sizeof(issuer)-1> iw{}; std::array<Logic::v8,sizeof(disclosure)-1> dw{}; std::array<Logic::v8,64*pb> pi{};
  for(std::size_t i=0;i<iw.size();++i)iw[i]=logic.template vbit<8>((wrong_presentation&&i==0)?'X':issuer[i]); for(std::size_t i=0;i<dw.size();++i)dw[i]=logic.template vbit<8>(disclosure[i]); for(std::size_t i=0;i<pi.size();++i)pi[i]=logic.template vbit<8>(pp[i]);
  std::array<typename proofs::FlatSHA256Circuit<Logic,proofs::BitPlucker<Logic,4>>::BlockWitness,pb> psw{};
  for(std::size_t b=0;b<pb;++b){for(std::size_t i=0;i<48;++i)psw[b].outw[i]=logic.konst(encoder.mkpacked_v32(praw[b].outw[i]));for(std::size_t i=0;i<64;++i){psw[b].oute[i]=logic.konst(encoder.mkpacked_v32(praw[b].oute[i]));psw[b].outa[i]=logic.konst(encoder.mkpacked_v32(praw[b].outa[i]));}for(std::size_t i=0;i<8;++i)psw[b].h1[i]=logic.konst(encoder.mkpacked_v32(praw[b].h1[i]));}
  const auto phd=sd_jwt_zk::sha256_ascii(presentation);const auto phn=nat(phd);Logic::v256 pbits{};for(std::size_t i=0;i<256;++i)pbits[i]=logic.bit(phn.bit(i));
  using Presentation=sd_jwt_zk::PresentationHashRelation<Logic,pb,sizeof(issuer)-1,sizeof(disclosure)-1>;
  Presentation::Input pin{iw,dw,pi,psw,pbits,hash};
  relation.assert_presentation_binding<pb,sizeof(issuer)-1,sizeof(disclosure)-1>(input,pin);
  return !backend.assertion_failed();
}
}  // namespace
int main(){ return accepts(false,false) && !accepts(true,false) && !accepts(false,true) && !accepts(false,false,true) ? 0 : 1; }
