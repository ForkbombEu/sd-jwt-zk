#include "sd_jwt_zk/api.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
using namespace sd_jwt_zk;
static int failed=0; static void check(bool ok,const char* what){if(!ok){++failed;std::cerr<<"FAIL: "<<what<<'\n';}}
static Bytes hex(std::string_view text){Bytes out;if(text.size()%2)return {};for(size_t i=0;i<text.size();i+=2){auto n=[](char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;};auto a=n(text[i]),b=n(text[i+1]);if(a<0||b<0)return {};out.push_back(static_cast<std::uint8_t>((a<<4)|b));}return out;}
static std::map<std::string,Bytes> golden(){std::ifstream input(std::string(SD_JWT_ZK_TESTDATA_DIR)+"/codec-golden-v1.txt");std::map<std::string,Bytes> out;std::string line;while(std::getline(input,line)){if(line.empty()||line[0]=='#')continue;auto at=line.find('=');if(at!=std::string::npos)out.emplace(line.substr(0,at),hex(line.substr(at+1)));}return out;}
int main(){
  const auto v=golden();check(v.size()==4,"load checked-in codec golden vectors");
  CircuitIdentity id{Binding::bearer,Trust::exact_key,256,{},"goldilocks",2,4};id.circuit_digest[0]=7;
  Request r{id,"https://verifier.example","nonce-1",1,2,{1,2},{3},{4},{5}};
  auto identity=encode_identity(id);check(identity&&identity.value.value()==v.at("identity"),"canonical identity golden bytes");
  auto encoded=encode_request(r);check(encoded&&encoded.value.value()==v.at("request"),"canonical request golden bytes");auto decoded=encoded?decode_request(*encoded.value):Result<Request>::fail(ErrorCode::malformed,"skip");check(decoded&&decoded.value->nonce==r.nonce,"request round trip");
  if(encoded){for(size_t i=0;i<encoded.value->size();++i){Bytes cut(encoded.value->begin(),encoded.value->begin()+static_cast<long>(i));check(!decode_request(cut),"every request truncation rejects");}Bytes trailing=*encoded.value;trailing.push_back(0);check(!decode_request(trailing),"request trailing rejects");}
  Envelope e{r,{1,2,3}};auto wire=encode_envelope(e);check(wire&&wire.value.value()==v.at("envelope"),"canonical envelope golden bytes");check(wire&&decode_envelope(*wire.value),"envelope round trip");if(wire){for(size_t i=0;i<wire.value->size();++i){Bytes cut(wire.value->begin(),wire.value->begin()+static_cast<long>(i));check(!decode_envelope(cut),"every envelope truncation rejects");}}
  auto seed=transcript_seed(r);check(Bytes(seed.begin(),seed.end())==v.at("transcript_seed"),"canonical transcript seed golden bytes");r.nonce="nonce-2";check(seed!=transcript_seed(r),"transcript nonce avalanche");r.nonce="nonce-1";r.identity.query_count=5;auto substituted=encode_request(r);check(substituted&&substituted.value.value()!=v.at("request"),"parameter substitution differs from golden request");
  Bytes unknown=v.at("identity");unknown[1]=3;check(!decode_identity(unknown),"unknown identity mode golden negative");
  auto hash=sha256_ascii("abc");check(hash[0]==0xba&&hash[1]==0x78&&hash[31]==0xad,"exact ASCII SHA-256 vector");
  check(!base64url_decode("A"),"noncanonical base64 length");check(!base64url_decode("AA="),"padding rejected");check(static_cast<bool>(base64url_decode("AA")),"base64url accepted");check(!decode_es256_signature("AA"),"short signature rejected");check(!decode_p256_jwk("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),"infinite point rejected");
  Bytes raw(64,1);auto sig=decode_es256_signature(base64url_encode(raw));check(sig&&es256_signature_is_low_s(*sig.value),"low-S decision");std::fill(raw.begin()+32,raw.end(),0xff);check(!decode_es256_signature(base64url_encode(raw)),"P-256 scalar range rejects");
  auto j=split_compact_jws("eyJhIjoxfQ.eyJiIjoyfQ.AA");check(static_cast<bool>(j),"compact JWS split");check(!split_compact_jws("a.b.c.d"),"extra delimiter rejected");
  check(static_cast<bool>(build_native_witness("eyJhIjoxfQ.eyJiIjoyfQ.AA~AA~")),"native witness accepts terminal tilde");check(!build_native_witness("eyJhIjoxfQ.eyJiIjoyfQ.AA~~"),"native witness rejects empty disclosure");Limits tight{};tight.max_input=8;check(!build_native_witness("eyJhIjoxfQ.eyJiIjoyfQ.AA~AA~",tight),"bounded native allocation");
  check(native_parsing_is_not_proof_verification(),"native parsing disclaimer");return failed?1:0;
}
