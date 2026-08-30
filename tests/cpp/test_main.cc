#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/bounded_json.h"
#include "sd_jwt_zk/issuer_registry.h"
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <thread>
#include <vector>
using namespace sd_jwt_zk;
static int failed=0; static void check(bool ok,const char* what){if(!ok){++failed;std::cerr<<"FAIL: "<<what<<'\n';}}
static Bytes hex(std::string_view text){Bytes out;if(text.size()%2)return {};for(size_t i=0;i<text.size();i+=2){auto n=[](char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;};auto a=n(text[i]),b=n(text[i+1]);if(a<0||b<0)return {};out.push_back(static_cast<std::uint8_t>((a<<4)|b));}return out;}
static std::map<std::string,Bytes> golden(){std::ifstream input(std::string(SD_JWT_ZK_TESTDATA_DIR)+"/codec-golden-v1.txt");std::map<std::string,Bytes> out;std::string line;while(std::getline(input,line)){if(line.empty()||line[0]=='#')continue;auto at=line.find('=');if(at!=std::string::npos)out.emplace(line.substr(0,at),hex(line.substr(at+1)));}return out;}
struct HolderProver final : HolderBoundProofProverV1 {
  std::vector<int> order;
  bool throw_on_bridge{};
  Result<Bytes> commit(HolderComponent component,const CircuitIdentity&,const Request&) override {order.push_back(component==HolderComponent::credential?1:2);return Result<Bytes>::ok(Bytes{static_cast<std::uint8_t>(component)});}
  Result<Bytes> bridge_public(const Request&,const CircuitIdentity&,const CircuitIdentity&,const Bytes& credential,const Bytes& kb) override {order.push_back(3);if(throw_on_bridge)throw std::runtime_error("bridge");if(credential!=Bytes{1}||kb!=Bytes{2})return Result<Bytes>::fail(ErrorCode::malformed,"commitment order");return Result<Bytes>::ok(Bytes(112,3));}
  Result<Bytes> prove(HolderComponent component,const CircuitIdentity&,const Request&,const Bytes& credential,const Bytes& kb,const Bytes& bridge) override {order.push_back(component==HolderComponent::credential?4:5);if(credential!=Bytes{1}||kb!=Bytes{2}||bridge!=Bytes(112,3))return Result<Bytes>::fail(ErrorCode::malformed,"proof transcript");return Result<Bytes>::ok(Bytes{static_cast<std::uint8_t>(static_cast<std::uint8_t>(component)+3)});}
};
struct HolderVerifier final : HolderBoundProofVerifierV1 {
  bool fail{};bool throw_on_verify{};int phase{};const HolderBoundEnvelope* expected{};
  bool verify(HolderComponent component,const CircuitIdentity&,const Request&,const Bytes& credential,const Bytes& kb,const Bytes& bridge,const Bytes& proof) override {if(throw_on_verify)throw std::runtime_error("verify");const auto wanted=phase==0?HolderComponent::credential:HolderComponent::kb;const bool ok=!fail&&component==wanted&&expected&&credential==expected->credential_commitment&&kb==expected->kb_commitment&&bridge==expected->bridge_public&&proof==(component==HolderComponent::credential?expected->credential_proof:expected->kb_proof);phase=(phase+1)%2;return ok;}
};
struct HolderReplay final : HolderBoundReplayStoreV1 { std::atomic<bool> used{false};bool throw_on_consume{};bool consume(std::string_view,std::string_view,std::uint64_t) override {if(throw_on_consume)throw std::runtime_error("replay");bool expected=false;return used.compare_exchange_strong(expected,true);} };
int main(){
  const auto v=golden();check(v.size()==4,"load checked-in codec golden vectors");
  CircuitIdentity id{Binding::bearer,Trust::exact_key,256,{},"goldilocks",2,4};id.circuit_digest[0]=7;
  Request r{id,"https://verifier.example","nonce-1",1,2,{1,2},{3},{4},{5}};
  auto identity=encode_identity(id);check(identity&&identity.value.value()==v.at("identity"),"canonical identity golden bytes");
  auto encoded=encode_request(r);check(encoded&&encoded.value.value()==v.at("request"),"canonical request golden bytes");auto decoded=encoded?decode_request(*encoded.value):Result<Request>::fail(ErrorCode::malformed,"skip");check(decoded&&decoded.value->nonce==r.nonce,"request round trip");
  if(encoded){for(size_t i=0;i<encoded.value->size();++i){Bytes cut(encoded.value->begin(),encoded.value->begin()+static_cast<long>(i));check(!decode_request(cut),"every request truncation rejects");}Bytes trailing=*encoded.value;trailing.push_back(0);check(!decode_request(trailing),"request trailing rejects");}
  Envelope e{r,{1,2,3}};auto wire=encode_envelope(e);check(wire&&wire.value.value()==v.at("envelope"),"canonical envelope golden bytes");check(wire&&decode_envelope(*wire.value),"envelope round trip");if(wire){for(size_t i=0;i<wire.value->size();++i){Bytes cut(wire.value->begin(),wire.value->begin()+static_cast<long>(i));check(!decode_envelope(cut),"every envelope truncation rejects");}}
  CircuitIdentity holder_id{Binding::holder_bound,Trust::exact_key,256,{},"p256-base",4,128};holder_id.circuit_digest[0]=1;
  CircuitIdentity kb_id=holder_id;kb_id.circuit_digest[0]=2;
  Request holder_request{holder_id,"https://verifier.example","holder-nonce",1,2,{1},{1},{}, {}};
  HolderBoundVerifierPolicyV1 holder_policy{holder_request,holder_id,kb_id};HolderProver holder_prover;auto produced=prove_holder_bound_envelope_v1(holder_policy,holder_prover);check(produced&&holder_prover.order==std::vector<int>({1,2,3,4,5}),"holder prover commits both components before bridge and proves in canonical order");
  HolderBoundEnvelope holder_envelope=produced?*produced.value:HolderBoundEnvelope{holder_request,holder_id,kb_id,{1},{2},Bytes(112,3),{4},{5}};
  auto holder_wire=encode_holder_bound_envelope(holder_envelope);check(holder_wire&&decode_holder_bound_envelope(*holder_wire.value),"ordered holder envelope round trip");
  if(holder_wire){for(size_t i=0;i<holder_wire.value->size();++i){Bytes cut(holder_wire.value->begin(),holder_wire.value->begin()+static_cast<long>(i));check(!decode_holder_bound_envelope(cut),"every holder envelope truncation rejects");}Bytes trailing=*holder_wire.value;trailing.push_back(0);check(!decode_holder_bound_envelope(trailing),"holder envelope trailing data rejects");}
  auto reversed=holder_envelope;std::swap(reversed.credential_identity,reversed.kb_identity);check(!encode_holder_bound_envelope(reversed),"holder component order is canonical");
  auto duplicate=holder_envelope;duplicate.kb_identity=duplicate.credential_identity;check(!encode_holder_bound_envelope(duplicate),"duplicate holder component identity rejects");
  auto missing=holder_envelope;missing.kb_proof.clear();check(!encode_holder_bound_envelope(missing),"missing holder component rejects");
  auto missing_credential=holder_envelope;missing_credential.credential_proof.clear();check(!encode_holder_bound_envelope(missing_credential),"missing credential proof rejects");auto missing_commitment=holder_envelope;missing_commitment.credential_commitment.clear();check(!encode_holder_bound_envelope(missing_commitment),"missing credential commitment rejects");auto short_bridge=holder_envelope;short_bridge.bridge_public.pop_back();check(!encode_holder_bound_envelope(short_bridge),"short holder bridge rejects");auto long_bridge=holder_envelope;long_bridge.bridge_public.push_back(0);check(!encode_holder_bound_envelope(long_bridge),"long holder bridge rejects");Limits holder_tight{};holder_tight.max_input=16;check(!encode_holder_bound_envelope(holder_envelope,holder_tight),"holder envelope obeys total input bound");holder_tight=Limits{};holder_tight.max_proof=0;check(!prove_holder_bound_envelope_v1(holder_policy,holder_prover,holder_tight),"holder prover obeys component proof bound");
  auto duplicate_component=holder_envelope;duplicate_component.kb_proof=duplicate_component.credential_proof;check(static_cast<bool>(encode_holder_bound_envelope(duplicate_component)),"typed envelope preserves distinct proof slots");HolderReplay duplicate_replay;HolderVerifier duplicate_verifier;duplicate_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(duplicate_component,holder_policy,1,duplicate_verifier,duplicate_replay),"duplicated holder component fails verification");
  HolderVerifier holder_verifier;holder_verifier.expected=&holder_envelope;HolderReplay holder_replay;
  auto accepted=verify_holder_bound_envelope_v1(holder_envelope,holder_policy,1,holder_verifier,holder_replay);check(accepted&&*accepted.value,"ordered holder verifier accepts matching pair");
  HolderVerifier replay_verifier;replay_verifier.expected=&holder_envelope;auto replayed=verify_holder_bound_envelope_v1(holder_envelope,holder_policy,1,replay_verifier,holder_replay);check(!replayed,"holder nonce double consume rejects");
  auto bad_holder_request=holder_request;bad_holder_request.nonce="other";HolderBoundVerifierPolicyV1 bad_request_policy{bad_holder_request,holder_id,kb_id};HolderReplay fresh_replay;HolderVerifier fresh_verifier;fresh_verifier.expected=&holder_envelope;auto request_rejected=verify_holder_bound_envelope_v1(holder_envelope,bad_request_policy,1,fresh_verifier,fresh_replay);check(!request_rejected&&fresh_verifier.phase==0,"holder request substitution rejects before proof dispatch");
  auto swapped_policy=holder_policy;std::swap(swapped_policy.credential_identity,swapped_policy.kb_identity);HolderReplay swap_replay;HolderVerifier swap_verifier;swap_verifier.expected=&holder_envelope;auto swapped_rejected=verify_holder_bound_envelope_v1(holder_envelope,swapped_policy,1,swap_verifier,swap_replay);check(!swapped_rejected,"reversed holder order rejects");
  auto bad_tags=holder_envelope;bad_tags.bridge_public[0]^=1;HolderReplay tag_replay;HolderVerifier tag_verifier;tag_verifier.expected=&holder_envelope;auto tag_rejected=verify_holder_bound_envelope_v1(bad_tags,holder_policy,1,tag_verifier,tag_replay);check(!tag_rejected&&!tag_replay.used,"bridge tag mutation rejects before replay consumption");
  auto bad_challenge=holder_envelope;bad_challenge.bridge_public.back()^=1;HolderReplay challenge_replay;HolderVerifier challenge_verifier;challenge_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(bad_challenge,holder_policy,1,challenge_verifier,challenge_replay),"bridge MAC challenge mutation rejects");auto swapped_proofs=holder_envelope;std::swap(swapped_proofs.credential_proof,swapped_proofs.kb_proof);HolderReplay proof_order_replay;HolderVerifier proof_order_verifier;proof_order_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(swapped_proofs,holder_policy,1,proof_order_verifier,proof_order_replay),"swapped holder proofs reject");auto changed_proof=holder_envelope;changed_proof.kb_proof[0]^=1;HolderReplay changed_proof_replay;HolderVerifier changed_proof_verifier;changed_proof_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(changed_proof,holder_policy,1,changed_proof_verifier,changed_proof_replay),"holder proof mutation rejects");
  auto bearer_holder=holder_envelope;bearer_holder.request.identity.binding=Binding::bearer;check(!encode_holder_bound_envelope(bearer_holder),"bearer evidence cannot use holder envelope");
  auto bearer_policy=holder_policy;bearer_policy.request.identity.binding=Binding::bearer;HolderReplay bearer_replay;HolderVerifier bearer_verifier;bearer_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(holder_envelope,bearer_policy,1,bearer_verifier,bearer_replay),"holder evidence cannot satisfy bearer identity policy");
  auto audience_policy=holder_policy;audience_policy.request.audience="https://other.example";HolderReplay audience_replay;HolderVerifier audience_verifier;audience_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(holder_envelope,audience_policy,1,audience_verifier,audience_replay),"holder audience substitution rejects");auto time_policy=holder_policy;time_policy.request.time_max=3;HolderReplay time_replay;HolderVerifier time_verifier;time_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(holder_envelope,time_policy,1,time_verifier,time_replay),"holder time-policy substitution rejects");auto policy_substitution=holder_policy;policy_substitution.request.policy[0]^=1;HolderReplay policy_replay;HolderVerifier policy_verifier;policy_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(holder_envelope,policy_substitution,1,policy_verifier,policy_replay),"holder claim-policy substitution rejects");auto identity_substitution=holder_policy;identity_substitution.kb_identity.circuit_digest[1]^=1;HolderReplay identity_replay;HolderVerifier identity_verifier;identity_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(holder_envelope,identity_substitution,1,identity_verifier,identity_replay),"holder proof identity substitution rejects");auto false_policy=holder_policy;false_policy.request.policy_result={0};HolderProver false_prover;check(!prove_holder_bound_envelope_v1(false_policy,false_prover),"unsatisfied holder policy cannot be proved");
  HolderReplay early_replay;HolderVerifier early_verifier;early_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(holder_envelope,holder_policy,0,early_verifier,early_replay),"holder request rejects before time window");HolderReplay late_replay;HolderVerifier late_verifier;late_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(holder_envelope,holder_policy,3,late_verifier,late_replay),"holder request rejects after time window");
  HolderProver throwing_prover;throwing_prover.throw_on_bridge=true;check(!prove_holder_bound_envelope_v1(holder_policy,throwing_prover),"holder prover callback exception fails closed");HolderReplay callback_replay;HolderVerifier callback_verifier;callback_verifier.expected=&holder_envelope;callback_verifier.throw_on_verify=true;check(!verify_holder_bound_envelope_v1(holder_envelope,holder_policy,1,callback_verifier,callback_replay),"holder verifier callback exception fails closed");HolderReplay throwing_replay;throwing_replay.throw_on_consume=true;HolderVerifier consume_verifier;consume_verifier.expected=&holder_envelope;check(!verify_holder_bound_envelope_v1(holder_envelope,holder_policy,1,consume_verifier,throwing_replay),"holder replay callback exception fails closed");
  HolderReplay concurrent_replay;bool concurrent_a{},concurrent_b{};auto verify_once=[&](bool& result){HolderVerifier verifier;verifier.expected=&holder_envelope;auto checked=verify_holder_bound_envelope_v1(holder_envelope,holder_policy,1,verifier,concurrent_replay);result=checked&&*checked.value;};std::thread first(verify_once,std::ref(concurrent_a));std::thread second(verify_once,std::ref(concurrent_b));first.join();second.join();check(concurrent_a!=concurrent_b,"concurrent holder nonce consumption authorizes exactly once");
  auto seed=transcript_seed(r);check(Bytes(seed.begin(),seed.end())==v.at("transcript_seed"),"canonical transcript seed golden bytes");r.nonce="nonce-2";check(seed!=transcript_seed(r),"transcript nonce avalanche");r.nonce="nonce-1";r.identity.query_count=5;auto substituted=encode_request(r);check(substituted&&substituted.value.value()!=v.at("request"),"parameter substitution differs from golden request");
  Bytes unknown=v.at("identity");unknown[1]=3;check(!decode_identity(unknown),"unknown identity mode golden negative");
  auto hash=sha256_ascii("abc");check(hash[0]==0xba&&hash[1]==0x78&&hash[31]==0xad,"exact ASCII SHA-256 vector");
  check(!base64url_decode("A"),"noncanonical base64 length");check(!base64url_decode("AA="),"padding rejected");check(static_cast<bool>(base64url_decode("AA")),"base64url accepted");check(!decode_es256_signature("AA"),"short signature rejected");check(!decode_p256_jwk("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),"infinite point rejected");
  Bytes raw(64,1);auto sig=decode_es256_signature(base64url_encode(raw));check(sig&&es256_signature_is_low_s(*sig.value),"low-S decision");std::fill(raw.begin()+32,raw.end(),0xff);check(!decode_es256_signature(base64url_encode(raw)),"P-256 scalar range rejects");
  auto j=split_compact_jws("eyJhIjoxfQ.eyJiIjoyfQ.AA");check(static_cast<bool>(j),"compact JWS split");check(!split_compact_jws("a.b.c.d"),"extra delimiter rejected");
  check(static_cast<bool>(build_native_witness("eyJhIjoxfQ.eyJiIjoyfQ.AA~AA~")),"native witness accepts terminal tilde");check(!build_native_witness("eyJhIjoxfQ.eyJiIjoyfQ.AA~~"),"native witness rejects empty disclosure");Limits tight{};tight.max_input=8;check(!build_native_witness("eyJhIjoxfQ.eyJiIjoyfQ.AA~AA~",tight),"bounded native allocation");
  auto flat=parse_restricted_issuer_payload("{\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"iss\":\"https://issuer.example\",\"vct\":\"example\",\"_sd_alg\":\"sha-256\"}");
  check(flat&&flat.value->issuer=="https://issuer.example"&&flat.value->explicit_sha256,"restricted payload explicit SHA grammar");
  auto omitted=parse_restricted_issuer_payload("{\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"iss\":\"did:example:issuer\",\"vct\":\"different-vct\"}");
  check(omitted&&omitted.value->issuer=="did:example:issuer"&&!omitted.value->explicit_sha256,"restricted payload variable slots and SHA default branch");
  check(!parse_restricted_issuer_payload("{\"iss\":\"https://issuer.example\",\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"vct\":\"example\"}"),"restricted payload rejects reordered substring form");
  check(!parse_restricted_issuer_payload("{\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"iss\":\"https://issuer.example\",\"vct\":\"example\"}x"),"restricted payload rejects hidden trailing bytes");
  check(!parse_restricted_issuer_payload("{\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"iss\":\"https://issuer.example\",\"vct\":\"example\",\"_sd\":[]}"),"restricted payload rejects duplicate reserved member");
  check(!parse_restricted_issuer_payload("{\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"], \"iss\":\"https://issuer.example\",\"vct\":\"example\"}"),"restricted payload rejects whitespace mutation");
  check(!parse_restricted_issuer_payload("{\"_sd\":[\"!LEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"iss\":\"https://issuer.example\",\"vct\":\"example\"}"),"restricted payload rejects malformed digest base64url");
  check(!parse_restricted_issuer_payload("{\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"iss\":\"https:\\\\issuer.example\",\"vct\":\"example\"}"),"restricted payload rejects escaped strings");
  const std::array<std::uint8_t, 32> gx{0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96};
  const std::array<std::uint8_t, 32> gy{0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
  const auto gxb64=base64url_encode({gx.begin(),gx.end()}), gyb64=base64url_encode({gy.begin(),gy.end()});
  const auto holder_json="{\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"iss\":\"https://issuer.example\",\"vct\":\"example\",\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""+gxb64+"\",\"y\":\""+gyb64+"\"}}}";
  auto holder=parse_restricted_issuer_payload(holder_json);
  check(holder&&holder.value->holder_key&&holder.value->holder_key->x==gx&&p256_key_is_valid(*holder.value->holder_key),"restricted payload accepts canonical cnf P-256 JWK");
  auto wrong_curve=holder_json;const auto curve_at=wrong_curve.find("P-256");wrong_curve.replace(curve_at,5,"P-384");check(!parse_restricted_issuer_payload(wrong_curve),"restricted payload rejects cnf curve mutation");
  auto wrong_type=holder_json;const auto type_at=wrong_type.find("\"EC\"");wrong_type.replace(type_at,4,"\"OKP\"");check(!parse_restricted_issuer_payload(wrong_type),"restricted payload rejects cnf key type mutation");
  auto wrong_coordinate=holder_json;const auto x_at=wrong_coordinate.find(gxb64);wrong_coordinate.replace(x_at,43,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");check(!parse_restricted_issuer_payload(wrong_coordinate),"restricted payload rejects non-curve cnf coordinate");
  auto short_coordinate=holder_json;short_coordinate.erase(short_coordinate.find(gxb64),1);check(!parse_restricted_issuer_payload(short_coordinate),"restricted payload rejects cnf coordinate length mutation");
  auto bad_alphabet=holder_json;bad_alphabet.replace(bad_alphabet.find(gxb64),1,"!");check(!parse_restricted_issuer_payload(bad_alphabet),"restricted payload rejects cnf coordinate alphabet mutation");
  auto padded_coordinate=holder_json;padded_coordinate.replace(padded_coordinate.find(gxb64),1,"=");check(!parse_restricted_issuer_payload(padded_coordinate),"restricted payload rejects padded cnf coordinate");
  auto duplicate_cnf=holder_json;duplicate_cnf.insert(duplicate_cnf.size()-1,",\"cnf\":{}");check(!parse_restricted_issuer_payload(duplicate_cnf),"restricted payload rejects duplicate cnf");
  auto alternate_cnf="{\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""+gxb64+"\",\"y\":\""+gyb64+"\"}},\"_sd\":[\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"],\"iss\":\"https://issuer.example\",\"vct\":\"example\"}";check(!parse_restricted_issuer_payload(alternate_cnf),"restricted payload rejects alternate cnf placement");
  IssuerAuthorizationRecordV1 registry_a{{gx,gy},"urn:example:alpha",10,20};
  IssuerAuthorizationRecordV1 registry_b{{gx,gy},"urn:example:beta",11,21};
  auto registry=build_issuer_registry_v1({registry_b,registry_a},3,7,1,30);
  check(registry&&registry.value->paths.size()==2,"registry builds bounded deterministic paths");
  auto reordered=build_issuer_registry_v1({registry_a,registry_b},3,7,1,30);
  check(registry&&reordered&&registry.value->root==reordered.value->root,"registry input order does not affect root");
  if(registry){
    const auto registry_golden=hex("7ac19e423541371a2d1894e49e67b4689aae662fce1a56a30cb25686e060258a");check(registry_golden.size()==registry.value->root.size()&&std::equal(registry.value->root.begin(),registry.value->root.end(),registry_golden.begin()),"registry root matches independent golden reference");
    check(issuer_registry_path_matches_v1(*registry.value,registry.value->paths[0]),"registry path matches root");
    auto sibling=registry.value->paths[0];sibling.siblings[0][0]^=1;check(!issuer_registry_path_matches_v1(*registry.value,sibling),"registry sibling mutation rejects");
    auto direction=registry.value->paths[0];direction.sibling_is_left[0]=!direction.sibling_is_left[0];check(!issuer_registry_path_matches_v1(*registry.value,direction),"registry direction mutation rejects");
    auto index=registry.value->paths[0];index.index^=1;check(!issuer_registry_path_matches_v1(*registry.value,index),"registry index mutation rejects");
    auto root=*registry.value;root.root[0]^=1;check(!issuer_registry_path_matches_v1(root,root.paths[0]),"registry root mutation rejects");
    auto depth=*registry.value;--depth.depth;check(!issuer_registry_path_matches_v1(depth,depth.paths[0]),"registry depth mutation rejects");
    auto epoch=*registry.value;++epoch.epoch;check(!issuer_registry_path_matches_v1(epoch,epoch.paths[0]),"registry epoch mutation rejects");
    const auto context=registry_trust_context_v1(*registry.value);auto context_wire=encode_registry_trust_context_v1(context);check(context_wire&&decode_registry_trust_context_v1(*context_wire.value),"registry public trust context canonical round trip");
    if(context_wire){auto trailing=*context_wire.value;trailing.push_back(0);check(!decode_registry_trust_context_v1(trailing),"registry context trailing byte rejects");auto malformed=*context_wire.value;malformed.back()=0;check(!decode_registry_trust_context_v1(malformed),"registry context depth mutation rejects");}
  }
  check(!build_issuer_registry_v1({registry_a,registry_a},3,7,1,30),"registry duplicate authorization rejects");
  auto bad_interval=registry_a;bad_interval.not_before=22;bad_interval.not_after=21;check(!build_issuer_registry_v1({bad_interval},3,7,1,30),"registry invalid authorization interval rejects");
  auto bad_vct=registry_a;bad_vct.vct="bad vct";check(!build_issuer_registry_v1({bad_vct},3,7,1,30),"registry malformed vct rejects");
  auto bad_key=registry_a;bad_key.issuer_key.x.fill(0);bad_key.issuer_key.y.fill(0);check(!build_issuer_registry_v1({bad_key},3,7,1,30),"registry invalid P-256 key rejects");
  check(!build_issuer_registry_v1({registry_a},0,7,1,30),"registry zero depth rejects");
  check(!build_issuer_registry_v1({registry_a},3,7,31,30),"registry invalid root validity rejects");
  auto empty_registry=build_issuer_registry_v1({},3,7,1,30);const auto empty_golden=hex("c8a4dbd2d4cce58e560e66c3d92c86221422af12f921eb6e2a3ecbf08bf2a193");check(empty_registry&&empty_registry.value->paths.empty()&&empty_golden.size()==empty_registry.value->root.size()&&std::equal(empty_registry.value->root.begin(),empty_registry.value->root.end(),empty_golden.begin()),"registry empty padding root matches independent golden");
  const auto kb_json="{\"aud\":\"https://verifier.example\",\"nonce\":\"fresh-1\",\"iat\":42,\"sd_hash\":\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"}";
  auto kb=parse_restricted_kb_jwt_payload(kb_json);check(kb&&kb.value->audience=="https://verifier.example"&&kb.value->nonce=="fresh-1"&&kb.value->issued_at==42,"restricted KB-JWT payload accepts complete canonical fields");
  check(!parse_restricted_kb_jwt_payload("{\"aud\":\"https://verifier.example\",\"nonce\":\"fresh-1\",\"iat\":042,\"sd_hash\":\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"}"),"restricted KB-JWT rejects noncanonical iat");
  check(!parse_restricted_kb_jwt_payload("{\"nonce\":\"fresh-1\",\"aud\":\"https://verifier.example\",\"iat\":42,\"sd_hash\":\"rLEgifZgOhgUULbOLeMVksZ2AUIx1zgSsOJRzqLabnU\"}"),"restricted KB-JWT rejects reordered fields");
  const auto general_json=parse_bounded_json(
      " { \"nested\" : [true, null, -12.50e+1, {\"emoji\":\"\\uD83D\\uDE03\"}], \"text\":\"\\u00e9\" } ");
  check(general_json&&general_json.value->kind==JsonKind::object&&general_json.value->members.size()==2&&
        general_json.value->members[0].second.elements.size()==4&&
        general_json.value->members[0].second.elements[3].members[0].second.scalar=="\xF0\x9F\x98\x83",
        "bounded JSON accepts recursive arrays, objects, escapes, and Unicode");
  check(general_json&&general_json.value->members[0].second.begin<general_json.value->members[0].second.end,
        "bounded JSON retains authenticated source ranges");
  check(json_number_equal("12.5","125e-1")&&json_number_equal("0","-0.000e99")&&
        !json_number_equal("12.5","12.6")&&!json_number_equal("100000000000000000001","100000000000000000000"),
        "bounded JSON compares numeric semantics");
  check(json_number_equal("1e+1","10")&&
        json_number_equal("1e18446744073709551616","10e18446744073709551615")&&
        !json_number_equal("01","1")&&!json_number_equal("1e+","1"),
        "bounded JSON number semantics are exact beyond machine exponents");
  check(!parse_bounded_json("{\"x\":1,\"x\":2}"),"bounded JSON rejects duplicate object names");
  check(!parse_bounded_json("[1,]"),"bounded JSON rejects trailing array comma");
  check(!parse_bounded_json("\"\\uD800\""),"bounded JSON rejects unpaired surrogate");
  check(!parse_bounded_json("\"\xC0\x80\""),"bounded JSON rejects overlong UTF-8");
  check(!parse_bounded_json("01"),"bounded JSON rejects leading-zero number");
  check(!parse_bounded_json("{}x"),"bounded JSON rejects hidden trailing bytes");
  JsonLimits shallow{};shallow.max_depth=1;check(!parse_bounded_json("[[0]]",shallow),"bounded JSON enforces depth bucket");
  JsonLimits tiny{};tiny.max_tokens=2;check(!parse_bounded_json("[0,1]",tiny),"bounded JSON enforces token bucket");
  check(native_parsing_is_not_proof_verification(),"native parsing disclaimer");return failed?1:0;
}
