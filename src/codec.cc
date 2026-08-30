#include "sd_jwt_zk/api.h"
#include <algorithm>
namespace sd_jwt_zk { namespace {
constexpr std::uint8_t version = 1;
bool utf8(std::string_view s) { int n=0; for (unsigned char c:s) { if(!n) { if(c<0x80) continue; if(c>=0xc2&&c<=0xdf)n=1; else if(c>=0xe0&&c<=0xef)n=2; else if(c>=0xf0&&c<=0xf4)n=3; else return false; } else { if((c&0xc0)!=0x80)return false; --n; } } return n==0; }
void u16(Bytes& o,std::uint16_t n){o.push_back(n>>8);o.push_back(n);}; void u32(Bytes& o,std::uint32_t n){for(int i=3;i>=0;--i)o.push_back(n>>(i*8));}; void u64(Bytes& o,std::uint64_t n){for(int i=7;i>=0;--i)o.push_back(n>>(i*8));}
struct Reader { const Bytes& b; size_t p=0; Result<std::uint8_t> byte(){if(p==b.size())return Result<std::uint8_t>::fail(ErrorCode::malformed,"truncated");return Result<std::uint8_t>::ok(b[p++]);} Result<std::uint16_t> r16(){auto a=byte(),c=byte();if(!a)return Result<std::uint16_t>::fail(a.error->code,a.error->message);if(!c)return Result<std::uint16_t>::fail(c.error->code,c.error->message);return Result<std::uint16_t>::ok((a.value.value()<<8)|c.value.value());} Result<std::uint32_t> r32(){std::uint32_t n=0;for(int i=0;i<4;i++){auto x=byte();if(!x)return Result<std::uint32_t>::fail(x.error->code,x.error->message);n=(n<<8)|x.value.value();}return Result<std::uint32_t>::ok(n);} Result<std::uint64_t> r64(){std::uint64_t n=0;for(int i=0;i<8;i++){auto x=byte();if(!x)return Result<std::uint64_t>::fail(x.error->code,x.error->message);n=(n<<8)|x.value.value();}return Result<std::uint64_t>::ok(n);} Result<Bytes> lp(size_t max){auto n=r32();if(!n)return Result<Bytes>::fail(n.error->code,n.error->message);if(n.value.value()>max||n.value.value()>b.size()-p)return Result<Bytes>::fail(ErrorCode::limit,"invalid bounded length");Bytes x(b.begin()+static_cast<long>(p),b.begin()+static_cast<long>(p+n.value.value()));p+=x.size();return Result<Bytes>::ok(std::move(x));} };
void lp(Bytes&o,const Bytes&x){u32(o,static_cast<std::uint32_t>(x.size()));o.insert(o.end(),x.begin(),x.end());} void lp(Bytes&o,std::string_view x){u32(o,static_cast<std::uint32_t>(x.size()));o.insert(o.end(),x.begin(),x.end());}
Result<void*> limits(const Limits&l,size_t n){return n<=l.max_input?Result<void*>::ok(nullptr):Result<void*>::fail(ErrorCode::limit,"input exceeds bound");}
}
Result<Bytes> encode_identity(const CircuitIdentity& x,const Limits& l){Bytes o{version,static_cast<std::uint8_t>(x.binding),static_cast<std::uint8_t>(x.trust)};if(x.capacity==0||x.field.empty()||!utf8(x.field)||x.field.size()>l.max_field||x.ligero_rate==0||x.query_count==0)return Result<Bytes>::fail(ErrorCode::unsupported,"unsupported circuit parameters");u32(o,x.capacity);o.insert(o.end(),x.circuit_digest.begin(),x.circuit_digest.end());lp(o,x.field);u16(o,x.ligero_rate);u16(o,x.query_count);return limits(l,o.size())?Result<Bytes>::ok(std::move(o)):Result<Bytes>::fail(ErrorCode::limit,"identity exceeds bound");}
Result<CircuitIdentity> decode_identity(const Bytes& b,const Limits&l){if(!limits(l,b.size()))return Result<CircuitIdentity>::fail(ErrorCode::limit,"identity exceeds bound");Reader r{b};auto v=r.byte(),m=r.byte(),t=r.byte();if(!v||!m||!t)return Result<CircuitIdentity>::fail(ErrorCode::malformed,"truncated identity");if(v.value.value()!=version)return Result<CircuitIdentity>::fail(ErrorCode::unsupported,"unknown relation version");if(m.value.value()>2||m.value.value()==0||t.value.value()>2||t.value.value()==0)return Result<CircuitIdentity>::fail(ErrorCode::unsupported,"unknown circuit mode");auto cap=r.r32();if(!cap)return Result<CircuitIdentity>::fail(cap.error->code,cap.error->message);CircuitIdentity x{static_cast<Binding>(m.value.value()),static_cast<Trust>(t.value.value()),cap.value.value(),{},"",0,0};if(x.capacity==0||r.p+32>b.size())return Result<CircuitIdentity>::fail(ErrorCode::malformed,"invalid identity");std::copy_n(b.begin()+static_cast<long>(r.p),32,x.circuit_digest.begin());r.p+=32;auto f=r.lp(l.max_field);auto rate=r.r16();auto q=r.r16();if(!f||!rate||!q)return Result<CircuitIdentity>::fail(ErrorCode::malformed,"truncated identity");x.field.assign(f.value->begin(),f.value->end());x.ligero_rate=rate.value.value();x.query_count=q.value.value();if(!utf8(x.field)||x.field.empty()||!x.ligero_rate||!x.query_count||r.p!=b.size())return Result<CircuitIdentity>::fail(r.p==b.size()?ErrorCode::unsupported:ErrorCode::noncanonical,"noncanonical identity");return Result<CircuitIdentity>::ok(std::move(x));}
Result<Bytes> encode_request(const Request& x,const Limits&l){auto i=encode_identity(x.identity,l);if(!i)return Result<Bytes>::fail(i.error->code,i.error->message);if(!utf8(x.audience)||!utf8(x.nonce)||x.time_min>x.time_max)return Result<Bytes>::fail(ErrorCode::utf8,"invalid request text or time");Bytes o{version};lp(o,*i.value);lp(o,x.audience);lp(o,x.nonce);u64(o,x.time_min);u64(o,x.time_max);lp(o,x.policy);lp(o,x.policy_result);lp(o,x.trust_public);lp(o,x.status_public);return limits(l,o.size())?Result<Bytes>::ok(std::move(o)):Result<Bytes>::fail(ErrorCode::limit,"request exceeds bound");}
Result<Request> decode_request(const Bytes&b,const Limits&l){if(!limits(l,b.size()))return Result<Request>::fail(ErrorCode::limit,"request exceeds bound");Reader r{b};auto v=r.byte();if(!v||v.value.value()!=version)return Result<Request>::fail(ErrorCode::unsupported,"unknown request version");auto ib=r.lp(l.max_field),a=r.lp(l.max_field),n=r.lp(l.max_field);auto lo=r.r64(),hi=r.r64();auto p=r.lp(l.max_field),pr=r.lp(l.max_field),tr=r.lp(l.max_field),st=r.lp(l.max_field);if(!ib||!a||!n||!lo||!hi||!p||!pr||!tr||!st||r.p!=b.size())return Result<Request>::fail(ErrorCode::malformed,"noncanonical request");auto id=decode_identity(*ib.value,l);if(!id)return Result<Request>::fail(id.error->code,id.error->message);Request x{*id.value,std::string(a.value->begin(),a.value->end()),std::string(n.value->begin(),n.value->end()),*lo.value,*hi.value,*p.value,*pr.value,*tr.value,*st.value};if(!utf8(x.audience)||!utf8(x.nonce)||x.time_min>x.time_max)return Result<Request>::fail(ErrorCode::utf8,"invalid request text");return Result<Request>::ok(std::move(x));}
Result<Bytes> encode_envelope(const Envelope&x,const Limits&l){auto r=encode_request(x.request,l);if(!r)return Result<Bytes>::fail(r.error->code,r.error->message);if(x.proof.empty()||x.proof.size()>l.max_proof)return Result<Bytes>::fail(ErrorCode::limit,"invalid proof size");Bytes o{version};lp(o,*r.value);lp(o,x.proof);return limits(l,o.size())?Result<Bytes>::ok(std::move(o)):Result<Bytes>::fail(ErrorCode::limit,"envelope exceeds bound");}
Result<Envelope> decode_envelope(const Bytes&b,const Limits&l){if(!limits(l,b.size()))return Result<Envelope>::fail(ErrorCode::limit,"envelope exceeds bound");Reader r{b};auto v=r.byte();if(!v||v.value.value()!=version)return Result<Envelope>::fail(ErrorCode::unsupported,"unknown envelope version");auto q=r.lp(l.max_input);if(!q)return Result<Envelope>::fail(q.error->code,q.error->message);auto request=decode_request(*q.value,l);if(!request)return Result<Envelope>::fail(request.error->code,request.error->message);if(r.p+4>b.size())return Result<Envelope>::fail(ErrorCode::malformed,"truncated proof length");auto proof=r.lp(l.max_proof);if(!proof||proof.value->empty()||r.p!=b.size())return Result<Envelope>::fail(ErrorCode::noncanonical,"trailing data or invalid proof");return Result<Envelope>::ok({*request.value,*proof.value});}
namespace {
bool holder_identity(const CircuitIdentity& identity) {
  return identity.binding == Binding::holder_bound &&
         identity.trust == Trust::exact_key;
}
bool identity_equal(const CircuitIdentity& left, const CircuitIdentity& right) {
  return left.binding == right.binding && left.trust == right.trust &&
         left.capacity == right.capacity &&
         left.circuit_digest == right.circuit_digest && left.field == right.field &&
         left.ligero_rate == right.ligero_rate && left.query_count == right.query_count;
}
bool request_equal(const Request& left, const Request& right, const Limits& limits) {
  const auto lhs = encode_request(left, limits);
  const auto rhs = encode_request(right, limits);
  return lhs && rhs && *lhs.value == *rhs.value;
}
Result<void*> holder_shape(const HolderBoundEnvelope& value, const Limits& limits) {
  if (!holder_identity(value.request.identity) ||
      !holder_identity(value.credential_identity) ||
      !holder_identity(value.kb_identity) ||
      value.credential_identity.trust != value.kb_identity.trust ||
      !identity_equal(value.request.identity, value.credential_identity) ||
      value.credential_identity.circuit_digest == value.kb_identity.circuit_digest ||
      value.request.audience.empty() || value.request.nonce.empty() ||
      value.request.policy.empty() || value.request.policy_result != Bytes{1} ||
      value.credential_commitment.empty() || value.kb_commitment.empty() ||
      value.credential_commitment.size() > limits.max_proof ||
      value.kb_commitment.size() > limits.max_proof ||
      value.bridge_public.size() != 112 || value.credential_proof.empty() ||
      value.kb_proof.empty() || value.credential_proof.size() > limits.max_proof ||
      value.kb_proof.size() > limits.max_proof ||
      value.status_proof.size() > limits.max_proof)
    return Result<void*>::fail(ErrorCode::malformed, "invalid holder proof envelope");
  return Result<void*>::ok(nullptr);
}
}
Result<Bytes> encode_holder_bound_envelope(const HolderBoundEnvelope& x,const Limits&l){
  if (!holder_shape(x,l)) return Result<Bytes>::fail(ErrorCode::malformed,"invalid holder proof envelope");
  if (x.request.status_public.empty() != x.status_proof.empty()) return Result<Bytes>::fail(ErrorCode::malformed,"status policy/proof mismatch");
  auto request=encode_request(x.request,l), credential=encode_identity(x.credential_identity,l), kb=encode_identity(x.kb_identity,l);
  if(!request||!credential||!kb)return Result<Bytes>::fail(ErrorCode::malformed,"noncanonical holder proof envelope");
  Bytes o{version,1}; lp(o,*request.value); lp(o,*credential.value); lp(o,*kb.value);
  lp(o,x.credential_commitment); lp(o,x.kb_commitment); lp(o,x.bridge_public);
  lp(o,x.credential_proof); lp(o,x.kb_proof); lp(o,x.status_proof);
  return limits(l,o.size())?Result<Bytes>::ok(std::move(o)):Result<Bytes>::fail(ErrorCode::limit,"holder proof envelope exceeds bound");
}
Result<HolderBoundEnvelope> decode_holder_bound_envelope(const Bytes&b,const Limits&l){
  if(!limits(l,b.size()))return Result<HolderBoundEnvelope>::fail(ErrorCode::limit,"holder proof envelope exceeds bound");
  Reader r{b};auto version_byte=r.byte(),schema=r.byte();
  if(!version_byte||!schema||version_byte.value.value()!=version||schema.value.value()!=1)return Result<HolderBoundEnvelope>::fail(ErrorCode::unsupported,"unknown holder proof envelope version");
  auto request_bytes=r.lp(l.max_input),credential_bytes=r.lp(l.max_field),kb_bytes=r.lp(l.max_field);
  auto credential_commitment=r.lp(l.max_proof),kb_commitment=r.lp(l.max_proof),bridge=r.lp(112),credential_proof=r.lp(l.max_proof),kb_proof=r.lp(l.max_proof),status_proof=r.lp(l.max_proof);
  if(!request_bytes||!credential_bytes||!kb_bytes||!credential_commitment||!kb_commitment||!bridge||!credential_proof||!kb_proof||!status_proof||r.p!=b.size())return Result<HolderBoundEnvelope>::fail(ErrorCode::noncanonical,"truncated or trailing holder proof envelope");
  auto request=decode_request(*request_bytes.value,l);
  auto credential=decode_identity(*credential_bytes.value,l);
  auto kb=decode_identity(*kb_bytes.value,l);
  if(!request||!credential||!kb)return Result<HolderBoundEnvelope>::fail(ErrorCode::malformed,"invalid holder proof envelope fields");
  HolderBoundEnvelope out{*request.value,*credential.value,*kb.value,*credential_commitment.value,*kb_commitment.value,*bridge.value,*credential_proof.value,*kb_proof.value,*status_proof.value};
  auto valid=holder_shape(out,l); if(!valid)return Result<HolderBoundEnvelope>::fail(valid.error->code,valid.error->message);
  return Result<HolderBoundEnvelope>::ok(std::move(out));
}
Result<HolderBoundEnvelope> prove_holder_bound_envelope_v1(
    const HolderBoundVerifierPolicyV1& request,
    HolderBoundProofProverV1& proof_prover, const Limits& limits) {
  if (!holder_identity(request.request.identity) ||
      !holder_identity(request.credential_identity) ||
      !holder_identity(request.kb_identity) ||
      request.credential_identity.trust != request.kb_identity.trust ||
      !identity_equal(request.request.identity, request.credential_identity) ||
      request.credential_identity.circuit_digest ==
          request.kb_identity.circuit_digest ||
      request.request.audience.empty() || request.request.nonce.empty() ||
      request.request.policy.empty() || request.request.policy_result != Bytes{1})
    return Result<HolderBoundEnvelope>::fail(
        ErrorCode::unsupported, "invalid holder proof request");
  try {
    auto credential_commitment = proof_prover.commit(
        HolderComponent::credential, request.credential_identity,
        request.request);
    if (!credential_commitment || credential_commitment.value->empty() ||
        credential_commitment.value->size() > limits.max_proof)
      return Result<HolderBoundEnvelope>::fail(
          ErrorCode::malformed,
          credential_commitment ? "credential commitment failed"
                                : credential_commitment.error->message);
    auto kb_commitment = proof_prover.commit(
        HolderComponent::kb, request.kb_identity, request.request);
    if (!kb_commitment || kb_commitment.value->empty() ||
        kb_commitment.value->size() > limits.max_proof)
      return Result<HolderBoundEnvelope>::fail(ErrorCode::malformed,
                                               "KB commitment failed");
    auto bridge = proof_prover.bridge_public(
        request.request, request.credential_identity, request.kb_identity,
        *credential_commitment.value, *kb_commitment.value);
    if (!bridge || bridge.value->size() != 112)
      return Result<HolderBoundEnvelope>::fail(
          ErrorCode::malformed, "holder bridge derivation failed");
    auto credential_proof = proof_prover.prove(
        HolderComponent::credential, request.credential_identity,
        request.request, *credential_commitment.value, *kb_commitment.value,
        *bridge.value);
    if (!credential_proof || credential_proof.value->empty() ||
        credential_proof.value->size() > limits.max_proof)
      return Result<HolderBoundEnvelope>::fail(ErrorCode::malformed,
                                               "credential proof failed");
    auto kb_proof = proof_prover.prove(
        HolderComponent::kb, request.kb_identity, request.request,
        *credential_commitment.value, *kb_commitment.value, *bridge.value);
    if (!kb_proof || kb_proof.value->empty() ||
        kb_proof.value->size() > limits.max_proof)
      return Result<HolderBoundEnvelope>::fail(ErrorCode::malformed,
                                               "KB proof failed");
    HolderBoundEnvelope envelope{
        request.request, request.credential_identity, request.kb_identity,
        std::move(*credential_commitment.value), std::move(*kb_commitment.value),
        std::move(*bridge.value), std::move(*credential_proof.value),
        std::move(*kb_proof.value), {}};
    const auto shape = holder_shape(envelope, limits);
    if (!shape)
      return Result<HolderBoundEnvelope>::fail(shape.error->code,
                                               shape.error->message);
    return Result<HolderBoundEnvelope>::ok(std::move(envelope));
  } catch (...) {
    return Result<HolderBoundEnvelope>::fail(
        ErrorCode::malformed, "holder proof callback failed");
  }
}
Result<bool> verify_holder_bound_envelope_v1(const HolderBoundEnvelope& envelope,
    const HolderBoundVerifierPolicyV1& expected, std::uint64_t now,
    HolderBoundProofVerifierV1& proof_verifier, HolderBoundReplayStoreV1& replay_store,
    const Limits& limits) {
  const auto shape = holder_shape(envelope, limits);
  if (!shape) return Result<bool>::fail(shape.error->code, shape.error->message);
  if (!holder_identity(expected.request.identity) ||
      !holder_identity(expected.credential_identity) ||
      !holder_identity(expected.kb_identity) ||
      expected.credential_identity.trust != expected.kb_identity.trust ||
      !identity_equal(expected.request.identity, expected.credential_identity) ||
      expected.credential_identity.circuit_digest ==
          expected.kb_identity.circuit_digest ||
      !request_equal(envelope.request, expected.request, limits) ||
      !identity_equal(envelope.credential_identity, expected.credential_identity) ||
      !identity_equal(envelope.kb_identity, expected.kb_identity))
    return Result<bool>::fail(ErrorCode::malformed, "holder envelope request or identity substitution");
  if (now < expected.request.time_min || now > expected.request.time_max)
    return Result<bool>::fail(ErrorCode::malformed, "holder request is outside its validity window");
  // Verify strictly in canonical order.  The KB verifier therefore sees the
  // same request, bridge values, and established credential commitment.
  try {
    if (!proof_verifier.verify(
            HolderComponent::credential, envelope.credential_identity,
            envelope.request, envelope.credential_commitment,
            envelope.kb_commitment, envelope.bridge_public,
            envelope.credential_proof) ||
        !proof_verifier.verify(
            HolderComponent::kb, envelope.kb_identity, envelope.request,
            envelope.credential_commitment, envelope.kb_commitment,
            envelope.bridge_public, envelope.kb_proof))
      return Result<bool>::fail(
          ErrorCode::malformed, "holder proof component verification failed");
    if (!replay_store.consume(expected.request.audience, expected.request.nonce,
                              expected.request.time_max))
      return Result<bool>::fail(
          ErrorCode::malformed, "holder nonce has already been consumed");
  } catch (...) {
    return Result<bool>::fail(ErrorCode::malformed,
                              "holder verifier callback failed");
  }
  return Result<bool>::ok(true);
}
std::array<std::uint8_t,32> transcript_seed(const Request&x){auto s=encode_request(x);if(!s)return {};std::string in="SDJWT-ZK-V1/transcript";in.append(reinterpret_cast<const char*>(s.value->data()),s.value->size());return sha256_ascii(in);}
} // namespace sd_jwt_zk
