#include "sd_jwt_zk/api.h"
#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
namespace sd_jwt_zk { namespace {
int sextet(char c) { if(c>='A'&&c<='Z')return c-'A';if(c>='a'&&c<='z')return c-'a'+26;if(c>='0'&&c<='9')return c-'0'+52;if(c=='-')return 62;if(c=='_')return 63;return -1; }
bool ascii(std::string_view s){return std::all_of(s.begin(),s.end(),[](unsigned char c){return c<128;});}
}
Result<Bytes> base64url_decode(std::string_view s,std::size_t limit){if(s.empty()||s.size()>limit||s.find('=')!=std::string_view::npos||s.size()%4==1)return Result<Bytes>::fail(ErrorCode::malformed,"invalid base64url");Bytes out;out.reserve((s.size()*3)/4);int bits=0,v=0;for(char c:s){auto n=sextet(c);if(n<0)return Result<Bytes>::fail(ErrorCode::malformed,"invalid base64url alphabet");v=(v<<6)|n;bits+=6;if(bits>=8){bits-=8;out.push_back(static_cast<std::uint8_t>(v>>bits));v&=(1<<bits)-1;}}if(bits&&(v!=0))return Result<Bytes>::fail(ErrorCode::noncanonical,"nonzero base64url tail");return Result<Bytes>::ok(std::move(out));}
std::string base64url_encode(const Bytes& b){static constexpr char a[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";std::string o;int bits=0,v=0;for(auto x:b){v=(v<<8)|x;bits+=8;while(bits>=6){bits-=6;o+=a[v>>bits];v&=(1<<bits)-1;}}if(bits)o+=a[v<<(6-bits)];return o;}
Result<CompactJws> split_compact_jws(std::string_view x,const Limits&l){if(x.empty()||x.size()>l.max_input||!ascii(x))return Result<CompactJws>::fail(ErrorCode::malformed,"invalid compact JWS input");auto a=x.find('.'),b=a==std::string_view::npos?a:x.find('.',a+1);if(a==std::string_view::npos||b==std::string_view::npos||x.find('.',b+1)!=std::string_view::npos||a==0||b==a+1||b+1==x.size())return Result<CompactJws>::fail(ErrorCode::malformed,"compact JWS requires three nonempty segments");for(auto s:{x.substr(0,a),x.substr(a+1,b-a-1),x.substr(b+1)}){auto d=base64url_decode(s,l.max_field);if(!d)return Result<CompactJws>::fail(d.error->code,d.error->message);}return Result<CompactJws>::ok({std::string(x.substr(0,a)),std::string(x.substr(a+1,b-a-1)),std::string(x.substr(b+1))});}
Result<P256Signature> decode_es256_signature(std::string_view x){auto b=base64url_decode(x,128);if(!b)return Result<P256Signature>::fail(b.error->code,b.error->message);if(b.value->size()!=64)return Result<P256Signature>::fail(ErrorCode::malformed,"ES256 signature must be 64 bytes");P256Signature s{};std::copy_n(b.value->begin(),32,s.r.begin());std::copy_n(b.value->begin()+32,32,s.s.begin());static constexpr std::array<std::uint8_t,32> order{0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};if(std::all_of(s.r.begin(),s.r.end(),[](auto v){return v==0;})||std::all_of(s.s.begin(),s.s.end(),[](auto v){return v==0;})||!std::lexicographical_compare(s.r.begin(),s.r.end(),order.begin(),order.end())||!std::lexicographical_compare(s.s.begin(),s.s.end(),order.begin(),order.end()))return Result<P256Signature>::fail(ErrorCode::malformed,"ES256 scalar outside P-256 order");return Result<P256Signature>::ok(s);}
bool es256_signature_is_low_s(const P256Signature& s){static constexpr std::array<std::uint8_t,32> half{0x7f,0xff,0xff,0xff,0x80,0x00,0x00,0x00,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8};return !std::lexicographical_compare(half.begin(),half.end(),s.s.begin(),s.s.end());}
Result<P256Key> decode_p256_jwk(std::string_view x,std::string_view y){auto xb=base64url_decode(x,64),yb=base64url_decode(y,64);if(!xb||!yb)return Result<P256Key>::fail(ErrorCode::malformed,"invalid P-256 coordinate");if(xb.value->size()!=32||yb.value->size()!=32)return Result<P256Key>::fail(ErrorCode::malformed,"P-256 coordinate must be 32 bytes");P256Key k{};std::copy(xb.value->begin(),xb.value->end(),k.x.begin());std::copy(yb.value->begin(),yb.value->end(),k.y.begin());if(std::all_of(k.x.begin(),k.x.end(),[](auto v){return v==0;})&&std::all_of(k.y.begin(),k.y.end(),[](auto v){return v==0;}))return Result<P256Key>::fail(ErrorCode::malformed,"P-256 infinity encoding rejected");return Result<P256Key>::ok(k);}
bool p256_key_is_valid(const P256Key& key){std::array<unsigned char,65> encoded{4};std::copy(key.x.begin(),key.x.end(),encoded.begin()+1);std::copy(key.y.begin(),key.y.end(),encoded.begin()+33);OSSL_PARAM params[]={OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,const_cast<char*>("prime256v1"),0),OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,encoded.data(),encoded.size()),OSSL_PARAM_construct_end()};EVP_PKEY_CTX* fromdata=EVP_PKEY_CTX_new_from_name(nullptr,"EC",nullptr);EVP_PKEY* pkey=nullptr;bool ok=fromdata&&EVP_PKEY_fromdata_init(fromdata)==1&&EVP_PKEY_fromdata(fromdata,&pkey,EVP_PKEY_PUBLIC_KEY,params)==1;EVP_PKEY_CTX* check=ok?EVP_PKEY_CTX_new(pkey,nullptr):nullptr;ok=check&&EVP_PKEY_public_check(check)==1;EVP_PKEY_CTX_free(check);EVP_PKEY_free(pkey);EVP_PKEY_CTX_free(fromdata);return ok;}
bool verify_es256_signature(const P256Key& key, std::string_view input,
                            const P256Signature& signature) {
  std::array<unsigned char, 65> encoded_key{4};
  std::copy(key.x.begin(), key.x.end(), encoded_key.begin() + 1);
  std::copy(key.y.begin(), key.y.end(), encoded_key.begin() + 33);
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                       const_cast<char*>("prime256v1"), 0),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                        encoded_key.data(), encoded_key.size()),
      OSSL_PARAM_construct_end()};
  EVP_PKEY_CTX* key_context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY* pkey = nullptr;
  bool ok = key_context && EVP_PKEY_fromdata_init(key_context) == 1 &&
            EVP_PKEY_fromdata(key_context, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1;
  EVP_MD_CTX* context = ok ? EVP_MD_CTX_new() : nullptr;
  ECDSA_SIG* sig = ok && context ? ECDSA_SIG_new() : nullptr;
  BIGNUM* r = sig ? BN_bin2bn(signature.r.data(), signature.r.size(), nullptr) : nullptr;
  BIGNUM* s = sig ? BN_bin2bn(signature.s.data(), signature.s.size(), nullptr) : nullptr;
  const bool signature_owns = r && s && ECDSA_SIG_set0(sig, r, s) == 1;
  ok = signature_owns;
  if (ok) {
    const int der_size = i2d_ECDSA_SIG(sig, nullptr);
    Bytes der(static_cast<std::size_t>(der_size));
    unsigned char* at = der.data();
    i2d_ECDSA_SIG(sig, &at);
    ok = EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
         EVP_DigestVerify(context, der.data(), der.size(),
                          reinterpret_cast<const unsigned char*>(input.data()), input.size()) == 1;
  }
  if (!signature_owns) { BN_free(r); BN_free(s); }
  ECDSA_SIG_free(sig); EVP_MD_CTX_free(context); EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(key_context);
  return ok;
}
SecretBytes::SecretBytes(Bytes b):bytes_(std::move(b)){} SecretBytes::~SecretBytes(){volatile std::uint8_t* p=bytes_.data();for(size_t i=0;i<bytes_.size();++i)p[i]=0;} SecretBytes::SecretBytes(SecretBytes&&o)noexcept:bytes_(std::move(o.bytes_)){} SecretBytes& SecretBytes::operator=(SecretBytes&&o)noexcept{if(this!=&o){volatile std::uint8_t* p=bytes_.data();for(size_t i=0;i<bytes_.size();++i)p[i]=0;bytes_=std::move(o.bytes_);}return *this;} const Bytes& SecretBytes::view()const{return bytes_;}
Result<NativeWitness> build_native_witness(std::string_view p,const Limits&l){if(p.empty()||p.size()>l.max_input||!ascii(p))return Result<NativeWitness>::fail(ErrorCode::secret,"credential syntax rejected");std::vector<std::string_view> parts;size_t start=0;while(start<=p.size()){auto e=p.find('~',start);parts.push_back(p.substr(start,e==std::string_view::npos?p.size()-start:e-start));if(e==std::string_view::npos)break;start=e+1;}if(!parts.empty()&&parts.back().empty())parts.pop_back();if(parts.size()<2||parts.front().empty())return Result<NativeWitness>::fail(ErrorCode::secret,"presentation syntax rejected");auto issuer=split_compact_jws(parts.front(),l);if(!issuer)return Result<NativeWitness>::fail(ErrorCode::secret,"issuer JWS rejected");NativeWitness out{*issuer.value,{},{}};for(size_t i=1;i<parts.size();++i){if(parts[i].empty())return Result<NativeWitness>::fail(ErrorCode::secret,"empty disclosure rejected");auto d=base64url_decode(parts[i],l.max_field);if(!d)return Result<NativeWitness>::fail(ErrorCode::secret,"disclosure rejected");out.disclosures.emplace_back(parts[i]);}return Result<NativeWitness>::ok(std::move(out));}
bool native_parsing_is_not_proof_verification(){return true;}
} // namespace sd_jwt_zk
