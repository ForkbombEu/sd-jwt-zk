#include "sd_jwt_zk/swiss_claims.h"

namespace {
bool check(const char* header, const char* payload,
           const std::vector<sd_jwt_zk::SwissTypedPolicy>& policies = {}) {
  return static_cast<bool>(sd_jwt_zk::validate_swiss_compact_claims(
      header, payload, {100, true, true}, policies));
}
}  // namespace
int main() {
  constexpr char kHeader[] = "{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\",\"profile_version\":\"swiss-profile-vc:1.0.0\"}";
  constexpr char kPayload[] = "{\"vct\":\"example\",\"exp\":101,\"nbf\":99,\"iat\":100,\"active\":true,\"age\":18,\"country\":\"CH\",\"birth_date\":\"2000-02-29\"}";
  if (!check(kHeader, kPayload, {{"active", sd_jwt_zk::SwissPolicyKind::boolean_value, "true"}, {"age", sd_jwt_zk::SwissPolicyKind::integer_range, "18", "20"}, {"country", sd_jwt_zk::SwissPolicyKind::equality, "CH"}, {"birth_date", sd_jwt_zk::SwissPolicyKind::date_range, "2000-01-01", "2000-12-31"}, {"vct", sd_jwt_zk::SwissPolicyKind::reveal}})) return 1;
  if (check("{\"alg\":\"none\",\"typ\":\"dc+sd-jwt\",\"profile_version\":\"swiss-profile-vc:1.0.0\"}", kPayload)) return 2;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":99}")) return 3;
  if (check(kHeader, "{\"vct\":\"x\",\"sub\":false,\"exp\":101}")) return 4;
  if (check(kHeader, kPayload, {{"age", sd_jwt_zk::SwissPolicyKind::integer_range, "19", "20"}})) return 5;
  if (check(kHeader, kPayload, {{"age", sd_jwt_zk::SwissPolicyKind::reveal}, {"age", sd_jwt_zk::SwissPolicyKind::reveal}})) return 6;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":101}")) return 7;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":100,\"expiry_date\":\"2027-02-29\"}")) return 8;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":100,\"aud\":false}")) return 9;
  if (!check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":100,\"_sd\":[\"digest\"],\"items\":[{\"...\":\"digest\"}]}")) return 10;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":100,\"claim\":{\"nested\":true}}")) return 11;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":100,\"items\":[[true]]}")) return 12;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":100,\"items\":[{\"...\":\"digest\",\"extra\":false}]}")) return 13;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":100,\"_sd_alg\":\"sha-512\"}")) return 14;
  if (check(kHeader, kPayload, {{"country", sd_jwt_zk::SwissPolicyKind::set_membership, {}, {}, {"DE", "FR"}}})) return 15;
  if (!check(kHeader, kPayload, {{"country", sd_jwt_zk::SwissPolicyKind::set_membership, {}, {}, {"CH", "DE"}}})) return 16;
  if (check(kHeader, kPayload, {{"active", sd_jwt_zk::SwissPolicyKind::equality, "true"}})) return 17;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"iat\":100,\"claim\":{\"value\":true}}", {{"claim.value", sd_jwt_zk::SwissPolicyKind::boolean_value, "true"}})) return 18;
  if (check(kHeader, "{\"vct\":false,\"exp\":101,\"iat\":100}")) return 19;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":\"101\",\"iat\":100}")) return 20;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101,\"nbf\":101,\"iat\":100}")) return 21;
  if (check(kHeader, "{\"vct\":\"x\",\"exp\":101}")) return 22;
  if (check(kHeader, kPayload, {{"birth_date", sd_jwt_zk::SwissPolicyKind::date_range, "2000-02-30", "2000-12-31"}})) return 23;
  if (check(kHeader, kPayload, {{"age", sd_jwt_zk::SwissPolicyKind::integer_range, "20", "18"}})) return 24;
  if (check(kHeader, kPayload, {{"country", sd_jwt_zk::SwissPolicyKind::reveal}, {"country", sd_jwt_zk::SwissPolicyKind::set_membership, {}, {}, {"CH"}}})) return 25;
  if (check("{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\",\"profile_version\":\"swiss-profile-vc:1.0.0\",\"nested\":{}}", kPayload)) return 26;
  return 0;
}
