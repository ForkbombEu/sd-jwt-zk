#include "sd_jwt_zk/swiss_claims.h"

#include <charconv>
#include <cctype>
#include <set>

namespace sd_jwt_zk {
namespace {
const JsonValue* member(const JsonValue& object, std::string_view name) {
  if (object.kind != JsonKind::object) return nullptr;
  for (const auto& item : object.members) if (item.first == name) return &item.second;
  return nullptr;
}
bool text(const JsonValue* value, std::string_view expected) {
  return value && value->kind == JsonKind::string && value->scalar == expected;
}
bool scalar(const JsonValue& value) {
  return value.kind == JsonKind::string || value.kind == JsonKind::number ||
         value.kind == JsonKind::boolean || value.kind == JsonKind::null_value;
}
bool root_array_element(const JsonValue& value) {
  if (scalar(value)) return true;
  // RFC 9901 array disclosures are the only object permitted below a root
  // array in this bounded, non-recursive Swiss profile.
  return value.kind == JsonKind::object && value.members.size() == 1 &&
         value.members.front().first == "..." &&
         value.members.front().second.kind == JsonKind::string;
}
bool bounded_nonrecursive_payload(const JsonValue& claims) {
  for (const auto& [name, value] : claims.members) {
    if (value.kind == JsonKind::object) return false;
    if (value.kind != JsonKind::array) continue;
    if (name == "_sd") {
      for (const auto& digest : value.elements)
        if (digest.kind != JsonKind::string) return false;
    } else {
      for (const auto& element : value.elements)
        if (!root_array_element(element)) return false;
    }
  }
  return true;
}
bool integer(const JsonValue& value, std::int64_t& out) {
  if (value.kind != JsonKind::number || value.scalar.find_first_of(".eE") != std::string::npos) return false;
  const auto result = std::from_chars(value.scalar.data(), value.scalar.data() + value.scalar.size(), out);
  return result.ec == std::errc{} && result.ptr == value.scalar.data() + value.scalar.size();
}
bool date(std::string_view value) {
  if (value.size() != 10 || value[4] != '-' || value[7] != '-') return false;
  for (const auto index : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U})
    if (!std::isdigit(static_cast<unsigned char>(value[index]))) return false;
  const auto number = [&value](std::size_t start, std::size_t count) {
    int result{};
    for (std::size_t i = start; i < start + count; ++i) result = result * 10 + value[i] - '0';
    return result;
  };
  const int year = number(0, 4), month = number(5, 2), day = number(8, 2);
  if (year == 0 || month < 1 || month > 12 || day < 1) return false;
  constexpr int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  int maximum = days[month - 1];
  if (month == 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))) ++maximum;
  return day <= maximum;
}
Result<bool> bad(const char* message) { return Result<bool>::fail(ErrorCode::malformed, message); }
}  // namespace
Result<bool> validate_swiss_compact_claims(std::string_view protected_header,
                                           std::string_view payload,
                                           const SwissTimePolicy& time_policy,
                                           const std::vector<SwissTypedPolicy>& policies,
                                           const JsonLimits& limits) {
  auto header = parse_bounded_json(protected_header, limits);
  auto claims = parse_bounded_json(payload, limits);
  if (!header || !claims || header.value->kind != JsonKind::object || claims.value->kind != JsonKind::object)
    return bad("Swiss header and payload must be objects");
  if (!text(member(*header.value, "alg"), "ES256") || !text(member(*header.value, "typ"), "dc+sd-jwt") ||
      !text(member(*header.value, "profile_version"), "swiss-profile-vc:1.0.0")) return bad("Swiss protected header");
  for (const auto& [_, value] : header.value->members)
    if (!scalar(value)) return bad("nested Swiss protected header");
  if (!bounded_nonrecursive_payload(*claims.value))
    return bad("recursive Swiss claim shape");
  if (!member(*claims.value, "vct") || member(*claims.value, "vct")->kind != JsonKind::string) return bad("missing top-level vct");
  if (const auto* algorithm = member(*claims.value, "_sd_alg");
      algorithm && !text(algorithm, "sha-256"))
    return bad("unsupported SD hash algorithm");
  for (const auto name : {"sub", "aud", "jti", "vct_version", "vct_subtype", "vct_subtype_version"}) {
    if (member(*claims.value, name)) return bad("registered claim must be disclosed");
  }
  if (member(*claims.value, "expiry_date")) return bad("expiry_date must be disclosed");
  for (const auto name : {"exp", "nbf", "iat"}) {
    if (const auto* value = member(*claims.value, name)) {
      std::int64_t timestamp{}; if (!integer(*value, timestamp) || timestamp < 0) return bad("registered time type");
      if (std::string_view(name) == "exp" && timestamp < static_cast<std::int64_t>(time_policy.now)) return bad("expired credential");
      if (std::string_view(name) == "nbf" && timestamp > static_cast<std::int64_t>(time_policy.now)) return bad("not yet valid credential");
      if (std::string_view(name) == "iat" && timestamp > static_cast<std::int64_t>(time_policy.now)) return bad("issued in future");
    } else if ((std::string_view(name) == "exp" && time_policy.require_expiry) ||
               (std::string_view(name) == "iat" && time_policy.require_issued_at)) return bad("missing required time");
  }
  std::set<std::string> paths;
  for (const auto& policy : policies) {
    if (policy.path.empty() || policy.path.find('.') != std::string::npos ||
        !paths.insert(policy.path).second)
      return bad("duplicate or recursive policy path");
    const auto* value = member(*claims.value, policy.path);
    if (!value) return bad("policy path absent");
    if (policy.kind == SwissPolicyKind::reveal) continue;
    if (policy.kind == SwissPolicyKind::boolean_value) {
      if (value->kind != JsonKind::boolean || value->scalar != policy.value) return bad("boolean policy");
    } else if (policy.kind == SwissPolicyKind::equality) {
      if (value->kind != JsonKind::string || value->scalar != policy.value) return bad("equality policy");
    } else if (policy.kind == SwissPolicyKind::set_membership) {
      if (value->kind != JsonKind::string || !std::set<std::string>(policy.set.begin(), policy.set.end()).contains(value->scalar)) return bad("set policy");
    } else if (policy.kind == SwissPolicyKind::date_range) {
      if (value->kind != JsonKind::string || !date(value->scalar) || !date(policy.value) ||
          !date(policy.upper) || policy.value > policy.upper || value->scalar < policy.value ||
          value->scalar > policy.upper) return bad("date range policy");
    } else if (policy.kind == SwissPolicyKind::integer_range) {
      std::int64_t actual{}, low{}, high{};
      const auto a = std::from_chars(policy.value.data(), policy.value.data() + policy.value.size(), low);
      const auto b = std::from_chars(policy.upper.data(), policy.upper.data() + policy.upper.size(), high);
      if (!integer(*value, actual) || a.ec != std::errc{} || b.ec != std::errc{} || low > high || actual < low || actual > high) return bad("integer range policy");
    } else {
      return bad("unknown policy kind");
    }
  }
  return Result<bool>::ok(true);
}
}  // namespace sd_jwt_zk
