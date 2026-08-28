#include "sd_jwt_zk/issuer_registry.h"

#include <algorithm>
#include <limits>
#include <string_view>

namespace sd_jwt_zk {
namespace {
constexpr std::string_view kLeafTag = "SDJWT-ZK/issuer-registry/v1/leaf";
constexpr std::string_view kNodeTag = "SDJWT-ZK/issuer-registry/v1/node";
constexpr std::string_view kEmptyTag = "SDJWT-ZK/issuer-registry/v1/empty";

void append_u64(Bytes& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8)
    out.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u32(Bytes& out, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8)
    out.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append(Bytes& out, std::string_view value) {
  out.insert(out.end(), value.begin(), value.end());
}

void append(Bytes& out, const std::array<std::uint8_t, 32>& value) {
  out.insert(out.end(), value.begin(), value.end());
}

bool valid_vct(std::string_view vct, const Limits& limits) {
  if (vct.empty() || vct.size() > limits.max_field) return false;
  for (unsigned char c : vct)
    if (c < 0x21 || c > 0x7e || c == '"' || c == '\\') return false;
  return true;
}

bool valid_record(const IssuerAuthorizationRecordV1& record,
                  const Limits& limits) {
  return p256_key_is_valid(record.issuer_key) && valid_vct(record.vct, limits) &&
         record.not_before <= record.not_after;
}

Bytes canonical_record(const IssuerAuthorizationRecordV1& record,
                       const Limits& limits) {
  Bytes value;
  if (!valid_record(record, limits)) return value;
  value.reserve(64 + 4 + record.vct.size() + 16);
  value.insert(value.end(), record.issuer_key.x.begin(), record.issuer_key.x.end());
  value.insert(value.end(), record.issuer_key.y.begin(), record.issuer_key.y.end());
  append_u32(value, static_cast<std::uint32_t>(record.vct.size()));
  append(value, record.vct);
  append_u64(value, record.not_before);
  append_u64(value, record.not_after);
  return value;
}

std::array<std::uint8_t, 32> hash(Bytes value) {
  return sha256_ascii(std::string_view(reinterpret_cast<const char*>(value.data()),
                                       value.size()));
}

std::array<std::uint8_t, 32> empty_node(std::uint8_t height) {
  Bytes input;
  append(input, kEmptyTag);
  input.push_back(height);
  return hash(std::move(input));
}

std::array<std::uint8_t, 32> internal_node(
    const std::array<std::uint8_t, 32>& left,
    const std::array<std::uint8_t, 32>& right) {
  Bytes input;
  append(input, kNodeTag);
  append(input, left);
  append(input, right);
  return hash(std::move(input));
}
}  // namespace

Result<Bytes> encode_registry_trust_context_v1(
    const RegistryTrustContextV1& context) {
  if (context.depth == 0 || context.depth > 20 ||
      context.valid_from > context.valid_until)
    return Result<Bytes>::fail(ErrorCode::malformed,
                               "invalid registry trust context");
  Bytes encoded{1};
  append(encoded, context.root);
  append_u64(encoded, context.epoch);
  append_u64(encoded, context.valid_from);
  append_u64(encoded, context.valid_until);
  encoded.push_back(context.depth);
  return Result<Bytes>::ok(std::move(encoded));
}

Result<RegistryTrustContextV1> decode_registry_trust_context_v1(
    const Bytes& encoded) {
  constexpr std::size_t kSize = 1 + 32 + 8 + 8 + 8 + 1;
  if (encoded.size() != kSize || encoded[0] != 1)
    return Result<RegistryTrustContextV1>::fail(ErrorCode::noncanonical,
                                                 "invalid registry context encoding");
  RegistryTrustContextV1 context;
  std::copy_n(encoded.begin() + 1, context.root.size(), context.root.begin());
  std::size_t at = 33;
  auto read_u64 = [&]() {
    std::uint64_t value{};
    for (int i = 0; i < 8; ++i) value = (value << 8) | encoded[at++];
    return value;
  };
  context.epoch = read_u64();
  context.valid_from = read_u64();
  context.valid_until = read_u64();
  context.depth = encoded[at];
  const auto canonical = encode_registry_trust_context_v1(context);
  if (!canonical)
    return Result<RegistryTrustContextV1>::fail(canonical.error->code,
                                                 canonical.error->message);
  return Result<RegistryTrustContextV1>::ok(context);
}

RegistryTrustContextV1 registry_trust_context_v1(const IssuerRegistryV1& registry) {
  return {registry.root, registry.epoch, registry.valid_from,
          registry.valid_until, registry.depth};
}

std::array<std::uint8_t, 32> issuer_registry_leaf_v1(
    const IssuerAuthorizationRecordV1& record) {
  const Limits limits{};
  const auto encoded = canonical_record(record, limits);
  if (encoded.empty()) return {};
  Bytes input;
  append(input, kLeafTag);
  // The sorted canonical bytes prevent duplicate/ordering ambiguity, while
  // the leaf relation deliberately commits to H(vct), not a variable-length
  // raw type string.  That is the fixed SHA-256 circuit preimage.
  append(input, record.issuer_key.x);
  append(input, record.issuer_key.y);
  const auto vct_hash = sha256_ascii(record.vct);
  append(input, vct_hash);
  append_u64(input, record.not_before);
  append_u64(input, record.not_after);
  return hash(std::move(input));
}

Result<IssuerRegistryV1> build_issuer_registry_v1(
    std::vector<IssuerAuthorizationRecordV1> records, std::uint8_t depth,
    std::uint64_t epoch, std::uint64_t valid_from, std::uint64_t valid_until,
    const Limits& limits) {
  if (depth == 0 || depth > 20 || valid_from > valid_until)
    return Result<IssuerRegistryV1>::fail(ErrorCode::limit,
                                           "invalid registry dimensions");
  const std::size_t capacity = std::size_t{1} << depth;
  if (records.size() > capacity || records.size() > limits.max_input)
    return Result<IssuerRegistryV1>::fail(ErrorCode::limit,
                                           "registry exceeds fixed capacity");
  struct Ordered { Bytes canonical; IssuerAuthorizationRecordV1 record; };
  std::vector<Ordered> ordered;
  ordered.reserve(records.size());
  for (auto& record : records) {
    auto canonical = canonical_record(record, limits);
    if (canonical.empty())
      return Result<IssuerRegistryV1>::fail(ErrorCode::malformed,
                                             "invalid issuer authorization");
    ordered.push_back({std::move(canonical), std::move(record)});
  }
  std::sort(ordered.begin(), ordered.end(), [](const Ordered& a, const Ordered& b) {
    return a.canonical < b.canonical;
  });
  for (std::size_t i = 1; i < ordered.size(); ++i)
    if (ordered[i - 1].canonical == ordered[i].canonical)
      return Result<IssuerRegistryV1>::fail(ErrorCode::noncanonical,
                                             "duplicate issuer authorization");

  std::vector<std::array<std::uint8_t, 32>> level(capacity);
  for (std::size_t i = 0; i < capacity; ++i)
    level[i] = i < ordered.size() ? issuer_registry_leaf_v1(ordered[i].record)
                                  : empty_node(0);
  IssuerRegistryV1 result{epoch, valid_from, valid_until, depth, {}, {}};
  result.paths.reserve(ordered.size());
  for (std::size_t i = 0; i < ordered.size(); ++i)
    result.paths.push_back({ordered[i].record, epoch, static_cast<std::uint32_t>(i), {}, {}});
  for (std::uint8_t height = 0; height < depth; ++height) {
    for (std::size_t i = 0; i < result.paths.size(); ++i) {
      const std::size_t slot = std::size_t{result.paths[i].index} >> height;
      result.paths[i].siblings.push_back(level[slot ^ 1]);
      result.paths[i].sibling_is_left.push_back((slot & 1U) != 0U);
    }
    std::vector<std::array<std::uint8_t, 32>> parent(level.size() / 2);
    for (std::size_t i = 0; i < parent.size(); ++i)
      parent[i] = internal_node(level[2 * i], level[2 * i + 1]);
    level = std::move(parent);
  }
  result.root = level.front();
  return Result<IssuerRegistryV1>::ok(std::move(result));
}

bool issuer_registry_path_matches_v1(const IssuerRegistryV1& registry,
                                     const IssuerRegistryPathV1& path) {
  if (registry.depth == 0 || registry.depth > 20 ||
      registry.valid_from > registry.valid_until ||
      path.epoch != registry.epoch ||
      path.siblings.size() != registry.depth ||
      path.sibling_is_left.size() != registry.depth ||
      path.index >= (std::uint32_t{1} << registry.depth) ||
      issuer_registry_leaf_v1(path.record) == std::array<std::uint8_t, 32>{})
    return false;
  auto current = issuer_registry_leaf_v1(path.record);
  for (std::uint8_t height = 0; height < registry.depth; ++height) {
    const bool expected_left = ((path.index >> height) & 1U) != 0U;
    if (path.sibling_is_left[height] != expected_left) return false;
    current = expected_left ? internal_node(path.siblings[height], current)
                            : internal_node(current, path.siblings[height]);
  }
  return current == registry.root;
}
}  // namespace sd_jwt_zk
