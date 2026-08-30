#include "sd_jwt_zk/disclosure_processing.h"

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <string_view>

#include "sd_jwt_zk/bounded_json_relation.h"

namespace sd_jwt_zk {
namespace {

template <class T>
Result<T> malformed(std::string message) {
  return Result<T>::fail(ErrorCode::malformed, std::move(message));
}

std::string disclosure_digest(std::string_view disclosure) {
  const auto bytes = sha256_ascii(disclosure);
  return base64url_encode(Bytes(bytes.begin(), bytes.end()));
}

std::string pointer_component(std::string_view input) {
  std::string result;
  result.reserve(input.size());
  for (const char byte : input) {
    if (byte == '~') result += "~0";
    else if (byte == '/') result += "~1";
    else result += byte;
  }
  return result;
}

std::string child_path(std::string_view parent, std::string_view component) {
  std::string result(parent);
  result.push_back('/');
  result += pointer_component(component);
  return result;
}

bool valid_digest_text(std::string_view digest) {
  if (digest.size() != 43) return false;
  const auto decoded = base64url_decode(digest, 64);
  return decoded && decoded.value->size() == 32;
}

int hex_digit(char byte) {
  if (byte >= '0' && byte <= '9') return byte - '0';
  if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
  if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;
  return -1;
}

std::optional<std::uint16_t> hex_quad(std::string_view input,
                                     std::size_t begin) {
  if (begin + 4 > input.size()) return std::nullopt;
  std::uint16_t result = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    const auto digit = hex_digit(input[begin + index]);
    if (digit < 0) return std::nullopt;
    result = static_cast<std::uint16_t>((result << 4) | digit);
  }
  return result;
}

Result<std::vector<DisclosureStringUnitAdvice>> string_units(
    std::string_view input, const JsonToken& token) {
  std::vector<DisclosureStringUnitAdvice> result;
  if (token.end < token.begin + 2 || token.end > input.size() ||
      input[token.begin] != '"' || input[token.end - 1] != '"')
    return malformed<std::vector<DisclosureStringUnitAdvice>>(
        "invalid string token range");
  std::size_t at = token.begin + 1;
  while (at < token.end - 1) {
    const std::size_t begin = at;
    std::uint32_t codepoint = 0;
    const auto first = static_cast<unsigned char>(input[at]);
    if (first == '\\') {
      if (++at >= token.end - 1)
        return malformed<std::vector<DisclosureStringUnitAdvice>>(
            "truncated string escape");
      const char escaped = input[at++];
      switch (escaped) {
        case '"': codepoint = '"'; break;
        case '\\': codepoint = '\\'; break;
        case '/': codepoint = '/'; break;
        case 'b': codepoint = 0x08; break;
        case 'f': codepoint = 0x0c; break;
        case 'n': codepoint = 0x0a; break;
        case 'r': codepoint = 0x0d; break;
        case 't': codepoint = 0x09; break;
        case 'u': {
          const auto high = hex_quad(input, at);
          if (!high) return malformed<std::vector<DisclosureStringUnitAdvice>>(
              "invalid unicode escape");
          at += 4;
          if (*high >= 0xd800 && *high <= 0xdbff) {
            if (at + 6 > token.end - 1 || input.substr(at, 2) != "\\u")
              return malformed<std::vector<DisclosureStringUnitAdvice>>(
                  "missing low surrogate");
            const auto low = hex_quad(input, at + 2);
            if (!low || *low < 0xdc00 || *low > 0xdfff)
              return malformed<std::vector<DisclosureStringUnitAdvice>>(
                  "invalid low surrogate");
            codepoint = 0x10000 +
                        ((static_cast<std::uint32_t>(*high) - 0xd800) << 10) +
                        (static_cast<std::uint32_t>(*low) - 0xdc00);
            at += 6;
          } else {
            if (*high >= 0xdc00 && *high <= 0xdfff)
              return malformed<std::vector<DisclosureStringUnitAdvice>>(
                  "unpaired low surrogate");
            codepoint = *high;
          }
          break;
        }
        default:
          return malformed<std::vector<DisclosureStringUnitAdvice>>(
              "invalid string escape");
      }
    } else {
      std::size_t width = 1;
      if (first < 0x80) {
        codepoint = first;
      } else if ((first & 0xe0) == 0xc0) {
        width = 2; codepoint = first & 0x1f;
      } else if ((first & 0xf0) == 0xe0) {
        width = 3; codepoint = first & 0x0f;
      } else if ((first & 0xf8) == 0xf0) {
        width = 4; codepoint = first & 0x07;
      } else {
        return malformed<std::vector<DisclosureStringUnitAdvice>>(
            "invalid UTF-8 leading byte");
      }
      if (at + width > token.end - 1)
        return malformed<std::vector<DisclosureStringUnitAdvice>>(
            "truncated UTF-8 string");
      for (std::size_t index = 1; index < width; ++index) {
        const auto continuation = static_cast<unsigned char>(input[at + index]);
        if ((continuation & 0xc0) != 0x80)
          return malformed<std::vector<DisclosureStringUnitAdvice>>(
              "invalid UTF-8 continuation");
        codepoint = (codepoint << 6) | (continuation & 0x3f);
      }
      at += width;
    }
    result.push_back({begin, at, codepoint});
  }
  return Result<std::vector<DisclosureStringUnitAdvice>>::ok(std::move(result));
}

struct SuppliedDisclosure {
  std::string encoded;
  std::string decoded;
  JsonValue parsed;
  std::vector<JsonToken> tokens;
  DisclosureKind kind{};

  const JsonValue& value() const {
    return parsed.elements[kind == DisclosureKind::object_property ? 2 : 1];
  }
};

struct PendingReference {
  DisclosureKind kind{};
  std::string digest;
  std::string container_path;
  std::string array_path;
  std::size_t parent{kRootDisclosureParent};
  std::size_t parent_depth{};
  std::size_t source{};
  std::size_t begin{};
  std::size_t end{};
  DisclosurePlacementWitness placement{};
};

class GraphBuilder {
 public:
  GraphBuilder(std::string_view issuer_payload,
               const std::vector<std::string>& disclosures,
               const DisclosureProcessingLimits& limits,
               bool validate = true)
      : issuer_payload_(issuer_payload),
        disclosures_(disclosures),
        limits_(limits),
        validate_(validate) {}

  Result<DisclosureGraphWitness> build() {
    if (disclosures_.size() > limits_.max_disclosures)
      return Result<DisclosureGraphWitness>::fail(ErrorCode::limit,
                                                   "disclosure limit");
    if (limits_.max_disclosure_depth == 0)
      return Result<DisclosureGraphWitness>::fail(ErrorCode::limit,
                                                   "disclosure depth limit");
    auto root = parse_bounded_json(issuer_payload_, limits_.json);
    if (!root)
      return Result<DisclosureGraphWitness>::fail(root.error->code,
                                                   root.error->message);
    if (root.value->kind != JsonKind::object)
      return malformed<DisclosureGraphWitness>("issuer payload must be an object");
    auto root_table =
        build_bounded_json_placement_table(issuer_payload_, limits_.json);
    if (!root_table)
      return Result<DisclosureGraphWitness>::fail(root_table.error->code,
                                                   root_table.error->message);
    graph_.source_tokens.push_back(root_table.value->tokens);
    graph_.source_parser_tables.push_back(std::move(*root_table.value));

    supplied_.reserve(disclosures_.size());
    for (std::size_t index = 0; index < disclosures_.size(); ++index) {
      const auto& encoded = disclosures_[index];
      auto decoded = base64url_decode(encoded, limits_.json.max_bytes);
      if (!decoded)
        return malformed<DisclosureGraphWitness>("invalid disclosure encoding");
      SuppliedDisclosure supplied;
      supplied.encoded = encoded;
      supplied.decoded.assign(decoded.value->begin(), decoded.value->end());
      auto parsed = parse_bounded_json(supplied.decoded, limits_.json);
      auto table =
          build_bounded_json_placement_table(supplied.decoded, limits_.json);
      if (!parsed || !table || parsed.value->kind != JsonKind::array ||
          (parsed.value->elements.size() != 2 &&
           parsed.value->elements.size() != 3) ||
          parsed.value->elements[0].kind != JsonKind::string)
        return malformed<DisclosureGraphWitness>("invalid disclosure shape");
      if (parsed.value->elements.size() == 3) {
        if (parsed.value->elements[1].kind != JsonKind::string ||
            parsed.value->elements[1].scalar.empty())
          return malformed<DisclosureGraphWitness>("invalid object disclosure name");
        const auto& name = parsed.value->elements[1].scalar;
        if (name == "_sd" || name == "_sd_alg" || name == "...")
          return malformed<DisclosureGraphWitness>("reserved disclosure name");
        supplied.kind = DisclosureKind::object_property;
      } else {
        supplied.kind = DisclosureKind::array_element;
      }
      supplied.parsed = std::move(*parsed.value);
      supplied.tokens = table.value->tokens;
      const auto digest = disclosure_digest(encoded);
      if (!digest_to_supplied_.emplace(digest, index).second)
        return malformed<DisclosureGraphWitness>("duplicate supplied disclosure");
      graph_.source_tokens.push_back(supplied.tokens);
      graph_.source_parser_tables.push_back(std::move(*table.value));
      supplied_.push_back(std::move(supplied));
    }

    std::vector<std::string> ancestry;
    auto scanned = scan_value(*root.value, "", kRootDisclosureParent, 0, 0,
                              true, ancestry);
    if (!scanned)
      return Result<DisclosureGraphWitness>::fail(scanned.error->code,
                                                   scanned.error->message);
    for (std::size_t supplied = 0; supplied < disclosures_.size(); ++supplied) {
      if (!used_supplied_.contains(supplied))
        return malformed<DisclosureGraphWitness>("unused disclosure");
    }
    graph_.signed_digest_count = seen_references_.size();
    if (validate_) {
      auto valid = validate_bounded_disclosure_graph(
          graph_, disclosures_, issuer_payload_, limits_);
      if (!valid)
        return Result<DisclosureGraphWitness>::fail(valid.error->code,
                                                     valid.error->message);
    }
    return Result<DisclosureGraphWitness>::ok(std::move(graph_));
  }

 private:
  static constexpr std::size_t kNoToken =
      std::numeric_limits<std::size_t>::max();

  std::size_t token_begin(std::size_t source, std::size_t begin,
                          JsonLexeme kind) const {
    const auto& tokens = graph_.source_tokens[source];
    for (std::size_t index = 0; index < tokens.size(); ++index) {
      if (tokens[index].begin == begin &&
          tokens[index].kind == static_cast<unsigned char>(kind))
        return index;
    }
    return kNoToken;
  }

  std::size_t token_end(std::size_t source, std::size_t end,
                        JsonLexeme kind) const {
    const auto& tokens = graph_.source_tokens[source];
    for (std::size_t index = 0; index < tokens.size(); ++index) {
      if (tokens[index].end == end &&
          tokens[index].kind == static_cast<unsigned char>(kind))
        return index;
    }
    return kNoToken;
  }

  std::pair<std::size_t, std::size_t> member_key_and_colon(
      std::size_t source, std::size_t value_begin) const {
    const auto& tokens = graph_.source_tokens[source];
    std::size_t value_token = kNoToken;
    for (std::size_t index = 0; index < tokens.size(); ++index) {
      if (tokens[index].begin == value_begin) {
        value_token = index;
        break;
      }
    }
    if (value_token == kNoToken || value_token == 0)
      return {kNoToken, kNoToken};
    auto previous = [&](std::size_t before) {
      while (before > 0) {
        --before;
        if (tokens[before].kind != static_cast<unsigned char>(
                                       JsonLexeme::whitespace))
          return before;
      }
      return kNoToken;
    };
    const auto colon = previous(value_token);
    if (colon == kNoToken ||
        tokens[colon].kind != static_cast<unsigned char>(JsonLexeme::colon))
      return {kNoToken, kNoToken};
    const auto marker = previous(colon);
    if (marker == kNoToken ||
        tokens[marker].kind != static_cast<unsigned char>(JsonLexeme::string))
      return {kNoToken, kNoToken};
    return {marker, colon};
  }

  Result<bool> scan_value(const JsonValue& value, const std::string& path,
                          std::size_t parent, std::size_t parent_depth,
                          std::size_t source, bool issuer_root,
                          std::vector<std::string>& ancestry) {
    if (value.kind == JsonKind::array) {
      for (std::size_t index = 0; index < value.elements.size(); ++index) {
        const auto& item = value.elements[index];
        const auto item_path = child_path(path, std::to_string(index));
        if (item.kind == JsonKind::object) {
          const auto placeholder = std::find_if(
              item.members.begin(), item.members.end(),
              [](const auto& member) { return member.first == "..."; });
          if (placeholder != item.members.end()) {
            if (item.members.size() != 1 ||
                placeholder->second.kind != JsonKind::string)
              return malformed<bool>("invalid array disclosure placeholder");
            PendingReference reference{DisclosureKind::array_element,
                                       placeholder->second.scalar,
                                       path,
                                       item_path,
                                       parent,
                                       parent_depth,
                                       source,
                                       placeholder->second.begin,
                                       placeholder->second.end};
            const auto [marker, colon] = member_key_and_colon(
                source, placeholder->second.begin);
            reference.placement.marker_token = marker;
            reference.placement.colon_token = colon;
            reference.placement.reference_token = token_begin(
                source, placeholder->second.begin, JsonLexeme::string);
            reference.placement.object_open_token =
                token_begin(source, item.begin, JsonLexeme::object_open);
            reference.placement.object_close_token =
                token_end(source, item.end, JsonLexeme::object_close);
            reference.placement.parent_array_open_token =
                token_begin(source, value.begin, JsonLexeme::array_open);
            reference.placement.array_index = index;
            auto resolved = resolve(reference, ancestry);
            if (!resolved) return resolved;
            continue;
          }
        }
        if (!claim_paths_.insert(item_path).second)
          return malformed<bool>("duplicate authenticated claim path");
        auto nested = scan_value(item, item_path, parent, parent_depth, source,
                                 false, ancestry);
        if (!nested) return nested;
      }
      return Result<bool>::ok(true);
    }
    if (value.kind != JsonKind::object) return Result<bool>::ok(true);

    const auto ellipsis = std::find_if(
        value.members.begin(), value.members.end(),
        [](const auto& member) { return member.first == "..."; });
    if (ellipsis != value.members.end())
      return malformed<bool>("array placeholder outside array element");

    // Register ordinary signed paths before resolving `_sd`, so member order
    // cannot influence duplicate-path rejection.
    for (const auto& [name, member] : value.members) {
      if (name == "_sd") continue;
      if (name == "_sd_alg") {
        if (!issuer_root || member.kind != JsonKind::string ||
            member.scalar != "sha-256")
          return malformed<bool>("nested or unsupported _sd_alg");
        continue;
      }
      const auto member_path = child_path(path, name);
      if (!claim_paths_.insert(member_path).second)
        return malformed<bool>("duplicate authenticated claim path");
    }

    for (const auto& [name, member] : value.members) {
      if (name == "_sd") {
        if (member.kind != JsonKind::array)
          return malformed<bool>("_sd must be a string array");
        for (const auto& digest : member.elements) {
          if (digest.kind != JsonKind::string)
            return malformed<bool>("_sd must be a string array");
          PendingReference reference{DisclosureKind::object_property,
                                     digest.scalar,
                                     path,
                                     {},
                                     parent,
                                     parent_depth,
                                     source,
                                     digest.begin,
                                     digest.end};
          const auto [marker, colon] = member_key_and_colon(source, member.begin);
          reference.placement.marker_token = marker;
          reference.placement.colon_token = colon;
          reference.placement.value_open_token =
              token_begin(source, member.begin, JsonLexeme::array_open);
          reference.placement.reference_token =
              token_begin(source, digest.begin, JsonLexeme::string);
          auto resolved = resolve(reference, ancestry);
          if (!resolved) return resolved;
        }
      } else if (name != "_sd_alg") {
        auto nested = scan_value(member, child_path(path, name), parent,
                                 parent_depth, source, false, ancestry);
        if (!nested) return nested;
      }
    }
    return Result<bool>::ok(true);
  }

  Result<bool> resolve(const PendingReference& reference,
                       std::vector<std::string>& ancestry) {
    if (!valid_digest_text(reference.digest))
      return malformed<bool>("invalid signed disclosure digest");
    if (std::find(ancestry.begin(), ancestry.end(), reference.digest) !=
        ancestry.end())
      return malformed<bool>("disclosure cycle");
    if (!seen_references_.insert(reference.digest).second)
      return malformed<bool>("duplicate disclosure digest occurrence");
    if (reference.parent_depth >= limits_.max_disclosure_depth)
      return Result<bool>::fail(ErrorCode::limit, "disclosure depth limit");

    const auto found = digest_to_supplied_.find(reference.digest);
    if (found == digest_to_supplied_.end()) {
      if (limits_.require_issuance_completeness)
        return malformed<bool>("unresolved signed disclosure");
      return Result<bool>::ok(true);
    }
    const auto supplied_index = found->second;
    const auto& supplied = supplied_[supplied_index];
    if (supplied.kind != reference.kind)
      return malformed<bool>("disclosure shape does not match reference kind");
    if (!used_supplied_.insert(supplied_index).second)
      return malformed<bool>("duplicate disclosure use");

    const auto depth = reference.parent_depth + 1;
    const JsonValue& disclosed_value = supplied.value();
    std::string resolved_path = reference.array_path;
    if (reference.kind == DisclosureKind::object_property) {
      resolved_path = child_path(reference.container_path,
                                 supplied.parsed.elements[1].scalar);
    }
    if (!claim_paths_.insert(resolved_path).second)
      return malformed<bool>("duplicate authenticated claim path");

    auto placement = reference.placement;
    if (reference.kind == DisclosureKind::object_property) {
      placement.component_token = token_begin(
          supplied_index + 1, supplied.parsed.elements[1].begin,
          JsonLexeme::string);
      if (placement.marker_token == kNoToken ||
          placement.colon_token == kNoToken ||
          placement.value_open_token == kNoToken ||
          placement.reference_token == kNoToken ||
          placement.component_token == kNoToken)
        return malformed<bool>("object disclosure placement range");
    } else if (placement.marker_token == kNoToken ||
               placement.colon_token == kNoToken ||
               placement.reference_token == kNoToken ||
               placement.object_open_token == kNoToken ||
               placement.object_close_token == kNoToken ||
               placement.parent_array_open_token == kNoToken) {
      return malformed<bool>("array disclosure placement range");
    }

    const std::size_t node_index = graph_.nodes.size();
    graph_.nodes.push_back({reference.kind,
                            supplied_index,
                            reference.parent,
                            depth,
                            reference.digest,
                            resolved_path,
                            {reference.source, reference.begin, reference.end},
                            {supplied_index + 1, supplied.parsed.begin,
                             supplied.parsed.end},
                            {supplied_index + 1, disclosed_value.begin,
                             disclosed_value.end},
                            disclosed_value.kind,
                            placement});

    ancestry.push_back(reference.digest);
    const auto references_before = seen_references_.size();
    auto nested = scan_value(disclosed_value, resolved_path, node_index, depth,
                             supplied_index + 1, false, ancestry);
    ancestry.pop_back();
    if (!nested) return nested;
    if (!limits_.allow_structured_nonrecursive &&
        (disclosed_value.kind == JsonKind::array ||
         disclosed_value.kind == JsonKind::object) &&
        seen_references_.size() == references_before)
      return malformed<bool>("structured non-recursive disclosure unsupported");
    return Result<bool>::ok(true);
  }

  std::string_view issuer_payload_;
  const std::vector<std::string>& disclosures_;
  const DisclosureProcessingLimits& limits_;
  std::vector<SuppliedDisclosure> supplied_;
  std::map<std::string, std::size_t> digest_to_supplied_;
  std::set<std::size_t> used_supplied_;
  std::set<std::string> seen_references_;
  std::set<std::string> claim_paths_;
  DisclosureGraphWitness graph_;
  bool validate_;
};

bool tokens_equal(const std::vector<JsonToken>& left,
                  const std::vector<JsonToken>& right) {
  if (left.size() != right.size()) return false;
  for (std::size_t index = 0; index < left.size(); ++index) {
    if (left[index].kind != right[index].kind ||
        left[index].begin != right[index].begin ||
        left[index].end != right[index].end)
      return false;
  }
  return true;
}

bool parser_tables_equal(const DisclosureParserTableAdvice& left,
                         const DisclosureParserTableAdvice& right) {
  if (!tokens_equal(left.tokens, right.tokens) ||
      left.strings.size() != right.strings.size() ||
      left.depths != right.depths || left.frames != right.frames ||
      left.container_ids != right.container_ids)
    return false;
  for (std::size_t token = 0; token < left.strings.size(); ++token) {
    if (left.strings[token].size() != right.strings[token].size()) return false;
    for (std::size_t unit = 0; unit < left.strings[token].size(); ++unit) {
      const auto& lhs = left.strings[token][unit];
      const auto& rhs = right.strings[token][unit];
      if (lhs.begin != rhs.begin || lhs.end != rhs.end ||
          lhs.codepoint != rhs.codepoint)
        return false;
    }
  }
  return true;
}

bool valid_range(const DisclosureSourceRange& range,
                 const std::vector<std::string>& sources) {
  return range.source < sources.size() && range.begin < range.end &&
         range.end <= sources[range.source].size();
}

bool exact_string_token(const DisclosureSourceRange& range,
                        const std::vector<std::vector<JsonToken>>& tokens) {
  if (range.source >= tokens.size()) return false;
  return std::any_of(tokens[range.source].begin(), tokens[range.source].end(),
                     [&](const JsonToken& token) {
                       return token.kind == static_cast<unsigned char>(
                                                JsonLexeme::string) &&
                              token.begin == range.begin &&
                              token.end == range.end;
                     });
}

bool token_boundary(const DisclosureSourceRange& range,
                    const std::vector<std::vector<JsonToken>>& tokens) {
  if (range.source >= tokens.size()) return false;
  const auto begin = std::any_of(
      tokens[range.source].begin(), tokens[range.source].end(),
      [&](const JsonToken& token) { return token.begin == range.begin; });
  const auto end = std::any_of(
      tokens[range.source].begin(), tokens[range.source].end(),
      [&](const JsonToken& token) { return token.end == range.end; });
  return begin && end;
}

std::optional<DisclosureKind> reference_kind_at(const JsonValue& value,
                                                std::size_t begin,
                                                std::size_t end) {
  if (value.kind == JsonKind::object) {
    for (const auto& [name, member] : value.members) {
      if (name == "_sd" && member.kind == JsonKind::array) {
        for (const auto& digest : member.elements) {
          if (digest.kind == JsonKind::string && digest.begin == begin &&
              digest.end == end)
            return DisclosureKind::object_property;
        }
      }
      if (const auto nested = reference_kind_at(member, begin, end))
        return nested;
    }
  } else if (value.kind == JsonKind::array) {
    for (const auto& item : value.elements) {
      if (item.kind == JsonKind::object && item.members.size() == 1 &&
          item.members[0].first == "..." &&
          item.members[0].second.kind == JsonKind::string &&
          item.members[0].second.begin == begin &&
          item.members[0].second.end == end)
        return DisclosureKind::array_element;
      if (const auto nested = reference_kind_at(item, begin, end)) return nested;
    }
  }
  return std::nullopt;
}

}  // namespace

Result<DisclosureParserTableAdvice> build_bounded_json_placement_table(
    std::string_view input, const JsonLimits& limits) {
  auto parsed = parse_bounded_json(input, limits);
  auto tokenized = tokenize_bounded_json(input, limits);
  if (!parsed || !tokenized)
    return Result<DisclosureParserTableAdvice>::fail(
        parsed ? tokenized.error->code : parsed.error->code,
        parsed ? tokenized.error->message : parsed.error->message);
  DisclosureParserTableAdvice table;
  table.tokens = std::move(*tokenized.value);
  table.strings.resize(table.tokens.size());
  for (std::size_t token = 0; token < table.tokens.size(); ++token) {
    if (table.tokens[token].kind !=
        static_cast<unsigned char>(JsonLexeme::string))
      continue;
    auto units = string_units(input, table.tokens[token]);
    if (!units)
      return Result<DisclosureParserTableAdvice>::fail(units.error->code,
                                                       units.error->message);
    table.strings[token] = std::move(*units.value);
  }

  table.depths.assign(table.tokens.size() + 1, 0);
  table.frames.assign(table.tokens.size() + 1,
                      std::vector<std::uint8_t>(limits.max_tokens + 1, 0));
  table.container_ids.assign(
      table.tokens.size() + 1,
      std::vector<std::size_t>(limits.max_tokens + 1, 0));
  std::vector<std::uint8_t> frames{1};
  std::vector<std::size_t> ids{0};
  table.depths[0] = 1;
  table.frames[0][0] = 1;
  const auto scalar = [](std::uint8_t kind) {
    return kind == static_cast<unsigned char>(JsonLexeme::string) ||
           kind == static_cast<unsigned char>(JsonLexeme::number) ||
           kind == static_cast<unsigned char>(JsonLexeme::true_value) ||
           kind == static_cast<unsigned char>(JsonLexeme::false_value) ||
           kind == static_cast<unsigned char>(JsonLexeme::null_value);
  };
  for (std::size_t token = 0; token < table.tokens.size(); ++token) {
    const auto kind = table.tokens[token].kind;
    auto& state = frames.back();
    bool valid = kind == static_cast<unsigned char>(JsonLexeme::whitespace);
    const bool expects_value =
        state == 1 || state == 6 || state == 8 || state == 9;
    if (!valid && expects_value && scalar(kind)) {
      state = state == 1 ? 2 : (state == 6 ? 7 : 10);
      valid = true;
    } else if (!valid && expects_value &&
               (kind == static_cast<unsigned char>(JsonLexeme::object_open) ||
                kind == static_cast<unsigned char>(JsonLexeme::array_open))) {
      state = state == 1 ? 2 : (state == 6 ? 7 : 10);
      frames.push_back(
          kind == static_cast<unsigned char>(JsonLexeme::object_open) ? 3 : 8);
      ids.push_back(token + 1);
      valid = true;
    } else if (!valid && (state == 3 || state == 4) &&
               kind == static_cast<unsigned char>(JsonLexeme::string)) {
      state = 5;
      valid = true;
    } else if (!valid && state == 5 &&
               kind == static_cast<unsigned char>(JsonLexeme::colon)) {
      state = 6;
      valid = true;
    } else if (!valid && state == 7 &&
               kind == static_cast<unsigned char>(JsonLexeme::comma)) {
      state = 4;
      valid = true;
    } else if (!valid && state == 10 &&
               kind == static_cast<unsigned char>(JsonLexeme::comma)) {
      state = 9;
      valid = true;
    } else if (!valid && frames.size() > 1 &&
               (((state == 3 || state == 7) &&
                 kind == static_cast<unsigned char>(JsonLexeme::object_close)) ||
                ((state == 8 || state == 10) &&
                 kind == static_cast<unsigned char>(JsonLexeme::array_close)))) {
      frames.pop_back();
      ids.pop_back();
      valid = true;
    }
    if (!valid || frames.size() > limits.max_depth + 1 ||
        frames.size() > limits.max_tokens + 1)
      return malformed<DisclosureParserTableAdvice>(
          "placement grammar table mismatch");
    table.depths[token + 1] = frames.size();
    for (std::size_t slot = 0; slot < frames.size(); ++slot) {
      table.frames[token + 1][slot] = frames[slot];
      table.container_ids[token + 1][slot] = ids[slot];
    }
  }
  if (frames.size() != 1 || frames[0] != 2)
    return malformed<DisclosureParserTableAdvice>(
        "incomplete placement grammar table");
  return Result<DisclosureParserTableAdvice>::ok(std::move(table));
}

Result<DisclosureGraphWitness> build_bounded_disclosure_graph(
    std::string_view issuer_payload, const std::vector<std::string>& disclosures,
    const DisclosureProcessingLimits& limits) {
  return GraphBuilder(issuer_payload, disclosures, limits).build();
}

Result<bool> validate_bounded_disclosure_graph(
    const DisclosureGraphWitness& graph,
    const std::vector<std::string>& disclosures,
    std::string_view issuer_payload,
    const DisclosureProcessingLimits& limits) {
  if (graph.nodes.size() > limits.max_disclosures ||
      graph.source_tokens.size() != disclosures.size() + 1 ||
      graph.source_parser_tables.size() != disclosures.size() + 1)
    return Result<bool>::fail(ErrorCode::limit, "disclosure graph size");
  std::vector<std::string> sources{std::string(issuer_payload)};
  std::vector<JsonValue> parsed_sources;
  std::vector<std::vector<JsonToken>> expected_tokens;
  std::vector<DisclosureParserTableAdvice> expected_tables;
  auto root = parse_bounded_json(issuer_payload, limits.json);
  auto root_table =
      build_bounded_json_placement_table(issuer_payload, limits.json);
  if (!root || !root_table)
    return malformed<bool>("invalid graph issuer source");
  parsed_sources.push_back(std::move(*root.value));
  expected_tokens.push_back(root_table.value->tokens);
  expected_tables.push_back(std::move(*root_table.value));
  for (const auto& disclosure : disclosures) {
    auto decoded = base64url_decode(disclosure, limits.json.max_bytes);
    if (!decoded) return malformed<bool>("invalid graph disclosure source");
    sources.emplace_back(decoded.value->begin(), decoded.value->end());
    auto parsed = parse_bounded_json(sources.back(), limits.json);
    auto table =
        build_bounded_json_placement_table(sources.back(), limits.json);
    if (!parsed || !table)
      return malformed<bool>("invalid graph disclosure source");
    parsed_sources.push_back(std::move(*parsed.value));
    expected_tokens.push_back(table.value->tokens);
    expected_tables.push_back(std::move(*table.value));
  }
  for (std::size_t source = 0; source < expected_tokens.size(); ++source) {
    if (!tokens_equal(graph.source_tokens[source], expected_tokens[source]))
      return malformed<bool>("disclosure graph token table mismatch");
    if (!parser_tables_equal(graph.source_parser_tables[source],
                             expected_tables[source]))
      return malformed<bool>("disclosure graph parser table mismatch");
  }
  std::set<std::string> paths;
  std::set<std::string> digests;
  std::set<std::size_t> supplied;
  for (std::size_t index = 0; index < graph.nodes.size(); ++index) {
    const auto& node = graph.nodes[index];
    if (node.supplied_index >= disclosures.size() ||
        !supplied.insert(node.supplied_index).second ||
        !digests.insert(node.digest).second || !paths.insert(node.path).second)
      return malformed<bool>("duplicate or invalid disclosure graph node");
    if (node.depth == 0 || node.depth > limits.max_disclosure_depth)
      return Result<bool>::fail(ErrorCode::limit, "disclosure depth limit");
    if (node.parent == kRootDisclosureParent) {
      if (node.depth != 1 || node.reference.source != 0)
        return malformed<bool>("invalid root disclosure edge");
    } else {
      if (node.parent >= index || node.depth != graph.nodes[node.parent].depth + 1 ||
          node.reference.source != graph.nodes[node.parent].supplied_index + 1)
        return malformed<bool>("cycle or invalid disclosure parent");
    }
    const auto& parsed_disclosure = parsed_sources[node.supplied_index + 1];
    if (parsed_disclosure.kind != JsonKind::array ||
        (parsed_disclosure.elements.size() != 2 &&
         parsed_disclosure.elements.size() != 3))
      return malformed<bool>("invalid graph disclosure shape");
    const auto expected_kind = parsed_disclosure.elements.size() == 3
                                   ? DisclosureKind::object_property
                                   : DisclosureKind::array_element;
    const auto& expected_value =
        parsed_disclosure.elements[expected_kind == DisclosureKind::object_property
                                       ? 2
                                       : 1];
    const auto reference_kind = reference_kind_at(
        parsed_sources[node.reference.source], node.reference.begin,
        node.reference.end);
    if (node.disclosure.source != node.supplied_index + 1 ||
        node.value.source != node.supplied_index + 1 ||
        node.kind != expected_kind || node.value_kind != expected_value.kind ||
        !reference_kind || *reference_kind != node.kind ||
        !valid_range(node.reference, sources) ||
        !valid_range(node.disclosure, sources) ||
        !valid_range(node.value, sources) ||
        !exact_string_token(node.reference, expected_tokens) ||
        !token_boundary(node.disclosure, expected_tokens) ||
        !token_boundary(node.value, expected_tokens) ||
        node.disclosure.begin != parsed_disclosure.begin ||
        node.disclosure.end != parsed_disclosure.end ||
        node.value.begin != expected_value.begin ||
        node.value.end != expected_value.end ||
        node.value.begin < node.disclosure.begin ||
        node.value.end > node.disclosure.end ||
        disclosure_digest(disclosures[node.supplied_index]) != node.digest)
      return malformed<bool>("disclosure graph range or digest mismatch");
  }
  auto canonical =
      GraphBuilder(issuer_payload, disclosures, limits, false).build();
  if (!canonical || canonical.value->nodes.size() != graph.nodes.size())
    return malformed<bool>("non-canonical disclosure placement graph");
  const auto same_placement = [](const DisclosurePlacementWitness& left,
                                 const DisclosurePlacementWitness& right) {
    return left.marker_token == right.marker_token &&
           left.colon_token == right.colon_token &&
           left.value_open_token == right.value_open_token &&
           left.reference_token == right.reference_token &&
           left.object_open_token == right.object_open_token &&
           left.object_close_token == right.object_close_token &&
           left.parent_array_open_token == right.parent_array_open_token &&
           left.component_token == right.component_token &&
           left.array_index == right.array_index;
  };
  for (std::size_t index = 0; index < graph.nodes.size(); ++index) {
    if (!same_placement(graph.nodes[index].placement,
                        canonical.value->nodes[index].placement))
      return malformed<bool>("forged disclosure placement or path index");
  }
  return Result<bool>::ok(true);
}

Result<DisclosureProcessingResult> process_bounded_disclosures(
    std::string_view issuer_payload, const std::vector<std::string>& disclosures,
    const DisclosureProcessingRequest& request) {
  auto graph = build_bounded_disclosure_graph(issuer_payload, disclosures,
                                               request.limits);
  if (!graph)
    return Result<DisclosureProcessingResult>::fail(graph.error->code,
                                                     graph.error->message);
  std::set<std::string> requested;
  for (const auto& path : request.selected_paths) {
    if (path.empty() || path.front() != '/' || !requested.insert(path).second)
      return malformed<DisclosureProcessingResult>("invalid or duplicate selected path");
  }
  DisclosureProcessingResult result{graph.value->signed_digest_count,
                                    graph.value->nodes.size(), {}};
  for (const auto& path : request.selected_paths) {
    const auto node = std::find_if(
        graph.value->nodes.begin(), graph.value->nodes.end(),
        [&](const auto& candidate) { return candidate.path == path; });
    if (node == graph.value->nodes.end())
      return malformed<DisclosureProcessingResult>("selected path is not disclosed");
    const auto decoded = base64url_decode(disclosures[node->supplied_index],
                                          request.limits.json.max_bytes);
    if (!decoded)
      return malformed<DisclosureProcessingResult>("selected disclosure encoding");
    const std::string json(decoded.value->begin(), decoded.value->end());
    result.selected.push_back({node->path, node->kind, node->value_kind,
                               json.substr(node->value.begin,
                                           node->value.end - node->value.begin)});
  }
  return Result<DisclosureProcessingResult>::ok(std::move(result));
}

Result<DisclosureProcessingResult> process_bounded_disclosures(
    std::string_view issuer_payload, const std::vector<std::string>& disclosures,
    const DisclosureProcessingLimits& limits) {
  return process_bounded_disclosures(
      issuer_payload, disclosures, DisclosureProcessingRequest{limits, {}});
}

}  // namespace sd_jwt_zk
