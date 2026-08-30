#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sd_jwt_zk/api.h"

namespace sd_jwt_zk {

// Byte offsets refer to the original, authenticated JSON input.  Decoded
// strings are UTF-8; number text retains its RFC 8259 spelling so a circuit
// can compare the same bounded byte range before applying a typed policy.
enum class JsonKind : std::uint8_t { null_value, boolean, number, string, array, object };
struct JsonValue {
  JsonKind kind{};
  std::size_t begin{};
  std::size_t end{};
  std::string scalar;
  std::vector<JsonValue> elements;
  std::vector<std::pair<std::string, JsonValue>> members;
};

struct JsonLimits {
  std::size_t max_bytes{4096};
  std::size_t max_depth{8};
  std::size_t max_tokens{256};
};

// Lexical ranges are emitted only after the native grammar has accepted the
// input.  They are the deterministic private advice consumed by the bounded
// circuit's gap-free range relation.
struct JsonToken {
  std::uint8_t kind{};
  std::size_t begin{};
  std::size_t end{};
};

Result<JsonValue> parse_bounded_json(std::string_view input,
                                     const JsonLimits& limits = {});
bool json_number_equal(std::string_view left, std::string_view right);
Result<std::vector<JsonToken>> tokenize_bounded_json(
    std::string_view input, const JsonLimits& limits = {});

}  // namespace sd_jwt_zk
