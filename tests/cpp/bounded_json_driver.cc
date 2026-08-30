#include "sd_jwt_zk/bounded_json.h"

#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace {

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool decode_hex(std::string_view encoded, std::string& out) {
  if ((encoded.size() & 1u) != 0) return false;
  out.clear();
  out.reserve(encoded.size() / 2);
  for (std::size_t i = 0; i < encoded.size(); i += 2) {
    const int high = hex_digit(encoded[i]);
    const int low = hex_digit(encoded[i + 1]);
    if (high < 0 || low < 0) return false;
    out.push_back(static_cast<char>((high << 4) | low));
  }
  return true;
}

void write_hex(std::string_view text) {
  static constexpr char digits[] = "0123456789abcdef";
  for (const unsigned char byte : text) {
    std::cout << digits[byte >> 4] << digits[byte & 15];
  }
}

void write_tree(const sd_jwt_zk::JsonValue& value) {
  using sd_jwt_zk::JsonKind;
  switch (value.kind) {
    case JsonKind::null_value:
      std::cout << "[\"null\"]";
      break;
    case JsonKind::boolean:
      std::cout << "[\"boolean\"," << value.scalar << ']';
      break;
    case JsonKind::number:
      std::cout << "[\"number\",\"" << value.scalar << "\"]";
      break;
    case JsonKind::string:
      std::cout << "[\"string\",\"";
      write_hex(value.scalar);
      std::cout << "\"]";
      break;
    case JsonKind::array:
      std::cout << "[\"array\",[";
      for (std::size_t i = 0; i < value.elements.size(); ++i) {
        if (i != 0) std::cout << ',';
        write_tree(value.elements[i]);
      }
      std::cout << "]]";
      break;
    case JsonKind::object:
      std::cout << "[\"object\",[";
      for (std::size_t i = 0; i < value.members.size(); ++i) {
        if (i != 0) std::cout << ',';
        std::cout << "[\"";
        write_hex(value.members[i].first);
        std::cout << "\",";
        write_tree(value.members[i].second);
        std::cout << ']';
      }
      std::cout << "]]";
      break;
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2 || argc > 5) return 64;
  std::string input;
  if (!decode_hex(argv[1], input)) return 65;
  sd_jwt_zk::JsonLimits limits{};
  if (argc > 2) limits.max_bytes = std::strtoull(argv[2], nullptr, 10);
  if (argc > 3) limits.max_depth = std::strtoull(argv[3], nullptr, 10);
  if (argc > 4) limits.max_tokens = std::strtoull(argv[4], nullptr, 10);
  const auto parsed = sd_jwt_zk::parse_bounded_json(input, limits);
  if (!parsed) {
    std::cout << "{\"accepted\":false,\"error\":"
              << static_cast<unsigned>(parsed.error->code) << "}\n";
    return 0;
  }
  std::cout << "{\"accepted\":true,\"tree\":";
  write_tree(*parsed.value);
  std::cout << "}\n";
  return 0;
}
