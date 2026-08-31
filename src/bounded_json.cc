/*
 * Copyright (C) 2026 by The Forkbomb Company
 * designed, written and maintained by Denis Roio
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sd_jwt_zk/bounded_json.h"

#include <algorithm>
#include <charconv>
#include <limits>
#include <set>
#include <tuple>

namespace sd_jwt_zk {
namespace {
class Parser {
 public:
  Parser(std::string_view input, const JsonLimits& limits) : input_(input), limits_(limits) {}
  Result<JsonValue> parse() {
    if (input_.empty() || input_.size() > limits_.max_bytes)
      return fail(ErrorCode::limit, "JSON byte limit");
    skip_ws();
    if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit");
    auto value = value_at(0);
    if (!value) return value;
    skip_ws();
    if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit");
    if (at_ != input_.size()) return fail(ErrorCode::malformed, "JSON trailing data");
    return value;
  }

 private:
  Result<JsonValue> fail(ErrorCode code, const char* message) const {
    return Result<JsonValue>::fail(code, message);
  }
  void skip_ws() {
    const auto begin = at_;
    while (at_ < input_.size() && (input_[at_] == ' ' || input_[at_] == '\n' ||
           input_[at_] == '\r' || input_[at_] == '\t')) ++at_;
    if (at_ != begin && !token()) limit_failed_ = true;
  }
  bool take(char c) { if (at_ >= input_.size() || input_[at_] != c) return false; ++at_; return true; }
  bool token() { return ++tokens_ <= limits_.max_tokens; }
  bool take_token(char c) { return take(c) && token(); }
  static int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  }
  static void append_utf8(std::string& out, std::uint32_t codepoint) {
    if (codepoint <= 0x7f) out.push_back(static_cast<char>(codepoint));
    else if (codepoint <= 0x7ff) { out.push_back(static_cast<char>(0xc0 | (codepoint >> 6))); out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f))); }
    else if (codepoint <= 0xffff) { out.push_back(static_cast<char>(0xe0 | (codepoint >> 12))); out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f))); }
    else { out.push_back(static_cast<char>(0xf0 | (codepoint >> 18))); out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f))); out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f))); }
  }
  bool code_unit(std::uint32_t& out) {
    if (at_ + 4 > input_.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) { const int value = hex(input_[at_++]); if (value < 0) return false; out = (out << 4) | static_cast<std::uint32_t>(value); }
    return true;
  }
  bool utf8(std::string& out) {
    const auto start = at_;
    const unsigned char first = static_cast<unsigned char>(input_[at_++]);
    unsigned count = first < 0xe0 ? 1 : first < 0xf0 ? 2 : first < 0xf8 ? 3 : 99;
    std::uint32_t cp = first & (count == 1 ? 0x1f : count == 2 ? 0x0f : 0x07);
    if (count == 99 || at_ + count > input_.size()) return false;
    for (unsigned i = 0; i < count; ++i) { const unsigned char next = static_cast<unsigned char>(input_[at_++]); if ((next & 0xc0) != 0x80) return false; cp = (cp << 6) | (next & 0x3f); }
    if ((count == 1 && cp < 0x80) || (count == 2 && cp < 0x800) || (count == 3 && cp < 0x10000) || (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) { at_ = start; return false; }
    out.append(input_.substr(start, at_ - start)); return true;
  }
  bool string(std::string& out) {
    if (!take('"') || !token()) return false;
    while (at_ < input_.size()) {
      const unsigned char c = static_cast<unsigned char>(input_[at_]);
      if (c == '"') { ++at_; return true; }
      if (c < 0x20) return false;
      if (c == '\\') {
        ++at_; if (at_ == input_.size()) return false;
        switch (input_[at_++]) {
          case '"': out.push_back('"'); break; case '\\': out.push_back('\\'); break; case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break; case 'f': out.push_back('\f'); break; case 'n': out.push_back('\n'); break; case 'r': out.push_back('\r'); break; case 't': out.push_back('\t'); break;
          case 'u': { std::uint32_t cp{}; if (!code_unit(cp)) return false; if (cp >= 0xd800 && cp <= 0xdbff) { if (at_ + 2 > input_.size() || input_[at_++] != '\\' || input_[at_++] != 'u') return false; std::uint32_t low{}; if (!code_unit(low) || low < 0xdc00 || low > 0xdfff) return false; cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00; } else if (cp >= 0xdc00 && cp <= 0xdfff) return false; append_utf8(out, cp); break; }
          default: return false;
        }
      } else if (c < 0x80) { out.push_back(static_cast<char>(c)); ++at_; }
      else if (!utf8(out)) return false;
    }
    return false;
  }
  Result<JsonValue> value_at(std::size_t depth) {
    if (depth > limits_.max_depth) return fail(ErrorCode::limit, "JSON depth limit");
    skip_ws();
    if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit");
    const std::size_t begin = at_;
    if (at_ == input_.size()) return fail(ErrorCode::malformed, "JSON missing value");
    if (input_[at_] == '"') { std::string text; if (!string(text)) return fail(ErrorCode::utf8, "invalid JSON string"); return Result<JsonValue>::ok({JsonKind::string, begin, at_, std::move(text), {}, {}}); }
    if (input_[at_] == '[') {
      if (depth >= limits_.max_depth)
        return fail(ErrorCode::limit, "JSON depth limit");
      return array(begin, depth);
    }
    if (input_[at_] == '{') {
      if (depth >= limits_.max_depth)
        return fail(ErrorCode::limit, "JSON depth limit");
      return object(begin, depth);
    }
    for (const auto& [literal, kind, scalar] : {std::tuple{"null", JsonKind::null_value, ""}, {"true", JsonKind::boolean, "true"}, {"false", JsonKind::boolean, "false"}}) if (input_.substr(at_, std::char_traits<char>::length(literal)) == literal) { if (!token()) return fail(ErrorCode::limit, "JSON token limit"); at_ += std::char_traits<char>::length(literal); return Result<JsonValue>::ok({kind, begin, at_, scalar, {}, {}}); }
    return number(begin);
  }
  Result<JsonValue> number(std::size_t begin) {
    if (!token()) return fail(ErrorCode::limit, "JSON token limit");
    const std::size_t start = at_; if (take('-') && at_ == input_.size()) return fail(ErrorCode::malformed, "invalid JSON number");
    if (take('0')) { if (at_ < input_.size() && input_[at_] >= '0' && input_[at_] <= '9') return fail(ErrorCode::noncanonical, "JSON leading zero"); }
    else { if (at_ == input_.size() || input_[at_] < '1' || input_[at_] > '9') return fail(ErrorCode::malformed, "invalid JSON number"); while (at_ < input_.size() && input_[at_] >= '0' && input_[at_] <= '9') ++at_; }
    if (take('.')) { const auto fraction = at_; while (at_ < input_.size() && input_[at_] >= '0' && input_[at_] <= '9') ++at_; if (at_ == fraction) return fail(ErrorCode::malformed, "invalid JSON fraction"); }
    if (at_ < input_.size() && (input_[at_] == 'e' || input_[at_] == 'E')) { ++at_; if (at_ < input_.size() && (input_[at_] == '+' || input_[at_] == '-')) ++at_; const auto exponent = at_; while (at_ < input_.size() && input_[at_] >= '0' && input_[at_] <= '9') ++at_; if (at_ == exponent) return fail(ErrorCode::malformed, "invalid JSON exponent"); }
    return Result<JsonValue>::ok({JsonKind::number, begin, at_, std::string(input_.substr(start, at_ - start)), {}, {}});
  }
  Result<JsonValue> array(std::size_t begin, std::size_t depth) {
    if (!take_token('[')) return fail(ErrorCode::limit, "JSON token limit");
    JsonValue out{JsonKind::array, begin, 0, {}, {}, {}};
    skip_ws();
    if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit");
    if (take_token(']')) { out.end = at_; return Result<JsonValue>::ok(std::move(out)); }
    while (true) { auto item = value_at(depth + 1); if (!item) return item; out.elements.push_back(std::move(*item.value)); skip_ws(); if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit"); if (take_token(']')) { out.end = at_; return Result<JsonValue>::ok(std::move(out)); } if (!take_token(',')) return fail(ErrorCode::malformed, "JSON array delimiter"); skip_ws(); if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit"); }
  }
  Result<JsonValue> object(std::size_t begin, std::size_t depth) {
    if (!take_token('{')) return fail(ErrorCode::limit, "JSON token limit");
    JsonValue out{JsonKind::object, begin, 0, {}, {}, {}}; std::set<std::string> names;
    skip_ws();
    if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit");
    if (take_token('}')) { out.end = at_; return Result<JsonValue>::ok(std::move(out)); }
    while (true) { std::string key; if (!string(key) || !names.insert(key).second) return fail(ErrorCode::malformed, "JSON duplicate or invalid object name"); skip_ws(); if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit"); if (!take_token(':')) return fail(ErrorCode::malformed, "JSON object colon"); auto item = value_at(depth + 1); if (!item) return item; out.members.emplace_back(std::move(key), std::move(*item.value)); skip_ws(); if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit"); if (take_token('}')) { out.end = at_; return Result<JsonValue>::ok(std::move(out)); } if (!take_token(',')) return fail(ErrorCode::malformed, "JSON object delimiter"); skip_ws(); if (limit_failed_) return fail(ErrorCode::limit, "JSON token limit"); }
  }
  std::string_view input_; const JsonLimits& limits_; std::size_t at_{}; std::size_t tokens_{}; bool limit_failed_{};
};
}  // namespace

Result<JsonValue> parse_bounded_json(std::string_view input, const JsonLimits& limits) { return Parser(input, limits).parse(); }
Result<std::vector<JsonToken>> tokenize_bounded_json(std::string_view input,
                                                     const JsonLimits& limits) {
  if (!parse_bounded_json(input, limits))
    return Result<std::vector<JsonToken>>::fail(ErrorCode::malformed, "invalid JSON");
  std::vector<JsonToken> out;
  const auto add = [&](std::uint8_t kind, std::size_t begin, std::size_t end) {
    out.push_back({kind, begin, end});
    return out.size() <= limits.max_tokens;
  };
  for (std::size_t at = 0; at < input.size();) {
    const std::size_t begin = at;
    const unsigned char byte = static_cast<unsigned char>(input[at]);
    std::uint8_t kind = 0;
    if (byte == ' ' || byte == '\n' || byte == '\r' || byte == '\t') {
      kind = 1; while (at < input.size() && (input[at] == ' ' || input[at] == '\n' || input[at] == '\r' || input[at] == '\t')) ++at;
    } else if (byte == '"') {
      kind = 2; ++at; while (at < input.size() && input[at] != '"') { if (input[at] == '\\') at += input[at + 1] == 'u' ? 6 : 2; else ++at; } ++at;
    } else if (byte == '-' || (byte >= '0' && byte <= '9')) {
      kind = 3; while (at < input.size() && ((input[at] >= '0' && input[at] <= '9') || input[at] == '-' || input[at] == '+' || input[at] == '.' || input[at] == 'e' || input[at] == 'E')) ++at;
    } else if (input.substr(at, 4) == "true") { kind = 4; at += 4;
    } else if (input.substr(at, 5) == "false") { kind = 5; at += 5;
    } else if (input.substr(at, 4) == "null") { kind = 6; at += 4;
    } else { kind = byte == '{' ? 7 : byte == '}' ? 8 : byte == '[' ? 9 : byte == ']' ? 10 : byte == ',' ? 11 : 12; ++at; }
    if (!add(kind, begin, at)) return Result<std::vector<JsonToken>>::fail(ErrorCode::limit, "JSON token limit");
  }
  return Result<std::vector<JsonToken>>::ok(std::move(out));
}
bool json_number_equal(std::string_view left, std::string_view right) {
  struct SignedDecimal { bool negative{}; std::string magnitude{"0"}; };
  struct Decimal { bool negative{}; std::string digits; SignedDecimal scale; };
  const auto add_magnitudes = [](std::string_view a, std::string_view b) {
    std::string out;
    int carry = 0;
    for (std::size_t i = 0; i < std::max(a.size(), b.size()) || carry; ++i) {
      const int av = i < a.size() ? a[a.size() - 1 - i] - '0' : 0;
      const int bv = i < b.size() ? b[b.size() - 1 - i] - '0' : 0;
      const int sum = av + bv + carry;
      out.push_back(static_cast<char>('0' + sum % 10));
      carry = sum / 10;
    }
    std::reverse(out.begin(), out.end());
    return out.empty() ? std::string("0") : out;
  };
  const auto compare_magnitudes = [](std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    if (a == b) return 0;
    return a < b ? -1 : 1;
  };
  const auto subtract_magnitudes = [&](std::string_view a, std::string_view b) {
    std::string out;
    int borrow = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
      int digit = a[a.size() - 1 - i] - '0' - borrow;
      const int bv = i < b.size() ? b[b.size() - 1 - i] - '0' : 0;
      if (digit < bv) { digit += 10; borrow = 1; } else borrow = 0;
      out.push_back(static_cast<char>('0' + digit - bv));
    }
    while (out.size() > 1 && out.back() == '0') out.pop_back();
    std::reverse(out.begin(), out.end());
    return out;
  };
  const auto add_signed = [&](SignedDecimal a, SignedDecimal b) {
    if (a.magnitude == "0") return b;
    if (b.magnitude == "0") return a;
    if (a.negative == b.negative) {
      a.magnitude = add_magnitudes(a.magnitude, b.magnitude);
      return a;
    }
    const int order = compare_magnitudes(a.magnitude, b.magnitude);
    if (order == 0) return SignedDecimal{};
    if (order > 0) {
      a.magnitude = subtract_magnitudes(a.magnitude, b.magnitude);
      return a;
    }
    b.magnitude = subtract_magnitudes(b.magnitude, a.magnitude);
    return b;
  };
  const auto normalize = [&](std::string_view text, Decimal& out) {
    std::size_t at{};
    out.negative = at < text.size() && text[at] == '-';
    at += out.negative;
    if (at == text.size()) return false;
    const auto integer = at;
    if (text[at] == '0') {
      ++at;
      if (at < text.size() && text[at] >= '0' && text[at] <= '9') return false;
    } else {
      if (text[at] < '1' || text[at] > '9') return false;
      while (at < text.size() && text[at] >= '0' && text[at] <= '9') ++at;
    }
    out.digits.assign(text.substr(integer, at - integer));
    std::size_t fractional{};
    if (at < text.size() && text[at] == '.') {
      const auto start = ++at;
      while (at < text.size() && text[at] >= '0' && text[at] <= '9') ++at;
      fractional = at - start;
      if (fractional == 0) return false;
      out.digits.append(text.substr(start, fractional));
    }
    SignedDecimal exponent{};
    if (at < text.size() && (text[at] == 'e' || text[at] == 'E')) {
      ++at;
      if (at < text.size() && (text[at] == '+' || text[at] == '-')) {
        exponent.negative = text[at] == '-';
        ++at;
      }
      const auto start = at;
      while (at < text.size() && text[at] >= '0' && text[at] <= '9') ++at;
      if (at == start) return false;
      exponent.magnitude = std::string(text.substr(start, at - start));
      const auto first = exponent.magnitude.find_first_not_of('0');
      exponent.magnitude = first == std::string::npos ? "0" : exponent.magnitude.substr(first);
      if (exponent.magnitude == "0") exponent.negative = false;
    }
    if (at != text.size()) return false;
    const auto first = out.digits.find_first_not_of('0');
    if (first == std::string::npos) {
      out.negative = false;
      out.digits = "0";
      out.scale = {};
      return true;
    }
    out.digits.erase(0, first);
    std::size_t trailing{};
    while (out.digits.size() > 1 && out.digits.back() == '0') {
      out.digits.pop_back();
      ++trailing;
    }
    const std::int64_t adjustment = static_cast<std::int64_t>(trailing) -
                                    static_cast<std::int64_t>(fractional);
    SignedDecimal delta{};
    delta.negative = adjustment < 0;
    delta.magnitude = std::to_string(adjustment < 0 ? -adjustment : adjustment);
    out.scale = add_signed(exponent, delta);
    return true;
  };
  Decimal a, b;
  return normalize(left, a) && normalize(right, b) &&
         a.negative == b.negative && a.digits == b.digits &&
         a.scale.negative == b.scale.negative &&
         a.scale.magnitude == b.scale.magnitude;
}
}  // namespace sd_jwt_zk
