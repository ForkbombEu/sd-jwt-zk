#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/bounded_json.h"

namespace sd_jwt_zk {

inline constexpr std::size_t kRootDisclosureParent =
    std::numeric_limits<std::size_t>::max();

enum class DisclosureKind : unsigned char {
  object_property = 1,
  array_element = 2,
};

struct DisclosureProcessingLimits {
  JsonLimits json{};
  std::size_t max_disclosures{32};
  std::size_t max_disclosure_depth{8};
  bool require_issuance_completeness{true};
  // The generic host-side graph builder retains experimental recursive parsing
  // for historical/full-family diagnostics. The supported L6 proof gate is
  // fixed, non-recursive, and two-slot; it is not Swiss-profile conformance.
  bool allow_structured_nonrecursive{false};
};

struct DisclosureSourceRange {
  // Source zero is the issuer payload. Source n+1 is supplied disclosure n.
  std::size_t source{};
  std::size_t begin{};
  std::size_t end{};
};

struct DisclosurePlacementWitness {
  std::size_t marker_token{};
  std::size_t colon_token{};
  std::size_t value_open_token{};
  std::size_t reference_token{};
  std::size_t object_open_token{};
  std::size_t object_close_token{};
  std::size_t parent_array_open_token{};
  std::size_t component_token{};
  std::size_t array_index{};
};

struct DisclosureStringUnitAdvice {
  std::size_t begin{};
  std::size_t end{};
  std::uint32_t codepoint{};
};

// Native, parser-derived handoff for the subset of BoundedJsonCircuitInput
// consumed by reference placement. Rows are indexed exactly like `tokens`.
// `depths`, `frames`, and `container_ids` contain token_count+1 states.
struct DisclosureParserTableAdvice {
  std::vector<JsonToken> tokens;
  std::vector<std::vector<DisclosureStringUnitAdvice>> strings;
  std::vector<std::size_t> depths;
  std::vector<std::vector<std::uint8_t>> frames;
  std::vector<std::vector<std::size_t>> container_ids;
};

// Prover-private graph advice. All offsets are produced from accepted bounded
// tokenizer/parser ranges; callers must not serialize this structure as a
// public proof result.
struct DisclosureGraphNode {
  DisclosureKind kind{};
  std::size_t supplied_index{};
  std::size_t parent{kRootDisclosureParent};
  std::size_t depth{};
  std::string digest;
  std::string path;  // RFC 6901 JSON Pointer after disclosure replacement.
  DisclosureSourceRange reference{};
  DisclosureSourceRange disclosure{};
  DisclosureSourceRange value{};
  JsonKind value_kind{};
  DisclosurePlacementWitness placement{};
};

struct DisclosureGraphWitness {
  std::vector<std::vector<JsonToken>> source_tokens;
  std::vector<DisclosureParserTableAdvice> source_parser_tables;
  std::vector<DisclosureGraphNode> nodes;
  std::size_t signed_digest_count{};
};

Result<DisclosureParserTableAdvice> build_bounded_json_placement_table(
    std::string_view input, const JsonLimits& limits = {});

struct SelectedDisclosureResult {
  std::string path;
  DisclosureKind kind{};
  JsonKind value_kind{};
  // Exact authenticated JSON spelling of the selected value only. Salts,
  // unselected names/values, and graph topology are intentionally omitted.
  std::string value_json;
};

struct DisclosureProcessingRequest {
  DisclosureProcessingLimits limits{};
  std::vector<std::string> selected_paths;
};

struct DisclosureProcessingResult {
  std::size_t signed_digest_count{};
  std::size_t resolved_disclosure_count{};
  std::vector<SelectedDisclosureResult> selected;
};

// Builds the complete holder-private authenticated graph. Three-element
// disclosures resolve object `_sd` entries and two-element disclosures resolve
// array `{ "...": digest }` placeholders; crossing the two forms is rejected.
Result<DisclosureGraphWitness> build_bounded_disclosure_graph(
    std::string_view issuer_payload, const std::vector<std::string>& disclosures,
    const DisclosureProcessingLimits& limits = {});

// Checks graph-only invariants again at a trust boundary. This is also the
// native mirror of FullDisclosureGraphRelation: topological parent order,
// exact depth, range ownership, unique paths/references, and configured depth.
Result<bool> validate_bounded_disclosure_graph(
    const DisclosureGraphWitness& graph,
    const std::vector<std::string>& disclosures,
    std::string_view issuer_payload,
    const DisclosureProcessingLimits& limits = {});

// Returns only explicitly selected authenticated values. An empty selection
// performs validation without exposing a claim path or value.
Result<DisclosureProcessingResult> process_bounded_disclosures(
    std::string_view issuer_payload, const std::vector<std::string>& disclosures,
    const DisclosureProcessingRequest& request);

// Backwards-compatible validation-only overload.
Result<DisclosureProcessingResult> process_bounded_disclosures(
    std::string_view issuer_payload, const std::vector<std::string>& disclosures,
    const DisclosureProcessingLimits& limits = {});

}  // namespace sd_jwt_zk
