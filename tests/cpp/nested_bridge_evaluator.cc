#include <algorithm>
#include <array>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"
#include "nested_es256_fixture.h"
#include "sd_jwt_zk/api.h"
#include "sd_jwt_zk/compact_opening_bridge_relation.h"
#include "sd_jwt_zk/disclosure_processing.h"
#include "sd_jwt_zk/flat_bearer_proof.h"

namespace {

using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;
using Bridge = sd_jwt_zk::CompactOpeningBridgeRelation<Logic, 102, 256, 6>;
using Sha = proofs::FlatSHA256Circuit<Logic, proofs::BitPlucker<Logic, 4>>;

constexpr std::string_view kHeader =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ";

std::string disclosure_digest(std::string_view disclosure) {
  const auto digest = sd_jwt_zk::sha256_ascii(disclosure);
  return sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(digest.begin(), digest.end()));
}

// This is deliberately a fixed two-slot evaluator, not a generic traversal:
// slot zero is a root `_sd` object-property disclosure and slot one is a root
// array `{ "...": digest }` placeholder. Keep every compact-bridge input here
// so the payload, SHA witness, signed public digest, decoded root, and active
// lengths are allocated exactly once by the relation invocation below.
bool evaluate_compact_bridge(std::string_view payload,
                             bool mutate_signed_public_digest) {
  if (payload.size() > 256) return false;
  const auto decoded_payload = sd_jwt_zk::base64url_decode(payload);
  if (!decoded_payload || decoded_payload.value->size() > Bridge::kDecoded)
    return false;

  std::array<unsigned char, 64 * 6> padded{};
  std::array<proofs::FlatSHA256Witness::BlockWitness, 6> raw_witness{};
  std::uint8_t block_count{};
  const std::string signing = std::string(kHeader) + "." + std::string(payload);
  if (!sd_jwt_zk::make_compact_sha_advice(signing, padded, raw_witness,
                                          block_count))
    return false;

  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  std::array<Logic::v8, 102> header{};
  std::array<Logic::v8, 256> encoded_payload{};
  std::array<Logic::v8, 64 * 6> sha_input{};
  std::array<Logic::v8, Bridge::kDecoded> decoded{};
  Logic::bitvec<8> header_length{}, payload_length{}, decoded_length{};
  logic.bits(8, header_length.data(), kHeader.size());
  logic.bits(8, payload_length.data(), payload.size());
  logic.bits(8, decoded_length.data(), decoded_payload.value->size());
  for (std::size_t index = 0; index < header.size(); ++index)
    header[index] = logic.template vbit<8>(
        index < kHeader.size() ? kHeader[index] : 0);
  for (std::size_t index = 0; index < encoded_payload.size(); ++index)
    encoded_payload[index] = logic.template vbit<8>(
        index < payload.size() ? payload[index] : 0);
  for (std::size_t index = 0; index < sha_input.size(); ++index)
    sha_input[index] = logic.template vbit<8>(padded[index]);
  for (std::size_t index = 0; index < decoded.size(); ++index)
    decoded[index] = logic.template vbit<8>(
        index < decoded_payload.value->size() ? (*decoded_payload.value)[index]
                                             : 0);

  proofs::BitPluckerEncoder<Field, 4> encoder(proofs::p256_base);
  std::array<Sha::BlockWitness, 6> witness{};
  for (std::size_t block = 0; block < witness.size(); ++block) {
    for (std::size_t word = 0; word < 48; ++word)
      witness[block].outw[word] =
          logic.konst(encoder.mkpacked_v32(raw_witness[block].outw[word]));
    for (std::size_t word = 0; word < 64; ++word) {
      witness[block].oute[word] =
          logic.konst(encoder.mkpacked_v32(raw_witness[block].oute[word]));
      witness[block].outa[word] =
          logic.konst(encoder.mkpacked_v32(raw_witness[block].outa[word]));
    }
    for (std::size_t word = 0; word < 8; ++word)
      witness[block].h1[word] =
          logic.konst(encoder.mkpacked_v32(raw_witness[block].h1[word]));
  }

  const auto digest = sd_jwt_zk::sha256_ascii(signing);
  Logic::v256 digest_bits{};
  std::array<Logic::EltW, 32> signed_public_digest{};
  for (std::size_t byte = 0; byte < digest.size(); ++byte) {
    for (std::size_t bit = 0; bit < 8; ++bit)
      digest_bits[(31 - byte) * 8 + bit] =
          logic.bit((digest[byte] >> bit) & 1U);
    signed_public_digest[byte] = logic.konst(proofs::p256_base.of_scalar(
        digest[byte] ^ (mutate_signed_public_digest && byte == 0 ? 1U : 0U)));
  }

  const Bridge::Input input{header, header_length, encoded_payload,
                             payload_length, sha_input, witness, digest_bits,
                             logic.template vbit<8>(block_count),
                             signed_public_digest, decoded, decoded_length};
  Bridge(logic).assert_valid(input);
  return !backend.assertion_failed();
}

struct TwoSlotCase {
  std::string object_disclosure;
  std::string array_disclosure;
  std::string payload_json;
  std::string object_value;
  std::string array_value;
};

TwoSlotCase make_two_slot_case(std::string object_value,
                               std::string array_value) {
  TwoSlotCase result;
  result.object_value = std::move(object_value);
  result.array_value = std::move(array_value);
  const std::string object_json =
      "[\"object-salt\",\"name\"," + result.object_value + "]";
  const std::string array_json = "[\"array-salt\"," + result.array_value + "]";
  result.object_disclosure = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(object_json.begin(), object_json.end()));
  result.array_disclosure = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(array_json.begin(), array_json.end()));
  result.payload_json =
      "{\"_sd\":[\"" + disclosure_digest(result.object_disclosure) +
      "\"],\"items\":[{\"...\":\"" +
      disclosure_digest(result.array_disclosure) + "\"}]}";
  return result;
}

bool has_exact_two_slot_root_relation(const TwoSlotCase& test_case) {
  const std::vector<std::string> disclosures{test_case.object_disclosure,
                                              test_case.array_disclosure};
  sd_jwt_zk::DisclosureProcessingLimits limits;
  limits.max_disclosures = 2;
  limits.max_disclosure_depth = 1;
  limits.allow_structured_nonrecursive = false;
  // This fixed relation authenticates exactly its two used slots; it does not
  // assert issuance completeness or no-decoy policy beyond that boundary.
  limits.require_issuance_completeness = false;
  sd_jwt_zk::DisclosureProcessingRequest request;
  request.limits = limits;
  request.selected_paths = {"/name", "/items/0"};
  const auto result = sd_jwt_zk::process_bounded_disclosures(
      test_case.payload_json, disclosures, request);
  const auto graph = sd_jwt_zk::build_bounded_disclosure_graph(
      test_case.payload_json, disclosures, limits);
  if (!result || !graph || disclosures.size() != 2 ||
      result.value->signed_digest_count != 2 ||
      result.value->resolved_disclosure_count != 2 ||
      result.value->selected.size() != 2 || graph.value->nodes.size() != 2 ||
      graph.value->signed_digest_count != 2)
    return false;

  const auto object = std::find_if(
      graph.value->nodes.begin(), graph.value->nodes.end(),
      [](const auto& node) {
        return node.kind == sd_jwt_zk::DisclosureKind::object_property;
      });
  const auto array = std::find_if(
      graph.value->nodes.begin(), graph.value->nodes.end(),
      [](const auto& node) {
        return node.kind == sd_jwt_zk::DisclosureKind::array_element;
      });
  if (object == graph.value->nodes.end() || array == graph.value->nodes.end() ||
      object->parent != sd_jwt_zk::kRootDisclosureParent ||
      array->parent != sd_jwt_zk::kRootDisclosureParent ||
      object->supplied_index != 0 || array->supplied_index != 1 ||
      object->reference.source != 0 || array->reference.source != 0 ||
      object->path != "/name" || array->path != "/items/0")
    return false;
  return result.value->selected[0].path == "/name" &&
         result.value->selected[0].value_json == test_case.object_value &&
         result.value->selected[1].path == "/items/0" &&
         result.value->selected[1].value_json == test_case.array_value;
}

bool rejects_fixed_two_slot_violation(const TwoSlotCase& valid) {
  // Every negative remains in the same small root shape and limits; none uses
  // the generic 32-slot family as evidence for this fixed relation.
  TwoSlotCase missing = valid;
  missing.payload_json = "{\"items\":[{\"...\":\"" +
      disclosure_digest(valid.array_disclosure) + "\"}]}";
  TwoSlotCase extra = valid;
  extra.payload_json = "{\"_sd\":[\"" +
      disclosure_digest(valid.object_disclosure) + "\",\"" +
      disclosure_digest(valid.object_disclosure) +
      "\"],\"items\":[{\"...\":\"" +
      disclosure_digest(valid.array_disclosure) + "\"}]}";
  TwoSlotCase wrong_placeholder = valid;
  wrong_placeholder.payload_json = "{\"_sd\":[\"" +
      disclosure_digest(valid.object_disclosure) +
      "\"],\"items\":[{\"...\":\"" +
      disclosure_digest(valid.array_disclosure) + "\",\"extra\":0}]}";
  TwoSlotCase recursive = valid;
  recursive.object_disclosure = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes{'[','"','s','"',',','"','n','a','m','e','"',',',
                        '{','"','x','"',':','t','r','u','e','}',']'});
  recursive.payload_json = "{\"_sd\":[\"" +
      disclosure_digest(recursive.object_disclosure) +
      "\"],\"items\":[{\"...\":\"" +
      disclosure_digest(recursive.array_disclosure) + "\"}]}";
  TwoSlotCase container = valid;
  container.array_disclosure = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes{'[','"','s','"',',','[','t','r','u','e',']',']'});
  container.payload_json = "{\"_sd\":[\"" +
      disclosure_digest(container.object_disclosure) +
      "\"],\"items\":[{\"...\":\"" +
      disclosure_digest(container.array_disclosure) + "\"}]}";
  TwoSlotCase wrong_digest = valid;
  wrong_digest.payload_json = "{\"_sd\":[\"" +
      disclosure_digest(valid.array_disclosure) +
      "\"],\"items\":[{\"...\":\"" +
      disclosure_digest(valid.object_disclosure) + "\"}]}";
  TwoSlotCase duplicate = valid;
  duplicate.array_disclosure = duplicate.object_disclosure;
  return !has_exact_two_slot_root_relation(missing) &&
         !has_exact_two_slot_root_relation(extra) &&
         !has_exact_two_slot_root_relation(wrong_placeholder) &&
         !has_exact_two_slot_root_relation(recursive) &&
         !has_exact_two_slot_root_relation(container) &&
         !has_exact_two_slot_root_relation(wrong_digest) &&
         !has_exact_two_slot_root_relation(duplicate);
}

}  // namespace

int main(int argc, char** argv) {
  const bool mutate_signed_public_digest =
      argc == 2 && std::string_view(argv[1]) == "--mutate-public-digest";
  if (argc != 1 && !mutate_signed_public_digest) return 64;

  // Across these two fixed cases, every supported opened scalar spelling is
  // covered without adding a third disclosure slot: boolean/integer then
  // string/null. Both cases remain one root object property plus one root
  // array placeholder.
  const std::array scalar_cases{make_two_slot_case("true", "42"),
                                make_two_slot_case("\"text\"", "null")};
  const auto& compact_case = scalar_cases.front();
  for (const auto& test_case : scalar_cases)
    if (!has_exact_two_slot_root_relation(test_case)) return 1;
  if (!rejects_fixed_two_slot_violation(compact_case)) return 1;
  const std::string payload_json = compact_case.payload_json;
  const std::string payload = sd_jwt_zk::base64url_encode(
      sd_jwt_zk::Bytes(payload_json.begin(), payload_json.end()));

  std::array<unsigned char, 64> raw_signature{};
  sd_jwt_zk::P256Key key{};
  if (!sd_jwt_zk::test::sign_nested_fixture_es256(
          std::string(kHeader) + "." + payload, raw_signature, &key))
    return 2;
  sd_jwt_zk::P256Signature signature{};
  std::copy_n(raw_signature.begin(), signature.r.size(), signature.r.begin());
  std::copy_n(raw_signature.begin() + signature.r.size(), signature.s.size(),
              signature.s.begin());
  if (!sd_jwt_zk::p256_key_is_valid(key) ||
      !sd_jwt_zk::verify_es256_signature(
          key, std::string(kHeader) + "." + payload, signature))
    return 3;

  const bool bridge_accepted =
      evaluate_compact_bridge(payload, mutate_signed_public_digest);
  if (mutate_signed_public_digest) {
    if (bridge_accepted) return 4;
    std::cout << "two-slot-signed-public-digest-mutation-rejected\n";
    return 0;
  }
  if (!bridge_accepted)
    return 5;
  std::cout << "two-slot-root-object-and-array-compact-bridge-accepted\n";
  return 0;
}
