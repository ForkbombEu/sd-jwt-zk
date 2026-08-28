#include "sd_jwt_zk/active_presentation_message_relation.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"

namespace {

using Field = proofs::Fp256Base;
using Backend = proofs::EvaluationBackend<Field>;
using Logic = proofs::Logic<Field, Backend>;

constexpr char kIssuer[] =
    "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsInByb2ZpbGVfdmVyc2lvbiI6InN3aXNzLXByb2ZpbGUtdmM6MS4wLjAifQ.eyJfc2QiOlsickxFZ2lmWmdPaGdVVUxiT0xlTVZrc1oyQVVJeDF6Z1NzT0pSenFMYWJuVSJdLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoiZXhhbXBsZSIsIl9zZF9hbGciOiJzaGEtMjU2In0.RS6qxwyHcY1UIV7JU60XommQaDyhl1NTMyE-EESB6-ViM6WjVNJC56lUFwZLW82dtNMbySOKZBphd8jfRAICBQ";
constexpr char kDisclosure[] = "WyJzYWx0LTAwMDEiLCJhZ2Vfb3ZlciIsdHJ1ZV0";

constexpr std::size_t kIssuerLength = sizeof(kIssuer) - 1;
constexpr std::size_t kDisclosureLength = sizeof(kDisclosure) - 1;
constexpr std::size_t kIssuerCapacity = kIssuerLength + 1;
constexpr std::size_t kDisclosureCapacity = kDisclosureLength + 1;
constexpr std::size_t kBlocks = 7;
constexpr std::size_t kPaddedBytes = kBlocks * 64;
constexpr std::size_t kMessageLength = kIssuerLength + 1 + kDisclosureLength + 1;

static_assert(kIssuerLength == 353);
static_assert(kDisclosureLength == 39);
static_assert(kMessageLength == 394);
static_assert(((kMessageLength + 9 + 63) / 64) == kBlocks);

using Relation = sd_jwt_zk::ActivePresentationMessageRelation<
    Logic, kIssuerCapacity, kDisclosureCapacity, kBlocks>;

enum class Mutation {
  kNone,
  kIssuerTail,
  kDisclosureTail,
  kIssuerLength,
  kFirstTilde,
  kSecondTilde,
  kPaddingStart,
  kZeroFill,
  kBitLength,
  kBlockCount,
};

const char* name(Mutation mutation) {
  switch (mutation) {
    case Mutation::kNone: return "valid-current-bounded-presentation";
    case Mutation::kIssuerTail: return "nonzero-inactive-issuer-tail";
    case Mutation::kDisclosureTail: return "nonzero-inactive-disclosure-tail";
    case Mutation::kIssuerLength: return "issuer-length-mismatch";
    case Mutation::kFirstTilde: return "first-tilde-mutation";
    case Mutation::kSecondTilde: return "second-tilde-mutation";
    case Mutation::kPaddingStart: return "padding-0x80-mutation";
    case Mutation::kZeroFill: return "padding-zero-fill-mutation";
    case Mutation::kBitLength: return "padding-final-bit-length-mutation";
    case Mutation::kBlockCount: return "block-count-mutation";
  }
  return "unknown";
}

bool accepts(Mutation mutation) {
  std::array<std::uint8_t, kPaddedBytes> padded{};
  for (std::size_t i = 0; i < kIssuerLength; ++i)
    padded[i] = static_cast<std::uint8_t>(kIssuer[i]);
  padded[kIssuerLength] = '~';
  for (std::size_t i = 0; i < kDisclosureLength; ++i)
    padded[kIssuerLength + 1 + i] = static_cast<std::uint8_t>(kDisclosure[i]);
  padded[kMessageLength - 1] = '~';
  padded[kMessageLength] = 0x80;
  const std::uint64_t bit_length = kMessageLength * 8;
  for (std::size_t i = 0; i < 8; ++i)
    padded[kPaddedBytes - 8 + i] = static_cast<std::uint8_t>(
        bit_length >> ((7 - i) * 8));

  if (mutation == Mutation::kFirstTilde) padded[kIssuerLength] = '.';
  if (mutation == Mutation::kSecondTilde) padded[kMessageLength - 1] = '.';
  if (mutation == Mutation::kPaddingStart) padded[kMessageLength] = 0;
  if (mutation == Mutation::kZeroFill) padded[kMessageLength + 1] = 1;
  if (mutation == Mutation::kBitLength) padded[kPaddedBytes - 1] ^= 1;

  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  std::array<Logic::v8, kIssuerCapacity> issuer{};
  std::array<Logic::v8, kDisclosureCapacity> disclosure{};
  std::array<Logic::v8, kPaddedBytes> padded_wire{};
  for (std::size_t i = 0; i < issuer.size(); ++i) {
    const auto byte = i < kIssuerLength ? static_cast<unsigned char>(kIssuer[i]) : 0;
    issuer[i] = logic.template vbit<8>(
        mutation == Mutation::kIssuerTail && i == kIssuerLength ? 'A' : byte);
  }
  for (std::size_t i = 0; i < disclosure.size(); ++i) {
    const auto byte = i < kDisclosureLength ? static_cast<unsigned char>(kDisclosure[i]) : 0;
    disclosure[i] = logic.template vbit<8>(
        mutation == Mutation::kDisclosureTail && i == kDisclosureLength ? 'A' : byte);
  }
  for (std::size_t i = 0; i < padded_wire.size(); ++i)
    padded_wire[i] = logic.template vbit<8>(padded[i]);

  Logic::bitvec<9> issuer_length{}, disclosure_length{}, block_count{};
  logic.bits(9, issuer_length.data(),
             mutation == Mutation::kIssuerLength ? kIssuerLength - 1 : kIssuerLength);
  logic.bits(9, disclosure_length.data(), kDisclosureLength);
  logic.bits(9, block_count.data(),
             mutation == Mutation::kBlockCount ? kBlocks - 1 : kBlocks);
  Relation(logic).assert_valid(issuer, issuer_length, disclosure,
                               disclosure_length, padded_wire, block_count);
  return !backend.assertion_failed();
}

// The full current presentation fixes the production-sized route and its
// inactive tails. Exercise the remaining local rejection branches on a tiny
// independently bounded message so this regression remains practical under
// EvaluationBackend.
bool accepts_small(Mutation mutation) {
  constexpr std::size_t issuer_length = 1;
  constexpr std::size_t disclosure_length = 1;
  constexpr std::size_t message_length = issuer_length + 1 + disclosure_length + 1;
  using SmallRelation = sd_jwt_zk::ActivePresentationMessageRelation<
      Logic, issuer_length + 1, disclosure_length + 1, 1>;
  std::array<std::uint8_t, 64> padded{};
  padded[0] = 'i';
  padded[1] = '~';
  padded[2] = 'd';
  padded[3] = '~';
  padded[message_length] = 0x80;
  padded[63] = static_cast<std::uint8_t>(message_length * 8);
  if (mutation == Mutation::kFirstTilde) padded[1] = '.';
  if (mutation == Mutation::kSecondTilde) padded[3] = '.';
  if (mutation == Mutation::kPaddingStart) padded[message_length] = 0;
  if (mutation == Mutation::kZeroFill) padded[message_length + 1] = 1;
  if (mutation == Mutation::kBitLength) padded[63] ^= 1;

  const Field field;
  Backend backend(field, false);
  Logic logic(&backend, field);
  std::array<Logic::v8, 2> issuer{};
  std::array<Logic::v8, 2> disclosure{};
  std::array<Logic::v8, 64> padded_wire{};
  issuer[0] = logic.template vbit<8>('i');
  issuer[1] = logic.template vbit<8>(mutation == Mutation::kIssuerTail ? 'A' : 0);
  disclosure[0] = logic.template vbit<8>('d');
  disclosure[1] = logic.template vbit<8>(mutation == Mutation::kDisclosureTail ? 'A' : 0);
  for (std::size_t i = 0; i < padded_wire.size(); ++i)
    padded_wire[i] = logic.template vbit<8>(padded[i]);
  Logic::bitvec<9> issuer_active{}, disclosure_active{}, block_count{};
  logic.bits(9, issuer_active.data(),
             mutation == Mutation::kIssuerLength ? issuer_length - 1 : issuer_length);
  logic.bits(9, disclosure_active.data(), disclosure_length);
  logic.bits(9, block_count.data(), mutation == Mutation::kBlockCount ? 0 : 1);
  SmallRelation(logic).assert_valid(issuer, issuer_active, disclosure,
                                    disclosure_active, padded_wire, block_count);
  return !backend.assertion_failed();
}

}  // namespace

int main() {
  const std::array cases{
      Mutation::kNone, Mutation::kIssuerTail, Mutation::kDisclosureTail,
      Mutation::kIssuerLength, Mutation::kFirstTilde, Mutation::kSecondTilde,
      Mutation::kPaddingStart, Mutation::kZeroFill, Mutation::kBitLength,
      Mutation::kBlockCount};
  bool passed = true;
  for (const auto mutation : cases) {
    const bool expected = mutation == Mutation::kNone;
    const bool current_fixture = mutation == Mutation::kNone ||
        mutation == Mutation::kIssuerTail || mutation == Mutation::kDisclosureTail;
    const bool actual = current_fixture ? accepts(mutation) : accepts_small(mutation);
    std::cout << name(mutation) << '=' << (actual ? "accepted" : "rejected") << '\n';
    passed = passed && actual == expected;
  }
  return passed ? 0 : 1;
}
