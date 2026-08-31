#include "sd_jwt_zk/presentation.h"

#include <iostream>

namespace {
using namespace sd_jwt_zk;

P256Key key() {
  P256Key value{};
  value.x = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
             0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
             0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
             0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
  value.y = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
             0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
             0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
             0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
  return value;
}

bool require(bool value, const char* message) {
  if (!value) std::cerr << message << '\n';
  return value;
}
}  // namespace

int main() {
  PresentationPolicyV1 policy{"https://verifier.example", "age-check", "fresh", 1,
                              2, key(), StatusRequirementV1::forbidden, std::nullopt};
  // Keep this contract test cheap: supported builders compile against their
  // typed return types without constructing the expensive proof circuits.
  [[maybe_unused]] auto bearer_builder = &BuildBearerPresentationRequestV1;
  [[maybe_unused]] auto holder_builder = &BuildHolderPresentationRequestV1;
  policy.status = StatusRequirementV1::required;
  if (!require(!BuildBearerPresentationRequestV1(policy),
               "required status cannot omit trusted snapshot")) return 1;
  policy.status = StatusRequirementV1::forbidden;
  policy.purpose = "bad\x1fpurpose";
  if (!require(!BuildBearerPresentationRequestV1(policy),
               "noncanonical audience-purpose separator rejects")) return 1;
  return 0;
}
