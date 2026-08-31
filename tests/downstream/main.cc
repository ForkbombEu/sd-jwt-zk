#include <sd_jwt_zk/presentation.h>

int main() {
  [[maybe_unused]] auto bearer = &sd_jwt_zk::BuildBearerPresentationRequestV1;
  [[maybe_unused]] auto holder = &sd_jwt_zk::BuildHolderPresentationRequestV1;
  return sd_jwt_zk::native_parsing_is_not_proof_verification() ? 0 : 1;
}
