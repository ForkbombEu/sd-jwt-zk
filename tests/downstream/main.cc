#include <sd_jwt_zk/api.h>
int main() { return sd_jwt_zk::native_parsing_is_not_proof_verification() ? 0 : 1; }
