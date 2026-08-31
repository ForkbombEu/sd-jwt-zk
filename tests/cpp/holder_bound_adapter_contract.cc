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

#include <iostream>
#include <type_traits>

#include "sd_jwt_zk/holder_bound_proof.h"

int main() {
  static_assert(std::is_final_v<sd_jwt_zk::HolderBoundCircuitProverV1>);
  static_assert(std::is_final_v<sd_jwt_zk::HolderBoundCircuitVerifierV1>);
  static_assert(std::is_base_of_v<sd_jwt_zk::HolderBoundProofProverV1,
                                  sd_jwt_zk::HolderBoundCircuitProverV1>);
  static_assert(std::is_base_of_v<sd_jwt_zk::HolderBoundProofVerifierV1,
                                  sd_jwt_zk::HolderBoundCircuitVerifierV1>);
  static constexpr char kPolicy[] = "age_over:eq:true";
  const sd_jwt_zk::Bytes expected(kPolicy, kPolicy + sizeof(kPolicy) - 1);
  if (sd_jwt_zk::holder_bound_policy_v1() != expected ||
      sd_jwt_zk::holder_bound_true_policy_result_v1() !=
          sd_jwt_zk::Bytes{1}) {
    std::cerr << "holder adapter policy contract mismatch\n";
    return 1;
  }
  std::cout << "holder circuit adapter contract passed\n";
  return 0;
}
