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

#include <sd_jwt_zk/presentation.h>

int main() {
  [[maybe_unused]] auto bearer = &sd_jwt_zk::BuildBearerPresentationRequestV1;
  [[maybe_unused]] auto holder = &sd_jwt_zk::BuildHolderPresentationRequestV1;
  return sd_jwt_zk::native_parsing_is_not_proof_verification() ? 0 : 1;
}
