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

#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

namespace sd_jwt_zk {

// Captured while the factory allocates its wires.  Longfellow intentionally
// erases input names after compilation, so this is the source-of-truth bridge
// from a fixture encoder to the exact DenseFiller order.
struct HolderDenseRangeV1 { std::string_view name; std::size_t first; std::size_t count; };
struct HolderDenseLayoutV1 {
  std::vector<HolderDenseRangeV1> ranges;
  std::size_t public_inputs{};
  std::size_t total_inputs{};
  void begin(std::size_t public_count) { ranges.clear(); public_inputs = public_count; }
  void add(std::string_view name, std::size_t first, std::size_t end) {
    ranges.push_back({name, first, end - first});
  }
  void finish(std::size_t total) { total_inputs = total; }
};

}  // namespace sd_jwt_zk
