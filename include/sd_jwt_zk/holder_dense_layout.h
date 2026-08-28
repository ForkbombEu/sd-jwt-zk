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
