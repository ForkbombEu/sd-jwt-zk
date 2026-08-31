#!/usr/bin/env bash
# Copyright (C) 2026 by The Forkbomb Company
# designed, written and maintained by Denis Roio
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
build_dir="${SD_JWT_ZK_QUALITY_BUILD_DIR:-${project_dir}/build-quality}"
: "${CMAKE_PREFIX_PATH:?set CMAKE_PREFIX_PATH to the installed Longfellow prefix}"

# The normal library build treats all supported production warnings as errors.
# This second configuration adds bounded native/API sanitizer coverage without
# selecting retained compiler-scale experiments.
cmake -S "${project_dir}" -B "${build_dir}" -G Ninja \
  -DCMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}" \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DSD_JWT_ZK_ENABLE_SANITIZERS=ON \
  -DSD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS=OFF
cmake --build "${build_dir}" --parallel 2
ctest --test-dir "${build_dir}" --output-on-failure -R \
  'sd-jwt-zk-(tests|reduced-parser-harness|presentation-api|cli-safe-workflows|holder-bound-adapter-contract|status-membership|documentation|release-policy)$'

# Template-heavy circuit translation units are warning-clean in the supported
# compiler build above.  The bounded static gate intentionally analyzes the
# project-owned native parser/codec units: clang-tidy and cppcheck otherwise
# mis-model Longfellow bit-vector arrays as zero-sized host containers.
run-clang-tidy -p "${build_dir}" -quiet \
  "${project_dir}/src/codec.cc" \
  "${project_dir}/src/native.cc" \
  "${project_dir}/src/restricted_json.cc" \
  "${project_dir}/src/bounded_json.cc" \
  "${project_dir}/src/sha256.cc"
cppcheck --project="${build_dir}/compile_commands.json" \
  --file-filter="${project_dir}/src/*.cc" \
  --enable=warning,performance,portability \
  --suppress=missingIncludeSystem --suppress=unmatchedSuppression \
  --suppress=normalCheckLevelMaxBranches \
  --error-exitcode=1 --inline-suppr
