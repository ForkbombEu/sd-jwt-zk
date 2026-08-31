#!/usr/bin/env bash
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
  -DSD_JWT_ZK_ENABLE_SANITIZERS=ON \
  -DSD_JWT_ZK_ENABLE_EXPENSIVE_PROOF_TESTS=OFF
cmake --build "${build_dir}" --parallel 2
ctest --test-dir "${build_dir}" --output-on-failure -R \
  'sd-jwt-zk-(tests|presentation-api|cli-safe-workflows|holder-bound-adapter-contract|status-membership|documentation|release-policy)$'
