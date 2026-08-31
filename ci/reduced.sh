#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
build_dir="${SD_JWT_ZK_BUILD_DIR:-${project_dir}/build-ci}"
install_dir="${SD_JWT_ZK_INSTALL_DIR:-${project_dir}/build-ci-install}"
: "${CMAKE_PREFIX_PATH:?set CMAKE_PREFIX_PATH to the installed Longfellow prefix}"

cmake -S "${project_dir}" -B "${build_dir}" -G Ninja \
  -DCMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}" \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
cmake --build "${build_dir}" --parallel 2
ctest --test-dir "${build_dir}" --output-on-failure
cmake --install "${build_dir}" --prefix "${install_dir}"
cmake -S "${project_dir}/tests/downstream" -B "${build_dir}/downstream" -G Ninja \
  -DCMAKE_PREFIX_PATH="${install_dir};${CMAKE_PREFIX_PATH}" \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
cmake --build "${build_dir}/downstream" --parallel 2
"${build_dir}/downstream/downstream"
npm --prefix "${project_dir}" ci --ignore-scripts
npm --prefix "${project_dir}" run docs:build
cmake --build "${build_dir}" --target package_source
