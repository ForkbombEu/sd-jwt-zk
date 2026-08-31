#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  printf '%s\n' 'usage: install-longfellow.sh PREFIX' >&2
  exit 64
fi
prefix="$1"
source_dir="${SD_JWT_ZK_LONGFELLOW_SOURCE:-}"
if [[ -z "${source_dir}" || ! -f "${source_dir}/CMakeLists.txt" ]]; then
  printf '%s\n' 'SD_JWT_ZK_LONGFELLOW_SOURCE must name a pinned checkout' >&2
  exit 64
fi
cmake -S "${source_dir}" -B "${prefix}-build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DCMAKE_INSTALL_PREFIX="${prefix}"
cmake --build "${prefix}-build" --parallel 2
cmake --install "${prefix}-build"
cmake -S "${source_dir}/projects/ecdsa" -B "${prefix}-ecdsa-build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DCMAKE_PREFIX_PATH="${prefix}" -DCMAKE_INSTALL_PREFIX="${prefix}"
cmake --build "${prefix}-ecdsa-build" --parallel 2
cmake --install "${prefix}-ecdsa-build"
