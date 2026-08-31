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
