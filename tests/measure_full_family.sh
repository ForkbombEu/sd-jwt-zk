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

set -euo pipefail
build_dir=${1:?build directory}
out=${2:?output file}
lane=${3:-bearer-exact}
start=$(date +%s)
timeout 150s prlimit --as=2306867200 -- /usr/bin/time \
  -f 'rss_kib=%M elapsed_s=%e exit=%x' \
  "$build_dir/sd-jwt-zk-full-disclosure-32-real-proof" "$lane" >"$out" 2>&1
end=$(date +%s)
printf 'family=full-disclosure-v1\njson_capacity=16\ntokens=8\ndepth=3\ndisclosures=32\nlane=%s\nproof_metrics=measured\ncommand=%s/sd-jwt-zk-full-disclosure-32-real-proof %s\nwall_seconds=%s\n' "$lane" "$build_dir" "$lane" "$((end-start))" >>"$out"
