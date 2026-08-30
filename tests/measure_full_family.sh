#!/usr/bin/env bash
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
