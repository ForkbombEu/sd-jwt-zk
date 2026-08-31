#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 || ! -f "$1" || -z "$2" ]]; then
  printf '%s\n' 'usage: write-checksum.sh ARCHIVE OUTPUT' >&2
  exit 64
fi
archive="$1"
output="$2"
output_dir="$(dirname -- "${output}")"
temporary="$(mktemp "${output_dir}/.SHA256SUMS.XXXXXX")"
cleanup() { [[ ! -e "${temporary}" ]] || unlink -- "${temporary}"; }
trap cleanup EXIT
(
  cd -- "$(dirname -- "${archive}")"
  sha256sum -- "$(basename -- "${archive}")"
) >"${temporary}"
chmod 0644 "${temporary}"
mv -f -- "${temporary}" "${output}"
trap - EXIT
