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
