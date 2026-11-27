#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
    exit 0
fi

for path in "$@"; do
    neutron-drive pin "$path"
done
