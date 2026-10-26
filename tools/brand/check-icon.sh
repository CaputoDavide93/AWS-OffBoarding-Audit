#!/bin/sh
# Fail if docs/assets/brand/icon.svg is not what the vendored brand kit draws.
set -e
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 tools/brand/brand_kit.py icon --repo AWS-Offboarding-Audit --out "$tmp" --sizes ""
if cmp -s "$tmp/icon.svg" docs/assets/brand/icon.svg; then
  echo "icon up to date"
else
  echo "stale, run: python3 tools/brand/brand_kit.py icon --repo AWS-Offboarding-Audit --out docs/assets/brand --sizes 256"
  exit 1
fi
