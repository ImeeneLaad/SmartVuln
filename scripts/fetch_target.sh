#!/usr/bin/env bash
# Fetch the pinned OWASP Juice Shop source used for SAST and the route map.
set -euo pipefail
TAG="${JUICE_SHOP_TAG:-v20.3.0}"
DEST="$(cd "$(dirname "$0")/.." && pwd)/targets/juice-shop"
if [ -d "$DEST/.git" ]; then
  echo "Juice Shop source already present at $DEST ($(git -C "$DEST" describe --tags --always))"
  exit 0
fi
mkdir -p "$(dirname "$DEST")"
git clone --depth 1 --branch "$TAG" https://github.com/juice-shop/juice-shop.git "$DEST"
echo "Fetched Juice Shop $TAG into $DEST"
