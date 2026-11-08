#!/usr/bin/env bash
# End-to-end demonstration: deploy target -> scan -> evaluate -> dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python}"

./scripts/fetch_target.sh
docker compose up -d juice-shop
$PY -m smartvuln health --timeout 180
$PY -m smartvuln scan --label "demo $(date +%F)"
$PY -m smartvuln evaluate --out data/evaluation.json
echo "Dashboard: http://127.0.0.1:5000"
$PY -m smartvuln serve
