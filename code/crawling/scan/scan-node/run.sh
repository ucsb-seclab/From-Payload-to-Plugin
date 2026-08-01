#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

XVFB_DISPLAY="${XVFB_DISPLAY:-:99}"
XVFB_RESOLUTION="${XVFB_RESOLUTION:-1366x768x24}"

echo "[run.sh] Starting Xvfb on display ${XVFB_DISPLAY} (${XVFB_RESOLUTION})"
Xvfb "${XVFB_DISPLAY}" -screen 0 "${XVFB_RESOLUTION}" >/tmp/xvfb.log 2>&1 &
XVFB_PID=$!
trap 'kill ${XVFB_PID}' EXIT
sleep 2

export DISPLAY="${XVFB_DISPLAY}"

exec python3 pool_worker.py "$@"
echo "Failed to launch pooled worker" >&2
exit 1
