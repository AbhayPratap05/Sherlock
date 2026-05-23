#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# cli.sh — Bitcoin chain analysis CLI
#
# Usage:
#   ./cli.sh --block <blk.dat> <rev.dat> <xor.dat>
#
# Block mode:
#   - Reads blk*.dat, rev*.dat, and xor.dat
#   - Parses all blocks and transactions
#   - Applies chain analysis heuristics to every transaction
#   - Writes per-block-file outputs:
#       out/<blk_stem>.json — machine-readable analysis report
#       out/<blk_stem>.md   — human-readable Markdown report
#     where <blk_stem> is the blk filename without extension (e.g., blk04330)
#   - Exits 0 on success, 1 on error
###############################################################################

error_json() {
  local code="$1"
  local message="$2"
  printf '{"ok":false,"error":{"code":"%s","message":"%s"}}\n' "$code" "$message"
}

# --- Block mode ---
if [[ "${1:-}" != "--block" ]]; then
  error_json "INVALID_ARGS" "Usage: cli.sh --block <blk.dat> <rev.dat> <xor.dat>"
  exit 1
fi

shift
if [[ $# -lt 3 ]]; then
  error_json "INVALID_ARGS" "Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p out
exec python3 "$SCRIPT_DIR/src/analyzer/main.py" "$1" "$2" "$3"
