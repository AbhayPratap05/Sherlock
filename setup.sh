#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# setup.sh — Install project dependencies
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Decompress block fixtures if not already present
for gz in "$SCRIPT_DIR/fixtures/"*.dat.gz; do
  dat="${gz%.gz}"
  if [[ ! -f "$dat" ]]; then
    echo "Decompressing $(basename "$gz")..."
    gunzip -k "$gz"
  fi
done

# Install web dependencies
if [[ -f "$SCRIPT_DIR/src/web/package.json" ]]; then
  echo "Installing web dependencies..."
  cd "$SCRIPT_DIR/src/web"
  npm install --silent
  npm run build --silent
  cd "$SCRIPT_DIR"
fi

echo "Setup complete"
