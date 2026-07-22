#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../install.sh" ]; then
  exec bash "$SCRIPT_DIR/../install.sh" "$@"
fi

exec bash <(curl -fsSL https://raw.githubusercontent.com/52Jerry/Node-Manager/main/install.sh) "$@"
