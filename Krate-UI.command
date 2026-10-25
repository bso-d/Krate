#!/usr/bin/env bash
set -euo pipefail

# Ensure working directory is the script directory (repository root or package root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Locate python3 (macOS Finder launches Terminal with a minimal PATH)
PYTHON_BIN=""
for candidate in python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "$candidate")"
    break
  fi
done

if [[ -z "$PYTHON_BIN" ]]; then
  echo "Error: Python 3 was not found in PATH or standard macOS paths." >&2
  echo "Please install Python 3.9+ (from https://www.python.org or via Homebrew) to run Krate Studio." >&2
  if command -v osascript >/dev/null 2>&1; then
    osascript -e 'display alert "Python 3 Not Found" message "Please install Python 3.9+ to run Krate Studio."' 2>/dev/null || true
  fi
  read -r -p "Press Enter to exit..." || true
  exit 1
fi

export PYTHONDONTWRITEBYTECODE=1

UI_SCRIPT="$SCRIPT_DIR/ui/krate_ui.py"
if [[ ! -f "$UI_SCRIPT" ]]; then
  echo "Error: Krate Studio script not found at: $UI_SCRIPT" >&2
  read -r -p "Press Enter to exit..." || true
  exit 1
fi

echo "========================================================================"
echo " Starting Krate Studio on macOS..."
echo "========================================================================"

# Launch krate_ui.py (automatically launches default browser via webbrowser.open)
exec "$PYTHON_BIN" -B "$UI_SCRIPT" "$@"
