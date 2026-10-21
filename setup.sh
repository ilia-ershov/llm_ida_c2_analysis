#!/usr/bin/env bash
#
# One-time setup for reverse_agent.
#
#   ./setup.sh [/path/to/IDA.app]
#
# Creates a virtualenv, installs dependencies, installs the idalib `idapro`
# wheel from your IDA installation, and activates idalib so IDA can be driven
# headlessly.
set -euo pipefail

IDA_APP="${1:-/Applications/IDA Professional 9.4.app}"
IDA_MACOS="$IDA_APP/Contents/MacOS"
IDALIB_PY="$IDA_MACOS/idalib/python"

if [[ ! -d "$IDA_APP" ]]; then
  echo "IDA installation not found at: $IDA_APP" >&2
  echo "Pass the path as the first argument, e.g. ./setup.sh '/Applications/IDA Professional 9.4.app'" >&2
  exit 1
fi

echo "==> Creating virtualenv (.venv)"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip >/dev/null

echo "==> Installing Python dependencies"
pip install -r requirements.txt

echo "==> Installing idalib wheel from IDA installation"
IDAPRO_WHL=$(ls "$IDALIB_PY"/idapro-*.whl 2>/dev/null | head -1 || true)
if [[ -z "$IDAPRO_WHL" ]]; then
  echo "Could not find idapro wheel under $IDALIB_PY" >&2
  exit 1
fi
pip install "$IDAPRO_WHL"

echo "==> Activating idalib (pointing idapro at $IDA_APP)"
python "$IDALIB_PY/py-activate-idalib.py" -d "$IDA_APP"

echo "==> Configuring IDAPython interpreter (idapyswitch)"
"$IDA_MACOS/idapyswitch" --auto-apply || true

echo
echo "Setup complete. Next:"
echo "  source .venv/bin/activate"
echo "  export DEEPSEEK_API_KEY=sk-...        # for the DeepSeek mapper"
echo "  python -m reverse_agent --binary samples/<name> --pcap samples/<name>.pcap --out out"
