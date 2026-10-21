#!/usr/bin/env bash
# Convenience wrapper: activate the venv and run the agent.
#
#   ./run.sh --binary samples/x86 --pcap samples/capture.pcap   # full pass
#   ./run.sh --binary samples/x86 --offline                      # no API key
#
# No samples are shipped with the repository: put your own under samples/
# (git-ignored) and analyse them only inside an isolated VM.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck disable=SC1091
source .venv/bin/activate

if [[ "$*" != *"--binary"* ]]; then
  echo "usage: ./run.sh --binary <file> [--pcap <file>] [--out out] [...]" >&2
  exit 1
fi
if [[ "$*" != *"--out"* ]]; then
  set -- "$@" --out out
fi

exec python -m reverse_agent "$@"
