#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"
docker build -t safeclaw-auditor:latest -f Dockerfile .
echo "SafeClaw sandbox image built successfully."
echo "Run: python3 scripts/sandbox.py /path/to/skill"
