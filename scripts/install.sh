#!/bin/bash
set -e
echo "Installing SafeClaw skill-security-audit..."
SKILLS_DIR="${OPENCLAW_SKILLS_DIR:-$HOME/.openclaw/skills}"
INSTALL_DIR="$SKILLS_DIR/skill-security-audit"
if [ -d "$INSTALL_DIR" ]; then
  echo "Updating existing installation..."
  cd "$INSTALL_DIR" && git pull
else
  echo "Installing to $INSTALL_DIR..."
  git clone https://github.com/safeclaw-sec/skill-security-audit.git "$INSTALL_DIR"
fi
if command -v docker &>/dev/null; then
  echo "Building sandbox Docker image..."
  cd "$INSTALL_DIR" && docker build -t safeclaw-auditor:latest -f Dockerfile .
  echo "Sandbox ready."
else
  echo "Docker not found — sandbox mode unavailable (audit still works without it)."
fi
echo ""
echo "Done! Usage:"
echo "  python3 $INSTALL_DIR/scripts/audit.py /path/to/skill"
echo "  python3 $INSTALL_DIR/scripts/sandbox.py /path/to/skill  (with Docker sandbox)"
