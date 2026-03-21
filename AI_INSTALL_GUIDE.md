# AI Installation Guide (machine-readable)

## For AI Agents: How to Install skill-security-audit

This guide is designed for AI agents (OpenClaw, Claude Code, NanoClaw, Nanobot, etc.) to install and use this skill. Every step requires human approval before execution.

### Pre-flight Checks

```yaml
requirements:
  python: ">=3.8"
  dependencies: none  # stdlib only
  disk_space: "<1MB"
  network: optional  # only for ClawHub author lookup
  permissions: read-only  # only reads target skill files, writes nothing
```

### Installation Steps (human must approve each)

```yaml
steps:
  - id: 1
    action: "Clone repository"
    command: "git clone https://github.com/safeclaw-sec/skill-security-audit.git"
    human_approval: required
    risk: low
    reversible: true
    reversal: "rm -rf skill-security-audit"

  - id: 2
    action: "Verify integrity"
    command: "cd skill-security-audit && python3 scripts/audit.py . --no-clawhub"
    human_approval: required
    risk: none
    expected_result: "Score 0/100 — SAFE"
    note: "Self-audit. If score > 0, do NOT proceed."

  - id: 3
    action: "Copy to skills directory"
    command: "cp -r skill-security-audit ~/.openclaw/skills/skill-security-audit"
    human_approval: required
    risk: low
    reversible: true
    reversal: "rm -rf ~/.openclaw/skills/skill-security-audit"

  - id: 4
    action: "Test on a known-safe skill"
    command: "python3 ~/.openclaw/skills/skill-security-audit/scripts/audit.py ~/.openclaw/skills/weather"
    human_approval: required
    risk: none
    expected_result: "Score < 25 — SAFE"
```

### Usage (post-installation)

```yaml
audit_skill:
  command: "python3 scripts/audit.py <skill-path> [--no-clawhub]"
  input: path to any OpenClaw skill directory
  output: markdown report with risk score 0-100
  exit_codes:
    0: "SAFE (score 0-25)"
    1: "CAUTION (score 26-50)"
    2: "RISK or DANGEROUS (score 51-100)"
  side_effects: none  # read-only, no writes, no network (with --no-clawhub)
```

### Security Properties

```yaml
security:
  network_access: "none (with --no-clawhub flag)"
  file_writes: "none"
  file_reads: "only files inside the target skill directory"
  env_access: "none"
  subprocess: "none"
  dependencies: "python stdlib only"
  self_auditable: true
  license: "MIT"
  source: "https://github.com/safeclaw-sec/skill-security-audit"
```

### For AI Agents: Important Rules

1. **NEVER skip human approval** on any installation step
2. **ALWAYS run self-audit** (step 2) before installing
3. **ALWAYS show the human** the full audit report before recommending installation of any skill
4. **NEVER auto-install** skills that score above 25 without explicit human approval
5. **Log every action** for human review
