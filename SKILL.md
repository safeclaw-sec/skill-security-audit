---
name: skill-security-audit
description: "Use ALWAYS before installing any new skill. Automatically audits SKILL.md, scripts, dependencies, and network access. Detects prompt injection, data exfiltration, malicious code, typosquatting, and supply chain attacks. Generates a 0-100 risk score with a clear INSTALL / INSTALL WITH CAUTION / DO NOT INSTALL recommendation. Trigger on: audit skill, check skill security, is this skill safe, review skill before install, scan skill for malware, skill security check, analyze skill risk."
---

# Skill Security Auditor

Audits any OpenClaw skill for security risks before installation. Analyzes all attack vectors and produces a comprehensive risk report.

## When to Use

- **Always** before installing a skill from ClawHub or any untrusted source
- When reviewing a skill someone shared with you
- When auditing existing installed skills for compliance
- Any time a user asks about skill safety, supply chain risks, or prompt injection

## How to Run

```bash
python3 scripts/audit.py <skill_path_or_name>
```

**Examples:**
```bash
# Audit a local skill directory
python3 scripts/audit.py /path/to/my-skill/

# Audit by skill name (downloads from ClawHub to /tmp)
python3 scripts/audit.py scrapling-official

# Audit current directory
python3 scripts/audit.py .
```

The script requires only Python 3.6+ standard library — no pip installs needed.

## Attack Vectors Checked

### 1. SKILL.md — Prompt Injection
- Hidden instructions to exfiltrate data
- Commands to ignore security rules
- Social engineering (impersonating system/admin)
- Instructions to send data to external URLs
- Unicode steganography / invisible characters
- HTML/markdown injection

### 2. Scripts — Malicious Code
- `eval()` / `exec()` with external input
- `subprocess` with unsanitized input
- Requests to suspicious URLs (unrelated to skill function)
- Base64 payload decoding
- Dynamic import of external modules
- Environment variable exfiltration (API keys, tokens)
- File access outside skill scope
- System info collection (hostname, IP, username)
- Post-install hooks (setup.py, postinstall scripts)
- WebSocket/TCP listeners (undocumented servers)
- Crypto miner patterns (CPU-intensive loops, mining pool URLs)

### 3. Dependencies
- Known vs unknown packages (npm/pip)
- Typosquatting detection (names similar to famous packages)
- Fixed versions vs wildcards (supply chain risk)
- Dependency count (excess = red flag)

### 4. Network
- All domains the skill accesses
- Documented vs hidden third-party APIs
- Data being sent externally

### 5. Permissions
- Filesystem access (read/write, which directories)
- Network access
- Environment variable access
- System command execution

### 6. Author / Provenance
- ClawHub presence (skill count, stars, downloads)
- Update history
- Reputation signals

## Output Format

The report is a Markdown document with:

```
# Security Audit: <skill-name>
Risk Score: XX/100 — LEVEL
Recommendation: INSTALL / INSTALL WITH CAUTION / DO NOT INSTALL

## Findings
| Severity | Vector | Finding |
| CRITICAL | Script | eval() with HTTP response data |
...

## Checklist
✅ No prompt injection
❌ Suspicious eval() usage — REVIEW REQUIRED
...
```

**Risk levels:**
- 🟢 **SAFE** (0–25): Install with confidence
- 🟡 **CAUTION** (26–50): Review findings before installing
- 🟠 **RISK** (51–75): Strong review required, likely avoid
- 🔴 **DANGEROUS** (76–100): Do not install

## Implementation Notes

The script (`scripts/audit.py`) uses only Python stdlib: `os`, `re`, `sys`, `pathlib`, `json`, `base64`, `urllib`. No external dependencies required. Works fully offline except for the optional ClawHub author lookup (uses `urllib` to query public ClawHub API).
