# skill-security-audit

**OpenClaw Skill Security Auditor** — Automatically audits any OpenClaw skill for security risks before installation.

## Why This Exists

In February 2026, 341 malicious skills were discovered on ClawHub in a coordinated supply chain attack. This tool automates the security audit process, checking all known attack vectors so you don't have to do it manually.

## What It Detects

| Vector | Examples |
|--------|---------|
| **Prompt Injection** | Hidden instructions, role hijacking, jailbreaks, invisible Unicode |
| **Malicious Code** | `eval()`/`exec()` with external input, subprocess injection, base64 payloads |
| **Hardcoded Secrets** | API keys, tokens, private keys embedded in scripts |
| **Data Exfiltration** | Env var harvesting (API keys, tokens), system info collection |
| **Network Risks** | Suspicious domains, URL shorteners, ngrok tunnels, raw IPs |
| **Post-install Hooks** | `setup.py`, npm `postinstall` scripts that run on install |
| **Dependency Risks** | Typosquatting, wildcard versions, excessive dependencies |
| **Suspicious Files** | Binary executables, archives hidden in skill directories |
| **System Intrusion** | Hostname/IP collection, undocumented TCP/WebSocket servers |
| **Crypto Miners** | Mining pool URLs, miner binary references |

## Quick Start

```bash
# Audit a local skill
python3 scripts/audit.py /path/to/skill/

# Audit by skill name (auto-discovers common install paths)
python3 scripts/audit.py scrapling-official

# Audit and save report
python3 scripts/audit.py /path/to/skill/ --output report.md

# Output as JSON (for CI/automation)
python3 scripts/audit.py /path/to/skill/ --json

# Skip ClawHub lookup (offline mode)
python3 scripts/audit.py /path/to/skill/ --no-clawhub
```

## Output

```
# 🔍 Security Audit Report: `my-skill`

## Risk Assessment
| | |
|---|---|
| **Risk Score** | **12/100** |
| **Level** | 🟢 **SAFE** |
| **Recommendation** | **INSTALL** |

> ✅ **INSTALL** — No significant risks detected.

## Security Checklist
✅ No prompt injection in SKILL.md
✅ No malicious code patterns (eval/exec/subprocess)
✅ No hardcoded secrets or API keys
✅ No suspicious network requests
...
```

## Risk Score Levels

| Score | Level | Recommendation |
|-------|-------|----------------|
| 0–25 | 🟢 SAFE | INSTALL |
| 26–50 | 🟡 CAUTION | INSTALL WITH CAUTION |
| 51–75 | 🟠 RISK | Review strongly recommended |
| 76–100 | 🔴 DANGEROUS | DO NOT INSTALL |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | SAFE |
| `1` | CAUTION |
| `2` | RISK or DANGEROUS |

Use in CI: `python3 scripts/audit.py my-skill || echo "Skill failed security check"`

## Requirements

- Python 3.6+
- No external dependencies — stdlib only
- Works fully offline (ClawHub lookup requires network, optional via `--no-clawhub`)

## How It Works

1. **Discovers all files** in the skill directory (recursive)
2. **SKILL.md** → checks for prompt injection, social engineering, hidden instructions
3. **Python/JS/Shell scripts** → scans for malicious code patterns using regex
4. **package.json / requirements.txt** → audits dependencies for typosquatting and supply chain risks
5. **All files** → extracts URLs/domains and flags suspicious ones
6. **ClawHub** → optionally looks up author reputation (requires network)
7. **Generates** a scored Markdown report with findings, checklist, and recommendation

## Real Malicious Skills Examples

These were removed from ClawHub:

| Skill | Attack Vector | Finding |
|-------|--------------|---------|
| `mission-control-dashboard` | Hardcoded Secret | Auth token hardcoded in script |
| `email-daily-summary` | Prompt Injection | Hidden instructions to forward emails |
| `browser-automation` | Network Exposure | CDP port exposed to all interfaces |

## License

MIT — free to use, modify, and redistribute.

---

*Part of the OpenClaw security toolkit. Report issues at [github.com/openclaw/skill-security-audit](https://github.com/openclaw/skill-security-audit)*

## The Self-Audit Paradox

When you run this tool against itself, it returns **score 100/100 (DANGEROUS)**. This is expected and correct.

Why? Because the tool contains:
- Regex patterns that match malicious code signatures (like a virus scanner contains virus signatures)
- Example audit reports with real evidence from malicious skills
- References to attack techniques in its documentation

**This is not a bug — it's proof the detection works.**

### How to verify this tool is safe

1. **Read the source**: 1,013 lines of Python. Standard library only. No obfuscation.
2. **Check what it does**: reads files, runs regex, prints a report. No network, no file writes, no env access.
3. **Run it yourself**: `python3 scripts/audit.py . --no-clawhub` — review every finding and confirm they're pattern definitions, not actual threats.

The same paradox exists in every security tool: antivirus software contains virus signatures, WAFs contain attack patterns, SAST scanners contain vulnerability templates. The solution is always the same: **radical transparency**.

