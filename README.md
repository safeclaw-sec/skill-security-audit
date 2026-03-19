# skill-security-audit

**OpenClaw Skill Security Auditor** — Automatically audits any OpenClaw skill for security risks before installation.

## Why This Exists

In February 2026, 824+ malicious skills were discovered on ClawHub in a coordinated supply chain attack called ClawHavoc. Atomic Stealer (macOS infostealer) was hidden inside innocent-looking skills. This tool automates the security audit process, checking all known attack vectors so you don't have to do it manually.

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
| **Size Anomalies** | Abnormally large skills that may exploit context window truncation |
| **Structural Anomalies** | Unusual comment ratios, payload-at-end-of-file patterns |

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
| **Total Lines** | 487 |

> ✅ **INSTALL** — No significant risks detected.

## Size Analysis
✅ Size is within normal range — no size-related alerts.

## Structural Analysis
✅ No structural anomalies detected.

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
2. **Size analysis** → calculates total line count and emits threshold-based alerts
3. **SKILL.md** → checks for prompt injection, social engineering, hidden instructions
4. **Python/JS/Shell scripts** → scans for malicious code patterns using regex
5. **Structural analysis** → comment ratio per file, finding distribution across file
6. **package.json / requirements.txt** → audits dependencies for typosquatting and supply chain risks
7. **All files** → extracts URLs/domains and flags suspicious ones
8. **ClawHub** → optionally looks up author reputation (requires network)
9. **Generates** a scored Markdown report with findings, checklist, and recommendation

## Size Alerts

Large skills aren't just complex — they can be weaponized. A skill with 50,000 "legitimate" lines followed by 3 malicious lines at the end exploits LLM context window truncation: the AI says "SAFE" because it never read the last 30% of the file.

| Size | Alert Level | Meaning |
|------|-------------|---------|
| < 500 lines | None | Normal |
| 500–1,999 lines | ⚪ INFO | Above average — review with attention |
| 2,000–4,999 lines | 🟡 MEDIUM | Increased risk of hidden payloads |
| 5,000–9,999 lines | 🟠 HIGH | Chunked review recommended |
| ≥ 10,000 lines | 🔴 CRITICAL | Possible context window attack |

> For skills > 2,000 lines, LLM-assisted review is recommended (coming in v3.0).

## Real Malicious Skills Examples

These were removed from ClawHub:

| Skill | Attack Vector | Finding |
|-------|--------------|---------|
| `mission-control-dashboard` | Hardcoded Secret | Auth token hardcoded in script |
| `email-daily-summary` | Prompt Injection | Hidden instructions to forward emails |
| `browser-automation` | Network Exposure | CDP port exposed to all interfaces |

## The Self-Audit Paradox

When you run this tool against itself, it returns **score 11/100 (SAFE)**. The tool contains regex patterns that match malicious code signatures (like a virus scanner contains virus signatures) — but it correctly identifies them as pattern definitions, not actual threats.

### How to verify this tool is safe

1. **Read the source**: ~1,500 lines of Python. Standard library only. No obfuscation.
2. **Check what it does**: reads files, runs regex, prints a report. No network writes, no file modifications, no env access.
3. **Run it yourself**: `python3 scripts/audit.py . --no-clawhub` — review every finding and confirm they're pattern definitions, not actual threats.

The same paradox exists in every security tool: antivirus software contains virus signatures, WAFs contain attack patterns, SAST scanners contain vulnerability templates. The solution is always the same: **radical transparency**.

## Research

### Context Window Attacks

A context window attack exploits the finite memory of LLM-based analysis. By padding a skill with large amounts of legitimate-looking code, an attacker can position a malicious payload beyond the point where the LLM's attention degrades or the context truncates. The LLM reviews the "safe" portion and returns a clean verdict.

**Mitigations:**
- Automatic size alerts (v1.1 — this release)
- Chunked analysis: divide skill into 2k-token blocks, analyze each independently (v3.0 planned)
- Human review of large skills

### Intent Analysis vs Pattern Matching

Pattern matching (grep/regex) detects **what** exists. LLM intent analysis detects **why** it exists.

The same line of code can be:
- An attack: `eval(base64.b64decode(payload))` in a data-extraction skill
- A defense: `eval(base64.b64decode(payload))` in a sandboxed code-runner that's explicitly documenting this pattern

Pattern matching generates false positives. Intent analysis can distinguish context. Both are needed — pattern matching as a first fast pass, LLM as a second verification layer (v3.0 planned).

### Size as Attack Vector

Skill size alone is a signal:
- Skills designed to hide payloads tend to be artificially inflated
- Legitimate skills rarely exceed 5,000 lines (most are under 1,000)
- Unusually large skills deserve extra scrutiny regardless of other findings

### Why We Built This

824+ malicious skills were found on ClawHub in February 2026. Existing tools only did simple pattern grep — insufficient for the sophistication of modern supply chain attacks. We built this from real-world experience auditing 50+ production skills and removing 3 malicious ones.

## Roadmap

### v1.1 (current) — Pattern Matching + Size Alerts + Structural Analysis
- 6 pattern-match categories: prompt injection, malicious code, hardcoded secrets, network, dependencies, permissions
- Size alerts: 5 threshold levels (< 500 to ≥ 10,000 lines)
- Structural analysis: comment ratio, finding distribution
- Self-audit score: 11/100 SAFE
- ~1,500 lines Python, stdlib only, MIT license

### v2.0 (planned) — Ephemeral Docker Sandbox
- Zero-trust execution environment: `--rm --network none --read-only`
- Skill mounted read-only inside ephemeral container
- Container created per audit, destroyed after
- No residue on host filesystem
- Entropy analysis per file section (detect obfuscation)
- Blocking large padding blocks (repetitive content)

### v3.0 (planned) — LLM Intent Analysis with Chunked Review
- LLM of the user's choice classifies each finding:
  - **MALICIOUS** — clear intent to cause harm
  - **DEFENSIVE** — intent to protect or detect
  - **AMBIGUOUS** — could go either way
  - **BENIGN** — false positive from pattern matching
- Chunked analysis: skill divided into 2k-token blocks
  - Each block analyzed independently
  - No single block large enough to truncate
  - Attackers can't hide payloads in "dead zones"
- Model-specific confidence scores at different context lengths
- Detects "ignore previous analysis" style anti-LLM evasion in code comments

## License

MIT — free to use, modify, and redistribute.

---

*SafeClaw Security — Born from real-world experience with 50+ production skills.*
