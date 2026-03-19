---
name: skill-security-audit
description: "Use ALWAYS before installing any new skill. Automatically audits SKILL.md, scripts, dependencies, and network access. Detects prompt injection, data exfiltration, malicious code, typosquatting, supply chain attacks, and suspicious skill size. Generates a 0-100 risk score with a clear INSTALL / INSTALL WITH CAUTION / DO NOT INSTALL recommendation. Trigger on: audit skill, check skill security, is this skill safe, review skill before install, scan skill for malware, skill security check, analyze skill risk."
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

# Audit by skill name (discovers common install paths)
python3 scripts/audit.py scrapling-official

# Audit current directory
python3 scripts/audit.py .

# Skip ClawHub lookup (offline mode)
python3 scripts/audit.py /path/to/skill --no-clawhub
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

### 7. Size Analysis (NEW in v1.1)
- Total line count across all skill files
- Alerts by threshold:
  - < 500 lines: no alert
  - 500–1,999: INFO — above average size
  - 2,000–4,999: MEDIUM — increased risk of hidden payloads
  - 5,000–9,999: HIGH — chunked review recommended
  - ≥ 10,000: CRITICAL — possible context window attack
- Large skills can exploit LLM context window truncation to hide payloads in "dead zones"

### 8. Structural Analysis (NEW in v1.1)
- Comment/code ratio per file
  - > 70% comments in a code file: MEDIUM alert (may hide payloads in comments)
- Finding distribution across file
  - All findings concentrated in last 20% of file: MEDIUM alert (classic payload positioning)

## Output Format

The report is a Markdown document with:

```
# Security Audit Report: <skill-name>
Risk Score: XX/100 — LEVEL
Recommendation: INSTALL / INSTALL WITH CAUTION / DO NOT INSTALL

## Size Analysis
⚪ INFO — Above average size (600 lines)...

## Structural Analysis
✅ No structural anomalies detected.

## Findings
| Severity | Vector | Finding | File | Line |
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

## Intent Analysis (Layer 2 — LLM-powered)

When the user asks for deeper analysis, use the two-step intent pipeline.
This uses YOUR OWN model — no external API calls or API keys required.

### When to use intent analysis
- Skill has MEDIUM or higher findings and you want to separate real threats from false positives
- User explicitly asks for "intent analysis" or "deep audit"
- Findings involve `eval()`, `exec()`, `os.environ`, network access — need human-level context

### Pipeline (5 steps)

**Step 1** — Run Layer 1 audit and export findings as JSON:
```bash
python3 scripts/audit.py <skill_path> --no-clawhub --json > /tmp/findings.json
```

**Step 2** — Generate classification prompts:
```bash
python3 scripts/intent_analyzer.py \
  --generate-prompts \
  --skill-path <skill_path> \
  --findings-json /tmp/findings.json \
  > /tmp/prompts.json
```

**Step 3** — Process each prompt with YOUR model:

Read `/tmp/prompts.json`. For each item in `prompts[]`, send the `prompt` field to your LLM.
Collect responses as a JSON array (one entry per finding, in order):
```json
[
  {"intent": "DEFENSIVE", "confidence": 0.9, "reasoning": "Pattern definitions, not attack code"},
  {"intent": "UTILITY",   "confidence": 0.8, "reasoning": "Reads env var for configuration"},
  ...
]
```
Save to `/tmp/responses.json`.

**Step 4** — Run analysis with responses:
```bash
python3 scripts/intent_analyzer.py \
  --analyze \
  --skill-path <skill_path> \
  --findings-json /tmp/findings.json \
  --responses-json /tmp/responses.json \
  --model <your-model-name> \
  > /tmp/intent_report.json
```

**Step 5** — Present the combined report to the user.

### Intent labels
| Label | Meaning | Score weight |
|-------|---------|-------------|
| MALICIOUS | Deliberately harmful (data theft, backdoor, injection) | 100 |
| AMBIGUOUS | Unclear intent, could go either way | 50 |
| UTILITY | Legitimate use of sensitive pattern (config, logging) | 10 |
| DEFENSIVE | Security tool detecting threats (like antivirus) | 0 |
| FALSE_POSITIVE | Pattern matched but no actual risk | 0 |

### Combined score formula
`combined_score = intent_score × 0.67 + anti_evasion_score × 0.33`

Anti-evasion checks (each adds 25 pts):
- **padding**: >50 consecutive identical lines (context window stuffing)
- **tail_payload**: >80% of findings in last 20% of file (classic hiding spot)
- **llm_injection**: injection strings found in code files
- **obfuscated**: high-entropy blocks >200 chars (base64/hex payloads)

### Supported model names for `--model`
`opus`, `sonnet`, `haiku`, `gemini-pro`, `gemini-flash`, `gpt-4o`, `deepseek`, `llama-70b`, `unknown`

---

## Roadmap

### v1.1 — Pattern Matching + Size + Structural
- 6 pattern categories + size alerts + structural analysis
- Python stdlib only, MIT license
- Self-audit score: ~22/100 SAFE

### v2.0 (planned) — Ephemeral Docker Sandbox
- Zero-trust execution: `--rm --network none --read-only`
- Skill mounted read-only, container dies after audit
- No residue on host
- Entropy analysis per section (detect obfuscation)

### v3.0 (current) — LLM Intent Analysis
- Uses the agent's own LLM — zero external API dependencies
- Two-step pipeline: generate-prompts → agent processes → analyze responses
- Anti-evasion: padding, tail payload, LLM injection, obfuscation detection
- Model confidence scoring table
- Combined score: intent (67%) + anti-evasion (33%)

## Implementation Notes

The script (`scripts/audit.py`) uses only Python stdlib: `os`, `re`, `sys`, `pathlib`, `json`, `base64`, `urllib`. No external dependencies required. Works fully offline except for the optional ClawHub author lookup (uses `urllib` to query public ClawHub API).
