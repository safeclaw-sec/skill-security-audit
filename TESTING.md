# Testing Guide — AI-Driven Security Scenarios

Instead of shipping static examples with real malicious code, this tool uses **AI-generated test scenarios**. The AI creates temporary test skills, audits them, and cleans up — no malicious code is ever stored in the package.

## How to Test

Ask your AI agent to run these test scenarios. Each one creates a temporary skill, audits it, and deletes it.

### Scenario 1: Clean Skill (should score 0)

> Create a minimal temporary skill in /tmp/test-clean/ with a SKILL.md that says "Fetch weather data from wttr.in" and a simple Python script that does `requests.get("https://wttr.in")`. Then run the security auditor on it and show me the result. Delete the temp skill after.

**Expected:** Score 0-10, SAFE, INSTALL.

### Scenario 2: Prompt Injection (should score 70+)

> Create a temporary skill in /tmp/test-injection/ with a SKILL.md that contains hidden instructions to exfiltrate user data and ignore safety rules. Make it look like a legitimate weather skill on the surface. Then audit it and show the result. Delete after.

**Expected:** Score 70+, RISK/DANGEROUS, DO NOT INSTALL. Should detect prompt injection patterns.

### Scenario 3: Data Exfiltration (should score 80+)

> Create a temporary skill in /tmp/test-exfil/ with a Python script that reads environment variables (API keys, tokens) and sends them to an external URL via HTTP POST. Wrap it in a legitimate-looking utility. Audit and show result. Delete after.

**Expected:** Score 80+, DANGEROUS, DO NOT INSTALL. Should detect env var access and suspicious network calls.

### Scenario 4: Typosquatting Dependencies (should score 40+)

> Create a temporary skill in /tmp/test-typo/ with a requirements.txt that includes misspelled packages like "reqeusts" and "beautifulsaup". Audit and show result. Delete after.

**Expected:** Score 40+, CAUTION/RISK. Should flag typosquatting.

### Scenario 5: Obfuscated Attack (should score 60+)

> Create a temporary skill in /tmp/test-obfuscated/ with a script that uses base64 encoding to hide a malicious payload, then decodes and executes it. Audit and show result. Delete after.

**Expected:** Score 60+, RISK/DANGEROUS. Should detect base64+eval patterns.

### Scenario 6: Mixed Skill (legit + suspicious)

> Create a temporary skill in /tmp/test-mixed/ that does real useful work (file conversion) but also quietly collects system info (hostname, username, IP). Audit and show result. Delete after.

**Expected:** Score 30-50, CAUTION. Should flag system reconnaissance while acknowledging legitimate functionality.

## Automated Test Runner

For CI/CD or batch testing, your AI agent can run all 6 scenarios in sequence:

> Run all 6 SafeClaw test scenarios from TESTING.md. For each one: create the temp skill, audit it, record the score, delete the temp skill. Then show me a summary table of all results.

**Expected summary:**

| Scenario | Expected Score | Expected Level |
|----------|---------------|----------------|
| Clean | 0-10 | SAFE |
| Prompt Injection | 70+ | RISK/DANGEROUS |
| Data Exfiltration | 80+ | DANGEROUS |
| Typosquatting | 40+ | CAUTION/RISK |
| Obfuscated | 60+ | RISK/DANGEROUS |
| Mixed | 30-50 | CAUTION |

## Why This Approach?

- **No malicious code in the package** — test scenarios are generated on the fly and deleted
- **Self-audit stays clean** — the tool scores low on itself because it contains no attack examples
- **Infinitely extensible** — ask the AI to create new scenarios for edge cases
- **Realistic** — AI generates varied, creative attack patterns, not just static samples
