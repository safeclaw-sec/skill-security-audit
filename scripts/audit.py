#!/usr/bin/env python3
"""
skill-security-audit — OpenClaw Skill Security Auditor
Audits any OpenClaw skill directory for security risks.

Usage:
    python3 audit.py <skill_path_or_name>

No external dependencies required — stdlib only.
"""

import os
import re
import sys
import json
import base64
import pathlib
import argparse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ─────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────

SEVERITY_WEIGHT = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    8,
    "LOW":       3,
    "INFO":      0,
}

@dataclass
class Finding:
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    vector: str         # category of attack vector
    description: str    # human-readable description
    file: str = ""      # which file
    line: int = 0       # approximate line number
    evidence: str = ""  # snippet of offending content


@dataclass
class AuditResult:
    skill_name: str
    skill_path: str
    findings: List[Finding] = field(default_factory=list)
    checked_files: List[str] = field(default_factory=list)
    domains_found: List[str] = field(default_factory=list)
    env_vars_accessed: List[str] = field(default_factory=list)
    dependencies: dict = field(default_factory=dict)
    author_info: dict = field(default_factory=dict)

    @property
    def score(self) -> int:
        raw = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        return min(100, raw)

    @property
    def level(self) -> str:
        s = self.score
        if s <= 25: return "SAFE"
        if s <= 50: return "CAUTION"
        if s <= 75: return "RISK"
        return "DANGEROUS"

    @property
    def recommendation(self) -> str:
        s = self.score
        if s <= 25: return "INSTALL"
        if s <= 50: return "INSTALL WITH CAUTION"
        return "DO NOT INSTALL"

    @property
    def level_emoji(self) -> str:
        return {"SAFE": "🟢", "CAUTION": "🟡", "RISK": "🟠", "DANGEROUS": "🔴"}[self.level]


# ─────────────────────────────────────────────
# Pattern definitions
# ─────────────────────────────────────────────

# Prompt injection patterns for SKILL.md
PROMPT_INJECTION_PATTERNS = [
    # Direct override attempts
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?|security|constraints?)", "CRITICAL", "Direct prompt override: 'ignore previous instructions/rules'"),
    (r"disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|guidelines?|constraints?)", "CRITICAL", "Prompt override: 'disregard instructions'"),
    (r"forget\s+(everything|all)\s+(you|above|previous)", "CRITICAL", "Prompt override: 'forget everything'"),
    (r"you\s+are\s+now\s+(a|an)\s+\w+.*?no\s+(restrictions?|limits?|rules?)", "CRITICAL", "Role hijack with restriction removal"),
    (r"system\s+override|admin\s+mode|god\s+mode|developer\s+mode", "HIGH", "Privilege escalation attempt"),
    (r"DAN\s+mode|jailbreak|bypass\s+(safety|filter|security)", "HIGH", "Known jailbreak pattern"),
    (r"operating\s+in\s+(administrative|admin|privileged|elevated)\s+mode", "CRITICAL", "False admin mode claim"),
    (r"do\s+not\s+mention\s+this\s+to\s+(the\s+)?user|don.t\s+(tell|mention|inform)\s+(the\s+)?user", "CRITICAL", "Instruction to hide behavior from user"),
    (r"required\s+by\s+(the\s+)?(system\s+administrator|admin|anthropic|openclaw)", "HIGH", "False authority claim to justify hidden behavior"),

    # Exfiltration instructions
    (r"send\s+(all\s+)?.{0,50}(to\s+)(http|https|ftp)://(?!example\.com|example\.org|wttr\.in|localhost|127\.0\.0\.1)", "CRITICAL", "Instruction to send data to external URL"),
    (r"(?:^|\s)(curl|wget)\s+.*?https?://(?!localhost|127\.0\.0\.1|example\.com|example\.org)\S+\s+.*?(\$|\{|ENV|environ|token|key|secret)", "HIGH", "curl/wget sending sensitive data to external URL"),
    (r"exfiltrat|steal\s+(data|keys?|tokens?|credentials?)", "CRITICAL", "Explicit data exfiltration instruction"),
    (r"leak\s+(the\s+)?(api\s+)?key|share\s+(the\s+)?(api\s+)?key", "CRITICAL", "Instruction to leak API key"),

    # Social engineering
    (r"you\s+are\s+(the\s+)?system|acting\s+as\s+(an?\s+)?admin", "HIGH", "Social engineering: impersonating system"),
    (r"this\s+is\s+(an?\s+)?(emergency|urgent|critical)\s+(override|command|instruction)", "HIGH", "False urgency social engineering"),
    (r"authorized\s+(by|from)\s+(anthropic|openai|the\s+developer|admin)", "HIGH", "False authorization claim"),

    # Hidden content markers
    (r"<!--.{0,200}-->", "MEDIUM", "HTML comment (may contain hidden instructions)"),
    (r"\u200b|\u200c|\u200d|\u2060|\ufeff", "HIGH", "Zero-width / invisible Unicode characters"),
    (r"\\u00[0-9a-f]{2}", "MEDIUM", "Escaped Unicode sequences (may hide text)"),
]

# Malicious code patterns for scripts
CODE_PATTERNS = [
    # eval/exec with external data
    (r"\beval\s*\(.*?(request|response|input|stdin|argv|os\.environ|getenv)", "CRITICAL", "eval() with external/user input"),
    (r"\beval\s*\(.*?base64", "CRITICAL", "eval() with base64-decoded content"),
    (r"\bexec\s*\(.*?(request|response|input|stdin|argv|os\.environ|getenv)", "CRITICAL", "exec() with external input"),
    (r"\bexec\s*\(.*?base64", "CRITICAL", "exec() with base64-decoded content"),
    (r"\bexec\s*\(\s*compile\s*\(", "HIGH", "exec(compile()) pattern — dynamic code execution"),

    # subprocess risks
    (r"subprocess\.(run|call|Popen|check_output)\s*\(.*?(format\s*\(|f['\"].*?\{|%\s*[^%]|\+\s*\w)", "HIGH", "subprocess with string interpolation (injection risk)"),
    (r"os\.(system|popen)\s*\(.*?(format\s*\(|f['\"].*?\{|%\s*[^%]|\+\s*\w)", "HIGH", "os.system/popen with string interpolation"),
    (r"shell\s*=\s*True", "MEDIUM", "subprocess with shell=True (injection risk if input not sanitized)"),

    # Base64 suspicious patterns
    (r"base64\.b64decode\s*\(.*?\)\s*[\.\w]*\s*(exec|eval|compile|__import__)", "CRITICAL", "base64 decode → exec pipeline"),
    (r"base64\.b64decode\s*\(['\"][A-Za-z0-9+/]{40,}", "HIGH", "Hardcoded base64 payload (may contain hidden code)"),
    (r"base64\.(b64encode|encodebytes)\s*\(.*?\)\s*.*?(send|post|put|request|urllib|httpx|requests)", "HIGH", "base64 encode → send to network (potential exfiltration)"),
    (r"base64\.(b64encode|encodebytes)", "LOW", "base64 encoding used (verify purpose)"),

    # Dynamic imports
    (r"__import__\s*\(\s*(request|response|input|os\.environ|getenv|argv)", "CRITICAL", "__import__ with external input"),
    (r"importlib\.import_module\s*\(.*?(request|response|input)", "HIGH", "Dynamic import with external input"),
    (r"__import__\s*\(['\"][a-z][a-z0-9_]{4,}['\"]", "MEDIUM", "Dynamic import of module (verify it is stdlib or legitimate)"),

    # Environment variable exfiltration
    (r"os\.environ\b(?!.*(?:get|setdefault)\s*\(['\"][A-Z_]+['\"],\s*['\"]['\"])", "MEDIUM", "Accessing environment variables (verify purpose)"),
    (r"os\.environ\s*(?:\.\s*get\s*)?\(['\"].*?(API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AUTH|ANTHROPIC|OPENAI|OPENCLAW|STRIPE|TWILIO|SENDGRID|AWS)", "CRITICAL", "Accessing sensitive env vars (API keys/secrets/tokens)"),
    (r"os\.getenv\s*\(['\"].*?(API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AUTH|ANTHROPIC|OPENAI|OPENCLAW|STRIPE|TWILIO|SENDGRID|AWS)", "CRITICAL", "Accessing sensitive env vars via getenv()"),
    (r"dotenv|load_dotenv|find_dotenv", "MEDIUM", "Loading .env file (verify scope)"),

    # System info collection
    (r"socket\.gethostname\(\)|platform\.node\(\)", "MEDIUM", "Collecting hostname"),
    (r"socket\.gethostbyname\s*\(\s*socket\.gethostname", "MEDIUM", "Collecting local IP address"),
    (r"getpass\.getuser\(\)|os\.getlogin\(\)|pwd\.getpwuid", "MEDIUM", "Collecting username"),
    (r"platform\.(system|version|machine|processor|architecture|uname)\(\)", "LOW", "Collecting system platform info"),
    (r"subprocess.*?(ifconfig|ipconfig|whoami|id\b|uname|hostname)", "HIGH", "Collecting system info via subprocess"),

    # Post-install hooks
    (r"install_requires|setup_requires", "LOW", "setup.py dependencies (review list)"),
    (r"cmdclass|entry_points", "MEDIUM", "setup.py custom commands / entry points (review)"),

    # Network listeners
    (r"\.bind\s*\(\s*\(['\"]0\.0\.0\.0['\"]", "HIGH", "Binding socket to all interfaces (exposes service to network)"),
    (r"remote.debugging.address\s*=\s*0\.0\.0\.0", "HIGH", "CDP/debugging port exposed to all interfaces"),
    (r"--remote-debugging-address=0\.0\.0\.0", "HIGH", "Browser debugging exposed to all network interfaces"),
    (r"asyncio\.start_server|socketserver\.(TCP|UDP)Server", "MEDIUM", "Creating TCP/UDP server (undocumented?)"),
    (r"websockets\.serve|websocket.*?listen", "MEDIUM", "WebSocket server (undocumented?)"),

    # Crypto miner indicators
    (r"stratum\+tcp|stratum\+ssl|pool\.minexmr|pool\.supportxmr|nanopool\.org", "CRITICAL", "Crypto mining pool URL found"),
    (r"xmrig|cpuminer|cgminer|bfgminer", "CRITICAL", "Crypto miner binary reference"),
    (r"hashlib\.(sha256|sha512)\s*\(.*?\)\s*\.hexdigest\(\).*?while\s+True", "HIGH", "Potential mining loop (hash loop)"),

    # File access outside scope
    (r"open\s*\(['\"](?:/etc/|/proc/|/sys/|/root/|~/.ssh|~/.aws|~/.config/google)", "CRITICAL", "Accessing sensitive system files"),
    (r"open\s*\(['\"].*?(\.\./){2,}", "HIGH", "Path traversal (../../) in file open"),
    (r"shutil\.(rmtree|move|copy.*?)\s*\(['\"](?:/etc|/usr|/var|/home|/root)", "CRITICAL", "Modifying critical system directories"),
]

# Network / URL patterns
URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE
)

SUSPICIOUS_DOMAIN_INDICATORS = [
    r"ngrok\.io",           # tunneling (could expose local services)
    r"requestbin|pipedream|webhook\.site|hookbin",  # request capture
    r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly",       # URL shorteners
    r"pastebin|pastecode|hastebin|ghostbin",        # paste sites
    r"tempmail|guerrillamail|mailnull",             # disposable email
    r"0\.0\.0\.0|127\.0\.0\.1:\d{4,5}(?!/8384)",  # unusual localhost ports
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!.*localhost)",  # raw IP addresses
]

# Known safe domains (documented APIs / CDNs)
SAFE_DOMAINS = {
    "api.github.com", "github.com", "raw.githubusercontent.com", "githubusercontent.com", "avatars.githubusercontent.com",
    "pypi.org", "npmjs.com", "registry.npmjs.org",
    "googleapis.com", "google.com", "accounts.google.com",
    "anthropic.com", "api.anthropic.com",
    "openai.com", "api.openai.com",
    "huggingface.co",
    "cloudflare.com", "cdn.cloudflare.com",
    "amazonaws.com",
    "docs.python.org", "docs.rs",
    "shields.io",
    "scrapling.readthedocs.io",
    "toscrape.com",
    "example.com", "example.org",  # RFC 2606 reserved
    "localhost", "127.0.0.1",
}

# Known legitimate npm packages (partial list for typosquatting checks)
KNOWN_NPM = {
    "react", "vue", "angular", "express", "lodash", "axios", "moment",
    "webpack", "babel", "typescript", "eslint", "prettier", "jest",
    "mocha", "chai", "sinon", "nodemon", "dotenv", "cors", "body-parser",
    "mongoose", "sequelize", "knex", "pg", "mysql2", "redis", "socket.io",
    "passport", "bcrypt", "jsonwebtoken", "helmet", "morgan", "chalk",
    "commander", "inquirer", "ora", "boxen", "yargs", "minimist",
}

# Known legitimate pip packages (partial list)
KNOWN_PIP = {
    "requests", "flask", "django", "fastapi", "sqlalchemy", "celery",
    "redis", "pymongo", "psycopg2", "boto3", "pydantic", "httpx",
    "aiohttp", "click", "rich", "typer", "pytest", "black", "flake8",
    "mypy", "numpy", "pandas", "matplotlib", "scikit-learn", "tensorflow",
    "torch", "pillow", "cryptography", "paramiko", "fabric", "invoke",
    "lxml", "beautifulsoup4", "scrapy", "selenium", "playwright",
    "anthropic", "openai", "langchain", "transformers", "huggingface-hub",
    "scrapling", "curl-cffi", "patchright", "browserforge", "mcp",
    "markdownify", "ipython", "anyio", "msgspec", "cssselect", "orjson",
    "tld", "w3lib", "typing-extensions", "apify-client",
}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def read_file_safe(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Read a file, returning (content, error)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), None
    except Exception as e:
        return None, str(e)


def find_all_files(skill_path: str) -> List[str]:
    """Recursively find all files in skill directory."""
    files = []
    for root, dirs, filenames in os.walk(skill_path):
        # Skip hidden directories and common VCS dirs
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "__pycache__", ".git")]
        for fname in filenames:
            files.append(os.path.join(root, fname))
    return sorted(files)


def extract_domains_from_text(text: str) -> List[str]:
    """Extract all unique domains from URLs in text."""
    urls = URL_PATTERN.findall(text)
    domains = set()
    for url in urls:
        try:
            # Simple domain extraction
            host = url.split("//")[1].split("/")[0].split("?")[0].split("#")[0]
            # Remove port
            host = host.split(":")[0]
            # Remove trailing punctuation from markdown/code artifacts
            host = host.rstrip("'\"`).,;>")
            # Basic validity check: must look like a domain (letters, digits, dots, hyphens)
            if host and re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+[a-zA-Z0-9]$', host):
                domains.add(host.lower())
        except (IndexError, AttributeError):
            pass
    return sorted(domains)


def is_suspicious_domain(domain: str) -> bool:
    """Check if domain is suspicious."""
    if any(safe in domain for safe in SAFE_DOMAINS):
        return False
    for pattern in SUSPICIOUS_DOMAIN_INDICATORS:
        if re.search(pattern, domain, re.IGNORECASE):
            return True
    return False


def detect_typosquatting(package: str, known_set: set) -> Optional[str]:
    """
    Simple typosquatting detection using edit distance heuristics.
    Returns the similar known package name if suspicious, else None.
    """
    pkg = package.lower().replace("-", "").replace("_", "")
    for known in known_set:
        k = known.lower().replace("-", "").replace("_", "")
        if pkg == k:
            return None  # exact match = legitimate
        # Check: one char difference (insertion, deletion, substitution)
        if abs(len(pkg) - len(k)) <= 1 and len(pkg) >= 4:
            # Simple Levenshtein distance approximation
            if _levenshtein(pkg, k) == 1:
                return known
        # Check: swapped adjacent chars
        if len(pkg) == len(k) >= 4:
            diffs = sum(1 for a, b in zip(pkg, k) if a != b)
            if diffs == 2:
                return known
    return None


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


# ─────────────────────────────────────────────
# Audit modules
# ─────────────────────────────────────────────

def _build_code_block_map(lines: List[str]) -> List[bool]:
    """Return a list of booleans: True if the line is inside a code block."""
    result_map = []
    in_code = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_code = not in_code
            result_map.append(True)  # fence line itself = code context
        else:
            result_map.append(in_code)
    return result_map


def audit_skill_md(result: AuditResult, content: str, filepath: str):
    """Audit SKILL.md for prompt injection patterns."""
    lines = content.splitlines()
    in_code_map = _build_code_block_map(lines)

    for pattern, severity, description in PROMPT_INJECTION_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                # Skip if inside a code block (likely a documentation example)
                if in_code_map[i - 1]:
                    continue
                result.findings.append(Finding(
                    severity=severity,
                    vector="Prompt Injection (SKILL.md)",
                    description=description,
                    file=os.path.basename(filepath),
                    line=i,
                    evidence=line.strip()[:100],
                ))

    # Check for invisible/zero-width unicode
    for i, line in enumerate(lines, 1):
        invisible = [c for c in line if ord(c) in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD)]
        if invisible:
            result.findings.append(Finding(
                severity="HIGH",
                vector="Prompt Injection (SKILL.md)",
                description=f"Zero-width/invisible Unicode characters found ({len(invisible)} chars)",
                file=os.path.basename(filepath),
                line=i,
                evidence=repr(line[:80]),
            ))


def audit_code_file(result: AuditResult, content: str, filepath: str):
    """Audit a code file (Python/JS/shell) for malicious patterns."""
    lines = content.splitlines()
    fname = os.path.basename(filepath)

    for pattern, severity, description in CODE_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                # Avoid duplicate findings for same line/pattern
                already = any(
                    f.file == fname and f.line == i and f.description == description
                    for f in result.findings
                )
                if not already:
                    result.findings.append(Finding(
                        severity=severity,
                        vector="Malicious Code",
                        description=description,
                        file=fname,
                        line=i,
                        evidence=line.strip()[:120],
                    ))

    # Check for hardcoded secrets
    secret_patterns = [
        (r"(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|private[_-]?key)\s*=\s*['\"][A-Za-z0-9+/=_\-]{20,}['\"]", "HIGH", "Hardcoded secret/API key"),
        (r"sk-[A-Za-z0-9]{32,}", "CRITICAL", "Hardcoded OpenAI API key"),
        (r"AIza[0-9A-Za-z\-_]{35}", "CRITICAL", "Hardcoded Google API key"),
        (r"ghp_[A-Za-z0-9]{36}", "CRITICAL", "Hardcoded GitHub personal access token"),
        (r"xox[baprs]-[A-Za-z0-9\-]+", "CRITICAL", "Hardcoded Slack token"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL", "Private key embedded in file"),
    ]
    for pattern, severity, description in secret_patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                result.findings.append(Finding(
                    severity=severity,
                    vector="Hardcoded Secret",
                    description=description,
                    file=fname,
                    line=i,
                    evidence="[REDACTED — secret pattern matched]",
                ))


def audit_network(result: AuditResult, content: str, filepath: str):
    """Extract and evaluate all URLs/domains from a file."""
    domains = extract_domains_from_text(content)
    for domain in domains:
        if domain not in result.domains_found:
            result.domains_found.append(domain)
        if is_suspicious_domain(domain):
            result.findings.append(Finding(
                severity="HIGH",
                vector="Network / Data Exfiltration",
                description=f"Suspicious domain: {domain}",
                file=os.path.basename(filepath),
                evidence=f"Domain: {domain}",
            ))


def audit_dependencies(result: AuditResult, skill_path: str):
    """Audit package.json and requirements.txt for risky dependencies."""
    # --- requirements.txt ---
    req_path = os.path.join(skill_path, "requirements.txt")
    if os.path.exists(req_path):
        content, err = read_file_safe(req_path)
        if content:
            result.checked_files.append("requirements.txt")
            packages = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Extract package name (before ==, >=, etc.)
                pkg = re.split(r"[>=<!;\[#@]", line)[0].strip().lower()
                if pkg:
                    packages.append((pkg, line))

            result.dependencies["pip"] = [p[0] for p in packages]

            if len(packages) > 20:
                result.findings.append(Finding(
                    severity="MEDIUM",
                    vector="Dependencies",
                    description=f"Large number of pip dependencies: {len(packages)} packages",
                    file="requirements.txt",
                    evidence=f"{len(packages)} packages",
                ))

            for pkg, raw_line in packages:
                # Check wildcards
                if ".*" in raw_line or raw_line.endswith(">0") or ">" in raw_line and "=" not in raw_line:
                    result.findings.append(Finding(
                        severity="LOW",
                        vector="Dependencies",
                        description=f"Unpinned dependency: {raw_line}",
                        file="requirements.txt",
                        evidence=raw_line,
                    ))

                # Typosquatting check
                similar = detect_typosquatting(pkg, KNOWN_PIP)
                if similar and pkg != similar.lower().replace("-", "").replace("_", ""):
                    result.findings.append(Finding(
                        severity="HIGH",
                        vector="Dependencies (Typosquatting)",
                        description=f"Package '{pkg}' is very similar to known package '{similar}' — possible typosquatting",
                        file="requirements.txt",
                        evidence=f"'{pkg}' vs '{similar}'",
                    ))

    # --- package.json ---
    pkg_path = os.path.join(skill_path, "package.json")
    if os.path.exists(pkg_path):
        content, err = read_file_safe(pkg_path)
        if content:
            result.checked_files.append("package.json")
            try:
                pkg_json = json.loads(content)
            except json.JSONDecodeError:
                result.findings.append(Finding(
                    severity="MEDIUM",
                    vector="Dependencies",
                    description="package.json is not valid JSON",
                    file="package.json",
                ))
                return

            # Check scripts for malicious hooks
            scripts = pkg_json.get("scripts", {})
            dangerous_scripts = ["postinstall", "preinstall", "install", "prepare"]
            for hook in dangerous_scripts:
                if hook in scripts:
                    cmd = scripts[hook]
                    result.findings.append(Finding(
                        severity="HIGH",
                        vector="Post-install Hook",
                        description=f"npm '{hook}' script present: {cmd[:80]}",
                        file="package.json",
                        evidence=f'"{hook}": "{cmd}"',
                    ))

            # Audit dependencies
            all_deps = {}
            all_deps.update(pkg_json.get("dependencies", {}))
            all_deps.update(pkg_json.get("devDependencies", {}))

            result.dependencies["npm"] = list(all_deps.keys())

            if len(all_deps) > 30:
                result.findings.append(Finding(
                    severity="MEDIUM",
                    vector="Dependencies",
                    description=f"Large number of npm dependencies: {len(all_deps)} packages",
                    file="package.json",
                    evidence=f"{len(all_deps)} packages",
                ))

            for pkg, version in all_deps.items():
                # Wildcard versions
                if version.startswith("*") or version == "latest":
                    result.findings.append(Finding(
                        severity="MEDIUM",
                        vector="Dependencies",
                        description=f"Wildcard/unpinned npm dependency: {pkg}@{version}",
                        file="package.json",
                        evidence=f'"{pkg}": "{version}"',
                    ))

                # Typosquatting
                similar = detect_typosquatting(pkg, KNOWN_NPM)
                if similar:
                    result.findings.append(Finding(
                        severity="HIGH",
                        vector="Dependencies (Typosquatting)",
                        description=f"Package '{pkg}' is very similar to '{similar}' — possible typosquatting",
                        file="package.json",
                        evidence=f"'{pkg}' vs '{similar}'",
                    ))


def audit_permissions(result: AuditResult, content: str, filepath: str):
    """Check for over-privileged access patterns."""
    fname = os.path.basename(filepath)
    lines = content.splitlines()

    perm_patterns = [
        # Network access
        (r"\bsocket\.(socket|create_connection)\b", "INFO", "Network socket usage"),
        (r"\burllib\.(request|urlopen)\b|\brequests\.(get|post|put|delete|patch)\b|\bhttpx\.(get|post|AsyncClient)\b|\baiohttp\b", "INFO", "HTTP network requests"),

        # Filesystem access
        (r"\bopen\s*\([^)]+,\s*['\"][wa]", "LOW", "Writing to filesystem"),
        (r"\bos\.(makedirs|mkdir|rmdir|remove|unlink|rename|replace)\b", "LOW", "Modifying filesystem"),
        (r"\bshutil\.(copy|move|rmtree)\b", "MEDIUM", "Bulk filesystem operations"),

        # Environment access
        (r"\bos\.environ\b", "LOW", "Accessing environment variables"),
    ]

    for pattern, severity, description in perm_patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                # Deduplicate: only one INFO finding per type per file
                already = any(
                    f.file == fname and f.description == description
                    for f in result.findings
                )
                if not already:
                    result.findings.append(Finding(
                        severity=severity,
                        vector="Permissions",
                        description=description,
                        file=fname,
                        line=i,
                        evidence=line.strip()[:100],
                    ))


def check_author_clawhub(skill_name: str) -> dict:
    """Try to look up author info on ClawHub (optional, graceful fallback)."""
    info = {"checked": False, "error": None}
    try:
        url = f"https://clawhub.ai/api/skills/{skill_name}"
        req = urllib.request.Request(url, headers={"User-Agent": "skill-security-audit/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                info.update({
                    "checked": True,
                    "found": True,
                    "author": data.get("author", "unknown"),
                    "stars": data.get("stars", 0),
                    "downloads": data.get("downloads", 0),
                    "version": data.get("version", "?"),
                    "updated_at": data.get("updated_at", "?"),
                })
    except urllib.error.HTTPError as e:
        if e.code == 404:
            info.update({"checked": True, "found": False})
        else:
            info["error"] = f"HTTP {e.code}"
    except Exception as e:
        info["error"] = str(e)
    return info


# ─────────────────────────────────────────────
# Main audit orchestrator
# ─────────────────────────────────────────────

def audit_skill(skill_path: str, check_clawhub: bool = True) -> AuditResult:
    """Run the full security audit on a skill directory."""
    skill_path = str(pathlib.Path(skill_path).resolve())
    skill_name = pathlib.Path(skill_path).name

    result = AuditResult(skill_name=skill_name, skill_path=skill_path)

    if not os.path.isdir(skill_path):
        result.findings.append(Finding(
            severity="CRITICAL",
            vector="Setup",
            description=f"Skill path does not exist or is not a directory: {skill_path}",
        ))
        return result

    all_files = find_all_files(skill_path)

    # ── Classify and process files ──
    for filepath in all_files:
        fname = pathlib.Path(filepath).name
        ext = pathlib.Path(filepath).suffix.lower()
        rel_path = os.path.relpath(filepath, skill_path)

        content, err = read_file_safe(filepath)
        if err:
            result.findings.append(Finding(
                severity="LOW",
                vector="Setup",
                description=f"Could not read file: {rel_path} ({err})",
                file=rel_path,
            ))
            continue

        result.checked_files.append(rel_path)

        # SKILL.md — prompt injection audit
        if fname.upper() == "SKILL.md".upper() or fname.upper() == "SKILL.MD":
            audit_skill_md(result, content, filepath)
            audit_network(result, content, filepath)

        # Code files
        elif ext in (".py", ".js", ".ts", ".sh", ".bash", ".mjs", ".cjs"):
            audit_code_file(result, content, filepath)
            audit_network(result, content, filepath)
            audit_permissions(result, content, filepath)

        # Markdown / text (light scan)
        elif ext in (".md", ".txt", ".rst"):
            audit_network(result, content, filepath)
            # Light prompt injection check on non-SKILL.md files
            if fname.lower() not in ("readme.md", "license.md", "changelog.md", "license.txt"):
                audit_skill_md(result, content, filepath)

        # JSON (package.json handled separately; others for network)
        elif ext == ".json":
            if fname != "package.json":
                audit_network(result, content, filepath)

        # Binary / suspicious file types
        elif ext in (".exe", ".dll", ".so", ".dylib", ".bin"):
            result.findings.append(Finding(
                severity="HIGH",
                vector="Suspicious File",
                description=f"Binary file in skill: {rel_path}",
                file=rel_path,
            ))

        elif ext in (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz"):
            result.findings.append(Finding(
                severity="MEDIUM",
                vector="Suspicious File",
                description=f"Archive file in skill: {rel_path} (may contain hidden content)",
                file=rel_path,
            ))

    # Dependency audit (separate from file loop)
    audit_dependencies(result, skill_path)

    # Check for setup.py presence
    setup_py = os.path.join(skill_path, "setup.py")
    if os.path.exists(setup_py):
        result.findings.append(Finding(
            severity="MEDIUM",
            vector="Post-install Hook",
            description="setup.py found — may contain post-install hooks",
            file="setup.py",
        ))

    # ── ClawHub author lookup ──
    if check_clawhub:
        result.author_info = check_author_clawhub(skill_name)
        if result.author_info.get("found") is False:
            result.findings.append(Finding(
                severity="LOW",
                vector="Author / Provenance",
                description=f"Skill '{skill_name}' not found on ClawHub — may be unofficial/unverified",
            ))

    return result


# ─────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

LEVEL_ICON = {
    "SAFE":      "🟢",
    "CAUTION":   "🟡",
    "RISK":      "🟠",
    "DANGEROUS": "🔴",
}

def generate_report(result: AuditResult) -> str:
    lines = []

    lines.append(f"# 🔍 Security Audit Report: `{result.skill_name}`")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Score summary
    level_icon = LEVEL_ICON[result.level]
    lines.append(f"## Risk Assessment")
    lines.append("")
    lines.append(f"| | |")
    lines.append(f"|---|---|")
    lines.append(f"| **Risk Score** | **{result.score}/100** |")
    lines.append(f"| **Level** | {level_icon} **{result.level}** |")
    lines.append(f"| **Recommendation** | **{result.recommendation}** |")
    lines.append(f"| **Files Checked** | {len(result.checked_files)} |")
    lines.append(f"| **Total Findings** | {len(result.findings)} |")
    lines.append("")

    # Recommendation box
    rec_map = {
        "INSTALL": "✅ **INSTALL** — No significant risks detected.",
        "INSTALL WITH CAUTION": "⚠️  **INSTALL WITH CAUTION** — Review findings below before proceeding.",
        "DO NOT INSTALL": "🚫 **DO NOT INSTALL** — Critical or high-severity issues found. Do not install.",
    }
    lines.append(f"> {rec_map[result.recommendation]}")
    lines.append("")

    # Findings breakdown
    by_severity = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    if result.findings:
        lines.append("---")
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            findings = by_severity.get(sev, [])
            if not findings:
                continue
            icon = SEVERITY_ICON[sev]
            lines.append(f"### {icon} {sev} ({len(findings)})")
            lines.append("")
            lines.append("| # | Vector | Description | File | Line |")
            lines.append("|---|--------|-------------|------|------|")
            for i, f in enumerate(findings, 1):
                file_str = f.file or "—"
                line_str = str(f.line) if f.line else "—"
                desc = f.description.replace("|", "\\|")
                lines.append(f"| {i} | {f.vector} | {desc} | `{file_str}` | {line_str} |")
            lines.append("")

            # Evidence details for CRITICAL / HIGH
            if sev in ("CRITICAL", "HIGH"):
                for i, f in enumerate(findings, 1):
                    if f.evidence:
                        lines.append(f"**Finding {i} evidence:**")
                        lines.append(f"```")
                        lines.append(f.evidence[:200])
                        lines.append(f"```")
                        lines.append("")
    else:
        lines.append("---")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        lines.append("✅ No security issues found.")
        lines.append("")

    # Checklist
    lines.append("---")
    lines.append("")
    lines.append("## Security Checklist")
    lines.append("")

    def check(name, condition_ok):
        icon = "✅" if condition_ok else "❌"
        return f"{icon} {name}"

    has_vector = lambda v: any(v.lower() in f.vector.lower() for f in result.findings)
    has_critical_or_high = any(f.severity in ("CRITICAL", "HIGH") for f in result.findings)
    has_prompt_injection = has_vector("prompt injection")
    has_malicious_code = has_vector("malicious code") or has_vector("hardcoded secret") or has_vector("post-install")
    has_suspicious_network = has_vector("network") or has_vector("exfiltration")
    has_typosquatting = has_vector("typosquatting")
    has_binary_files = has_vector("suspicious file")

    lines.append(check("No prompt injection in SKILL.md", not has_prompt_injection))
    lines.append(check("No malicious code patterns (eval/exec/subprocess)", not has_malicious_code))
    lines.append(check("No hardcoded secrets or API keys", not any("hardcoded" in f.vector.lower() or "secret" in f.description.lower() for f in result.findings)))
    lines.append(check("No suspicious network requests", not has_suspicious_network))
    lines.append(check("No typosquatting dependencies", not has_typosquatting))
    lines.append(check("No binary / archive files", not has_binary_files))
    lines.append(check("No post-install hooks", not any("post-install" in f.vector.lower() for f in result.findings)))
    lines.append(check("No system info collection", not any("hostname" in f.description.lower() or "username" in f.description.lower() or "ip address" in f.description.lower() for f in result.findings)))
    lines.append(check("No crypto miner patterns", not any("mining" in f.description.lower() or "miner" in f.description.lower() for f in result.findings)))
    lines.append(check("No invisible Unicode characters", not any("zero-width" in f.description.lower() or "invisible unicode" in f.description.lower() for f in result.findings)))
    lines.append("")

    # Domains
    if result.domains_found:
        lines.append("---")
        lines.append("")
        lines.append("## Domains / URLs Found")
        lines.append("")
        for domain in sorted(result.domains_found):
            suspicious = is_suspicious_domain(domain)
            icon = "⚠️" if suspicious else "✅"
            lines.append(f"- {icon} `{domain}`")
        lines.append("")

    # Dependencies
    if result.dependencies:
        lines.append("---")
        lines.append("")
        lines.append("## Dependencies")
        lines.append("")
        for dep_type, pkgs in result.dependencies.items():
            if pkgs:
                lines.append(f"**{dep_type.upper()}** ({len(pkgs)} packages): " + ", ".join(f"`{p}`" for p in pkgs[:20]))
                if len(pkgs) > 20:
                    lines.append(f"  *(+{len(pkgs)-20} more)*")
                lines.append("")

    # Author info
    if result.author_info.get("checked"):
        lines.append("---")
        lines.append("")
        lines.append("## Author / Provenance (ClawHub)")
        lines.append("")
        if result.author_info.get("found"):
            lines.append(f"- **Author:** {result.author_info.get('author', '?')}")
            lines.append(f"- **Stars:** {result.author_info.get('stars', '?')}")
            lines.append(f"- **Downloads:** {result.author_info.get('downloads', '?')}")
            lines.append(f"- **Version:** {result.author_info.get('version', '?')}")
            lines.append(f"- **Last updated:** {result.author_info.get('updated_at', '?')}")
        elif result.author_info.get("found") is False:
            lines.append(f"⚠️ Skill `{result.skill_name}` not found on ClawHub — may be local/unofficial.")
        else:
            lines.append(f"ℹ️ ClawHub lookup skipped or failed: {result.author_info.get('error', 'unknown error')}")
        lines.append("")

    # Files checked
    lines.append("---")
    lines.append("")
    lines.append("## Files Audited")
    lines.append("")
    for f in result.checked_files[:50]:
        lines.append(f"- `{f}`")
    if len(result.checked_files) > 50:
        lines.append(f"- *(+{len(result.checked_files)-50} more files)*")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"*Generated by [skill-security-audit](https://clawhub.ai) — OpenClaw Security Auditor*")
    lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw Skill Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 audit.py /path/to/my-skill/
  python3 audit.py scrapling-official
  python3 audit.py .
  python3 audit.py /path/to/skill --output report.md
  python3 audit.py /path/to/skill --no-clawhub
        """,
    )
    parser.add_argument("skill_path", help="Path to skill directory or skill name (for ClawHub lookup)")
    parser.add_argument("--output", "-o", help="Save report to file (default: print to stdout)")
    parser.add_argument("--no-clawhub", action="store_true", help="Skip ClawHub author lookup")
    parser.add_argument("--json", action="store_true", help="Output raw JSON findings instead of markdown report")

    args = parser.parse_args()

    skill_path = args.skill_path

    # Resolve path
    if not os.path.isdir(skill_path):
        # Try interpreting as a skill name relative to known locations
        candidates = [
            os.path.expanduser(f"~/.openclaw/skills/{skill_path}"),
            os.path.expanduser(f"~/.openclaw/workspace/skills/{skill_path}"),
            f"/usr/lib/node_modules/openclaw/skills/{skill_path}",
        ]
        for candidate in candidates:
            if os.path.isdir(candidate):
                skill_path = candidate
                print(f"ℹ️  Found skill at: {skill_path}", file=sys.stderr)
                break
        else:
            print(f"❌ Skill not found at '{args.skill_path}'", file=sys.stderr)
            print(f"   Tried:", file=sys.stderr)
            for c in candidates:
                print(f"   - {c}", file=sys.stderr)
            sys.exit(1)

    print(f"🔍 Auditing skill: {skill_path}", file=sys.stderr)
    print(f"   Check ClawHub: {not args.no_clawhub}", file=sys.stderr)
    print("", file=sys.stderr)

    result = audit_skill(skill_path, check_clawhub=not args.no_clawhub)

    if args.json:
        output = json.dumps({
            "skill_name": result.skill_name,
            "skill_path": result.skill_path,
            "score": result.score,
            "level": result.level,
            "recommendation": result.recommendation,
            "findings_count": len(result.findings),
            "findings": [
                {
                    "severity": f.severity,
                    "vector": f.vector,
                    "description": f.description,
                    "file": f.file,
                    "line": f.line,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
            "domains": result.domains_found,
            "dependencies": result.dependencies,
            "author_info": result.author_info,
        }, indent=2)
    else:
        output = generate_report(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"✅ Report saved to: {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code: 0 = safe, 1 = caution, 2 = risk/dangerous
    if result.level == "SAFE":
        sys.exit(0)
    elif result.level == "CAUTION":
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
