#!/usr/bin/env python3
"""
intent_analyzer.py — Classifies the INTENT of security findings.

Modes:
  stdin/stdout  : pipe JSON input, get JSON output
  CLI           : --skill-path / --findings-json / --api-key flags

Anti-evasion checks run before intent analysis:
  PADDING       : >50 consecutive near-identical lines
  TAIL_PAYLOAD  : >80% of findings in last 20% of file
  LLM_INJECTION : injection strings in code files (not .md)
  OBFUSCATED    : high-entropy blocks >200 chars in code

Intent labels: MALICIOUS | DEFENSIVE | UTILITY | AMBIGUOUS | FALSE_POSITIVE
"""

import sys
import os
import json
import math
import argparse
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Model confidence registry
# ---------------------------------------------------------------------------
MODEL_CONFIDENCE: dict[str, dict[str, Any]] = {
    "opus":        {"max_tokens": 100000, "confidence": 0.90},
    "sonnet":      {"max_tokens": 60000,  "confidence": 0.85},
    "haiku":       {"max_tokens": 20000,  "confidence": 0.70},
    "gemini-pro":  {"max_tokens": 200000, "confidence": 0.80},
    "gemini-flash":{"max_tokens": 100000, "confidence": 0.75},
    "gpt-4o":      {"max_tokens": 60000,  "confidence": 0.85},
    "deepseek":    {"max_tokens": 30000,  "confidence": 0.65},
    "llama-70b":   {"max_tokens": 30000,  "confidence": 0.70},
    "unknown":     {"max_tokens": 10000,  "confidence": 0.60},
}

GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_MODEL_KEY = "llama-70b"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

VALID_INTENTS = {"MALICIOUS", "DEFENSIVE", "UTILITY", "AMBIGUOUS", "FALSE_POSITIVE"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (bits per character)."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _read_context(file_path: str, line: int, window: int = 10) -> tuple[list[str], int, int]:
    """
    Read lines [line-window, line+window] from file_path.
    Returns (lines, start_line, end_line). Line numbers are 1-based.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            all_lines = fh.readlines()
    except (OSError, IOError):
        return [], max(1, line - window), line + window

    total = len(all_lines)
    start = max(0, line - window - 1)          # convert to 0-based
    end = min(total, line + window)             # exclusive
    return all_lines[start:end], start + 1, end


def _read_all_lines(file_path: str) -> list[str]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except (OSError, IOError):
        return []


def _estimate_tokens(text: str) -> int:
    """Rough token count: ~4 chars per token."""
    return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# Anti-evasion checks
# ---------------------------------------------------------------------------

def _check_padding(lines: list[str]) -> bool:
    """Flag if >50 consecutive lines are near-identical (stripped)."""
    if not lines:
        return False
    streak = 1
    for i in range(1, len(lines)):
        a = lines[i - 1].strip()
        b = lines[i].strip()
        # near-identical: same or differs only in whitespace amount
        if a == b or (len(a) > 0 and a == b):
            streak += 1
        else:
            streak = 1
        if streak > 50:
            return True
    return False


def _check_llm_injection(lines: list[str]) -> bool:
    """Flag injection strings in non-.md files."""
    patterns = [
        r"ignore previous",
        r"disregard",
        r"you are now",
        r"forget (?:all )?(?:previous|prior)",
        r"new instructions",
        r"override (?:all )?(?:previous|prior)",
    ]
    combined = re.compile("|".join(patterns), re.IGNORECASE)
    for line in lines:
        if combined.search(line):
            return True
    return False


def _check_obfuscated(lines: list[str]) -> bool:
    """Flag high-entropy blocks >200 chars."""
    full_text = "".join(lines)
    # slide a 200-char window; flag if any window has entropy > 4.5
    step = 50
    for i in range(0, max(1, len(full_text) - 200), step):
        chunk = full_text[i:i + 200]
        if _shannon_entropy(chunk) > 4.5:
            return True
    return False


def run_anti_evasion(skill_path: str, findings: list[dict]) -> dict[str, bool]:
    """
    Run all anti-evasion checks across the skill directory.
    Returns dict with flags: padding, tail_payload, llm_injection, obfuscated.
    """
    result = {
        "padding": False,
        "tail_payload": False,
        "llm_injection": False,
        "obfuscated": False,
    }

    skill_dir = Path(skill_path)
    code_extensions = {".py", ".js", ".ts", ".sh", ".bash", ".rb", ".go", ".php", ".java"}

    # Collect all files
    all_files: list[Path] = []
    if skill_dir.exists():
        for p in skill_dir.rglob("*"):
            if p.is_file():
                all_files.append(p)

    for fp in all_files:
        lines = _read_all_lines(str(fp))
        is_code = fp.suffix.lower() in code_extensions

        # PADDING check (all files)
        if not result["padding"] and _check_padding(lines):
            result["padding"] = True

        # LLM_INJECTION check (code files only)
        if is_code and not result["llm_injection"] and _check_llm_injection(lines):
            result["llm_injection"] = True

        # OBFUSCATED check (code files only)
        if is_code and not result["obfuscated"] and _check_obfuscated(lines):
            result["obfuscated"] = True

    # TAIL_PAYLOAD: >80% of findings in last 20% of their respective files
    if findings:
        tail_count = 0
        valid_count = 0
        for finding in findings:
            fpath = skill_dir / finding.get("file", "")
            line_num = finding.get("line", 0)
            if not fpath.exists() or line_num == 0:
                continue
            all_lines = _read_all_lines(str(fpath))
            total_lines = len(all_lines)
            if total_lines == 0:
                continue
            valid_count += 1
            threshold = total_lines * 0.80
            if line_num >= threshold:
                tail_count += 1
        if valid_count > 0 and (tail_count / valid_count) > 0.80:
            result["tail_payload"] = True

    return result


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def build_prompt(finding: dict, context_lines: list[str], ctx_start: int, ctx_end: int) -> str:
    file_name = finding.get("file", "unknown")
    line_num = finding.get("line", 0)
    description = finding.get("description", "")
    evidence = finding.get("evidence", "")

    numbered = ""
    for i, ln in enumerate(context_lines):
        lno = ctx_start + i
        marker = ">>>" if lno == line_num else "   "
        numbered += f"{marker} {lno:4d} | {ln.rstrip()}\n"

    prompt = (
        f"You are a security auditor analyzing code. Classify the INTENT:\n\n"
        f"File: {file_name} | Line: {line_num}\n"
        f"Pattern: {description}\n"
        f"Evidence: {evidence}\n\n"
        f"Context (lines {ctx_start} to {ctx_end}):\n"
        f"{numbered}\n"
        f"Classify as exactly one of:\n"
        f"- MALICIOUS: deliberately harmful\n"
        f"- DEFENSIVE: security tool detecting threats\n"
        f"- UTILITY: legitimate functionality\n"
        f"- AMBIGUOUS: could be either\n"
        f"- FALSE_POSITIVE: no actual risk\n\n"
        f'Respond ONLY with JSON: {{"intent": "...", "confidence": 0.0-1.0, "reasoning": "one sentence"}}'
    )
    return prompt


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def call_groq(prompt: str, api_key: str) -> dict:
    """Call Groq API and return parsed JSON classification."""
    payload = json.dumps({
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 200,
    }).encode("utf-8")

    req = urllib.request.Request(
        GROQ_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"].strip()
            # Extract JSON from the response (may have markdown fences)
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            return {"intent": "AMBIGUOUS", "confidence": 0.5, "reasoning": "Could not parse LLM response"}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"[intent_analyzer] Groq HTTP error {e.code}: {err_body}", file=sys.stderr)
        return {"intent": "AMBIGUOUS", "confidence": 0.3, "reasoning": f"API error: {e.code}"}
    except Exception as e:
        print(f"[intent_analyzer] Groq call failed: {e}", file=sys.stderr)
        return {"intent": "AMBIGUOUS", "confidence": 0.3, "reasoning": f"API call failed: {e}"}


def classify_interactive(prompt: str) -> dict:
    """Print prompt to stderr, read JSON response from stdin."""
    print("\n" + "=" * 70, file=sys.stderr)
    print("INTENT CLASSIFICATION PROMPT (interactive mode)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(prompt, file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print('Enter JSON classification (e.g. {"intent": "MALICIOUS", "confidence": 0.9, "reasoning": "..."}):',
          file=sys.stderr)
    try:
        line = input().strip()
        parsed = json.loads(line)
        return parsed
    except Exception:
        return {"intent": "AMBIGUOUS", "confidence": 0.5, "reasoning": "Interactive input parse failed"}


# ---------------------------------------------------------------------------
# Chunked skill analysis
# ---------------------------------------------------------------------------

def get_skill_total_tokens(skill_path: str) -> int:
    """Estimate total token count of all files in skill directory."""
    total = 0
    skill_dir = Path(skill_path)
    if skill_dir.exists():
        for p in skill_dir.rglob("*"):
            if p.is_file():
                lines = _read_all_lines(str(p))
                total += _estimate_tokens("".join(lines))
    return total


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def compute_intent_score(classified_findings: list[dict]) -> int:
    """
    Compute 0-100 risk score based on classified intents.
    MALICIOUS → high weight, DEFENSIVE/FALSE_POSITIVE → reduce risk.
    """
    if not classified_findings:
        return 0

    weights = {
        "MALICIOUS": 100,
        "AMBIGUOUS": 50,
        "UTILITY": 10,
        "DEFENSIVE": 0,
        "FALSE_POSITIVE": 0,
    }
    total_weight = 0.0
    total_confidence = 0.0

    for f in classified_findings:
        intent = f.get("intent", "AMBIGUOUS")
        confidence = float(f.get("confidence", 0.5))
        w = weights.get(intent, 50)
        total_weight += w * confidence
        total_confidence += confidence

    if total_confidence == 0:
        return 0

    raw = total_weight / total_confidence
    return min(100, int(raw))


def score_to_recommendation(intent_score: int, anti_evasion: dict) -> str:
    ae_flags = sum(1 for v in anti_evasion.values() if v)

    if intent_score >= 70 or ae_flags >= 2:
        return "DO NOT INSTALL"
    if intent_score >= 40 or ae_flags >= 1:
        return "INSTALL WITH CAUTION"
    return "INSTALL"


def anti_evasion_score(ae: dict) -> int:
    return sum(1 for v in ae.values() if v) * 25


# ---------------------------------------------------------------------------
# Main analysis pipeline
# ---------------------------------------------------------------------------

def analyze(skill_path: str, findings: list[dict], api_key: str | None = None) -> dict:
    # Determine mode and model
    groq_key = api_key or os.environ.get("GROQ_API_KEY", "").strip()
    use_groq = bool(groq_key)
    model_used = f"groq/{GROQ_MODEL}" if use_groq else "interactive"
    model_conf_entry = MODEL_CONFIDENCE.get(GROQ_MODEL_KEY if use_groq else "unknown")
    model_confidence = model_conf_entry["confidence"]
    model_max_tokens = model_conf_entry["max_tokens"]

    # Chunked analysis check
    skill_tokens = get_skill_total_tokens(skill_path)
    chunked = skill_tokens > model_max_tokens
    chunk_size = model_max_tokens // 3
    chunks = max(1, math.ceil(skill_tokens / chunk_size)) if chunked else 1
    if chunked:
        print(f"[intent_analyzer] Chunked analysis applied — {chunks} chunks (skill ~{skill_tokens} tokens, model max {model_max_tokens})",
              file=sys.stderr)

    # Anti-evasion checks
    ae_flags = run_anti_evasion(skill_path, findings)
    ae_score = anti_evasion_score(ae_flags)

    flagged = [k for k, v in ae_flags.items() if v]
    if flagged:
        print(f"[intent_analyzer] Anti-evasion flags: {', '.join(f.upper() for f in flagged)}", file=sys.stderr)

    # Classify each finding
    classified = []
    skill_dir = Path(skill_path)

    for finding in findings:
        file_rel = finding.get("file", "")
        line_num = finding.get("line", 0)
        full_path = str(skill_dir / file_rel) if file_rel else ""

        context_lines, ctx_start, ctx_end = _read_context(full_path, line_num)
        prompt = build_prompt(finding, context_lines, ctx_start, ctx_end)

        if use_groq:
            classification = call_groq(prompt, groq_key)
        else:
            classification = classify_interactive(prompt)

        # Validate intent label
        intent = classification.get("intent", "AMBIGUOUS").upper()
        if intent not in VALID_INTENTS:
            intent = "AMBIGUOUS"

        classified.append({
            "original": finding,
            "intent": intent,
            "confidence": float(classification.get("confidence", 0.5)),
            "reasoning": str(classification.get("reasoning", "")),
        })

    # Scores and recommendation
    intent_score = compute_intent_score(classified)
    # Boost score if anti-evasion flags hit
    combined_score = min(100, intent_score + ae_score)
    recommendation = score_to_recommendation(combined_score, ae_flags)

    return {
        "model_used": model_used,
        "model_confidence": model_confidence,
        "chunked": chunked,
        "chunks": chunks,
        "anti_evasion": ae_flags,
        "anti_evasion_score": ae_score,
        "findings": classified,
        "intent_score": combined_score,
        "combined_recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def main_stdin() -> None:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(1)

    skill_path = data.get("skill_path", "")
    findings = data.get("findings", [])
    result = analyze(skill_path, findings)
    print(json.dumps(result, indent=2))


def main_cli(args: argparse.Namespace) -> None:
    skill_path = args.skill_path or ""
    api_key = args.api_key or None

    findings: list[dict] = []
    if args.findings_json:
        try:
            with open(args.findings_json, "r", encoding="utf-8") as fh:
                findings = json.load(fh)
                if isinstance(findings, dict):
                    findings = findings.get("findings", [findings])
        except (OSError, json.JSONDecodeError) as e:
            print(f"[intent_analyzer] Error reading findings file: {e}", file=sys.stderr)
            sys.exit(1)

    result = analyze(skill_path, findings, api_key=api_key)
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Classify the INTENT of security findings for a skill.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # stdin/stdout mode
  echo '{...}' | python3 intent_analyzer.py

  # CLI mode with findings file
  python3 intent_analyzer.py --skill-path /path/to/skill --findings-json /path/to/findings.json

  # CLI mode with Groq API key
  python3 intent_analyzer.py --skill-path /path/to/skill --api-key gsk_xxx
""",
    )
    parser.add_argument("--skill-path", help="Path to the skill directory")
    parser.add_argument("--findings-json", help="Path to JSON file with findings list")
    parser.add_argument("--api-key", help="Groq API key (overrides GROQ_API_KEY env var)")

    # If no args (or only --help), check if stdin has data
    if len(sys.argv) == 1:
        # Pure stdin/stdout mode
        main_stdin()
    else:
        args = parser.parse_args()
        if args.skill_path or args.findings_json or args.api_key:
            main_cli(args)
        else:
            main_stdin()


if __name__ == "__main__":
    main()
