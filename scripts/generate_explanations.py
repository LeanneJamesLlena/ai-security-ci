#!/usr/bin/env python3
"""
Generate plain-language LLM explanations for Semgrep findings.

Install:
    pip install google-genai

Environment:
    GEMINI_API_KEY=<your_key>
or:
    GOOGLE_API_KEY=<your_key>

Input:
    semgrep-results.json

Output:
    llm-explanations.json
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, List

from google import genai


INPUT_FILE = "semgrep-results.json"
OUTPUT_FILE = "llm-explanations.json"
MODEL_NAME = "gemini-2.5-flash"
SLEEP_SECONDS = 1.0


def get_api_key() -> str:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print(
            "Error: GEMINI_API_KEY or GOOGLE_API_KEY environment variable is required.",
            file=sys.stderr,
        )
        sys.exit(1)
    return api_key


def load_semgrep_results(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {path} not found in current directory.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse {path}: {e}", file=sys.stderr)
        sys.exit(1)

    results = data.get("results")
    if not isinstance(results, list):
        print("Error: Input JSON does not contain a valid 'results' array.", file=sys.stderr)
        sys.exit(1)

    return results


def safe_get_finding_fields(finding: Dict[str, Any]) -> Dict[str, Any]:
    extra = finding.get("extra") or {}
    start = finding.get("start") or {}

    check_id = str(finding.get("check_id", "unknown-rule"))
    severity = str(extra.get("severity", "UNKNOWN"))
    path = str(finding.get("path", "unknown-path"))
    line = start.get("line", "unknown-line")
    code_line = extra.get("lines", "")
    message = str(extra.get("message", ""))

    if not isinstance(code_line, str):
        code_line = str(code_line)

    return {
        "check_id": check_id,
        "severity": severity,
        "path": path,
        "line": line,
        "code_line": code_line.strip(),
        "message": message,
    }


def build_prompt(fields: Dict[str, Any]) -> str:
    return f"""You are a security assistant helping a developer understand a static analysis finding. Explain the following Semgrep security finding in plain language for a developer who may not be familiar with this vulnerability type.

Rule: {fields['check_id']}
Severity: {fields['severity']}
File: {fields['path']}, line {fields['line']}
Code: {fields['code_line']}
Semgrep message: {fields['message']}

Please provide:
1. What this finding means in plain language
2. Why this is a security risk and what an attacker could do
3. What specific part of the code is the problem and why
4. What kind of fix would be appropriate with a brief code example

Keep the explanation clear and practical. Do not be overly technical.
"""


def extract_response_text(response: Any) -> str:
    text = getattr(response, "text", None)
    if isinstance(text, str) and text.strip():
        return text.strip()

    candidates = getattr(response, "candidates", None)
    if candidates:
        parts: List[str] = []
        for candidate in candidates:
            content = getattr(candidate, "content", None)
            if not content:
                continue
            candidate_parts = getattr(content, "parts", None) or []
            for part in candidate_parts:
                part_text = getattr(part, "text", None)
                if isinstance(part_text, str) and part_text.strip():
                    parts.append(part_text.strip())
        if parts:
            return "\n".join(parts)

    return "ERROR: No text returned by Gemini."


def generate_explanation(client: genai.Client, prompt: str) -> str:
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
    )
    return extract_response_text(response)


def save_output(path: str, entries: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


def main() -> None:
    api_key = get_api_key()
    findings = load_semgrep_results(INPUT_FILE)
    client = genai.Client(api_key=api_key)

    output_entries: List[Dict[str, Any]] = []
    total = len(findings)

    if total == 0:
        print("No findings found in semgrep-results.json")
        save_output(OUTPUT_FILE, output_entries)
        print(f"Saved empty output to {OUTPUT_FILE}")
        return

    for index, finding in enumerate(findings, start=1):
        fields = safe_get_finding_fields(finding)
        print(
            f"Processing finding {index}/{total}: "
            f"{fields['check_id']} at {fields['path']}:{fields['line']}"
        )

        prompt = build_prompt(fields)

        try:
            explanation = generate_explanation(client, prompt)
        except Exception as e:
            explanation = f"ERROR: {e}"

        output_entries.append(
            {
                "check_id": fields["check_id"],
                "severity": fields["severity"],
                "path": fields["path"],
                "line": fields["line"],
                "code_line": fields["code_line"],
                "message": fields["message"],
                "explanation": explanation,
            }
        )

        time.sleep(SLEEP_SECONDS)

    save_output(OUTPUT_FILE, output_entries)
    print(f"Done. Saved {len(output_entries)} explanations to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()