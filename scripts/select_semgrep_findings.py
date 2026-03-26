#!/usr/bin/env python3
"""
Select exactly one Semgrep finding per target vulnerability category.

This is used to build clean evaluation materials for a study:
- Keep Semgrep Registry findings where available (official messages).
- Fill gaps with minimal fallback rules in `.semgrep/rules.yml`.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


TARGETS: List[str] = [
    "SQL injection",
    "Command injection",
    "Hardcoded secrets",
    "Path traversal",
    "Insecure deserialization",
    "Insecure SSL verification",
]


def _severity_rank(sev: Optional[str]) -> int:
    if not sev:
        return 0
    sev_u = str(sev).upper()
    if sev_u == "ERROR":
        return 3
    if sev_u == "WARNING":
        return 2
    if sev_u == "INFO":
        return 1
    return 0


def _vclass(result: Dict[str, Any]) -> Optional[str]:
    extra = result.get("extra") or {}
    meta = extra.get("metadata") or {}
    vclasses = meta.get("vulnerability_class")
    if isinstance(vclasses, list) and vclasses:
        v = vclasses[0]
        return str(v) if v is not None else None
    if isinstance(vclasses, str) and vclasses:
        return vclasses
    return None


def _category_from_result(result: Dict[str, Any]) -> Optional[str]:
    # Prefer explicit vulnerability class from Semgrep metadata.
    v = _vclass(result)
    if v:
        v_norm = v.strip()
        if v_norm == "SQL Injection":
            return "SQL injection"
        if v_norm == "Command Injection":
            return "Command injection"
        if v_norm == "Hardcoded secrets":
            return "Hardcoded secrets"
        if v_norm == "Path traversal":
            return "Path traversal"
        if v_norm == "Insecure deserialization":
            return "Insecure deserialization"
        if v_norm == "Insecure SSL verification":
            return "Insecure SSL verification"

        # Handle variants (defensive).
        v_l = v_norm.lower()
        if "sql injection" in v_l:
            return "SQL injection"
        if "command injection" in v_l:
            return "Command injection"
        if "hardcoded" in v_l and "secret" in v_l:
            return "Hardcoded secrets"
        if "path traversal" in v_l:
            return "Path traversal"
        if "deserialization" in v_l:
            return "Insecure deserialization"
        if "ssl" in v_l and ("verify" in v_l or "verification" in v_l):
            return "Insecure SSL verification"
        if "insecure ssl verification" in v_l:
            return "Insecure SSL verification"

    # Fallback: infer from check_id for registry rules.
    check_id = (result.get("check_id") or "").lower()
    if "formatted-sql-query" in check_id or "sql-injection" in check_id:
        return "SQL injection"
    if "subprocess-shell-true" in check_id or "command-injection" in check_id:
        return "Command injection"
    if "pickle.loads" in (check_id or "") or "insecure-deserialization" in check_id:
        return "Insecure deserialization"
    if "verify-false" in check_id or "insecure-ssl-verification" in check_id:
        return "Insecure SSL verification"
    if "hardcoded-secrets" in check_id:
        return "Hardcoded secrets"
    if "path-traversal" in check_id:
        return "Path traversal"

    return None


def _start_line(result: Dict[str, Any]) -> int:
    start = result.get("start") or {}
    line = start.get("line")
    return int(line) if isinstance(line, (int, float, str)) else 10**9


def _pref_score(category: str, result: Dict[str, Any]) -> int:
    check_id = (result.get("check_id") or "")

    if category == "SQL injection":
        return 100 if "formatted-sql-query" in check_id else 0
    if category == "Command injection":
        if "subprocess-shell-true" in check_id:
            return 100
        if "dangerous-subprocess-use" in check_id:
            return 50
        if "dangerous-system-call" in check_id:
            return 40
        return 0
    if category == "Hardcoded secrets":
        return 0
    if category == "Path traversal":
        return 0
    if category == "Insecure deserialization":
        return 0
    if category == "Insecure SSL verification":
        return 0
    return 0


@dataclass(frozen=True)
class Candidate:
    category: str
    severity_rank: int
    pref: int
    start_line: int
    result: Dict[str, Any]


def _select_exactly_one(candidates: List[Candidate], category: str) -> Candidate:
    # Sort: higher severity, higher preference, earlier in file.
    candidates_sorted = sorted(
        candidates,
        key=lambda c: (
            -c.severity_rank,
            -c.pref,
            c.start_line,
        ),
    )
    best = candidates_sorted[0]
    return best


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: select_semgrep_findings.py <input_json> <output_json>", file=sys.stderr)
        return 2

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results")
    if not isinstance(results, list):
        print("Input JSON missing `results` array.", file=sys.stderr)
        return 2

    candidates_by_cat: Dict[str, List[Candidate]] = {t: [] for t in TARGETS}

    for r in results:
        category = _category_from_result(r)
        if not category:
            continue
        if category not in candidates_by_cat:
            continue
        sev_rank = _severity_rank((r.get("extra") or {}).get("severity"))
        pref = _pref_score(category, r)
        start_line = _start_line(r)
        candidates_by_cat[category].append(
            Candidate(
                category=category,
                severity_rank=sev_rank,
                pref=pref,
                start_line=start_line,
                result=r,
            )
        )

    missing = [t for t in TARGETS if not candidates_by_cat[t]]
    if missing:
        print(f"Missing categories with no findings: {', '.join(missing)}", file=sys.stderr)
        return 1

    chosen: List[Dict[str, Any]] = []
    for category in TARGETS:
        best = _select_exactly_one(candidates_by_cat[category], category)
        chosen.append(best.result)

    if len(chosen) != 6:
        print(f"Internal error: expected 6 chosen results, got {len(chosen)}", file=sys.stderr)
        return 1

    # Overwrite only the `results` array; keep the rest of Semgrep's JSON intact.
    data_out = dict(data)
    data_out["results"] = chosen

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data_out, f, ensure_ascii=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

