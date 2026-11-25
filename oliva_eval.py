#!/usr/bin/env python3
"""Offline harness quality gate: source-backed claims and token costs.

No network traffic, no agent execution, no model calls, no auto-promotion.
Expected facts and evidence IDs must be declared by the benchmark author.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def analyze(run: dict, required: set[str], known_evidence: set[str]) -> dict:
    claims = run.get("claims", [])
    if not isinstance(claims, list):
        raise ValueError("claims must be an array")
    if any(not isinstance(claim, dict) for claim in claims):
        raise ValueError("each claim must be an object")
    all_texts = [str(row.get("text", "")).casefold().strip() for row in claims]
    good_claims = [row for row in claims if isinstance(row.get("evidence_ids"), list)
                   and row["evidence_ids"]
                   and all(isinstance(e, str) and e in known_evidence
                           for e in row["evidence_ids"])]
    supplied = set(all_texts)
    covered = len({item for item in required if item in supplied})
    tokens_in = run.get("input_tokens")
    tokens_out = run.get("output_tokens")
    if any(type(value) is not int or value < 0 for value in (tokens_in, tokens_out)):
        raise ValueError("input_tokens and output_tokens must be nonnegative integers")
    violations = run.get("policy_violations", 0)
    if type(violations) is not int or violations < 0:
        raise ValueError("policy_violations must be a nonnegative integer")
    return {
        "total_tokens": tokens_in + tokens_out,
        "required_claims_covered": covered,
        "required_claims_total": len(required),
        "grounded_claims": len(good_claims),
        "claims_total": len(claims),
        "duplicate_claims": len(all_texts) - len(supplied),
        "policy_violations": violations,
    }


def compare(fixture: dict) -> dict:
    required = fixture.get("expected_claims")
    evidence = fixture.get("evidence_ids")
    if not isinstance(required, list) or not isinstance(evidence, list) or \
            any(not isinstance(x, str) for x in required + evidence):
        raise ValueError("expected_claims and evidence_ids must be arrays of strings")
    golden = {item.casefold().strip() for item in required}
    known = set(evidence)
    base = analyze(fixture["baseline"], golden, known)
    candidate = analyze(fixture["candidate"], golden, known)
    quality_gate = (
        candidate["policy_violations"] == 0
        and candidate["required_claims_covered"] == len(golden)
        and candidate["grounded_claims"] == candidate["claims_total"]
        and candidate["duplicate_claims"] == 0
        and candidate["required_claims_covered"] >= base["required_claims_covered"]
        and candidate["grounded_claims"] >= min(base["grounded_claims"], len(golden))
    )
    fewer_tokens = candidate["total_tokens"] < base["total_tokens"]
    return {
        "scenario_id": fixture.get("scenario_id", "unnamed"),
        "baseline": base,
        "candidate": candidate,
        "saved_tokens": base["total_tokens"] - candidate["total_tokens"],
        "saved_pct": round(100 * (1 - candidate["total_tokens"] / max(1, base["total_tokens"])), 2),
        "quality_gate_passed": quality_gate,
        "prefer_candidate": quality_gate and fewer_tokens,
        "note": "Offline quality proxy, not proof of correct security findings or permission to auto-promote",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="JSON with baseline, candidate, golden facts")
    args = parser.parse_args()
    result = compare(json.loads(args.fixture.read_text(encoding="utf-8")))
    print(json.dumps(result, indent=2))
    if not result["quality_gate_passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
