"""Read-only, general-purpose and token-budgeted session snapshot.

This module never executes an action. The source is the existing status operation,
whose authorization semantics are unchanged. Only allowlisted data is returned.
"""
from __future__ import annotations

import json
from math import ceil
from typing import Any


def estimate_tokens(value: Any) -> int:
    """Portable estimate, NOT a substitute for provider token metering."""
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return ceil(len(raw) / 4)


def _cut(value: object, limit: int) -> str:
    text = str(value) if value is not None else ""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def compact_status(status: dict, max_tokens: int = 550) -> dict:
    """Compress an existing status dict into a deterministic, bounded snapshot.

    The policy document, shell logs, complete evidence and secret-bearing scope
    fields are deliberately not copied into the prompt. Expand explicitly with
    the original tools whenever the summary is insufficient.
    """
    if type(max_tokens) is not int or not 200 <= max_tokens <= 2400:
        raise ValueError("max_tokens must be an integer between 200 and 2400")
    if not isinstance(status, dict):
        raise ValueError("status must be a dict")

    source_scope = status.get("scope") if isinstance(status.get("scope"), dict) else {}
    case = status.get("case") if isinstance(status.get("case"), dict) else {}
    snapshot = {
        "profile": _cut(status.get("profile", "unconfigured"), 24),
        "engagement_mode": _cut(status.get("engagement_mode", ""), 30),
        "case_id": _cut(case.get("target_id") or "", 80) or None,
        "scope": {
            key: _cut(source_scope[key], 120)
            for key in ("program_id", "target_ip", "target_url", "repository_url")
            if isinstance(source_scope.get(key), str) and source_scope[key]
        },
    }
    counts = case.get("counts") if isinstance(case.get("counts"), dict) else {}
    if counts:
        snapshot["hypothesis_counts"] = {
            key: value for key, value in counts.items()
            if key in {"open", "supported", "rejected", "confirmed"} and type(value) is int
        }
    active = case.get("active_hypotheses") if isinstance(case.get("active_hypotheses"), list) else []
    snapshot["hypotheses"] = [
        {
            "id": _cut(row.get("hypothesis_id", ""), 24),
            "status": _cut(row.get("status", ""), 16),
            "claim": _cut(row.get("claim", ""), 140),
            "evidence_count": len(row.get("evidence_ids", []))
            if isinstance(row.get("evidence_ids"), list) else 0,
        }
        for row in active[-4:] if isinstance(row, dict)
    ]
    services = status.get("services") if isinstance(status.get("services"), list) else []
    snapshot["services"] = [
        {
            "port": row.get("port"),
            "service": _cut(row.get("service", ""), 36),
            "state": _cut(row.get("state", ""), 14),
        }
        for row in services[:8]
        if isinstance(row, dict) and isinstance(row.get("port"), int)
    ]
    recent = status.get("recent_attempts") if isinstance(status.get("recent_attempts"), list) else []
    snapshot["recent"] = [
        {
            "id": _cut(row.get("attempt_id", ""), 24),
            "operation": _cut(row.get("operation", ""), 35),
            "outcome": _cut(row.get("outcome", ""), 30),
        }
        for row in recent[-5:] if isinstance(row, dict)
    ]
    methods = status.get("relevant_methods") if isinstance(status.get("relevant_methods"), list) else []
    snapshot["methods"] = [
        {
            "id": _cut(row.get("method_id", ""), 24),
            "phase": _cut(row.get("phase", ""), 25),
            "signal": _cut(row.get("signal", ""), 120),
            "status": _cut(row.get("status", "candidate"), 20),
        }
        for row in methods[:4] if isinstance(row, dict)
    ]
    focus = status.get("focus") if isinstance(status.get("focus"), dict) else {}
    if focus:
        snapshot["focus"] = {
            key: focus[key]
            for key in ("exhausted", "avenue", "branch_key")
            if key in focus and type(focus[key]) in {bool, str}
        }

    original = estimate_tokens(status)
    # Reduce low-value arrays first, keeping profile/scope/case identification.
    truncated = False
    while estimate_tokens(snapshot) + 14 > max_tokens:
        removed = False
        for key in ("methods", "recent", "services", "hypotheses"):
            if snapshot[key]:
                snapshot[key].pop(0)
                removed = True
                truncated = True
                break
        if not removed:
            if "focus" in snapshot:
                del snapshot["focus"]
                truncated = True
            elif "hypothesis_counts" in snapshot:
                del snapshot["hypothesis_counts"]
                truncated = True
            else:
                break
    snapshot["truncated"] = truncated or estimate_tokens(status) > max_tokens
    snapshot["estimated_tokens"] = estimate_tokens(snapshot) + 6
    snapshot["source_estimated_tokens"] = original
    # The source estimate can itself increase the envelope by a few tokens;
    # enforce the actual output budget before returning.
    while estimate_tokens(snapshot) > max_tokens:
        for key in ("methods", "recent", "services", "hypotheses"):
            if snapshot[key]:
                snapshot[key].pop(0)
                break
        else:
            snapshot.pop("hypothesis_counts", None)
            snapshot.pop("focus", None)
            if estimate_tokens(snapshot) > max_tokens:
                raise ValueError("max_tokens too small for required context")
    snapshot["estimated_tokens"] = estimate_tokens(snapshot)
    return snapshot
