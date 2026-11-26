"""Offline efficiency scorecard for the privacy-preserving Codex exporter.

Only accepts metrics plus a redacted timeline. Does not parse raw sessions.
Treat reported outcome separately from independently verified success.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import json


def analyze(metrics: dict, timeline: list | None = None, reported_outcome: str = "unknown") -> dict:
    if not isinstance(metrics, dict) or (timeline is not None and not isinstance(timeline, list)):
        raise ValueError("metrics must be an object, timeline must be an array")
    if reported_outcome not in {"unknown", "completed", "partial", "failed"}:
        raise ValueError("invalid outcome")
    activity = metrics.get("activity", {})
    cumulative = metrics.get("usage", {}).get("reported_cumulative", {})
    def nonneg(k):
        v = cumulative.get(k)
        return v if type(v) is int and v >= 0 else None
    tin, cache, tout, total = [nonneg(k) for k in
                               ("input_tokens", "cached_input_tokens", "output_tokens", "total_tokens")]
    if tin is not None and cache is not None and cache > tin:
        raise ValueError("cached input tokens exceed total input tokens")
    if tin is not None and tout is not None and total is not None and total != tin + tout:
        raise ValueError("provider counters inconsistent: total != input + output")
    tool_counts = Counter(activity.get("tool_calls_by_name", {}) if isinstance(activity.get("tool_calls_by_name"), dict) else {})
    timeline_counts = Counter(row.get("tool") for row in (timeline or [])
                              if isinstance(row, dict) and row.get("event") == "tool_call"
                              and isinstance(row.get("tool"), str))
    if not tool_counts:
        tool_counts = timeline_counts
    calls = activity.get("tool_calls") if type(activity.get("tool_calls")) is int else sum(tool_counts.values())
    repeats = activity.get("exact_argument_repeat_calls")
    repeats = repeats if type(repeats) is int else None
    result = {
        "schema": "oliva-efficiency-report-v2", "reported_outcome": reported_outcome,
        "outcome_verified": None, "provider": metrics.get("session", {}).get("provider"),
        "models": metrics.get("session", {}).get("models_seen", {}),
        "git_revision": metrics.get("repository", {}).get("commit") if isinstance(metrics.get("repository"), dict) else None,
        "tokens": {"input": tin, "cached_input_subset": cache,
                   "uncached_input": tin - cache if tin is not None and cache is not None else None,
                   "output": tout, "reported_total": total},
        "activity": {"calls": calls, "compactions": activity.get("compactions"),
                     "same_argument_repeats": repeats,
                     "repeat_pct": round(100 * repeats / calls, 2) if repeats is not None and calls else None,
                     "by_tool": dict(tool_counts.most_common())},
        "top_tools": [{"tool": name, "calls": count} for name, count in tool_counts.most_common(8)],
        "limitations": [
            "Cumulative reported tokens are not equal to invoice cost.",
            "Cached tokens are included within input and must not be added twice.",
            "Repeated arguments do not prove wasted operations.",
            "A visual tool output's string length is not an image-token count.",
            "Success is user reported; source files do not verify technical completion.",
        ],
    }
    return result


def from_files(metrics_path: Path, timeline_path: Path | None = None,
               outcome: str = "unknown") -> dict:
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    timeline = json.loads(timeline_path.read_text(encoding="utf-8")) if timeline_path else None
    return analyze(metrics, timeline, outcome)
