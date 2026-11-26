"""Optional profile tool filtering and neutral MCP naming.

Both features are opt-in and fixed at MCP startup. Neither is a security
boundary; underlying scope authorization remains in the original bridge.
"""
from __future__ import annotations

import os

COMMON = {
    "oliva_checkpoint", "oliva_artifact", "oliva_visual", "oliva_progress",
    "oliva_context", "lab_status", "lab_case", "lab_attempts", "lab_review",
    "lab_hypothesis", "lab_focus", "lab_memory", "lab_method", "lab_text",
    "lab_evidence", "lab_scope", "lab_program_status", "lab_program_check",
    "lab_program_activate",
}
PROFILE_TOOLS = {
    "LAB": {"lab_preflight", "lab_scan", "lab_http", "lab_web_http",
            "lab_tcp", "lab_pcap", "lab_ssh", "lab_ssh_probe"},
    "BB-Web": {"lab_program_http", "lab_program_discover", "lab_program_paths",
               "lab_program_finding", "lab_program_findings"},
    "BB-Code": {"lab_code_status", "lab_code_finding", "lab_program_findings"},
}


def canonical_name(name: str) -> str:
    """Map a public, generic oliva_* alias onto the stable legacy name."""
    if name in {"oliva_context", "oliva_checkpoint", "oliva_artifact", "oliva_visual", "oliva_progress"}:
        return name
    if name.startswith("oliva_"):
        return "lab_" + name.removeprefix("oliva_")
    return name


def public_name(name: str, style: str) -> str:
    if style == "generic" and name.startswith("lab_"):
        return "oliva_" + name.removeprefix("lab_")
    return name


def visible(tools: list[dict], profile: str | None = None,
            names: str | None = None) -> list[dict]:
    """Return unchanged tool list by default, optionally filter and alias."""
    selected = os.environ.get("OLIVA_MCP_PROFILE", "").strip() if profile is None else profile
    style = os.environ.get("OLIVA_MCP_NAMES", "legacy").strip() if names is None else names
    if style not in {"legacy", "generic"}:
        raise ValueError("OLIVA_MCP_NAMES must be legacy or generic")
    if selected and selected.lower() != "all" and selected not in PROFILE_TOOLS:
        raise ValueError("OLIVA_MCP_PROFILE must be LAB, BB-Web, BB-Code, or all")
    allowed = (COMMON | PROFILE_TOOLS[selected]) if selected in PROFILE_TOOLS else None
    filtered = [item for item in tools if allowed is None or item["name"] in allowed]
    if style == "legacy":
        return filtered
    return [{**item, "name": public_name(item["name"], style)} for item in filtered]
