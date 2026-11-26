"""Optional, append-only MCP observability. Records digests, never arguments or outputs.

Native client tools (Codex view_image / exec_command) are NOT intercepted.
Set OLIVA_WATCH=1 to enable; no telemetry is sent to a network service.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets

from .common import canonical, utc_now


def _salt(folder: Path) -> bytes:
    path = folder / ".salt"
    folder.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return path.read_bytes()
    with os.fdopen(fd, "wb") as stream:
        salt = secrets.token_bytes(32)
        stream.write(salt)
    return salt


def record(repo: Path, tool: str, arguments: dict, result: object, *, enabled: bool | None = None) -> bool:
    if enabled is None:
        enabled = os.environ.get("OLIVA_WATCH", "0") == "1"
    if not enabled:
        return False
    if not isinstance(tool, str) or not tool.isascii() or not tool.replace("_", "").isalnum():
        raise ValueError("tool name must be ASCII letters/digits/underscores")
    folder = repo / "work" / "efficiency"
    salt = _salt(folder)
    args = canonical(arguments)
    output = canonical(result)
    signature = lambda data: hashlib.sha256(salt + data).hexdigest()
    # No target name, command, arguments or tool output are written, only hashes.
    row = {"at": utc_now(), "tool": tool, "args_sig": signature(args),
           "result_sig": signature(output), "result_chars": len(output.decode("utf-8")),
           "token_estimate": (len(output) + 3) // 4, "source": "mcp"}
    file = folder / "mcp_events.jsonl"
    fd = os.open(str(file), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    return True


def summarize(repo: Path, repeat_threshold: int = 3) -> dict:
    if type(repeat_threshold) is not int or not 2 <= repeat_threshold <= 20:
        raise ValueError("repeat_threshold must be 2..20")
    file = repo / "work" / "efficiency" / "mcp_events.jsonl"
    if not file.is_file():
        return {"mcp_calls": 0, "repeated_same_input_and_output": 0, "patterns": []}
    calls = 0
    repeats = 0
    prev = None
    streak = 0
    patterns = {}
    with file.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except (ValueError, TypeError):
                continue
            calls += 1
            key = (row.get("tool"), row.get("args_sig"), row.get("result_sig"))
            if key == prev:
                streak += 1
                repeats += 1
            else:
                streak = 1
            if streak == repeat_threshold:
                patterns[key] = patterns.get(key, 0) + 1
            prev = key
    return {"mcp_calls": calls, "repeated_same_input_and_output": repeats,
            "patterns": [{"tool": key[0], "streaks_reaching_threshold": count}
                         for key, count in sorted(patterns.items())],
            "note": "Passive consecutive repeat alerts. Dynamic polling may be intentional; never blocks calls."}
