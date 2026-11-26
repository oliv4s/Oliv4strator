"""Opt-in, minimal MCP lifecycle journal for diagnosing stalled calls.

Records tool name, random call ID, timestamps and outcome. Never writes
arguments, responses, targets or credentials. No tracing sent to network.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import time
from uuid import uuid4

from .common import utc_now


def enabled() -> bool:
    return os.environ.get('OLIVA_TRACE_MCP', '0') == '1'


def _write(repo: Path, event: dict) -> None:
    folder = repo / 'work' / 'efficiency'
    folder.mkdir(parents=True, exist_ok=True)
    file = folder / 'mcp_lifecycle.jsonl'
    fd = os.open(file, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(event, separators=(',', ':')) + '\n').encode('utf-8'))
    finally:
        os.close(fd)


def start(repo: Path, tool_name: str) -> tuple[str, float] | None:
    if not enabled():
        return None
    if not tool_name or not tool_name.isascii() or not tool_name.replace('_','').isalnum():
        tool_name = 'unknown'
    call_id = uuid4().hex
    _write(repo, {'event': 'started', 'id': call_id, 'tool': tool_name, 'at': utc_now()})
    return call_id, time.monotonic()


def finish(repo: Path, marker: tuple[str, float] | None, *, error: bool = False) -> None:
    if marker is None:
        return
    call_id, start_clock = marker
    _write(repo, {'event': 'finished', 'id': call_id, 'at': utc_now(),
                  'duration_ms': round((time.monotonic() - start_clock) * 1000), 'error': error})
