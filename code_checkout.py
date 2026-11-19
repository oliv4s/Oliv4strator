"""Read-only provenance checks for a BB-Code checkout."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess

import scope_target


SSH_REMOTE = re.compile(r"git@([A-Za-z0-9.-]+):(.+)\Z")


def canonical_remote(value: str | None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    match = SSH_REMOTE.fullmatch(value)
    if match:
        value = f"https://{match.group(1)}/{match.group(2)}"
    if value.endswith(".git"):
        value = value[:-4]
    try:
        origin, path = scope_target.web_url(value)
    except ValueError:
        return None
    if not origin.startswith("https://") or path == "/" or "?" in path:
        return None
    return origin + path.rstrip("/")


def _git(checkout: Path, *args: str) -> str | None:
    try:
        run = subprocess.run(["git", "-C", str(checkout), *args], capture_output=True,
                             text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return run.stdout.strip() if run.returncode == 0 else None


def inspect(checkout: Path, repository_url: str) -> dict:
    top = _git(checkout, "rev-parse", "--show-toplevel")
    if not top:
        return {"git_repository": False, "checkout_path": str(checkout),
                "repository_url": repository_url, "matches_scope": None,
                "revision": None, "remote_origin": None}
    remote = _git(checkout, "remote", "get-url", "origin")
    normalized = canonical_remote(remote)
    return {"git_repository": True, "checkout_path": str(checkout),
            "repository_url": repository_url, "matches_scope":
            normalized == repository_url if normalized else None,
            "revision": _git(checkout, "rev-parse", "HEAD"),
            "remote_origin": normalized}
