"""Small, standard-library-only storage helpers."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$")


def safe_id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError("identifier must contain only letters, digits, _, -, or . (max 80)")
    return value


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path: Path, fallback: object) -> object:
    if not path.is_file():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
