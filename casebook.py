"""Durable, per-target evidence and hypotheses for IP and web labs."""

from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import fcntl
import time
import ipaddress
import json
import os
from pathlib import Path
import re
from uuid import uuid4


EVIDENCE_ID = re.compile(r"(?:[0-9a-f]{12}|[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12})\Z")
HYPOTHESIS_ID = re.compile(r"h-[0-9a-f]{12}\Z")
STATUSES = {"open", "supported", "rejected", "confirmed"}


def case_dir(root: Path, target_id: str) -> Path:
    if re.fullmatch(r"(?:web|program|code)-[0-9a-f]{16}", target_id):
        return root / "cases" / target_id
    address = ipaddress.ip_address(target_id)
    if address.version != 4 or address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("Dirección de caso inválida")
    return root / "cases" / str(address)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def record_event(root: Path, ip: str, kind: str, detail: dict) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    event_id = stamp + "-" + uuid4().hex[:12]
    item = {"event_id": event_id, "at": now(), "target_id": ip,
            "target_ip": None if ip.startswith(("web-", "program-", "code-")) else ip, "kind": kind, "detail": detail}
    atomic_json(case_dir(root, ip) / "events" / (event_id + ".json"), item)
    return item


def events(root: Path, ip: str, limit: int = 20) -> list[dict]:
    directory = case_dir(root, ip) / "events"
    if not directory.exists():
        return []
    found = []
    for path in sorted(directory.glob("*.json"))[-limit:]:
        try:
            found.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return found


def event_ids(root: Path, ip: str) -> set[str]:
    directory = case_dir(root, ip) / "events"
    return {path.stem for path in directory.glob("*.json")} if directory.exists() else set()


def hypotheses(root: Path, ip: str) -> list[dict]:
    path = case_dir(root, ip) / "hypotheses.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Expediente de hipótesis inválido")
    return data


def _text(value: object, label: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValueError(f"{label}: usa entre {minimum} y {maximum} caracteres")
    return value.strip()


def _evidence(value: object, known: set[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > 10:
        raise ValueError("evidence_ids debe ser una lista de hasta 10 IDs")
    result = []
    for item in value:
        if not isinstance(item, str) or not EVIDENCE_ID.fullmatch(item) or item not in known:
            raise ValueError("Referencia de evidencia no encontrada en este caso")
        if item not in result:
            result.append(item)
    return result


@contextmanager
def hypothesis_lock(root: Path, target_id: str, timeout_seconds: float = 5.0):
    """Bounded, cross-process advisory lock for hypothesis file mutations on POSIX.

    Does not govern tools or external actions. A long wait fails rather than
    blocking the entire MCP indefinitely. Lock file remains between calls.
    """
    parent = case_dir(root, target_id)
    parent.mkdir(parents=True, exist_ok=True)
    path = parent / ".hypotheses.lock"
    if path.is_symlink():
        raise ValueError("Hypothesis lock path must not be a symlink")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        start = time.monotonic()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() - start > timeout_seconds:
                    raise TimeoutError("hypothesis update busy: lock acquisition exceeded 5 seconds")
                time.sleep(0.04)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def change_hypothesis(root: Path, ip: str, request: dict, known_evidence: set[str]) -> dict:
    with hypothesis_lock(root, ip):
        return _change_hypothesis_unlocked(root, ip, request, known_evidence)


def _change_hypothesis_unlocked(root: Path, ip: str, request: dict, known_evidence: set[str]) -> dict:
    action = request.get("action")
    current = hypotheses(root, ip)
    if action == "propose":
        claim = _text(request.get("claim"), "claim", 12, 240)
        expected = _text(request.get("expected"), "expected", 8, 240)
        next_test = _text(request.get("next_test"), "next_test", 8, 300)
        confidence = request.get("confidence", "low")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError("Confianza inválida")
        evidence = _evidence(request.get("evidence_ids", []), known_evidence)
        if not evidence:
            raise ValueError("Una hipótesis necesita al menos un evidence_id observado")
        if confidence == "high" and len(evidence) < 2:
            raise ValueError("Confianza alta requiere dos evidencias observadas distintas")
        existing = next((row for row in current if row["claim"].casefold() == claim.casefold() and
                         row["status"] != "rejected"), None)
        if existing:
            return {"hypothesis": existing, "existing": True}
        if sum(bool(row["status"] in {"open", "supported"} and row.get("evidence_ids")) for row in current) >= 4:
            raise ValueError("Hay cuatro hipótesis activas con evidencia; valora o cierra una antes de abrir otra")
        if len(current) >= 200:
            raise ValueError("Máximo de 200 hipótesis por caso")
        item = {"hypothesis_id": "h-" + uuid4().hex[:12], "claim": claim, "expected": expected,
                "next_test": next_test, "confidence": confidence, "status": "open",
                "evidence_ids": evidence, "note": "", "created_at": now(), "updated_at": now()}
        current.append(item)
    elif action == "assess":
        identifier = request.get("hypothesis_id")
        if not isinstance(identifier, str) or not HYPOTHESIS_ID.fullmatch(identifier):
            raise ValueError("hypothesis_id inválido")
        item = next((row for row in current if row["hypothesis_id"] == identifier), None)
        if item is None:
            raise ValueError("Hipótesis no encontrada en este caso")
        status = request.get("status")
        if status not in STATUSES:
            raise ValueError("Estado de hipótesis inválido")
        evidence = _evidence(request.get("evidence_ids", []), known_evidence)
        note = _text(request.get("note"), "note", 8, 300)
        # Retry-safe if the preceding call committed before Codex received it.
        if (item["status"] == status and item.get("note", "") == note
                and set(evidence).issubset(item.get("evidence_ids", []))):
            return {"hypothesis": item, "existing": True}
        if status != "open" and not evidence:
            raise ValueError("Una valoración necesita evidencia nueva")
        if status != "open" and not any(identifier not in item["evidence_ids"] for identifier in evidence):
            raise ValueError("Una valoración necesita un evidence_id posterior distinto")
        item["status"] = status
        item["evidence_ids"] = list(dict.fromkeys(item["evidence_ids"] + evidence))[-20:]
        item["note"] = note
        item["updated_at"] = now()
    else:
        raise ValueError("Usa action propose o assess")
    atomic_json(case_dir(root, ip) / "hypotheses.json", current)
    return {"hypothesis": item, "existing": False}


def summary(root: Path, ip: str) -> dict:
    current = hypotheses(root, ip)
    counts = {state: sum(row["status"] == state for row in current) for state in STATUSES}
    return {"target_id": ip, "target_ip": None if ip.startswith(("web-", "program-", "code-")) else ip, "counts": counts,
            "active_hypotheses": [row for row in current if row["status"] in {"open", "supported"}][-12:],
            "recent_events": events(root, ip, 12)}
