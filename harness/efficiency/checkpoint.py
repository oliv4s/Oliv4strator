"""Explicit, versioned case checkpoints containing small references only.

No external actions. Checkpoints DO NOT authorize tool use and never replace
scope checks. Original casebook remains authoritative. No raw evidence,
credentials, shell outputs, HTTP bodies, or target details are accepted.
"""
from __future__ import annotations

from pathlib import Path
from .common import atomic_json, read_json, safe_id, utc_now

_VALID_STATES = {"open", "paused", "closed", "archived", "unconfigured"}


def _rows(rows: object, kind: str, max_rows: int = 32) -> list[dict]:
    if not isinstance(rows, list) or len(rows) > max_rows:
        raise ValueError(f"{kind} must be a list with at most {max_rows} items")
    out = []
    for row in rows:
        if not isinstance(row, dict) or set(row) - {"id", "evidence_ids", "note"}:
            raise ValueError(f"{kind} allows only id, evidence_ids, note")
        item = {"id": safe_id(row.get("id"))}
        evidence = row.get("evidence_ids", [])
        if not isinstance(evidence, list) or len(evidence) > 12:
            raise ValueError("evidence_ids must be a list of up to 12 IDs")
        item["evidence_ids"] = [safe_id(x) for x in evidence]
        note = row.get("note", "")
        if not isinstance(note, str) or len(note) > 160 or "\n" in note:
            raise ValueError("note must be a single line of up to 160 characters")
        # Notes are optional and must be reviewed to avoid writing secrets.
        if note:
            item["note"] = note
        out.append(item)
    if len({x["id"] for x in out}) != len(out):
        raise ValueError("duplicate IDs in " + kind)
    return out


def store_path(repo: Path, case_id: str) -> Path:
    return repo / "work" / "efficiency" / "checkpoints" / f"{safe_id(case_id)}.json"


def save(repo: Path, case_id: str, payload: dict, expected_revision: int | None = None) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("checkpoint payload must be an object")
    allowed = {"state", "facts", "decisions", "pending"}
    if set(payload) - allowed:
        raise ValueError("unsupported checkpoint fields; only references and notes permitted")
    state = payload.get("state", "open")
    if state not in _VALID_STATES:
        raise ValueError("invalid case state")
    path = store_path(repo, case_id)
    previous = read_json(path, {})
    revision = previous.get("revision", 0)
    if expected_revision is not None and (type(expected_revision) is not int or revision != expected_revision):
        raise ValueError("checkpoint revision mismatch; refresh before writing")
    rows = {k: _rows(payload.get(k, []), k) for k in ("facts", "decisions", "pending")}
    # Compare only meaningful state, excluding revision and timestamp. A save with
    # identical meaning must not increase revisions or rewrite the file.
    if previous and previous.get("state") == state and all(previous.get(k) == v for k, v in rows.items()):
        return {"case_id": safe_id(case_id), "revision": revision, "state": state,
                "changed": False, "counts": {k: len(v) for k, v in rows.items()}}
    record = {
        "schema": "oliva-checkpoint-v2", "case_id": safe_id(case_id),
        "revision": revision + 1, "updated_at": utc_now(), "state": state,
        **rows,
        "authorization": "not_granted_by_checkpoint",
    }
    atomic_json(path, record)
    return {"case_id": record["case_id"], "revision": record["revision"], "state": state,
            "changed": True, "counts": {k: len(record[k]) for k in ("facts", "decisions", "pending")}}


def load(repo: Path, case_id: str, mode: str = "summary", max_items: int = 10) -> dict:
    if mode not in {"summary", "details"}:
        raise ValueError("mode must be summary or details")
    if type(max_items) is not int or not 1 <= max_items <= 32:
        raise ValueError("max_items must be an integer 1..32")
    record = read_json(store_path(repo, case_id), None)
    if record is None:
        return {"case_id": safe_id(case_id), "exists": False}
    result = {
        "case_id": record["case_id"], "exists": True,
        "revision": record["revision"], "state": record["state"],
        "counts": {k: len(record[k]) for k in ("facts", "decisions", "pending")},
        "authorization": "not_granted_by_checkpoint",
    }
    for field in ("facts", "decisions", "pending"):
        selected = record[field][:max_items]
        result[field] = selected if mode == "details" else [row["id"] for row in selected]
        result[field + "_more"] = len(record[field]) > max_items
    return result
