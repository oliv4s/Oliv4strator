"""Reusable pentest decision methods, separate from per-target evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

import casebook


PHASES = {"recon", "enumeration", "validation", "code_review", "initial_access", "post_access", "privilege_escalation"}
RESULTS = {"supported", "refuted", "inconclusive"}
METHOD_ID = re.compile(r"m-[0-9a-f]{12}\Z")
TECHNOLOGY = re.compile(r"[a-z0-9][a-z0-9_.-]{1,39}\Z")
PRIVATE_DETAIL = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|HTB\{|(?i:password|passwd|token|secret|flag)\s*[:=]|\bCVE-\d{4}-\d{4,}\b", re.I)
FIELDS = {"signal": (12, 220), "question": (12, 180), "test": (12, 300),
          "supports": (8, 220), "refutes": (8, 220),
          "next_if_supported": (8, 250), "next_if_refuted": (8, 250),
          "pitfall": (0, 220)}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: object, name: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValueError(f"{name}: usa entre {minimum} y {maximum} caracteres")
    cleaned = value.strip()
    if PRIVATE_DETAIL.search(cleaned):
        raise ValueError("La metodología no debe guardar IP, CVE concreto, secretos ni flags")
    return cleaned


def _technology(value: object) -> str:
    if not isinstance(value, str) or not TECHNOLOGY.fullmatch(value.lower()):
        raise ValueError("technology debe ser un servicio, plataforma o 'any'")
    return value.lower()


def methods(root: Path) -> list[dict]:
    path = root / "memory" / "methods.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Biblioteca metodológica inválida")
    return data


def relevant(root: Path, technologies: set[str] | None = None, phase: str | None = None,
             limit: int = 12) -> list[dict]:
    if phase is not None and phase not in PHASES:
        raise ValueError("Fase metodológica inválida")
    names = {name.lower() for name in technologies} if technologies is not None else None
    matches = [row for row in methods(root)
               if (phase is None or row["phase"] == phase) and
               (names is None or row["technology"] in names or row["technology"] == "any")]
    return sorted(matches, key=lambda row: (row.get("observations", 0), row.get("updated_at", "")),
                  reverse=True)[:limit]


def _evidence(value: object, known: set[str]) -> str:
    if not isinstance(value, str) or not casebook.EVIDENCE_ID.fullmatch(value) or value not in known:
        raise ValueError("Indica un evidence_id real del caso actual")
    return value


def record(root: Path, ip: str, request: dict, known: set[str]) -> dict:
    action = request.get("action")
    result = request.get("result")
    if result not in RESULTS:
        raise ValueError("result debe ser supported, refuted o inconclusive")
    evidence = _evidence(request.get("evidence_id"), known)
    stored = methods(root)
    if action == "add":
        phase = request.get("phase")
        if phase not in PHASES:
            raise ValueError("Fase metodológica inválida")
        technology = _technology(request.get("technology", "any"))
        fields = {name: _text(request.get(name, "") if name == "pitfall" else request.get(name),
                              name, *limits) for name, limits in FIELDS.items()}
        identity = "m-" + hashlib.sha256(json.dumps(
            [phase, technology, fields["signal"].casefold(), fields["question"].casefold()],
            ensure_ascii=False).encode("utf-8")).hexdigest()[:12]
        item = next((row for row in stored if row["method_id"] == identity), None)
        if item is None:
            if len(stored) >= 500:
                raise ValueError("Biblioteca metodológica completa; revisa duplicados")
            item = {"method_id": identity, "phase": phase, "technology": technology,
                    **fields, "observations": 0, "results": {key: 0 for key in RESULTS},
                    "status": "candidate", "created_at": _now(), "updated_at": _now()}
            stored.append(item)
    elif action == "observe":
        identifier = request.get("method_id")
        if not isinstance(identifier, str) or not METHOD_ID.fullmatch(identifier):
            raise ValueError("method_id inválido")
        item = next((row for row in stored if row["method_id"] == identifier), None)
        if item is None:
            raise ValueError("Método no encontrado")
    else:
        raise ValueError("Usa action add u observe")

    links_path = casebook.case_dir(root, ip) / "method_feedback.json"
    links = json.loads(links_path.read_text(encoding="utf-8")) if links_path.exists() else []
    if not isinstance(links, list):
        raise ValueError("Referencias metodológicas del caso inválidas")
    duplicate = any(row.get("method_id") == item["method_id"] and row.get("evidence_id") == evidence
                    for row in links)
    if not duplicate:
        links.append({"method_id": item["method_id"], "evidence_id": evidence,
                      "result": result, "at": _now()})
        casebook.atomic_json(links_path, links)
        item["observations"] += 1
        item.setdefault("results", {key: 0 for key in RESULTS})[result] += 1
        item["updated_at"] = _now()
        casebook.atomic_json(root / "memory" / "methods.json", stored)
        casebook.record_event(root, ip, "method_feedback",
                              {"method_id": item["method_id"], "evidence_id": evidence,
                               "result": result})
    return {"method": item, "existing_evidence": duplicate,
            "note": "Método candidato: comprobar la señal y la interpretación en cada contexto"}
