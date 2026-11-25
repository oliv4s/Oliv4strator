"""Local, reviewable minimal-PoC records for a bug bounty program."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from uuid import uuid4

import casebook
import program_policy
import scope_target


FINDING_ID = re.compile(r"f-[0-9a-f]{12}\Z")
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
AUTH = re.compile(r"(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)\S+")
COOKIE = re.compile(r"(?i)(Cookie\s*:\s*)[^\r\n]+")
SECRET = re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)=([^\s&;'\"]+)")


def _text(value: object, name: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValueError(f"{name} debe tener entre {minimum} y {maximum} caracteres")
    value = value.strip()
    value = AUTH.sub(r"\1[REDACTED]", value)
    value = COOKIE.sub(r"\1[REDACTED]", value)
    value = SECRET.sub(r"\1=[REDACTED]", value)
    return EMAIL.sub("[REDACTED_EMAIL]", value)


def _folder(root: Path, scope: dict) -> Path:
    identifier = scope_target.active_case_id(scope)
    if not identifier or not identifier.startswith(("program-", "code-")):
        raise ValueError("Activa primero un programa bug bounty")
    return casebook.case_dir(root, identifier) / "findings"


def add(root: Path, scope: dict, policy: dict, request: dict,
        known_attempt_ids: set[str]) -> dict:
    decision = program_policy.evaluate(policy, request.get("affected_url"),
                                       request.get("surface"), request.get("basis"))
    if decision["decision"] != "allow":
        raise ValueError("El hallazgo debe afectar a un activo autorizado: " + decision["reason"])
    evidence = request.get("confirming_attempt_ids")
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 2 or \
            not all(isinstance(item, str) and item in known_attempt_ids for item in evidence) or \
            len(evidence) != len(set(evidence)):
        raise ValueError("Cita uno o dos elementos de evidencia decisiva de este expediente")
    steps = request.get("reproduction_steps")
    if not isinstance(steps, list) or not 2 <= len(steps) <= 20:
        raise ValueError("Documenta entre 2 y 20 pasos de reproducción")
    steps = [_text(step, "Paso", 8, 2000) for step in steps]
    item = {
        "finding_id": "f-" + uuid4().hex[:12],
        "program_id": scope["program_id"],
        "policy_sha256": scope["program_policy_sha256"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "verified_minimal_poc",
        "title": _text(request.get("title"), "Título", 8, 160),
        "category": _text(request.get("category"), "Categoría", 3, 100),
        "affected_url": decision["url"],
        "proof": _text(request.get("proof"), "Prueba observada", 20, 2000),
        "impact_hypothesis": _text(request.get("impact_hypothesis"), "Impacto posible", 12, 1500),
        "technical_reproduction": _text(request.get("technical_reproduction"),
                                         "Solicitud, comando o secuencia técnica", 20, 4000),
        "reproduction_steps": steps,
        "confirming_attempt_ids": evidence,
        "further_impact_validation": "requires_separate_human_request",
        "submission": "manual_review_pending",
    }
    folder = _folder(root, scope)
    folder.mkdir(parents=True, exist_ok=True)
    casebook.atomic_json(folder / (item["finding_id"] + ".json"), item)
    markdown = ["# " + item["title"], "", "Estado: PoC mínima verificada; informe pendiente de revisión.",
                "", "## Activo y tipo", "", item["affected_url"], "", item["category"],
                "", "## Reproducción", ""]
    for index, step in enumerate(steps, 1):
        markdown.append(f"{index}. " + step.replace("\n", "\n   "))
    markdown += ["", "## Solicitud, comando o secuencia técnica", "",
                 "    " + item["technical_reproduction"].replace("\n", "\n    "),
                 "", "## Prueba observada", "", item["proof"],
                 "", "## Impacto posible", "", item["impact_hypothesis"],
                 "", "## Evidencias decisivas", "", ", ".join(evidence),
                 "", "## Capturas", "", "Pendiente de adjuntar manualmente si el programa las exige.",
                 "", "Revisar y completar manualmente antes de enviar el reporte.\n"]
    (folder / (item["finding_id"] + ".md")).write_text("\n".join(markdown), encoding="utf-8")
    return {"finding_id": item["finding_id"], "status": item["status"],
            "report_file": str(folder / (item["finding_id"] + ".md")),
            "next_action": "Detén las pruebas de este hallazgo; solicita una decisión humana para validar más impacto"}


def add_code(root: Path, scope: dict, policy: dict, request: dict,
             known_evidence_ids: set[str]) -> dict:
    decision = program_policy.evaluate_code(policy, request.get("repository_url") or scope.get("repository_url"))
    if decision["decision"] != "allow" or decision["repository_url"] != scope.get("repository_url"):
        raise ValueError("El hallazgo debe afectar al repositorio activo autorizado")
    evidence = request.get("confirming_evidence_ids")
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 10 or \
            len(evidence) != len(set(evidence)) or \
            not all(isinstance(item, str) and item in known_evidence_ids for item in evidence):
        raise ValueError("Cita entre uno y diez eventos o intentos reales del expediente")
    steps = request.get("reproduction_steps")
    if not isinstance(steps, list) or not 2 <= len(steps) <= 30:
        raise ValueError("Documenta entre 2 y 30 pasos de reproducción")
    steps = [_text(step, "Paso", 8, 2000) for step in steps]
    item = {
        "finding_id": "f-" + uuid4().hex[:12],
        "program_id": scope["program_id"],
        "profile": "BB-Code",
        "policy_sha256": scope["program_policy_sha256"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "verified_local_poc",
        "title": _text(request.get("title"), "Título", 8, 160),
        "category": _text(request.get("category"), "Categoría", 3, 100),
        "affected_url": decision["repository_url"],
        "affected_version": _text(request.get("affected_version"), "Versión o revisión", 1, 200),
        "source_location": _text(request.get("source_location"), "Archivo y función", 3, 500),
        "conditions": _text(request.get("conditions"), "Condiciones de explotación", 12, 2000),
        "proof": _text(request.get("proof"), "Efecto observado", 20, 3000),
        "impact_hypothesis": _text(request.get("impact_hypothesis"), "Impacto posible", 12, 2000),
        "technical_reproduction": _text(request.get("technical_reproduction"),
                                        "Comandos o código de reproducción", 20, 6000),
        "reproduction_steps": steps,
        "confirming_evidence_ids": evidence,
        "related_advisories": _text(request.get("related_advisories"),
                                    "Avisos relacionados y búsqueda previa", 30, 1200),
        "submission": "manual_review_pending",
    }
    folder = _folder(root, scope)
    folder.mkdir(parents=True, exist_ok=True)
    casebook.atomic_json(folder / (item["finding_id"] + ".json"), item)
    markdown = ["# " + item["title"], "", "Estado: PoC local verificada; informe pendiente de revisión.",
                "", "## Repositorio, versión y ubicación", "", item["affected_url"],
                "", item["affected_version"], "", item["source_location"],
                "", "## Condiciones de explotación", "", item["conditions"],
                "", "## Pasos de reproducción", ""]
    markdown.extend(f"{index}. {step}" for index, step in enumerate(steps, 1))
    markdown += ["", "## Comandos o código", "", "    " + item["technical_reproduction"].replace("\n", "\n    "),
                 "", "## Efecto observado", "", item["proof"],
                 "", "## Impacto posible y límites", "", item["impact_hypothesis"],
                 "", "## Avisos previos y posible duplicado", "", item["related_advisories"],
                 "", "## Evidencia local", "", ", ".join(evidence),
                 "", "Revisar y completar manualmente antes de enviar el reporte.\n"]
    (folder / (item["finding_id"] + ".md")).write_text("\n".join(markdown), encoding="utf-8")
    return {"finding_id": item["finding_id"], "status": item["status"],
            "report_file": str(folder / (item["finding_id"] + ".md")),
            "next_action": "Revisa el borrador y continúa con otras causas raíz independientes"}


def view(root: Path, scope: dict, finding_id: str | None = None) -> dict:
    folder = _folder(root, scope)
    if finding_id is not None:
        if not isinstance(finding_id, str) or not FINDING_ID.fullmatch(finding_id):
            raise ValueError("finding_id inválido")
        path = folder / (finding_id + ".json")
        item = json.loads(path.read_text(encoding="utf-8"))
        return item
    items = []
    for path in sorted(folder.glob("f-*.json")) if folder.exists() else []:
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
            items.append({key: row.get(key) for key in
                          ("finding_id", "title", "category", "affected_url", "created_at", "status", "profile")})
        except (OSError, ValueError):
            continue
    return {"total": len(items), "findings": items}
