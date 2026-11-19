"""Optional investigation branches and advisory progress for a lab case."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys

import casebook
import scope_target


AVENUES = {
    "recon", "authentication", "authorization", "input_validation",
    "file_handling", "business_logic", "cryptography", "initial_access",
    "post_access", "privilege_escalation", "other",
}
ACTION_KINDS = {"shell", "lab_attempt"}
KEY = re.compile(r"[a-z][a-z0-9_-]{2,49}\Z")
BASE_ACTIONS = 18
BASE_MINUTES = 20
EXTENSION_ACTIONS = 8
EXTENSION_MINUTES = 10


def now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(value: datetime) -> str:
    return value.isoformat()


def active_id(root: Path) -> str | None:
    try:
        data = json.loads((root / "scope.json").read_text(encoding="utf-8"))
        return scope_target.active_case_id(data)
    except (OSError, ValueError, TypeError):
        return None


def path(root: Path, target_id: str) -> Path:
    return casebook.case_dir(root, target_id) / "focus.json"


def load(root: Path, target_id: str) -> dict | None:
    file = path(root, target_id)
    if not file.exists():
        return None
    data = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("target_id") != target_id:
        raise ValueError("Estado de investigación inválido para este destino")
    return data


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _events_since(root: Path, target_id: str, start: str) -> list[dict]:
    folder = casebook.case_dir(root, target_id) / "events"
    if not folder.exists():
        return []
    result = []
    # Event filenames are UTC sortable. Avoid opening the whole case history on
    # every tool call, especially on the Windows-mounted WSL filesystem.
    earliest = (_datetime(start) - timedelta(seconds=1)).strftime("%Y%m%dT%H%M%SZ")
    for file in folder.glob("*.json"):
        if file.name[:16] < earliest:
            continue
        try:
            row = json.loads(file.read_text(encoding="utf-8"))
            if row.get("kind") in ACTION_KINDS and _datetime(row["at"]) >= _datetime(start):
                result.append(row)
        except (OSError, ValueError, TypeError, KeyError):
            continue
    return result


def status(root: Path, target_id: str) -> dict:
    state = load(root, target_id)
    if state is None or not state.get("active"):
        return {"target_id": target_id, "active": False, "needs_focus": True,
                "message": "Puedes abrir una línea con lab_focus si ayuda a organizar la investigación."}
    used = sum(row["event_id"] != state.get("baseline_evidence_id")
               for row in _events_since(root, target_id, state["started_at"]))
    remaining_calls = max(0, state["max_actions"] - used)
    remaining_seconds = max(0, int((_datetime(state["expires_at"]) - now()).total_seconds()))
    exhausted = remaining_calls == 0 or remaining_seconds == 0
    return {"target_id": target_id, "active": True,
            "avenue": state["avenue"], "branch_key": state["branch_key"],
            "question": state["question"], "test": state["test"],
            "expected": state["expected"], "basis": state["basis"],
            "used_actions": used, "remaining_actions": remaining_calls,
            "remaining_seconds": remaining_seconds, "exhausted": exhausted,
            "extensions": state.get("extensions", 0),
            "history": state.get("history", [])[-4:],
            "message": ("Tiempo o acciones orientativas agotadas. Revisa la evidencia y decide si continuar o pivotar."
                        if exhausted else "Continúa con la prueba discriminante y registra el resultado.")}


def enforce(root: Path, target_id: str) -> None:
    current = status(root, target_id)
    if not current["active"]:
        raise ValueError("Falta una línea de investigación. Llama lab_focus(action=start) con pregunta, evidencia y prueba.")
    if current["exhausted"]:
        raise ValueError(
            f"Línea '{current['branch_key']}' agotada ({current['used_actions']} acciones). "
            "Resume el resultado y llama lab_focus(action=pivot) con una prueba diferente. "
            "Solo puedes ampliarla una vez si citas evidencia nueva con lab_focus(action=extend)."
        )


def _text(request: dict, name: str, minimum: int, maximum: int = 280) -> str:
    value = request.get(name)
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValueError(f"{name}: escribe entre {minimum} y {maximum} caracteres")
    return value.strip()


def _evidence_after(root: Path, target_id: str, evidence_id: str, started_at: str) -> bool:
    if not isinstance(evidence_id, str) or not casebook.EVIDENCE_ID.fullmatch(evidence_id):
        return False
    file = casebook.case_dir(root, target_id) / "events" / (evidence_id + ".json")
    try:
        item = json.loads(file.read_text(encoding="utf-8"))
        return (item.get("kind") in ACTION_KINDS and
                _datetime(item["at"]) >= _datetime(started_at))
    except (OSError, ValueError, TypeError, KeyError):
        return False


def change(root: Path, target_id: str, request: dict) -> dict:
    action = request.get("action")
    if action == "status":
        return status(root, target_id)
    previous = load(root, target_id)
    if action in {"start", "pivot"}:
        if action == "start" and previous and previous.get("active"):
            raise ValueError("Ya hay una línea activa; usa action=pivot para cambiarla")
        if action == "pivot" and (not previous or not previous.get("active")):
            raise ValueError("No hay línea activa; usa action=start")
        avenue = request.get("avenue")
        if avenue not in AVENUES:
            raise ValueError("avenue inválida")
        key = request.get("branch_key")
        if not isinstance(key, str) or not KEY.fullmatch(key):
            raise ValueError("branch_key debe ser un identificador distinto en minúsculas")
        question = _text(request, "question", 15)
        test = _text(request, "test", 15)
        expected = _text(request, "expected", 12)
        basis = _text(request, "basis", 12)
        history = list(previous.get("history", [])) if previous else []
        if action == "pivot":
            if key == previous["branch_key"] or question.casefold() == previous["question"].casefold():
                raise ValueError("El pivot necesita una pregunta y branch_key diferentes")
            prior_result = _text(request, "prior_result", 20)
            if avenue == previous["avenue"] and status(root, target_id)["exhausted"]:
                if not _evidence_after(root, target_id, request.get("evidence_id"), previous["started_at"]):
                    raise ValueError("Tras agotar esta vía, seguir en la misma área requiere un event_id nuevo")
                _text(request, "new_observation", 20)
            history.append({"avenue": previous["avenue"], "branch_key": previous["branch_key"],
                            "question": previous["question"], "result": prior_result,
                            "used_actions": status(root, target_id)["used_actions"], "ended_at": stamp(now())})
            if key in {row["branch_key"] for row in history[-4:]}:
                raise ValueError("Esa línea se probó recientemente; elige una prueba nueva")
        time = now()
        state = {"target_id": target_id, "active": True, "avenue": avenue,
                 "branch_key": key, "question": question, "test": test,
                 "expected": expected, "basis": basis, "started_at": stamp(time),
                 "expires_at": stamp(time + timedelta(minutes=BASE_MINUTES)),
                 "max_actions": BASE_ACTIONS, "extensions": 0, "history": history[-30:]}
        casebook.atomic_json(path(root, target_id), state)
        casebook.record_event(root, target_id, "focus", {"action": action,
                              "avenue": avenue, "branch_key": key})
        return status(root, target_id)
    if action == "extend":
        if not previous or not previous.get("active"):
            raise ValueError("No hay línea activa")
        if previous.get("extensions", 0) >= 1:
            raise ValueError("Esta línea ya recibió su única ampliación; cambia de hipótesis")
        evidence_id = request.get("evidence_id")
        if not _evidence_after(root, target_id, evidence_id, previous["started_at"]):
            raise ValueError("La ampliación requiere un event_id nuevo de esta línea")
        _text(request, "new_observation", 20)
        _text(request, "test", 15)
        previous["test"] = request["test"].strip()
        previous["started_at"] = stamp(now())
        previous["expires_at"] = stamp(now() + timedelta(minutes=EXTENSION_MINUTES))
        previous["max_actions"] = EXTENSION_ACTIONS
        previous["extensions"] = 1
        previous["baseline_evidence_id"] = evidence_id
        casebook.atomic_json(path(root, target_id), previous)
        casebook.record_event(root, target_id, "focus", {"action": action,
                              "branch_key": previous["branch_key"], "evidence_id": evidence_id})
        return status(root, target_id)
    if action == "close":
        if not previous or not previous.get("active"):
            raise ValueError("No hay línea activa")
        result = _text(request, "prior_result", 20)
        previous["history"].append({"avenue": previous["avenue"],
                                    "branch_key": previous["branch_key"], "result": result,
                                    "used_actions": status(root, target_id)["used_actions"],
                                    "ended_at": stamp(now())})
        previous["active"] = False
        casebook.atomic_json(path(root, target_id), previous)
        casebook.record_event(root, target_id, "focus", {"action": action,
                              "branch_key": previous["branch_key"]})
        return status(root, target_id)
    raise ValueError("Usa action status, start, pivot, extend o close")


def main() -> int:
    root = Path(__file__).resolve().parent
    target_id = active_id(root)
    if target_id is None:
        print("Sin objetivo activo")
        return 0
    try:
        enforce(root, target_id)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
