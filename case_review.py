"""Compact, read-only feedback report for one authorized lab case."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
import re

import casebook
import focus_state


WAIT = re.compile(r"\b(?:sleep|Start-Sleep)\s+(?:-Seconds\s+)?\d+\b", re.I)


def summarize(root: Path, ip: str, attempts: list[dict]) -> dict:
    events = casebook.events(root, ip, 10_000)
    hypotheses = casebook.hypotheses(root, ip)
    shell = [row for row in events if row.get("kind") == "shell"]
    lab = [row for row in events if row.get("kind") == "lab_attempt"]
    waits = [row for row in shell if WAIT.search(row.get("detail", {}).get("command", ""))]
    ssh_failures = [row for row in lab if row.get("detail", {}).get("operation") in {"ssh", "ssh_probe"}
                    and row.get("detail", {}).get("exit_code") == 255]
    ungrounded = [row for row in hypotheses if not row.get("evidence_ids")]
    open_hypotheses = [row for row in hypotheses if row.get("status") in {"open", "supported"}]
    slow = sorted(shell, key=lambda row: row.get("detail", {}).get("duration_ms") or 0,
                  reverse=True)[:5]
    findings = []
    if ungrounded:
        findings.append("Hay hipótesis sin evidencia enlazada; calibra la confianza y cierra cada prueba antes de abrir más vías")
    if ssh_failures:
        findings.append("Hay conexiones SSH con exit_code 255; verifica autenticación antes de tratarlas como avance")
    if waits:
        findings.append("Hay esperas pasivas; usa sondeos con plazo corto y condición de parada explícita")
    if len(shell) > 3 * max(1, len(lab)):
        findings.append("Predomina shell sobre herramientas estructuradas; conserva resultados comparables para los flujos largos")
    focus = focus_state.status(root, ip)
    repeated_crypto = [row for row in shell if re.search(r"\b(?:brute|crack|rockyou|wordlist|hmac|hashcat)\b",
                                                      row.get("detail", {}).get("command", ""), re.I)]
    if len(repeated_crypto) >= 12:
        findings.append("Se repitieron muchas pruebas de claves o diccionarios; exige indicio de baja entropía y un límite de parada")
    if focus.get("exhausted"):
        findings.append("La línea de investigación superó el tiempo o acciones orientativos; revisa si hay evidencia nueva o conviene pivotar")
    report_dir = casebook.case_dir(root, ip) / "findings"
    reports = []
    for path in sorted(report_dir.glob("f-*.json")) if report_dir.exists() else []:
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(item, dict) and isinstance(item.get("finding_id"), str):
            reports.append({key: item.get(key) for key in
                            ("finding_id", "profile", "title", "category", "status")})
    finding_events = {row.get("detail", {}).get("finding_id"): row["event_id"]
                      for row in events if row.get("kind") in {"program_finding", "code_finding"}}
    method_evidence = {row.get("detail", {}).get("evidence_id")
                       for row in events if row.get("kind") == "method_feedback"}
    learning_candidates = [{**item, "evidence_id": finding_events[item["finding_id"]]}
                           for item in reports if item["finding_id"] in finding_events and
                           finding_events[item["finding_id"]] not in method_evidence]
    return {
        "target_id": ip,
        "target_ip": None if ip.startswith(("web-", "program-", "code-")) else ip,
        "event_count": len(events),
        "shell_calls": len(shell),
        "lab_calls": len(lab),
        "attempt_outcomes": dict(Counter(row.get("outcome", "unknown") for row in attempts)),
        "hypotheses": {"total": len(hypotheses), "active": len(open_hypotheses),
                       "without_evidence": len(ungrounded),
                       "high_confidence_without_evidence": sum(row.get("confidence") == "high" for row in ungrounded)},
        "ssh_exit_255": len(ssh_failures),
        "wait_commands": len(waits),
        "shell_duration_ms_sum": sum(row.get("detail", {}).get("duration_ms") or 0 for row in shell),
        "slow_event_ids": [row["event_id"] for row in slow],
        "method_feedback_count": sum(row.get("kind") == "method_feedback" for row in events),
        "documented_findings": reports[-20:],
        "learning_candidates": learning_candidates[-10:],
        "focus": focus,
        "crypto_guess_commands": len(repeated_crypto),
        "findings": findings,
        "note": "Métricas de observación; una llamada completada no demuestra éxito técnico ni acceso",
    }
