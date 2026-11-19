#!/usr/bin/env python3
"""Local stdio MCP adapter for the existing Oliv4strator Python core.

Run this on the Kali WSL2 Codex host. Codex and Claude retain their native
tools; this server supplies durable scope, evidence and reporting helpers.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from typing import Any

import lab_bridge


def schema(properties: dict[str, dict] | None = None, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties or {},
            "required": required or [], "additionalProperties": False}


S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
HEADERS = {"type": "object", "additionalProperties": S}
STRINGS = {"type": "array", "items": S}


def tool(name: str, description: str, properties: dict | None = None,
         required: list[str] | None = None, read_only: bool = False) -> dict:
    return {"name": name, "description": description,
            "inputSchema": schema(properties, required),
            "annotations": {"readOnlyHint": read_only, "openWorldHint": False}}


TOOLS = [
    tool("lab_status", "Estado del destino, servicios, intentos y foco. Empieza aquí.", read_only=True),
    tool("lab_case", "Expediente del destino activo con hipótesis y eventos recientes.", read_only=True),
    tool("lab_attempts", "Historial compacto de pruebas del destino activo. Consulta antes de repetir una sonda o tras compactar contexto.",
         {"filter_operation": {"type": "string", "enum": sorted(lab_bridge.ACTION_OPERATIONS | {"shell"})},
          "port": I, "limit": I}, read_only=True),
    tool("lab_preflight", "Comprueba sin tráfico de red la ruta local a la IP y si un puerto de callback está escuchando fuera de loopback.",
         {"listener_port": I, "callback_host": S}, read_only=True),
    tool("lab_review", "Métricas de atasco y revisión de una sesión.", read_only=True),
    tool("lab_focus", "Organiza opcionalmente una línea de investigación y consulta su progreso. El presupuesto es orientativo y no bloquea pruebas.",
         {"action": {"type": "string", "enum": ["status", "start", "pivot", "extend", "close"]},
          "avenue": {"type": "string", "enum": ["recon", "authentication", "authorization", "input_validation", "file_handling", "business_logic", "cryptography", "initial_access", "post_access", "privilege_escalation", "other"]},
          "branch_key": S, "question": S, "basis": S, "test": S,
          "expected": S, "prior_result": S, "evidence_id": S, "new_observation": S}, ["action"]),
    tool("lab_hypothesis", "Propón o valora una hipótesis usando IDs reales de evidencia.",
         {"action": {"type": "string", "enum": ["propose", "assess"]},
          "hypothesis_id": S, "claim": S, "expected": S, "next_test": S,
          "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
          "status": {"type": "string", "enum": ["open", "supported", "rejected", "confirmed"]},
          "evidence_ids": STRINGS, "note": S}, ["action"]),
    tool("lab_memory", "Consulta métodos de pentesting reutilizables por tecnología o fase.",
         {"technology": S, "phase": {"type": "string", "enum": ["recon", "enumeration", "validation", "code_review", "initial_access", "post_access", "privilege_escalation"]}}, read_only=True),
    tool("lab_text", "Lee o busca texto por páginas en archivos del proyecto y artifact:<id>.",
         {"source": S, "mode": {"type": "string", "enum": ["lines", "search"]},
          "start": I, "count": I, "query": S}, ["source"], read_only=True),
    tool("lab_evidence", "Registra una observación ya obtenida con shell, navegador o prueba local, junto con su control, para citarla en hipótesis e informes. No ejecuta pruebas.",
         {"source": {"type": "string", "enum": ["browser", "shell", "local_test", "manual", "mcp"]},
          "observation": S, "control": S}, ["source", "observation"]),
    tool("lab_method", "Guarda o contrasta una decisión metodológica reutilizable con evidencia real.",
         {"action": {"type": "string", "enum": ["add", "observe"]}, "method_id": S,
          "phase": {"type": "string", "enum": ["recon", "enumeration", "validation", "code_review", "initial_access", "post_access", "privilege_escalation"]},
          "technology": S, "signal": S, "question": S, "test": S, "supports": S,
          "refutes": S, "next_if_supported": S, "next_if_refuted": S, "pitfall": S,
          "evidence_id": S, "result": {"type": "string", "enum": ["supported", "refuted", "inconclusive"]}},
         ["action", "evidence_id", "result"]),
    tool("lab_scope", "Perfil LAB: fija o cambia la IP o URL exacta indicada por el usuario. La nota es opcional; el prompt del usuario define el destino.",
         {"ip": S, "url": S, "authorization_note": S}),
    tool("lab_program_status", "Muestra programas disponibles, política activa, tráfico realizado y límites locales opcionales.",
         read_only=True),
    tool("lab_code_status", "BB-Code: comprueba revisión Git y si el remoto origin del checkout coincide con el repositorio autorizado; no envía tráfico.",
         read_only=True),
    tool("lab_program_check", "Comprueba una URL web o repositorio contra la política del programa sin enviar tráfico.",
         {"program_id": S, "url": S, "repository_url": S, "surface": S,
          "basis": S}, read_only=True),
    tool("lab_program_activate", "Activa BB-Web o BB-Code según la política. Para BB-Code indica checkout_path; el prompt del usuario define el programa autorizado. Omite límites locales salvo petición expresa.",
         {"program_id": S, "profile": {"type": "string", "enum": ["BB-Web", "BB-Code"]},
          "repository_url": S, "checkout_path": S, "authorization_note": S,
          "hourly_limit": I, "min_interval_seconds": I},
         ["program_id"]),
    tool("lab_program_http", "Una petición HTTPS dentro del programa activo; aplica los identificadores HTTP requeridos, límites locales configurados y no sigue redirecciones. Compara controles y variantes con efecto observable.",
         {"url": S, "method": S, "surface": S,
          "basis": S, "interaction": {"type": "string", "enum": ["non_mutating", "own_test_account"]},
          "headers": HEADERS, "cookie": S, "session": S, "body": S, "retry_reason": S},
         ["url", "method"]),
    tool("lab_program_discover", "Hace un solo GET autorizado y extrae rutas de HTML, robots.txt, sitemaps o JS; no visita los enlaces encontrados. Usa las rutas observadas para ampliar hipótesis con criterio.",
         {"url": S, "surface": S, "basis": S, "headers": HEADERS,
          "cookie": S, "session": S, "retry_reason": S}, ["url"]),
    tool("lab_program_paths", "Comprueba hasta 30 rutas elegidas en un origen autorizado con GET/HEAD. Cada petición pasa por la política y se detiene ante 429/503.",
         {"base_url": S, "paths": STRINGS,
          "method": {"type": "string", "enum": ["GET", "HEAD"]},
          "reason": S, "surface": S, "basis": S, "headers": HEADERS,
          "cookie": S, "session": S, "start_index": I, "retry_reason": S},
         ["base_url", "paths", "reason"]),
    tool("lab_program_finding", "Documenta una candidata concreta ya verificada con uno o dos intentos decisivos y pasos completos; permite seguir investigando otras vías. Genera un borrador local para revisión manual.",
         {"title": S, "category": S, "affected_url": S, "surface": S, "basis": S,
          "proof": S, "impact_hypothesis": S, "technical_reproduction": S,
          "reproduction_steps": STRINGS,
          "confirming_attempt_ids": STRINGS},
         ["title", "category", "affected_url", "proof", "impact_hypothesis",
          "technical_reproduction", "reproduction_steps", "confirming_attempt_ids"]),
    tool("lab_program_findings", "Lista o lee borradores locales de PoC del programa activo.",
         {"finding_id": S}, read_only=True),
    tool("lab_code_finding", "BB-Code: guarda una PoC local reproducible con versión, ruta de código, condiciones, efecto observado y evidencia del expediente; genera borrador Markdown.",
         {"title": S, "category": S, "repository_url": S, "affected_version": S,
          "source_location": S, "conditions": S, "proof": S,
          "impact_hypothesis": S, "technical_reproduction": S,
          "reproduction_steps": STRINGS, "confirming_evidence_ids": STRINGS,
          "related_advisories": S},
         ["title", "category", "affected_version", "source_location", "conditions",
          "proof", "impact_hypothesis", "technical_reproduction", "reproduction_steps",
          "confirming_evidence_ids"]),
    tool("lab_scan", "Escanea puertos TCP de la IP aprobada; conserva el inventario previo.",
         {"ports": S, "retry_reason": S}, ["ports"]),
    tool("lab_http", "HTTP contra IP y puerto observados, con Host virtual y sesiones.",
         {"port": I, "method": S, "path": S, "host": S, "headers": HEADERS,
          "cookie": S, "session": S, "follow_redirects": B, "body": S,
          "tls": B, "save": B, "retry_reason": S}, ["port", "method", "path"]),
    tool("lab_web_http", "HTTP contra el origen web exacto aprobado; no sigue redirecciones externas.",
         {"method": S, "path": S, "headers": HEADERS, "cookie": S,
          "session": S, "follow_redirects": B, "body": S, "tls_verify": B,
          "save": B, "retry_reason": S}, ["method", "path"]),
    tool("lab_tcp", "Lee un banner o envía un payload corto al puerto observado.",
         {"port": I, "payload": S, "retry_reason": S}, ["port"]),
    tool("lab_pcap", "Analiza un artefacto PCAP guardado y extrae solicitudes FTP.",
         {"artifact_id": S, "retry_reason": S}, ["artifact_id"]),
    tool("lab_ssh", "Ejecuta un comando SSH en IP y puerto observados. Valida acceso primero con command=id.",
         {"port": I, "username": S, "password": S, "command": S, "retry_reason": S},
         ["username", "password", "command"]),
    tool("lab_ssh_probe", "Tras SSH validado, ejecuta una sonda fija de identidad, permisos o flags.",
         {"port": I, "username": S, "password": S,
          "probe": {"type": "string", "enum": ["identity", "system", "groups", "sudo", "capabilities", "suid", "user_flag", "root_flag"]},
          "retry_reason": S}, ["username", "password", "probe"]),
]
BY_NAME = {item["name"]: item for item in TOOLS}


def call(name: str, arguments: object) -> dict:
    if name not in BY_NAME:
        return {"content": [{"type": "text", "text": f"Herramienta desconocida: {name}"}], "isError": True}
    if not isinstance(arguments, dict):
        return {"content": [{"type": "text", "text": "Argumentos JSON inválidos"}], "isError": True}
    allowed = set(BY_NAME[name]["inputSchema"]["properties"])
    extra = set(arguments) - allowed
    if extra:
        return {"content": [{"type": "text", "text": f"Campos no admitidos: {', '.join(sorted(extra))}"}], "isError": True}
    operation = name.removeprefix("lab_")
    # Never accept an operation value from arguments: callers can only invoke
    # named MCP tools, not arbitrary bridge operations.
    try:
        data = lab_bridge.dispatch({"operation": operation, **arguments})
        return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}],
                "isError": False}
    except (OSError, ValueError, RuntimeError, KeyError, sqlite3.Error) as error:
        return {"content": [{"type": "text", "text": str(error)[:1200]}], "isError": True}


def response(request: dict[str, Any]) -> dict | None:
    method = request.get("method")
    identifier = request.get("id")
    if identifier is None:  # MCP notifications do not receive a response.
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": identifier, "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "oliv4strator-lab", "version": "0.1.0"},
            "instructions": (
                "Solo opera el destino o programa indicado por el usuario y registrado en scope.json. "
                "Consulta lab_status.profile: LAB, BB-Web o BB-Code. "
                "En BB-Web usa la política del programa para todo el tráfico, incluso con herramientas nativas. "
                "En BB-Code verifica repositorio y versión; prueba el código localmente con controles. "
                "Explora varias hipótesis con controles; "
                "limita a una o dos pruebas solo la verificación final de cada candidata fuerte. "
                "El MCP aplica las cabeceras de identidad requeridas por el perfil. "
                "Consulta lab_attempts antes de repetir pruebas; "
                "lab_preflight verifica rutas y listeners de callback. El foco es orientativo. "
                "Las herramientas nativas conservan la libertad de investigación y deben respetar el alcance."
            )}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": identifier, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": identifier, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = request.get("params") or {}
        result = call(params.get("name", ""), params.get("arguments", {}))
        return {"jsonrpc": "2.0", "id": identifier, "result": result}
    return {"jsonrpc": "2.0", "id": identifier,
            "error": {"code": -32601, "message": f"Método desconocido: {method}"}}


def serve() -> None:
    for line in sys.stdin:
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("Se esperaba un objeto JSON-RPC")
            result = response(item)
        except (ValueError, TypeError, KeyError) as error:
            result = {"jsonrpc": "2.0", "id": None,
                      "error": {"code": -32600, "message": str(error)[:500]}}
        if result is not None:
            sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve()
