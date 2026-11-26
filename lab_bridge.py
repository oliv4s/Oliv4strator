#!/usr/bin/env python3
"""Structured Kali actions for the OpenCode lab plugin; no shell interpreter."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from urllib.parse import urlsplit
from uuid import uuid4
import xml.etree.ElementTree as ET

import casebook
import case_review
import code_checkout
import focus_state
import lab_http
import method_memory
import program_discovery
import program_findings
import program_policy
import scope_target


ROOT = Path(__file__).resolve().parent
SCOPE = ROOT / "scope.json"
RUNS = ROOT / "runs"
ARTIFACTS = ROOT / "artifacts"
MEMORY = ROOT / "memory"
ATTEMPTS = MEMORY / "attempts.jsonl"
PORTS = re.compile(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*\Z")
ARTIFACT_ID = re.compile(r"[0-9a-f]{12}\Z")
ACTION_OPERATIONS = {"scan", "http", "web_http", "program_http", "program_discover", "program_paths", "tcp", "pcap", "ssh", "ssh_probe"}
TEXT_EXTENSIONS = {".txt", ".log", ".json", ".jsonl", ".html", ".htm", ".js", ".xml", ".csv", ".md", ".bin"}


def scope() -> dict:
    return json.loads(SCOPE.read_text(encoding="utf-8"))


def target() -> str:
    ip = scope().get("target_ip")
    if not isinstance(ip, str):
        raise ValueError("Esta acción requiere una IP de laboratorio activa; usa lab_scope para fijarla")
    return valid_ip(ip)


def active_target_id() -> str:
    identifier = scope_target.active_case_id(scope())
    if identifier is None:
        raise ValueError("Fija primero una IP o URL de laboratorio con lab_scope")
    casebook.case_dir(ROOT, identifier)
    return identifier


def web_target() -> tuple[str, str, int]:
    origin = scope().get("target_url")
    if not isinstance(origin, str):
        raise ValueError("Esta acción requiere una URL web activa; usa lab_scope para fijarla")
    canonical, _ = scope_target.web_url(origin)
    if canonical != origin:
        raise ValueError("Origen web guardado inválido")
    parsed = urlsplit(origin)
    return origin, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def valid_ip(value: object) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("IP inválida") from exc
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise ValueError("El objetivo debe ser una IPv4 concreta indicada por el usuario")
    return str(ip)


def record(operation: str, result: dict) -> dict:
    RUNS.mkdir(exist_ok=True)
    item = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "operation": operation,
            "target_id": scope_target.active_case_id(scope()),
            "target_ip": scope().get("target_ip"), "target_url": scope().get("target_url"), **result}
    with (RUNS / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, ensure_ascii=False) + "\n")
    return item


def services() -> dict:
    if not isinstance(scope().get("target_ip"), str):
        return {}
    path = RUNS / "services.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("target_ip") != target():
        return {}
    return data.get("ports", {})


def observed_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("Puerto inválido")
    if services().get(str(value), {}).get("state") != "open":
        raise ValueError("Escanea y observa primero ese puerto abierto")
    return value


def recent_attempts(limit: int = 100) -> list[dict]:
    identifier = scope_target.active_case_id(scope())
    if identifier is None:
        return []
    paths = [ATTEMPTS, casebook.case_dir(ROOT, identifier) / "attempts.jsonl"]
    found = {}
    for path in paths:
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                    if row.get("target_id", row.get("target_ip")) == identifier and isinstance(row.get("attempt_id"), str):
                        found[row["attempt_id"]] = row
                except ValueError:
                    continue
    return sorted(found.values(), key=lambda row: row.get("at", ""))[-limit:]


def action_signature(request: dict) -> str:
    MEMORY.mkdir(exist_ok=True)
    key_file = MEMORY / ".key"
    try:
        with key_file.open("xb") as stream:
            stream.write(secrets.token_bytes(32))
        key_file.chmod(0o600)
    except FileExistsError:
        pass
    key = key_file.read_bytes()
    canonical = {k: v for k, v in request.items() if k not in {"retry_reason", "basis"}}
    payload = json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()[:20]


def inventory_revision() -> str:
    inventory = RUNS / "services.json"
    auth = RUNS / "ssh_auth.json"
    state = (inventory.read_bytes() if inventory.exists() else b"") + b"\0" + \
            (auth.read_bytes() if auth.exists() else b"")
    return hashlib.sha256(state).hexdigest()[:12]


def action_summary(request: dict) -> str:
    operation = request["operation"]
    port = request.get("port")
    if operation == "scan":
        return "scan " + str(request.get("ports", ""))[:60]
    if operation == "http":
        path = urlsplit(str(request.get("path", "/"))).path[:100]
        return f"HTTP {request.get('method', 'GET')} {port} {path} Host={str(request.get('host', 'IP'))[:60]}"
    if operation == "web_http":
        path = urlsplit(str(request.get("path", "/"))).path[:100]
        return f"WEB HTTP {request.get('method', 'GET')} {path} {str(scope().get('target_url', ''))[:80]}"
    if operation in {"program_http", "program_discover"}:
        parsed = urlsplit(str(request.get("url", "")))
        return f"PROGRAM {operation.removeprefix('program_').upper()} {request.get('method', 'GET')} {parsed.scheme}://{parsed.netloc}{parsed.path[:100]}"
    if operation == "program_paths":
        parsed = urlsplit(str(request.get("base_url", "")))
        paths = request.get("paths")
        return f"PROGRAM PATHS {parsed.scheme}://{parsed.netloc} ({len(paths) if isinstance(paths, list) else 0} rutas)"
    if operation == "tcp":
        return f"TCP {port} ({len(str(request.get('payload', '')).encode('utf-8'))} bytes enviados)"
    if operation in {"ssh", "ssh_probe"}:
        return f"SSH {port or 22} ({'sonda ' + str(request.get('probe')) if operation == 'ssh_probe' else 'comando'})"
    return f"PCAP {str(request.get('artifact_id', ''))[:12]}"


def record_attempt(request: dict, signature: str, revision: str,
                   error: Exception | None = None, result: dict | None = None) -> dict:
    identifier = active_target_id()
    case = casebook.case_dir(ROOT, identifier)
    case.mkdir(parents=True, exist_ok=True)
    port = request.get("port")
    if request["operation"] in {"web_http", "program_http", "program_discover"}:
        parsed = urlsplit(scope()["target_url"] if request["operation"] == "web_http" else
                          str(request.get("url", "")))
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        service = ("http" if request["operation"] in {"web_http", "program_http", "program_discover"} else
                   services().get(str(port), {}).get("service", "") if isinstance(port, int) else "")
    except ValueError:
        service = ""
    message = str(error) if error else ""
    outcome = "error" if error else "completed"
    if not error and result is not None and request["operation"] in {"ssh", "ssh_probe"}:
        exit_code = result.get("exit_code")
        if exit_code != 0:
            outcome = ("auth_failed" if exit_code == 255 and
                       "permission denied" in result.get("stderr", "").lower()
                       else "command_failed")
            message = f"SSH exit_code={exit_code}; acceso o comando sin confirmar"
    for name in ("password", "body", "payload", "command"):
        value = request.get(name)
        if isinstance(value, str) and len(value) >= 4:
            message = message.replace(value, "[redacted]")
    item = {"attempt_id": uuid4().hex[:12], "at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "target_id": identifier, "target_ip": scope().get("target_ip"),
            "target_url": scope().get("target_url"), "operation": request["operation"],
            "port": port if isinstance(port, int) else None, "service": service,
            "summary": action_summary(request), "signature": signature, "inventory_revision": revision,
            "post_inventory_revision": inventory_revision(),
            "outcome": outcome,
            "error": message[:180]}
    if result is not None:
        if isinstance(result.get("status"), int):
            item["status_code"] = result["status"]
        if isinstance(result.get("exit_code"), int):
            item["exit_code"] = result["exit_code"]
    with (case / "attempts.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, ensure_ascii=False) + "\n")
    return item


def attempts_view(request: dict) -> dict:
    limit = request.get("limit", 60)
    operation, port = request.get("filter_operation"), request.get("port")
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("limit debe estar entre 1 y 200")
    if operation is not None and operation not in ACTION_OPERATIONS | {"shell"}:
        raise ValueError("Operación de filtro inválida")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("Puerto de filtro inválido")
    rows = [row for row in recent_attempts(5000)
            if (operation is None or row.get("operation") == operation) and
            (port is None or row.get("port") == port)]
    shell_events = ([row for row in casebook.events(ROOT, active_target_id(), 5000)
                     if row.get("kind") == "shell"]
                    if operation in {None, "shell"} and port is None else [])
    groups: dict[tuple[str, str], dict] = {}
    for row in rows:
        key = (row.get("signature") or row["attempt_id"], row.get("post_inventory_revision") or
               row.get("inventory_revision") or "")
        if key not in groups:
            groups[key] = {"first_attempt_id": row["attempt_id"], "count": 0,
                           "first_outcome": row.get("outcome")}
        groups[key]["count"] += 1
        groups[key]["last"] = row
    for event in shell_events:
        detail = event.get("detail", {})
        key = ("shell", detail.get("command_sha256") or event["event_id"])
        if key not in groups:
            groups[key] = {"first_attempt_id": event["event_id"], "count": 0,
                           "first_outcome": detail.get("status", "completed")}
        groups[key]["count"] += 1
        groups[key]["last"] = {"attempt_id": event["event_id"], "at": event.get("at"),
                               "operation": "shell", "summary": detail.get("command", "")[:160],
                               "outcome": detail.get("status", "completed"),
                               "output_excerpt": detail.get("output_excerpt", "")[:240]}
    selected = sorted(groups.values(), key=lambda group: group["last"].get("at", ""))[-limit:]
    return {"target_id": active_target_id(), "total_attempts": len(rows),
            "shell_calls": len(shell_events),
            "distinct_tests": len(groups), "tests": [
                {"attempt_id": group["last"]["attempt_id"],
                 "first_attempt_id": group["first_attempt_id"],
                 "count": group["count"], "at": group["last"].get("at"),
                 "operation": group["last"].get("operation"),
                 "port": group["last"].get("port"),
                 "summary": group["last"].get("summary"),
                 "first_outcome": group["first_outcome"],
                 "last_outcome": group["last"].get("outcome"),
                 "status_code": group["last"].get("status_code"),
                 "exit_code": group["last"].get("exit_code"),
                 "error": group["last"].get("error", ""),
                 "output_excerpt": group["last"].get("output_excerpt", "")}
                for group in selected]}


def preflight(request: dict) -> dict:
    """Inspect the local route and optional callback listener without network traffic."""
    identifier = active_target_id()
    ip = scope().get("target_ip")
    callback_host = request.get("callback_host")
    if callback_host is not None:
        try:
            callback_address = ipaddress.ip_address(callback_host)
        except ValueError as error:
            raise ValueError("callback_host debe ser una IP local concreta") from error
        if callback_address.version != 4 or callback_address.is_loopback or callback_address.is_unspecified:
            raise ValueError("callback_host debe ser una IPv4 local no loopback")
        callback_host = str(callback_address)
    route = None
    if isinstance(ip, str):
        try:
            run = subprocess.run(["ip", "-j", "route", "get", ip], capture_output=True,
                                 text=True, timeout=5, check=False)
            routes = json.loads(run.stdout) if run.returncode == 0 else []
            if routes:
                route = {key: routes[0].get(key) for key in ("dev", "src", "prefsrc", "gateway")
                         if routes[0].get(key) is not None}
            else:
                route = {"error": run.stderr[:180] or "No se encontró ruta local"}
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            route = {"error": str(error)[:180]}
    listener_port = request.get("listener_port")
    listener = None
    if listener_port is not None:
        if type(listener_port) is not int or not 1 <= listener_port <= 65535:
            raise ValueError("listener_port inválido")
        try:
            run = subprocess.run(["ss", "-H", "-ltn"], capture_output=True, text=True,
                                 timeout=5, check=False)
            if run.returncode:
                listener = {"port": listener_port, "listening": None,
                            "error": run.stderr[:180] or "ss no pudo consultar sockets"}
            else:
                addresses = []
                for line in run.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[3].rsplit(":", 1)[-1] == str(listener_port):
                        addresses.append(parts[3])
                external = any(not address.startswith(("127.", "[::1]", "::1:"))
                               for address in addresses)
                listener = {"port": listener_port, "listening": bool(addresses),
                            "bound_addresses": addresses[:8], "callback_ready": external,
                            "state": ("ready" if external else
                                      "loopback_only" if addresses else "missing")}
                if callback_host:
                    listener["accepts_callback_host"] = any(
                        address.startswith(("0.0.0.0:", "*:")) or
                        address.rsplit(":", 1)[0] == callback_host
                        for address in addresses)
        except (OSError, subprocess.TimeoutExpired) as error:
            listener = {"port": listener_port, "listening": None, "error": str(error)[:180]}
    route_source = (route.get("prefsrc") or route.get("src")) if isinstance(route, dict) else None
    return {"target_id": identifier, "route": route, "listener": listener,
            "callback_host": callback_host,
            "callback_host_matches_route": (callback_host == route_source
                                            if callback_host and route_source else None),
            "note": "Lectura local. Antes de un payload con callback, confirma puerto escuchando y LHOST de la VPN."}


def repeat_candidate(signature: str, revision: str) -> dict | None:
    prior = next((row for row in reversed(recent_attempts(5000))
                  if row.get("signature") == signature), None)
    if prior is None:
        return None
    context = prior.get("post_inventory_revision") or prior.get("inventory_revision")
    return prior if context == revision else None


def repeat_is_static(request: dict) -> bool:
    operation = request["operation"]
    if operation in {"scan", "pcap"}:
        return True
    if operation == "tcp" and not request.get("payload"):
        return True
    if operation in {"http", "web_http", "program_http", "program_discover"}:
        return (request.get("method", "GET").upper() in {"GET", "HEAD", "OPTIONS"} and
                not request.get("cookie") and not request.get("session"))
    return False


def relevant_methods(technology: str | None = None, phase: str | None = None) -> list[dict]:
    if technology is not None:
        names = {method_memory._technology(technology)}
    else:
        names = {row.get("service", "").lower() for row in services().values()
                 if row.get("state") == "open"}
        if scope().get("target_url") or scope_target.profile(scope()) == "BB-Web":
            names.add("http")
        if scope_target.profile(scope()) == "BB-Code":
            names.add("source-code")
        if (RUNS / "ssh_auth.json").exists():
            names.add("linux")
    return method_memory.relevant(ROOT, names, phase)


def set_scope(request: dict) -> dict:
    raw_ip, raw_url = request.get("ip"), request.get("url")
    if (raw_ip is None) == (raw_url is None):
        raise ValueError("Indica exactamente una IP o una URL HTTP(S) del laboratorio")
    ip = valid_ip(raw_ip) if raw_ip is not None else None
    origin, start_path = scope_target.web_url(raw_url) if raw_url is not None else (None, None)
    note = request.get("authorization_note")
    if note is not None and (not isinstance(note, str) or len(note) > 300):
        raise ValueError("authorization_note debe ser texto de hasta 300 caracteres")
    note = note.strip() if isinstance(note, str) else ""
    if not note:
        note = "Destino indicado por el usuario en el prompt"
    previous = scope()
    prior_id = scope_target.active_case_id(previous)
    identifier = ip or scope_target.web_case_id(origin)
    if ip and prior_id != identifier:
        saved = casebook.case_dir(ROOT, identifier) / "services.json"
        inventory = json.loads(saved.read_text(encoding="utf-8")) if saved.exists() else {"target_ip": ip, "ports": {}}
        if inventory.get("target_ip") != ip or not isinstance(inventory.get("ports"), dict):
            raise ValueError("Inventario guardado inválido para este caso")
    else:
        inventory = {"target_ip": None, "target_url": origin, "ports": {}}
    if previous.get("target_ip") and prior_id != identifier:
        casebook.atomic_json(casebook.case_dir(ROOT, prior_id) / "services.json",
                             {"target_ip": prior_id, "ports": services()})
    new_scope = {"profile": "LAB", "engagement_mode": "lab_machine" if ip else "web_challenge",
                 "target_ip": ip, "target_url": origin, "start_path": start_path,
                 "authorization_note": note}
    casebook.atomic_json(SCOPE, new_scope)
    if prior_id != identifier:
        RUNS.mkdir(exist_ok=True)
        casebook.atomic_json(RUNS / "services.json", inventory)
        (RUNS / "ssh_auth.json").unlink(missing_ok=True)
    casebook.atomic_json(casebook.case_dir(ROOT, identifier) / "scope.json", new_scope)
    return record("scope", {"profile": "LAB", "authorization_note": note, "start_path": start_path})


def program_status() -> dict:
    current = scope()
    program_id = current.get("program_id")
    available = sorted(path.parent.name for path in (ROOT / "programs").glob("*/policy.draft.json"))
    if not program_id:
        return {"active": False, "available_programs": available}
    policy, digest = program_policy.active(ROOT, current)
    limit = current.get("program_hourly_limit")
    current_profile = scope_target.profile(current)
    return {"active": True, "profile": current_profile, "program_id": program_id, "name": policy["name"],
            "program_type": policy.get("program_type", "bug_bounty"),
            "policy_sha256": digest,
            "web_assets": [{"id": item["id"], "kind": item["kind"]}
                           for item in policy.get("web_assets", [])],
            "code_assets": [{"id": item["id"], "repository_url": item["url"]}
                            for item in policy.get("code_assets", [])],
            "checkout_path": current.get("checkout_path") if current_profile == "BB-Code" else None,
            "manual_assets": [item["id"] for item in policy.get("manual_assets", [])],
            "participant_identity_configured": program_policy.operator_identity(ROOT, program_id, policy) is not None
            if current_profile == "BB-Web" and
            policy.get("required_http_headers", {}).get("user_agent_prefix_template") else False,
            "budget": program_policy.budget(ROOT, program_id, limit),
            "min_interval_seconds": current.get("program_min_interval_seconds", 0),
            "limitations": (["Las cabeceras HTTP y límites locales se aplican en lab_program_http; "
                              "las herramientas nativas siguen las reglas del programa por instrucciones"]
                             if current_profile == "BB-Web" else
                             ["Las pruebas locales del repositorio usan shell; no hay tráfico web autorizado por este perfil"])}


def program_check(request: dict) -> dict:
    program_id = request.get("program_id") or scope().get("program_id")
    if not program_id:
        raise ValueError("Indica program_id o activa un programa")
    if (request.get("url") is None) == (request.get("repository_url") is None):
        raise ValueError("Indica exactamente una URL web o repository_url")
    policy, digest = program_policy.load(ROOT, program_id)
    decision = (program_policy.evaluate_code(policy, request["repository_url"])
                if request.get("repository_url") is not None else
                program_policy.evaluate(policy, request.get("url"), request.get("surface"),
                                        request.get("basis")))
    return {"program_id": program_id, "policy_sha256": digest,
            "active": scope().get("program_id") == program_id and
                      scope().get("program_policy_sha256") == digest,
            **decision}


def activate_program(request: dict) -> dict:
    program_id = request.get("program_id")
    policy, digest = program_policy.load(ROOT, program_id)
    selected_profile = request.get("profile")
    if selected_profile is None:
        if policy.get("web_assets") and not policy.get("code_assets"):
            selected_profile = "BB-Web"
        elif policy.get("code_assets") and not policy.get("web_assets"):
            selected_profile = "BB-Code"
        else:
            raise ValueError("El programa tiene activos web y código; indica profile=BB-Web o BB-Code")
    if selected_profile not in {"BB-Web", "BB-Code"}:
        raise ValueError("Usa profile=BB-Web o BB-Code")
    if (selected_profile == "BB-Web" and not policy.get("web_assets")) or \
            (selected_profile == "BB-Code" and not policy.get("code_assets")):
        raise ValueError("El perfil elegido no tiene activos en la política")
    if selected_profile == "BB-Web":
        program_policy.operator_identity(ROOT, program_id, policy)
    repository_url = request.get("repository_url")
    checkout_path = request.get("checkout_path")
    if selected_profile == "BB-Code":
        if repository_url is None and len(policy["code_assets"]) == 1:
            repository_url = policy["code_assets"][0]["url"]
        if repository_url is None:
            raise ValueError("Indica repository_url de uno de los activos de código")
        decision = program_policy.evaluate_code(policy, repository_url)
        if decision["decision"] != "allow":
            raise ValueError(decision["reason"])
        if not isinstance(checkout_path, str) or not checkout_path.strip():
            raise ValueError("BB-Code requiere checkout_path del repositorio local")
        checkout = Path(checkout_path).expanduser().resolve(strict=True)
        if not checkout.is_dir():
            raise ValueError("checkout_path debe ser una carpeta existente")
        checkout_path = str(checkout)
        repository_url = decision["repository_url"]
        checkout_info = code_checkout.inspect(checkout, repository_url)
        if checkout_info["matches_scope"] is False:
            raise ValueError("El remoto origin del checkout no coincide con el repositorio autorizado")
    elif repository_url is not None or checkout_path is not None:
        raise ValueError("repository_url y checkout_path solo corresponden a BB-Code")
    note = request.get("authorization_note")
    if note is not None and (not isinstance(note, str) or len(note) > 300):
        raise ValueError("authorization_note debe ser texto de hasta 300 caracteres")
    note = note.strip() if isinstance(note, str) else ""
    if not note:
        note = "Activación solicitada mediante lab_program_activate"
    limit = request.get("hourly_limit")
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("hourly_limit debe ser un entero positivo si se configura")
    interval = request.get("min_interval_seconds", 0)
    if type(interval) is not int or not 0 <= interval <= 3600:
        raise ValueError("min_interval_seconds debe estar entre 0 y 3600")
    previous = scope()
    prior_id = scope_target.active_case_id(previous)
    if previous.get("target_ip") and prior_id:
        casebook.atomic_json(casebook.case_dir(ROOT, prior_id) / "services.json",
                             {"target_ip": prior_id, "ports": services()})
    new_scope = {"profile": selected_profile,
                 "engagement_mode": "bug_bounty" if selected_profile == "BB-Web" else "bug_bounty_code",
                 "target_ip": None, "target_url": None, "start_path": None,
                 "program_id": program_id, "program_policy_sha256": digest,
                 "program_hourly_limit": limit, "program_min_interval_seconds": interval,
                 "authorization_note": note}
    if selected_profile == "BB-Code":
        new_scope.update({"repository_url": repository_url, "checkout_path": checkout_path})
    casebook.atomic_json(SCOPE, new_scope)
    identifier = scope_target.active_case_id(new_scope)
    if prior_id != identifier:
        RUNS.mkdir(exist_ok=True)
        casebook.atomic_json(RUNS / "services.json", {"target_ip": None, "program_id": program_id, "ports": {}})
        (RUNS / "ssh_auth.json").unlink(missing_ok=True)
    casebook.atomic_json(casebook.case_dir(ROOT, identifier) / "scope.json", new_scope)
    return record("program_activate", {"profile": selected_profile,
                                       "program_id": program_id, "name": policy["name"],
                                       "policy_sha256": digest, "hourly_limit": limit,
                                       "min_interval_seconds": interval})


def parse_ports(raw: object) -> str:
    if not isinstance(raw, str) or not PORTS.fullmatch(raw):
        raise ValueError("Usa puertos como 21,22,80 o 1-65535")
    for part in raw.split(","):
        values = [int(x) for x in part.split("-")]
        if any(not 1 <= x <= 65535 for x in values) or len(values) == 2 and values[0] > values[1]:
            raise ValueError("Rango de puertos inválido")
    return raw


def scan(request: dict) -> dict:
    ip, ports = target(), parse_ports(request.get("ports"))
    command = ["nmap", "-sT", "-Pn", "-sV", "--version-light", "--max-retries", "1",
               "--host-timeout", "15m", "-p", ports, "-oX", "-", ip]
    result = subprocess.run(command, capture_output=True, text=True, timeout=930, check=False)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout)[-1000:] or "Nmap falló")
    root = ET.fromstring(result.stdout)
    found = []
    for node in root.findall(".//host/ports/port"):
        if node.get("protocol") != "tcp":
            continue
        state = node.find("state")
        service = node.find("service")
        found.append({"port": int(node.attrib["portid"]), "state": state.get("state", "unknown") if state is not None else "unknown",
                      "service": service.get("name", "") if service is not None else "",
                      "product": service.get("product", "") if service is not None else "",
                      "version": service.get("version", "") if service is not None else ""})
    previous = services()
    for row in found:
        previous[str(row["port"])] = row
    RUNS.mkdir(exist_ok=True)
    (RUNS / "services.json").write_text(json.dumps({"target_ip": ip, "ports": previous},
                                                ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    casebook.atomic_json(casebook.case_dir(ROOT, ip) / "services.json",
                         {"target_ip": ip, "ports": previous})
    return record("scan", {"ports_requested": ports, "observed": found,
                           "open_inventory": [x for x in previous.values() if x["state"] == "open"]})


def http_request(request: dict) -> dict:
    ip, port = target(), observed_port(request.get("port"))
    return record("http", lab_http.request(ROOT, ARTIFACTS, ip, port, request))


def web_http_request(request: dict) -> dict:
    origin, host, port = web_target()
    return record("web_http", lab_http.request(ROOT, ARTIFACTS, host, port, request,
                                               web_origin=origin, case_id=active_target_id()))


def program_http_request(request: dict, *, discovery: bool = False) -> dict:
    current = scope()
    policy, _ = program_policy.active(ROOT, current)
    decision = program_policy.evaluate(policy, request.get("url"), request.get("surface"),
                                       request.get("basis"))
    if decision["decision"] != "allow":
        raise ValueError(decision["reason"] + "; consulta lab_program_check")
    method = "GET" if discovery else request.get("method", "GET")
    if not isinstance(method, str) or method.upper() not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Método HTTP no admitido")
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        allowed_interactions = ({"non_mutating", "own_test_account"} if method.upper() == "POST"
                                else {"own_test_account"})
        if request.get("interaction") not in allowed_interactions:
            raise ValueError("Indica interaction=own_test_account para cambios en tu cuenta de prueba")
        if not isinstance(request.get("basis"), str) or len(request["basis"].strip()) < 12:
            raise ValueError("Explica el efecto esperado y por qué cumple las reglas del programa")
    origin, path = scope_target.web_url(request["url"])
    host = urlsplit(origin).hostname
    headers = request.get("headers")
    if headers is not None and not isinstance(headers, dict):
        raise ValueError("Cabeceras HTTP inválidas")
    headers = dict(headers or {})
    identity = program_policy.operator_identity(ROOT, current["program_id"], policy)
    if identity:
        requirements = policy["required_http_headers"]
        username_header = requirements["username_header"]
        user_agent = next((value for name, value in headers.items()
                           if isinstance(name, str) and name.lower() == "user-agent"), "Oliv4strator/1")
        if not isinstance(user_agent, str):
            raise ValueError("User-Agent inválido")
        headers = {name: value for name, value in headers.items()
                   if isinstance(name, str) and name.lower() not in {"user-agent", username_header.lower()}}
        headers["User-Agent"] = requirements["user_agent_prefix_template"].replace(
            "{username}", identity["username"]) + user_agent
        headers[username_header] = identity["username"]
    data = {"method": method, "path": path, "headers": headers,
            "body": request.get("body", ""), "cookie": request.get("cookie"),
            "session": request.get("session"), "follow_redirects": False,
            "tls_verify": True, "save": False}
    program_id = current["program_id"]
    token = program_policy.reserve(ROOT, program_id, current.get("program_hourly_limit"),
                                   current.get("program_min_interval_seconds", 0))
    response = None
    try:
        response = lab_http.request(ROOT, ARTIFACTS, host, 443, data,
                                    web_origin=origin, case_id=active_target_id(),
                                    response_limit=1_048_576 if discovery else 65_536,
                                    text_limit=1_048_576 if discovery else 12_000,
                                    save_artifacts=False,
                                    user_agent_suffix=policy.get("required_http_headers", {}).get("user_agent_append", ""))
    finally:
        program_policy.release(ROOT, program_id, token,
                               response.get("status") if response else None,
                               response.get("headers", {}).get("retry-after") if response else None)
    record("program_discover" if discovery else "program_http",
           {"program_id": program_id, "url": origin + urlsplit(path).path,
                            "method": method.upper(), "status": response["status"],
                            "bytes": response["bytes"]})
    if discovery:
        found = program_discovery.extract(policy, origin + path, response.get("text", ""),
                                          response.get("headers", {}).get("content-type", ""))
        return {"program_id": program_id, "url": origin + path, "status": response["status"],
                "bytes": response["bytes"], "response_capped": response.get("response_capped", False),
                **found}
    return {"program_id": program_id, "url": origin + path, **response}


def program_paths_request(request: dict) -> dict:
    policy, _ = program_policy.active(ROOT, scope())
    base_url = request.get("base_url")
    origin, _ = scope_target.web_url(base_url)
    decision = program_policy.evaluate(policy, base_url, request.get("surface"), request.get("basis"))
    if decision["decision"] != "allow":
        raise ValueError(decision["reason"] + "; consulta lab_program_check")
    reason = request.get("reason")
    if not isinstance(reason, str) or not 12 <= len(reason.strip()) <= 300:
        raise ValueError("Explica de dónde salen las rutas elegidas")
    paths = request.get("paths")
    if not isinstance(paths, list) or not 1 <= len(paths) <= 30 or \
            not all(isinstance(path, str) for path in paths) or len(paths) != len(set(paths)):
        raise ValueError("Indica de 1 a 30 rutas únicas por lote")
    for path in paths:
        canonical_origin, _ = scope_target.web_url(origin + path)
        if canonical_origin != origin or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Cada ruta debe empezar por / y permanecer en el origen")
    method = request.get("method", "GET")
    if method not in {"GET", "HEAD"}:
        raise ValueError("La enumeración de rutas solo admite GET o HEAD")
    start_index = request.get("start_index", 0)
    if type(start_index) is not int or not 0 <= start_index < len(paths):
        raise ValueError("start_index inválido")
    results = []
    stopped = None
    next_index = len(paths)
    for index in range(start_index, len(paths)):
        path = paths[index]
        single = {"operation": "program_http", "url": origin + path, "method": method,
                  "surface": request.get("surface"), "basis": request.get("basis")}
        if request.get("session") is not None:
            single["session"] = request["session"]
        if request.get("cookie") is not None:
            single["cookie"] = request["cookie"]
        if request.get("headers") is not None:
            single["headers"] = request["headers"]
        if request.get("retry_reason") is not None:
            single["retry_reason"] = request["retry_reason"]
        try:
            response = dispatch(single)
        except ValueError as error:
            stopped, next_index = str(error)[:180], index
            break
        if response.get("deferred"):
            stopped, next_index = response["reason"], index
            break
        results.append({"path": path, "status": response.get("status"),
                        "bytes": response.get("bytes"), "skipped": response.get("skipped", False),
                        "location": response.get("headers", {}).get("location")})
        if response.get("status") in {429, 503}:
            stopped, next_index = "Respuesta 429/503; se detiene el lote", index + 1
            break
    return {"base_url": origin, "method": method, "reason": reason.strip(),
            "requested": len(paths), "tested": len(results), "start_index": start_index,
            "next_index": next_index, "stopped_reason": stopped, "results": results}


def tcp(request: dict) -> dict:
    ip, port = target(), observed_port(request.get("port"))
    payload = request.get("payload", "")
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > 2048:
        raise ValueError("Payload TCP demasiado grande")
    with socket.create_connection((ip, port), timeout=8) as connection:
        connection.settimeout(3)
        if payload:
            connection.sendall(payload.encode("utf-8"))
        try:
            response = connection.recv(8192)
        except socket.timeout:
            response = b""
    return record("tcp", {"port": port, "sent_bytes": len(payload.encode("utf-8")),
                          "response": response.decode("utf-8", "replace")})


def pcap(request: dict) -> dict:
    identifier = request.get("artifact_id")
    if not isinstance(identifier, str) or not ARTIFACT_ID.fullmatch(identifier):
        raise ValueError("Artefacto inválido")
    file = ARTIFACTS / (identifier + ".bin")
    if not file.is_file():
        raise ValueError("Artefacto no encontrado")
    command = ["tshark", "-r", str(file), "-Y", "ftp.request", "-T", "fields",
               "-e", "tcp.stream", "-e", "ftp.request.command", "-e", "ftp.request.arg"]
    run = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
    rows = run.stdout.splitlines()[:100]
    return record("pcap", {"artifact_id": identifier, "exit_code": run.returncode,
                           "ftp_requests": rows, "error": run.stderr[:500] if run.returncode else ""})


def text_file(request: dict) -> Path:
    source = request.get("source")
    if not isinstance(source, str) or not 1 <= len(source) <= 160:
        raise ValueError("Indica un archivo relativo del proyecto o artifact:<id>")
    if source.startswith("artifact:"):
        identifier = source.split(":", 1)[1]
        if not ARTIFACT_ID.fullmatch(identifier):
            raise ValueError("ID de artefacto inválido")
        candidates = [ARTIFACTS / (identifier + extension) for extension in (".txt", ".bin")]
        file = next((item for item in candidates if item.is_file()), None)
        if file is None:
            raise ValueError("Artefacto no encontrado")
        file = file.resolve()
        if not file.is_relative_to(ARTIFACTS.resolve()):
            raise ValueError("Artefacto fuera del proyecto")
    else:
        if source.startswith(("/", "\\")) or "\\" in source or ":" in source or ".." in Path(source).parts:
            raise ValueError("Ruta fuera del proyecto")
        file = (ROOT / source).resolve()
        if not file.is_relative_to(ROOT.resolve()) or not file.is_file():
            raise ValueError("Archivo no encontrado dentro del proyecto")
    if file.suffix.lower() not in TEXT_EXTENSIONS or file.stat().st_size > 8_000_000:
        raise ValueError("Tipo de archivo no admitido o tamaño mayor de 8 MB")
    return file


def text_inspect(request: dict) -> dict:
    file = text_file(request)
    mode = request.get("mode", "lines")
    if mode not in {"lines", "search"}:
        raise ValueError("Usa mode lines o search")
    lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    if mode == "lines":
        start, count = request.get("start", 1), request.get("count", 80)
        if type(start) is not int or type(count) is not int or not 1 <= start <= max(1, len(lines)) or not 1 <= count <= 200:
            raise ValueError("Rango de líneas inválido")
        selected = [(index + 1, line[:500]) for index, line in enumerate(lines[start - 1:start - 1 + count], start - 1)]
    else:
        query = request.get("query")
        if not isinstance(query, str) or not 2 <= len(query) <= 100:
            raise ValueError("Busca una cadena literal de 2 a 100 caracteres")
        selected = [(index, line[:500]) for index, line in enumerate(lines, 1)
                    if query.casefold() in line.casefold()][:100]
    return {"source": request["source"], "total_lines": len(lines),
            "matches": [{"line": number, "text": text} for number, text in selected],
            "truncated": len(selected) == 100 if mode == "search" else start - 1 + count < len(lines)}


SSH_PROBES = {
    "identity": "id",
    "system": "uname -a; cat /etc/os-release",
    "groups": "groups",
    "sudo": "sudo -n -l",
    "capabilities": "getcap -r / 2>/dev/null | head -80",
    "suid": "find / -perm -4000 -type f 2>/dev/null | head -80",
    "user_flag": "cat ~/user.txt",
    "root_flag": "id -u; cat /root/root.txt",
}


def ssh(request: dict, probe: bool = False) -> dict:
    ip, port = target(), observed_port(request.get("port", 22))
    username, password = (request.get(name) for name in ("username", "password"))
    command = SSH_PROBES.get(request.get("probe")) if probe else request.get("command")
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", username):
        raise ValueError("Usuario SSH inválido")
    if not isinstance(password, str) or not 1 <= len(password) <= 200:
        raise ValueError("Contraseña SSH inválida")
    if not isinstance(command, str) or not 1 <= len(command) <= 500:
        raise ValueError("Comando SSH inválido")
    if port not in {22, 2222}:
        raise ValueError("SSH solo en puerto 22 o 2222 observado")
    fingerprint = hashlib.sha256(f"{ip}\0{port}\0{username}\0{password}".encode()).hexdigest()
    auth_file = RUNS / "ssh_auth.json"
    if probe:
        try:
            auth = json.loads(auth_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            auth = {}
        if auth.get("fingerprint") != fingerprint:
            raise ValueError("Valida primero esta credencial SSH con lab_ssh y el comando id")
    env = {**os.environ, "SSHPASS": password}
    argv = ["sshpass", "-e", "ssh", "-p", str(port), "-o", "BatchMode=no",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8",
            "-o", "NumberOfPasswordPrompts=1", "-o", "UserKnownHostsFile=" + str(RUNS / "known_hosts"),
            f"{username}@{ip}", command]
    RUNS.mkdir(exist_ok=True)
    run = subprocess.run(argv, capture_output=True, text=True, timeout=35, env=env, check=False)
    if not probe and command == "id" and run.returncode == 0 and "uid=" in run.stdout:
        auth_file.write_text(json.dumps({"target_ip": ip, "port": port, "username": username,
                                         "fingerprint": fingerprint}) + "\n", encoding="utf-8")
    result = {"port": port, "username": username, "command": command, "exit_code": run.returncode,
              "stdout": run.stdout[:12000], "stderr": run.stderr[:1000]}
    if len(run.stdout) > 12000:
        ARTIFACTS.mkdir(exist_ok=True)
        identifier = uuid4().hex[:12]
        (ARTIFACTS / (identifier + ".txt")).write_text(run.stdout[:8_000_000], encoding="utf-8")
        result["full_output"] = "artifact:" + identifier
        result["stdout_truncated"] = True
    return record("ssh_probe" if probe else "ssh", result)


def dispatch(request: dict) -> dict:
    operation = request.get("operation")
    if operation == "program_status":
        return program_status()
    if operation == "program_check":
        return program_check(request)
    if operation == "code_status":
        current = scope()
        if scope_target.profile(current) != "BB-Code":
            raise ValueError("Activa primero un perfil BB-Code")
        program_policy.active(ROOT, current)
        return code_checkout.inspect(Path(current["checkout_path"]), current["repository_url"])
    if operation == "program_activate":
        return activate_program(request)
    if operation == "program_finding":
        current = scope()
        if scope_target.profile(current) != "BB-Web":
            raise ValueError("Usa lab_code_finding para hallazgos del perfil BB-Code")
        policy, _ = program_policy.active(ROOT, current)
        known = {row["attempt_id"] for row in recent_attempts(5000)}
        known |= casebook.event_ids(ROOT, active_target_id())
        result = program_findings.add(ROOT, current, policy, request, known)
        event = casebook.record_event(ROOT, active_target_id(), "program_finding",
                                      {"finding_id": result["finding_id"], "status": result["status"]})
        return {**result, "evidence_id": event["event_id"]}
    if operation == "code_finding":
        current = scope()
        if scope_target.profile(current) != "BB-Code":
            raise ValueError("Activa primero un perfil BB-Code")
        policy, _ = program_policy.active(ROOT, current)
        identifier = active_target_id()
        known = {row["attempt_id"] for row in recent_attempts(5000)}
        known |= casebook.event_ids(ROOT, identifier)
        result = program_findings.add_code(ROOT, current, policy, request, known)
        event = casebook.record_event(ROOT, identifier, "code_finding",
                                      {"finding_id": result["finding_id"], "status": result["status"]})
        return {**result, "evidence_id": event["event_id"]}
    if operation == "program_findings":
        current = scope()
        program_policy.active(ROOT, current)
        return program_findings.view(ROOT, current, request.get("finding_id"))
    if operation == "status":
        current = scope()
        mode = scope_target.engagement_mode(current)
        if mode == "invalid":
            raise ValueError("scope.json contiene modos de trabajo incompatibles")
        workflow = (program_policy.active(ROOT, current)[0].get("operator_workflow", {})
                    if mode in {"bug_bounty", "bug_bounty_code"} else
                    {"goal": "user_defined_lab_objective"} if mode in {"lab_machine", "web_challenge"} else {})
        identifier = scope_target.active_case_id(current)
        return {"profile": scope_target.profile(current), "engagement_mode": mode, "workflow": workflow,
                "scope": current, "services": list(services().values()) if identifier else [],
                "recent_attempts": recent_attempts(100)[-15:],
                "relevant_methods": relevant_methods() if identifier else [],
                "focus": focus_state.status(ROOT, identifier) if identifier else None,
                "case": {key: value for key, value in casebook.summary(ROOT, identifier).items()
                         if key != "recent_events"} if identifier else None}
    if operation == "case":
        identifier = active_target_id()
        return {**casebook.summary(ROOT, identifier), "scope": scope(),
                "services": list(services().values()), "focus": focus_state.status(ROOT, identifier)}
    if operation == "attempts":
        return attempts_view(request)
    if operation == "preflight":
        return preflight(request)
    if operation == "focus":
        return focus_state.change(ROOT, active_target_id(), request)
    if operation == "review":
        identifier = active_target_id()
        return {**case_review.summarize(ROOT, identifier, recent_attempts(5000)), "scope": scope()}
    if operation == "hypothesis":
        identifier = active_target_id()
        known = {row["attempt_id"] for row in recent_attempts(5000)}
        known |= casebook.event_ids(ROOT, identifier)
        changed = casebook.change_hypothesis(ROOT, identifier, request, known)
        if not changed["existing"]:
            casebook.record_event(ROOT, identifier, "hypothesis", {
                "hypothesis_id": changed["hypothesis"]["hypothesis_id"],
                "status": changed["hypothesis"]["status"], "existing": False})
        return changed
    if operation == "method":
        identifier = active_target_id()
        known = {row["attempt_id"] for row in recent_attempts(5000)}
        known |= casebook.event_ids(ROOT, identifier)
        return method_memory.record(ROOT, identifier, request, known)
    if operation == "memory":
        technology = request.get("technology", request.get("service"))
        phase = request.get("phase")
        if scope_target.active_case_id(scope()):
            return {"recent_attempts": recent_attempts(30),
                    "methods": relevant_methods(technology, phase)}
        names = {method_memory._technology(technology)} if technology is not None else None
        return {"recent_attempts": [], "methods": method_memory.relevant(ROOT, names, phase)}
    if operation == "text":
        return text_inspect(request)
    if operation == "evidence":
        identifier = active_target_id()
        source = request.get("source")
        if source not in {"browser", "shell", "local_test", "manual", "mcp"}:
            raise ValueError("Indica source=browser, shell, local_test, manual o mcp")
        observation = program_findings._text(request.get("observation"), "Observación", 12, 1200)
        control = program_findings._text(request.get("control", "Sin control aún"), "Control", 3, 800)
        event = casebook.record_event(ROOT, identifier, "observation", {
            "source": source, "observation": observation, "control": control,
            "provenance": ("datos aportados manualmente" if source == "manual" else
                           "resumen declarado por el agente tras observar una herramienta")})
        return {"evidence_id": event["event_id"], "target_id": identifier,
                "observation": observation, "control": control}
    if operation == "learn":
        raise ValueError("lab_learn se retiró: usa lab_method para guardar decisiones reutilizables")
    if operation == "scope":
        return set_scope(request)
    if operation not in ACTION_OPERATIONS:
        raise ValueError("Operación desconocida")
    active_target_id()
    if operation in {"program_http", "program_discover", "program_paths"}:
        if scope_target.profile(scope()) != "BB-Web":
            raise ValueError("Las herramientas web requieren un perfil BB-Web activo")
        program_policy.active(ROOT, scope())
    retry_reason = request.get("retry_reason")
    if retry_reason is not None and (not isinstance(retry_reason, str) or
                                     not 3 <= len(retry_reason.strip()) <= 300):
        raise ValueError("Explica brevemente qué cambió antes de reintentar")
    signature, revision = action_signature(request), inventory_revision()
    prior = repeat_candidate(signature, revision)
    if prior and not retry_reason and (repeat_is_static(request) or
                                      prior.get("outcome") in {"error", "auth_failed", "command_failed"}):
        return {"skipped": True, "target_id": active_target_id(),
                "prior_attempt_id": prior["attempt_id"], "prior_outcome": prior.get("outcome"),
                "prior_summary": prior.get("summary"), "prior_error": prior.get("error", ""),
                "status_code": prior.get("status_code"), "exit_code": prior.get("exit_code"),
                "reason": "Prueba idéntica en el mismo contexto; no se envió tráfico nuevo. "
                          "Usa lab_attempts o indica retry_reason si cambió el estado."}
    actions = {"scan": scan, "http": http_request, "web_http": web_http_request,
               "program_http": program_http_request,
               "program_discover": lambda item: program_http_request(item, discovery=True),
               "program_paths": program_paths_request,
               "tcp": tcp, "pcap": pcap,
               "ssh": ssh, "ssh_probe": lambda item: ssh(item, probe=True)}
    started = time.monotonic()
    try:
        result = actions[operation](request)
    except program_policy.BudgetPause as pause:
        return {"deferred": True, "target_id": active_target_id(),
                "retry_after_seconds": pause.seconds, "reason": str(pause),
                "sent_request": False}
    except (OSError, ValueError, RuntimeError, KeyError, sqlite3.Error, subprocess.TimeoutExpired, ET.ParseError,
            http.client.HTTPException) as exc:
        attempt = record_attempt(request, signature, revision, error=exc)
        identifier = scope_target.active_case_id(scope())
        if identifier:
            casebook.record_event(ROOT, identifier, "lab_attempt", {
                "attempt_id": attempt["attempt_id"], "operation": operation,
                "summary": attempt["summary"], "outcome": "error", "error": attempt["error"],
                "duration_ms": round((time.monotonic() - started) * 1000)})
        raise ValueError(f"{exc} [attempt_id={attempt['attempt_id']}]") from exc
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    attempt = record_attempt(request, signature, revision, result=result)
    detail = {"attempt_id": attempt["attempt_id"], "operation": operation,
              "summary": attempt["summary"], "outcome": attempt["outcome"],
              "duration_ms": result["duration_ms"]}
    for field in ("port", "status", "artifact_id", "exit_code", "ports_requested"):
        if field in result:
            detail[field] = result[field]
    casebook.record_event(ROOT, active_target_id(), "lab_attempt", detail)
    result["attempt_id"] = attempt["attempt_id"]
    if prior:
        result["repeat_of"] = prior["attempt_id"]
    if operation == "scan":
        result["relevant_methods"] = relevant_methods()
    return result


if __name__ == "__main__":
    try:
        item = json.load(sys.stdin)
        if not isinstance(item, dict):
            raise ValueError("Entrada JSON inválida")
        print(json.dumps({"ok": True, "data": dispatch(item)}, ensure_ascii=False))
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired, ET.ParseError,
            http.client.HTTPException) as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:1000]}, ensure_ascii=False))
        raise SystemExit(1)
