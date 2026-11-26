#!/usr/bin/env python3
"""Codex local tool hook: visible scope checks and shell events."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import casebook
from harness.efficiency import approvals as hook_approvals
import focus_state


ROOT = Path(__file__).resolve().parent.parent
NETWORK_CLI = re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+|proxychains\s+)?"
                         r"(curl|wget|nmap|ffuf|gobuster|feroxbuster|dirsearch|"
                         r"sqlmap|nikto|wfuzz|hydra|ssh|scp|sftp|git|nc|netcat|ncat|ping)\b", re.I)
CODE_NETWORK = re.compile(r"\b(?:fetch|requests\.(?:get|post|put|delete|request)|"
                          r"httpx\.(?:get|post|put|delete|request)|urllib\.request\.urlopen)\s*\(", re.I)
URLS = re.compile(r"https?://[^\s'\"`<>()]+", re.I)
IPS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def denied(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
            "permissionDecision": "deny", "permissionDecisionReason": reason}}


def current_scope() -> dict:
    try:
        return json.loads((ROOT / "scope.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def read_only_external(command: str, cli_name: str) -> bool:
    """Only permit read-only downloads from explicitly allowlisted hosts."""
    if cli_name == "git":
        return bool(re.search(r"\bgit\s+(?:clone|fetch|pull|ls-remote|submodule)\b", command, re.I))
    if cli_name not in {"curl", "wget"}:
        return False
    if re.search(r"(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode)?|-F|--form|-T|"
                 r"--upload-file|-X|--request)(?:\s|=|$)", command, re.I):
        return False
    if re.search(r"--method\s+(?:POST|PUT|PATCH|DELETE)\b", command, re.I):
        return False
    return True


def visible_scope_check(command: str, scope: dict) -> None:
    if scope.get("program_id"):
        # Native tools are part of BB-Web and BB-Code. Program rules and asset
        # boundaries are instructions; this regex hook cannot prove where an
        # arbitrary script or browser request will send traffic.
        return
    cli = NETWORK_CLI.search(command)
    if cli and cli.group(1).lower() == "git" and not re.search(
            r"\bgit\s+(?:clone|fetch|pull|ls-remote|submodule|push)\b", command, re.I):
        cli = None
    coded = CODE_NETWORK.search(command)
    if not cli and not coded:
        return
    urls = [match.group().rstrip(".,;:") for match in URLS.finditer(command)]
    ip, origin = scope.get("target_ip"), scope.get("target_url")
    allowed_hosts = {host.lower().rstrip(".") for host in scope.get("allowed_hosts") or []
                     if isinstance(host, str)}
    external = {host.lower().rstrip(".") for host in scope.get("external_allowlist") or []
                if isinstance(host, str)}
    if not ip and not origin:
        if urls and all(urlsplit(url).hostname in {"localhost", "127.0.0.1"} for url in urls):
            return
        raise ValueError("No hay destino aprobado. Usa lab_scope antes de enviar tráfico de red.")
    if cli and cli.group(1).lower() == "curl" and re.search(r"(?:^|\s)(?:-L|--location)(?:\s|$)", command):
        raise ValueError("Curl con redirecciones automáticas puede salir del alcance; usa lab_http.")
    if cli and cli.group(1).lower() == "wget" and "--max-redirect=0" not in command:
        raise ValueError("Wget sigue redirecciones; usa lab_http.")
    target_urls = []
    external_only = False
    for url in urls:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        if host not in external:
            target_urls.append(url)
            continue
        cli_name = cli.group(1).lower() if cli else ""
        if not read_only_external(command, cli_name):
            raise ValueError(f"Acceso externo solo de lectura con curl/wget/git: {host}")
        external_only = True
    if external_only and not target_urls:
        for found in IPS.findall(command):
            if found != ip and not found.startswith("127."):
                raise ValueError(f"IP {found} fuera del alcance activo; solicita lab_scope.")
        return
    urls = target_urls
    if origin:
        if cli and cli.group(1).lower() not in {"curl", "wget"}:
            raise ValueError("El destino actual es un origen web; usa lab_web_http.")
        if not urls:
            raise ValueError("Destino web no verificable; usa lab_web_http.")
        for url in urls:
            parsed = urlsplit(url)
            candidate = f"{parsed.scheme}://{parsed.netloc}"
            if candidate != origin and parsed.hostname not in {"localhost", "127.0.0.1"}:
                raise ValueError(f"Origen {candidate} fuera del alcance; solicita lab_scope.")
    else:
        for url in urls:
            host = urlsplit(url).hostname
            resolved = re.search(r"--resolve\s+[^\s:]+:\d+:" + re.escape(ip) + r"(?:\s|$)", command)
            if host in allowed_hosts:
                if resolved:
                    continue
                raise ValueError(f"{host} es alias del objetivo; usa --resolve {host}:PUERTO:{ip} o lab_http")
            if host not in {ip, "localhost", "127.0.0.1"} and not resolved:
                raise ValueError(f"Host {host} fuera del alcance; usa lab_http con Host o solicita lab_scope.")
        for found in IPS.findall(command):
            if found != ip and not found.startswith("127."):
                raise ValueError(f"IP {found} fuera del alcance activo; solicita lab_scope.")


def redact(value: str) -> str:
    value = re.sub(r"\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+",
                   r"\1=[redacted]", value, flags=re.I)
    value = re.sub(r"\b(Authorization\s*:\s*(?:Bearer|Basic)\s+)\S+",
                   r"\1[redacted]", value, flags=re.I)
    value = re.sub(r"\bsshpass\s+-p\s+(?:'[^']*'|\"[^\"]*\"|\S+)",
                   "sshpass -p [redacted]", value, flags=re.I)
    return re.sub(r"HTB\{[^}]{1,200}\}", "HTB{redacted}", value)


def handle(phase: str, item: dict) -> dict | None:
    if item.get("tool_name") != "Bash":
        return None
    command = (item.get("tool_input") or {}).get("command")
    if not isinstance(command, str) or not command:
        return denied("Comando shell no verificable") if phase == "pre" else None
    scope = current_scope()
    target_id = focus_state.active_id(ROOT)
    if phase == "pre":
        try:
            visible_scope_check(command, scope)
        except (ValueError, OSError) as error:
            try:
                hook_approvals.record(ROOT, str(error))
            except (ValueError, OSError):
                pass
            return denied(str(error))
        return None
    if phase == "post" and target_id:
        output = item.get("tool_response")
        text = output if isinstance(output, str) else json.dumps(output, ensure_ascii=False, default=str)
        detail = {
            "source": os.environ.get("OLIVA_FRONTEND", "codex"), "session_id": item.get("session_id"),
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
            "output_bytes": len(text.encode()),
            "output_sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
        if not scope.get("program_id"):
            detail.update({"command": redact(command)[:600],
                           "output_excerpt": redact(text)[:1200]})
        casebook.record_event(ROOT, target_id, "shell", detail)
    return None


def main() -> None:
    phase = sys.argv[1] if len(sys.argv) > 1 else ""
    if phase not in {"pre", "post"}:
        raise SystemExit("Usa pre o post")
    try:
        item = json.load(sys.stdin)
        if not isinstance(item, dict):
            raise ValueError("Entrada de hook inválida")
        result = handle(phase, item)
        if result is not None:
            print(json.dumps(result, ensure_ascii=False))
    except (OSError, ValueError, TypeError) as error:
        if phase == "pre":
            print(json.dumps(denied(f"Hook de laboratorio: {error}"), ensure_ascii=False))
        else:
            print(json.dumps({"systemMessage": f"Telemetría de laboratorio: {error}"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
