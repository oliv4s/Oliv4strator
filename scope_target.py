"""Canonical, exact targets for IP labs and browser-based challenges."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit


LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def web_url(value: object) -> tuple[str, str]:
    """Return (origin, initial path). The approved unit is one exact origin."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or \
            any(char.isspace() for char in value) or "\\" in value:
        raise ValueError("Indica una URL HTTP(S) concreta, sin espacios")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or \
            parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("La URL debe tener esquema HTTP(S), host y no incluir credenciales ni fragmento")
    host = parsed.hostname
    if not host:
        raise ValueError("Host web inválido")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise ValueError("Dominio web inválido") from exc
        if len(host) > 253 or not all(LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("Dominio web inválido")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Puerto web inválido") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Puerto web inválido")
    scheme = parsed.scheme.lower()
    default = 443 if scheme == "https" else 80
    authority = f"[{host}]" if ":" in host else host
    origin = f"{scheme}://{authority}" + (f":{port}" if port and port != default else "")
    path = parsed.path or "/"
    if path.startswith("//") or "\r" in path or "\n" in path:
        raise ValueError("Ruta inicial inválida")
    if parsed.query:
        path += "?" + parsed.query
    return origin, path


def web_case_id(origin: str) -> str:
    return "web-" + hashlib.sha256(origin.encode("utf-8")).hexdigest()[:16]


def engagement_mode(scope: dict) -> str:
    selected = [bool(scope.get("program_id")), bool(scope.get("target_ip")), bool(scope.get("target_url"))]
    if sum(selected) > 1:
        return "invalid"
    if selected[0]:
        return "bug_bounty"
    if selected[1]:
        return "lab_machine"
    if selected[2]:
        return "web_challenge"
    return "unconfigured"


def active_case_id(scope: dict) -> str | None:
    program_id = scope.get("program_id")
    if isinstance(program_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{2,79}", program_id):
        return "program-" + hashlib.sha256(program_id.encode("utf-8")).hexdigest()[:16]
    ip = scope.get("target_ip")
    if isinstance(ip, str):
        return ip
    origin = scope.get("target_url")
    if isinstance(origin, str):
        return web_case_id(origin)
    return None
