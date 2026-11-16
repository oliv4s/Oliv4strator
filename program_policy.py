"""Versioned, fail-closed policy and traffic budget for bug bounty programs."""

from __future__ import annotations

import hashlib
import json
from contextlib import closing
from datetime import timezone
from email.utils import parsedate_to_datetime
import math
from pathlib import Path
import re
import secrets
import sqlite3
import time
from urllib.parse import urlsplit

import scope_target


PROGRAM_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,79}\Z")


class BudgetPause(ValueError):
    def __init__(self, reason: str, seconds: float):
        self.seconds = max(1, math.ceil(seconds))
        super().__init__(reason)


def policy_path(root: Path, program_id: str) -> Path:
    if not isinstance(program_id, str) or not PROGRAM_ID.fullmatch(program_id):
        raise ValueError("Identificador de programa inválido")
    return root / "programs" / program_id / "policy.draft.json"


def load(root: Path, program_id: str) -> tuple[dict, str]:
    path = policy_path(root, program_id)
    raw = path.read_bytes()
    policy = json.loads(raw)
    if not isinstance(policy, dict) or policy.get("program_id") != program_id or \
            policy.get("state") != "draft_not_enforced" or \
            policy.get("default_decision") != "deny":
        raise ValueError("Política de programa inválida o sin denegación por defecto")
    assets = policy.get("web_assets")
    if not isinstance(assets, list) or not assets:
        raise ValueError("La política no tiene activos web")
    for asset in assets:
        if not isinstance(asset, dict) or asset.get("scheme") != "https":
            raise ValueError("Solo se admiten activos HTTPS en este perfil")
        if asset.get("kind") == "exact_host_set":
            hosts = asset.get("hosts")
            if not isinstance(hosts, list) or not hosts or \
                    not all(isinstance(host, str) for host in hosts) or \
                    len(hosts) != len(set(hosts)) or \
                    not all(isinstance(host, str) and host == host.lower() and
                            scope_target.web_url("https://" + host)[0] == "https://" + host
                            for host in hosts):
                raise ValueError("Lista de hosts de país inválida")
            if asset.get("application_boundary") != "all_routes":
                surfaces = asset.get("allowed_surfaces")
                if not isinstance(surfaces, list) or not surfaces or \
                        not all(isinstance(item, str) and item for item in surfaces):
                    raise ValueError("La superficie de aplicación debe quedar definida")
        elif asset.get("kind") == "exact_host_plus_subdomains":
            host = asset.get("base_host")
            if not isinstance(host, str) or \
                    scope_target.web_url("https://" + host)[0] != "https://" + host or \
                    asset.get("include_base_host") is not True or \
                    asset.get("include_subdomains") is not True:
                raise ValueError("Base de API inválida")
        else:
            raise ValueError("Tipo de activo no implementado")
    source = policy.get("source")
    if not isinstance(source, dict):
        raise ValueError("Falta la procedencia de la política")
    source_file = path.parent / "source.txt"
    if not source_file.is_file() or hashlib.sha256(source_file.read_bytes()).hexdigest() != source.get("raw_sha256"):
        raise ValueError("El texto fuente cambió; revisa y vuelve a aprobar la política")
    required_headers = policy.get("required_http_headers", {})
    if not isinstance(required_headers, dict):
        raise ValueError("Cabeceras del programa inválidas")
    suffix = required_headers.get("user_agent_append", "")
    if not isinstance(suffix, str) or len(suffix) > 100 or "\r" in suffix or "\n" in suffix:
        raise ValueError("Identificador HTTP inválido")
    return policy, hashlib.sha256(raw).hexdigest()


def active(root: Path, scope: dict) -> tuple[dict, str]:
    program_id = scope.get("program_id")
    if not program_id or scope.get("target_ip") or scope.get("target_url"):
        raise ValueError("No hay un programa bug bounty activo")
    policy, digest = load(root, program_id)
    if digest != scope.get("program_policy_sha256"):
        raise ValueError("La política cambió después de aprobarse; activa de nuevo el programa")
    return policy, digest


def evaluate(policy: dict, url: object, surface: object = None, basis: object = None) -> dict:
    origin, path = scope_target.web_url(url)
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or parsed.port is not None:
        return {"decision": "deny", "reason": "Este perfil solo cubre HTTPS en el puerto 443", "url": str(url)}
    host = parsed.hostname
    for asset in policy["web_assets"]:
        kind = asset["kind"]
        matched = (host in asset["hosts"] if kind == "exact_host_set" else
                   host == asset["base_host"] or host.endswith("." + asset["base_host"]))
        if not matched:
            continue
        result = {"url": origin + path, "host": host, "matched_asset": asset["id"]}
        if kind == "exact_host_set" and asset.get("application_boundary") != "all_routes":
            if surface not in asset["allowed_surfaces"]:
                return {**result, "decision": "review",
                        "reason": "El host solo cubre una superficie de aplicación concreta; indica surface y basis"}
            if not isinstance(basis, str) or not 12 <= len(basis.strip()) <= 500:
                return {**result, "decision": "review",
                        "reason": "Explica qué evidencia vincula esta ruta al comercio electrónico"}
        return {**result, "decision": "allow", "reason": "Activo explícito del programa",
                "surface": surface if kind == "exact_host_set" else "api"}
    return {"url": origin + path, "host": host, "decision": "deny",
            "reason": "No figura entre los activos web autorizados por el programa"}


def _db(root: Path, program_id: str) -> sqlite3.Connection:
    path = policy_path(root, program_id).parent / "traffic.sqlite3"
    connection = sqlite3.connect(path, timeout=5, isolation_level=None)
    connection.execute("CREATE TABLE IF NOT EXISTS requests (at REAL NOT NULL)")
    connection.execute("CREATE TABLE IF NOT EXISTS inflight (token TEXT PRIMARY KEY, expires REAL NOT NULL)")
    connection.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value REAL NOT NULL)")
    return connection


def budget(root: Path, program_id: str, hourly_limit: int | None) -> dict:
    now = time.time()
    path = policy_path(root, program_id).parent / "traffic.sqlite3"
    if not path.exists():
        return {"hourly_limit": hourly_limit, "used_last_hour": 0,
                "remaining_last_hour": hourly_limit, "cooldown_seconds": 0}
    with closing(_db(root, program_id)) as connection:
        used = connection.execute("SELECT COUNT(*) FROM requests WHERE at > ?", (now - 3600,)).fetchone()[0]
        cooldown = connection.execute("SELECT value FROM state WHERE key='cooldown_until'").fetchone()
    return {"hourly_limit": hourly_limit, "used_last_hour": used,
            "remaining_last_hour": max(0, hourly_limit - used) if hourly_limit is not None else None,
            "cooldown_seconds": max(0, round(cooldown[0] - now)) if cooldown else 0}


def reserve(root: Path, program_id: str, hourly_limit: int | None,
            min_interval_seconds: float = 0.0) -> str:
    now = time.time()
    connection = _db(root, program_id)
    begun = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        begun = True
        connection.execute("DELETE FROM inflight WHERE expires < ?", (now,))
        cooldown = connection.execute("SELECT value FROM state WHERE key='cooldown_until'").fetchone()
        if cooldown and cooldown[0] > now:
            raise BudgetPause("Pausa del programa tras 429/503", cooldown[0] - now)
        if connection.execute("SELECT 1 FROM inflight LIMIT 1").fetchone():
            raise BudgetPause("Ya hay una petición del programa en curso", 5)
        used, last, oldest = connection.execute(
            "SELECT COUNT(*), MAX(at), MIN(at) FROM requests WHERE at > ?", (now - 3600,)).fetchone()
        if hourly_limit is not None and used >= hourly_limit:
            raise BudgetPause("Presupuesto horario agotado", oldest + 3600 - now)
        if last and now - last < min_interval_seconds:
            raise BudgetPause("Intervalo mínimo entre peticiones", min_interval_seconds - (now - last))
        token = secrets.token_hex(16)
        connection.execute("INSERT INTO requests(at) VALUES (?)", (now,))
        connection.execute("INSERT INTO inflight(token, expires) VALUES (?, ?)", (token, now + 90))
        connection.execute("COMMIT")
        return token
    except Exception:
        if begun:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def retry_after_seconds(value: object) -> int | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value.isdecimal():
        return min(int(value), 604_800)
    try:
        parsed = parsedate_to_datetime(value)
        stamp = (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()
    except (ValueError, TypeError, OverflowError):
        return None
    return max(0, min(math.ceil(stamp - time.time()), 604_800))


def release(root: Path, program_id: str, token: str, status: int | None = None,
            retry_after: object = None) -> None:
    with closing(_db(root, program_id)) as connection:
        connection.execute("DELETE FROM inflight WHERE token=?", (token,))
        wait = retry_after_seconds(retry_after) if status in {429, 503} else None
        if wait:
            connection.execute("INSERT INTO state(key,value) VALUES ('cooldown_until',?) "
                               "ON CONFLICT(key) DO UPDATE SET value=MAX(value,excluded.value)",
                               (time.time() + wait,))
