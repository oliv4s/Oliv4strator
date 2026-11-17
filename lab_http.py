"""HTTP requests bound to a scanned lab IP or one approved web origin."""

from __future__ import annotations

from http.cookies import SimpleCookie, CookieError
import http.client
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

import casebook


HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,251}(?::[0-9]{1,5})?\Z")
HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
SESSION = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
REDIRECTS = {301, 302, 303, 307, 308}
SELECTED_HEADERS = {"content-type", "content-length", "location", "server", "www-authenticate",
                    "x-powered-by", "cache-control", "retry-after", "allow", "vary", "etag",
                    "access-control-allow-origin", "access-control-allow-credentials",
                    "access-control-allow-methods", "access-control-expose-headers",
                    "content-security-policy", "x-frame-options", "x-content-type-options"}


class BoundHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the approved IP while using the requested vhost for TLS SNI."""

    def __init__(self, ip: str, port: int, sni: str, timeout: int):
        super().__init__(ip, port, timeout=timeout, context=ssl._create_unverified_context())
        self._sni = sni

    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._sni)


def _host(value: object, ip: str) -> str:
    if value is None:
        return ip
    if not isinstance(value, str) or not HOST.fullmatch(value) or ".." in value:
        raise ValueError("Host virtual inválido")
    return value.lower()


def _path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or \
            "\\" in value or len(value) > 2048 or "\r" in value or "\n" in value:
        raise ValueError("Ruta HTTP inválida")
    return value


def _headers(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 20:
        raise ValueError("Usa un máximo de 20 cabeceras")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not HEADER.fullmatch(key) or key.lower() in {"host", "cookie", "content-length"}:
            raise ValueError("Nombre de cabecera HTTP inválido o reservado")
        if not isinstance(item, str) or len(item) > 2000 or "\r" in item or "\n" in item:
            raise ValueError("Valor de cabecera HTTP inválido")
        result[key] = item
    return result


def _cookie_header(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 4096 or "\r" in value or "\n" in value:
        raise ValueError("Cookie inválida")
    return value


def _jar_path(root: Path, ip: str) -> Path:
    return casebook.case_dir(root, ip) / "http_sessions.json"


def _load_jar(root: Path, ip: str) -> dict:
    path = _jar_path(root, ip)
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _session_key(session: str, host: str, port: int) -> str:
    return f"{session}|{host}|{port}"


def _update_cookies(jar: dict, key: str, response_headers: list[tuple[str, str]]) -> list[str]:
    current = jar.setdefault(key, {})
    for name, value in response_headers:
        if name.lower() != "set-cookie":
            continue
        parsed = SimpleCookie()
        try:
            parsed.load(value)
        except CookieError:
            continue
        for cookie_name, morsel in parsed.items():
            if len(cookie_name) <= 100 and len(morsel.value) <= 2000 and len(current) < 30:
                current[cookie_name] = morsel.value
    return sorted(current)


def _cookie_metadata(response_headers: list[tuple[str, str]]) -> list[dict]:
    """Show cookie names and attributes without disclosing session values."""
    result = []
    for header, value in response_headers:
        if header.lower() != "set-cookie":
            continue
        parsed = SimpleCookie()
        try:
            parsed.load(value)
        except CookieError:
            continue
        for name, morsel in parsed.items():
            if len(result) >= 30:
                return result
            result.append({"name": name[:100], "secure": bool(morsel["secure"]),
                           "httponly": bool(morsel["httponly"]),
                           "samesite": morsel["samesite"][:30],
                           "path": morsel["path"][:100], "domain": morsel["domain"][:100]})
    return result


def request(root: Path, artifacts: Path, ip: str, port: int, data: dict, *,
            web_origin: str | None = None, case_id: str | None = None,
            response_limit: int = 8_000_000, text_limit: int = 12_000,
            save_artifacts: bool = True, user_agent_suffix: str = "") -> dict:
    method = str(data.get("method", "GET")).upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("Método HTTP no permitido")
    path = _path(data.get("path", "/"))
    if web_origin is not None:
        approved = urlsplit(web_origin)
        approved_port = approved.port or (443 if approved.scheme == "https" else 80)
        if approved_port != port or approved.hostname != ip:
            raise ValueError("Origen web aprobado incoherente")
        host = approved.netloc
        if data.get("host") is not None and data["host"].lower() != host:
            raise ValueError("Host distinto del origen web aprobado; fija otro alcance")
        tls = approved.scheme == "https"
        if data.get("tls") is not None and data["tls"] is not tls:
            raise ValueError("El esquema HTTP(S) difiere del origen web aprobado")
    else:
        host = _host(data.get("host"), ip)
        tls = data.get("tls", port in {443, 8443})
    if type(tls) is not bool:
        raise ValueError("TLS inválido")
    verify_tls = data.get("tls_verify", True)
    if type(verify_tls) is not bool or (web_origin is None and "tls_verify" in data):
        raise ValueError("tls_verify solo se admite como booleano en retos web")
    body = data.get("body", "")
    if not isinstance(body, str) or len(body.encode("utf-8")) > 16_384:
        raise ValueError("Cuerpo HTTP demasiado grande")
    extra_headers = _headers(data.get("headers"))
    if not save_artifacts and data.get("save"):
        raise ValueError("Este perfil no permite guardar cuerpos de respuesta completos")
    cookie = _cookie_header(data.get("cookie"))
    session = data.get("session")
    if session is not None and (not isinstance(session, str) or not SESSION.fullmatch(session)):
        raise ValueError("Nombre de sesión HTTP inválido")
    follow = data.get("follow_redirects", False)
    if type(follow) is not bool:
        raise ValueError("follow_redirects debe ser booleano")
    jar = _load_jar(root, case_id or ip) if session else {}
    redirects = []
    result = {}
    for _ in range(4):
        if web_origin is not None:
            connection = (http.client.HTTPSConnection(ip, port, timeout=12,
                                                     context=ssl.create_default_context() if verify_tls else ssl._create_unverified_context())
                          if tls else http.client.HTTPConnection(ip, port, timeout=12))
        else:
            connection = (BoundHTTPSConnection(ip, port, host.split(":", 1)[0], 12)
                          if tls else http.client.HTTPConnection(ip, port, timeout=12))
        try:
            headers = {"Host": host, **extra_headers}
            user_agent = next((value for name, value in extra_headers.items()
                               if name.lower() == "user-agent"), "Oliv4strator/1")
            for name in list(headers):
                if name.lower() == "user-agent":
                    del headers[name]
            headers["User-Agent"] = user_agent.rstrip() + user_agent_suffix
            if body and not any(key.lower() == "content-type" for key in headers):
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            key = _session_key(session, host, port) if session else None
            if cookie is not None:
                headers["Cookie"] = cookie
            elif key and jar.get(key):
                headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in jar[key].items())
            connection.request(method, path, body=body.encode("utf-8") if body else None, headers=headers)
            response = connection.getresponse()
            content = response.read(response_limit + 1)
            truncated = len(content) > response_limit
            if truncated and response_limit == 8_000_000:
                raise ValueError("Respuesta mayor de 8 MB")
            if truncated:
                content = content[:response_limit]
            response_headers = response.getheaders()
            cookie_details = _cookie_metadata(response_headers)
            cookie_names = sorted({item["name"] for item in cookie_details})
            if key:
                _update_cookies(jar, key, response_headers)
            if session:
                casebook.atomic_json(_jar_path(root, case_id or ip), jar)
            selected = {name.lower(): value[:300] for name, value in response_headers
                        if name.lower() in SELECTED_HEADERS}
            result = {"port": port, "method": method, "path": path, "host": host, "tls": tls,
                      "status": response.status, "headers": selected, "bytes": len(content),
                      "text": content[:text_limit].decode("utf-8", "replace"),
                      "cookie_names": cookie_names, "cookie_attributes": cookie_details,
                      "redirect_chain": redirects.copy()}
            if truncated:
                result["response_capped"] = True
            if save_artifacts and (data.get("save") is True or len(content) > text_limit):
                artifacts.mkdir(exist_ok=True)
                identifier = uuid4().hex[:12]
                (artifacts / (identifier + ".bin")).write_bytes(content)
                result["artifact_id"] = identifier
                result["text_truncated"] = len(content) > text_limit
            elif len(content) > text_limit:
                result["text_truncated"] = True
            location = selected.get("location")
            if not (follow and method in {"GET", "HEAD"} and response.status in REDIRECTS and location and
                    len(redirects) < 3):
                return result
            current_url = ("https" if tls else "http") + "://" + host + path
            next_url = urlsplit(urljoin(current_url, location))
            next_tls = next_url.scheme == "https"
            next_port = next_url.port or (443 if next_tls else 80)
            if web_origin is not None and (next_url.scheme != approved.scheme or
                                           next_url.hostname != approved.hostname or
                                           next_port != approved_port):
                result["redirect_not_followed"] = "Otro origen web; solicita lab_scope antes de visitarlo"
                return result
            if next_url.scheme not in {"http", "https"} or next_port != port or next_tls != tls:
                result["redirect_not_followed"] = "El destino cambia de esquema o puerto; escanéalo y solicítalo por separado"
                return result
            next_host = approved.netloc if web_origin is not None else _host(next_url.netloc, ip)
            next_path = _path((next_url.path or "/") + ("?" + next_url.query if next_url.query else ""))
            redirects.append({"status": response.status, "location": location[:300]})
            host, path = next_host, next_path
            cookie = None
        finally:
            connection.close()
    return result
