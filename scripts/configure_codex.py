#!/usr/bin/env python3
"""Pin the Codex MCP server to this installation's absolute Kali paths."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "codex_lab_mcp.py"
CONFIG = ROOT / ".codex" / "config.toml"


def handshake() -> None:
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "oliva-setup", "version": "1"}}}
    result = subprocess.run([sys.executable, str(SERVER)], cwd=ROOT,
                            input=json.dumps(request) + "\n", text=True,
                            capture_output=True, timeout=10, check=False)
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("El MCP no respondió al handshake:\n" + result.stderr[-3000:])
    try:
        reply = json.loads(result.stdout.splitlines()[0])
    except json.JSONDecodeError as error:
        raise RuntimeError("El MCP devolvió una respuesta no JSON:\n" + result.stdout[:1000]) from error
    if reply.get("id") != 1 or reply.get("result", {}).get("serverInfo", {}).get("name") != "oliv4strator-lab":
        raise RuntimeError("Respuesta de handshake inesperada: " + str(reply)[:1000])


def absolute_config(source: str) -> str:
    start = source.find("[mcp_servers.oliva_lab]\n")
    if start < 0:
        raise ValueError("No se encontró [mcp_servers.oliva_lab] en .codex/config.toml")
    end = source.find("\n[", start + 1)
    if end < 0:
        end = len(source)
    section = source[start:end]
    values = {"command": json.dumps(sys.executable),
              "args": "[" + json.dumps(str(SERVER)) + "]",
              "cwd": json.dumps(str(ROOT))}
    for key, value in values.items():
        section, count = re.subn(rf"(?m)^{key}\s*=\s*.*$",
                                 lambda _: f"{key} = {value}", section)
        if count != 1:
            raise ValueError(f"Falta la clave {key} en la configuración MCP")
    configured = source[:start] + section + source[end:]
    for tool in ("lab_scope", "lab_program_activate"):
        marker = f"[mcp_servers.oliva_lab.tools.{tool}]"
        position = configured.find(marker)
        if position < 0:
            continue
        section_end = configured.find("\n[", position + len(marker))
        if section_end < 0:
            section_end = len(configured)
        tool_section = configured[position:section_end]
        tool_section = re.sub(r'(?m)^approval_mode\s*=\s*"approve"\s*$',
                              'approval_mode = "auto"', tool_section)
        configured = configured[:position] + tool_section + configured[section_end:]
    return configured


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Solo comprobar el handshake")
    args = parser.parse_args()
    handshake()
    if args.check:
        print("Handshake MCP correcto")
        return
    current = CONFIG.read_text(encoding="utf-8")
    configured = absolute_config(current)
    if configured != current:
        CONFIG.write_text(configured, encoding="utf-8")
    print(f"Handshake MCP correcto. Codex usará {SERVER} con {sys.executable}.")
    print("Si Codex avisa de proyecto no confiable, añade en ~/.codex/config.toml:")
    print(f"[projects.{json.dumps(str(ROOT))}]\ntrust_level = \"trusted\"")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error)) from error
