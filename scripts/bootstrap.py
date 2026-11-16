#!/usr/bin/env python3
"""Initialize local state and verify both CLI adapters after cloning."""

import json
from pathlib import Path
import shutil

import configure_codex
import sync_skills


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    scope = ROOT / "scope.json"
    if not scope.exists():
        shutil.copy2(ROOT / "scope.example.json", scope)
    config = ROOT / ".codex" / "config.toml"
    if not config.exists():
        shutil.copy2(ROOT / ".codex" / "config.example.toml", config)
    configure_codex.handshake()
    configured = configure_codex.absolute_config(config.read_text(encoding="utf-8"))
    config.write_text(configured, encoding="utf-8")
    count = sync_skills.sync()
    print(f"MCP correcto; {count} skills listas para Codex y Claude Code.")
    print("Para confiar en el proyecto desde Codex, añade a ~/.codex/config.toml:")
    print(f"[projects.{json.dumps(str(ROOT))}]\ntrust_level = \"trusted\"")
    print("Inicia codex o claude desde esta carpeta.")


if __name__ == "__main__":
    main()
