#!/usr/bin/env python3
"""Validate the shared Codex and Claude Code skill library."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".agents" / "skills"
CLAUDE = ROOT / ".claude" / "skills"
ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def validate() -> list[str]:
    errors: list[str] = []
    files = sorted(SOURCE.glob("*/SKILL.md"))
    if not files:
        return ["No se encontraron skills en .agents/skills"]
    claude_files = sorted(CLAUDE.glob("*/SKILL.md"))
    if len(claude_files) != len(files):
        errors.append("El número de skills de Claude difiere de Codex")
    for path in files:
        name = path.parent.name
        content = path.read_text(encoding="utf-8")
        if not ID.fullmatch(name):
            errors.append(f"{name}: ID inválido")
        if not content.startswith("---\n") or "\n---\n" not in content[4:]:
            errors.append(f"{name}: frontmatter incompleto")
        front = content.split("---", 2)[1] if content.startswith("---") else ""
        manifest_name = re.search(r"(?m)^name:\s*(.+?)\s*$", front)
        if not manifest_name or manifest_name.group(1) != name:
            errors.append(f"{name}: name debe coincidir con el directorio")
        if not re.search(r"(?m)^description:\s*\S", front):
            errors.append(f"{name}: falta description")
        if IP.search(content) or "HTB{" in content or "cases/10." in content:
            errors.append(f"{name}: detalle de un objetivo dentro de una skill general")
        if len(content) > 5_000:
            errors.append(f"{name}: más de 5000 caracteres; divide o resume")
        claude_path = CLAUDE / name / "SKILL.md"
        if not claude_path.is_file() or claude_path.read_bytes() != path.read_bytes():
            errors.append(f"{name}: copia Claude desactualizada; ejecuta sync_skills.py")
    return errors


if __name__ == "__main__":
    problems = validate()
    if problems:
        print("\n".join(problems), file=sys.stderr)
        raise SystemExit(1)
    print(f"{len(list(SOURCE.glob('*/SKILL.md')))} skills válidas")
