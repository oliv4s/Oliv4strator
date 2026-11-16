#!/usr/bin/env python3
"""Copy canonical Codex skills into Claude Code's project skill directory."""

from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".agents" / "skills"
DESTINATION = ROOT / ".claude" / "skills"


def sync() -> int:
    files = sorted(SOURCE.glob("*/SKILL.md"))
    if not files:
        raise RuntimeError("No hay skills en .agents/skills")
    for source in files:
        destination = DESTINATION / source.parent.name / "SKILL.md"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists() or destination.read_bytes() != source.read_bytes():
            shutil.copy2(source, destination)
    return len(files)


if __name__ == "__main__":
    print(f"{sync()} skills sincronizadas con Claude Code")
