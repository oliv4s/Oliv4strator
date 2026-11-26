"""Anonymized audit of local hook denials; not Codex native approval prompts."""
from __future__ import annotations
from collections import Counter
import json
import os
from pathlib import Path
from .common import utc_now

CATEGORIES = {'missing_scope', 'out_of_scope', 'redirect', 'unverifiable', 'other'}


def classify(reason: str) -> str:
    lower = reason.lower()
    if 'no hay destino aprobado' in lower:
        return 'missing_scope'
    if 'fuera del alcance' in lower:
        return 'out_of_scope'
    if 'redireccion' in lower or 'redirecciones' in lower:
        return 'redirect'
    if 'no verificable' in lower or 'no verificable' in lower:
        return 'unverifiable'
    return 'other'


def record(repo: Path, reason: str) -> None:
    folder = Path(repo) / 'work' / 'efficiency'
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'hook_denials.jsonl'
    if path.is_symlink():
        raise ValueError('refusing symlink log')
    payload = json.dumps({'at': utc_now(), 'category': classify(reason)}, separators=(',', ':'))
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        os.write(fd, (payload + '\n').encode())
    finally:
        os.close(fd)


def summary(repo: Path) -> dict:
    path = Path(repo) / 'work' / 'efficiency' / 'hook_denials.jsonl'
    if not path.exists():
        return {'hook_denials': 0, 'categories': {}, 'native_codex_approvals': 'not_observable'}
    if path.is_symlink():
        raise ValueError('refusing symlink log')
    counts = Counter()
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if data.get('category') in CATEGORIES:
                counts[data['category']] += 1
    return {'hook_denials': sum(counts.values()), 'categories': dict(counts),
            'native_codex_approvals': 'not_observable',
            'note': 'Codex permission prompts are not automatically available to this hook.'}
