"""Managed per-case scratch directories and explicit artifact retention.

No implicit deletion. Does not manipulate /tmp or files outside work/temp.
Native shells only honor the workspace when launched with TMPDIR set by the user.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import time
from uuid import uuid4

import casebook
from .common import atomic_json, safe_id, utc_now

MARKER = '.oliva-workspace.json'
OWNER = 'oliv4strator-workspace-v1'
MAX_RETAIN_BYTES = 50 * 1024 * 1024


def _directory(path: Path, *, create: bool = False) -> Path:
    """Reject symlinks in workspace paths; 0700 for newly created directories."""
    path = Path(os.path.abspath(path))
    ancestors = list(reversed((path, *path.parents)))
    for part in ancestors:
        if part.is_symlink():
            raise ValueError(f'symlink in managed path: {part}')
        if part.exists():
            if not part.is_dir():
                raise ValueError(f'not a directory: {part}')
        elif create:
            part.mkdir(mode=0o700)
        else:
            raise FileNotFoundError(str(part))
    return path


def location(repo: Path, case_id: str, session_id: str) -> Path:
    casebook.case_dir(Path(repo), case_id)  # reuse canonical case-id validation
    safe_id(session_id)
    return Path(os.path.abspath(repo)) / 'work' / 'temp' / case_id / session_id


def _marker(path: Path, case_id: str, session_id: str) -> dict:
    marker = path / MARKER
    if marker.is_symlink():
        raise ValueError('workspace marker cannot be a symlink')
    if not marker.is_file():
        raise ValueError('unmanaged workspace: missing marker')
    value = json.loads(marker.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or any(value.get(k) != v for k,v in
        {'owner': OWNER, 'case_id': case_id, 'session_id': session_id}.items()):
        raise ValueError('unmanaged workspace: marker mismatch')
    return value


def prepare(repo: Path, case_id: str, session_id: str) -> Path:
    path = location(repo, case_id, session_id)
    existed = path.exists()
    _directory(path, create=True)
    marker = path / MARKER
    if marker.exists() or marker.is_symlink():
        _marker(path, case_id, session_id)
    else:
        if existed and any(path.iterdir()):
            raise ValueError('refusing to adopt a populated unmanaged directory')
        atomic_json(marker, {'owner': OWNER, 'case_id': case_id, 'session_id': session_id,
                             'created_at': utc_now(), 'retained': []})
    return path


def _scan(path: Path) -> tuple[list[Path], int, float]:
    """Scan without traversing links; refuse them so cleanup cannot follow them."""
    if path.is_symlink():
        raise ValueError('workspace is a symlink')
    files: list[Path] = []
    total = 0
    newest = 0.0
    for current, directories, filenames in os.walk(path, followlinks=False):
        current_path = Path(current)
        for name in directories + filenames:
            child = current_path / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f'symlink found; review manually: {child}')
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ValueError(f'special file found; review manually: {child}')
            newest = max(newest, info.st_mtime)
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink > 1:
                    raise ValueError(f'hardlinked file found; review manually: {child}')
                files.append(child)
                total += info.st_size
    return files, total, newest


def inspect(repo: Path, case_id: str, session_id: str) -> dict:
    path = location(repo, case_id, session_id)
    _directory(path)
    manifest = _marker(path, case_id, session_id)
    files, total, newest = _scan(path)
    return {'case_id': case_id, 'session_id': session_id, 'workspace': str(path),
            'files': len(files)-1, 'bytes': total,
            'retained_count': len(manifest.get('retained', [])),
            'newest_modification_utc': (datetime.fromtimestamp(newest, timezone.utc).isoformat()
                                         if newest else None),
            'file_names': [str(p.relative_to(path)) for p in files if p.name != MARKER][:100]}


def retain(repo: Path, case_id: str, session_id: str, relative_file: str,
           note: str = '') -> dict:
    path = location(repo, case_id, session_id)
    _directory(path)
    manifest = _marker(path, case_id, session_id)
    if not isinstance(relative_file, str) or not relative_file or '\\' in relative_file:
        raise ValueError('relative_file must be a relative POSIX path')
    rel = PurePosixPath(relative_file)
    if rel.is_absolute() or any(x in {'.', '..'} for x in rel.parts) or rel.name == MARKER:
        raise ValueError('relative_file must stay inside workspace')
    if not isinstance(note, str) or len(note) > 160 or '\n' in note:
        raise ValueError('note must be one line, at most 160 characters')
    source = path
    for part in rel.parts:
        source = source / part
        if source.is_symlink():
            raise ValueError('refusing symlink artifact')
    info = source.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('artifact must be a regular non-hardlinked file')
    if info.st_size > MAX_RETAIN_BYTES:
        raise ValueError('artifact too large for automatic retention')
    target_dir = casebook.case_dir(Path(repo), case_id) / 'evidence' / 'retained-artifacts'
    _directory(target_dir, create=True)
    # Copy to a new file in the case directory before atomic publication.
    tmp = target_dir / ('.staging-' + uuid4().hex)
    digest = hashlib.sha256()
    try:
        with source.open('rb') as inp, tmp.open('xb') as out:
            os.chmod(tmp, 0o600)
            for block in iter(lambda: inp.read(65536), b''):
                digest.update(block)
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        if source.stat().st_size != info.st_size:
            raise ValueError('artifact changed during retention')
        suffix = re.sub(r'[^A-Za-z0-9._-]', '_', rel.name)[:60]
        name = digest.hexdigest()[:20] + '-' + suffix
        dest = target_dir / name
        if dest.is_symlink():
            raise ValueError('destination is symlink')
        if dest.exists():
            if hashlib.sha256(dest.read_bytes()).hexdigest() != digest.hexdigest():
                raise ValueError('retained artifact hash collision')
        else:
            os.replace(tmp, dest)
        row = {'path': str(dest.relative_to(Path(repo))), 'source': str(rel),
               'sha256': digest.hexdigest(), 'bytes': info.st_size, 'note': note,
               'retained_at': utc_now()}
        manifest['retained'] = [r for r in manifest.get('retained', [])
                                if not (r['source'] == str(rel) and r['sha256'] == row['sha256'])]
        manifest['retained'].append(row)
        atomic_json(path / MARKER, manifest)
        return row
    finally:
        tmp.unlink(missing_ok=True)


def clean(repo: Path, case_id: str, session_id: str,
          *, apply: bool = False, min_age_hours: float = 24.0) -> dict:
    if not isinstance(min_age_hours, (int,float)) or not 0 <= min_age_hours <= 24*365:
        raise ValueError('min_age_hours must be 0..8760')
    path = location(repo, case_id, session_id)
    _directory(path)
    _marker(path, case_id, session_id)
    files, total, newest = _scan(path)
    result = {'workspace': str(path), 'files': len(files)-1, 'bytes': total,
              'deleted': False, 'min_age_hours': min_age_hours}
    if apply:
        age = (time.time() - newest) / 3600
        if age < min_age_hours:
            raise ValueError(f'workspace was modified recently ({age:.2f}h); refusing cleanup')
        # This is a user-triggered delete, restricted to a marked workspace.
        shutil.rmtree(path)
        result['deleted'] = True
    return result
