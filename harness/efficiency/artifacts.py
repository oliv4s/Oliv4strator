"""Per-case, local artifact lifecycle; no target, network or global /tmp actions.

An agent explicitly calls finalize once its work is finished. A managed
workspace is removed from the active tree by atomic rename to a recoverable
quarantine. Only previously registered, unchanged disposable files are deleted
immediately. Unknown files remain recoverable until retention expiry.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import time
from uuid import uuid4

import casebook
from . import workspace
from .common import atomic_json, safe_id, utc_now

QUARANTINE_DAYS = 7
MAX_ITEMS = 1000


def _paths(repo: Path, case_id: str, session_id: str) -> tuple[Path, Path]:
    active = workspace.location(repo, case_id, session_id)
    archived = Path(os.path.abspath(repo)) / 'work' / 'quarantine' / case_id / session_id
    return active, archived


@contextmanager
def _locked(repo: Path, case_id: str, session_id: str):
    """Cross-process workspace lock; never use the workspace being renamed."""
    active, _ = _paths(repo, case_id, session_id)
    lock_folder = active.parent.parent.parent / 'locks' / case_id
    workspace._directory(lock_folder, create=True)
    path = lock_folder / (safe_id(session_id) + '.lock')
    if path.is_symlink():
        raise ValueError('lock is a symlink')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        begin = time.monotonic()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() - begin > 5.0:
                    raise TimeoutError('workspace is busy; retry later')
                time.sleep(.05)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _rel(path: str) -> str:
    if not isinstance(path, str) or not path or '\\' in path:
        raise ValueError('file must be a relative POSIX path')
    rel = PurePosixPath(path)
    if rel.is_absolute() or rel.parts[0] == '..' or '..' in rel.parts or rel.name == workspace.MARKER:
        raise ValueError('file must stay inside managed workspace')
    if any(p in {'', '.', '..'} for p in rel.parts):
        raise ValueError('invalid artifact path')
    return str(rel)


def _regular(path: Path, root: Path) -> os.stat_result:
    if not root.is_dir() or root.is_symlink():
        raise ValueError('invalid managed workspace')
    candidate = root
    for part in path.relative_to(root).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError('symlink is not allowed')
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError('artifact must be a regular non-hardlinked file')
    return st


def _hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(131072), b''):
            h.update(block)
    return h.hexdigest()


def prepare(repo: Path, case_id: str, session_id: str) -> dict:
    with _locked(repo, case_id, session_id):
        active, archived = _paths(repo, case_id, session_id)
        if archived.exists() or archived.is_symlink():
            raise ValueError('session is finalized; use a new session ID')
        path = workspace.prepare(repo, case_id, session_id)
        return {'workspace': str(path), 'state': 'active', 'case_id': case_id,
                'session_id': session_id}


def status(repo: Path, case_id: str, session_id: str) -> dict:
    active, archived = _paths(repo, case_id, session_id)
    if archived.exists() or archived.is_symlink():
        workspace._directory(archived)
        marker = workspace._marker(archived, case_id, session_id)
        return {'case_id': case_id, 'session_id': session_id, 'state': 'finalized',
                'retained': len(marker.get('retained', [])),
                'quarantined': marker.get('quarantined_count', None),
                'discarded': len(marker.get('discarded_files', [])),
                'recovery_path': str(archived)}
    if active.exists():
        marker = workspace._marker(active, case_id, session_id)
        files, _, _ = workspace._scan(active)
        return {'case_id': case_id, 'session_id': session_id,
                'state': marker.get('state', 'active'),
                'files': len(files) - 1,
                'registered': len(marker.get('disposable', [])),
                'retained': len(marker.get('retained', []))}
    return {'case_id': case_id, 'session_id': session_id, 'state': 'missing'}


def register(repo: Path, case_id: str, session_id: str, file: str,
             disposition: str, evidence_ids: list[str] | None = None,
             note: str = '') -> dict:
    """Register only known evidence or explicitly disposable scratch files.

    Unregistered content is never automatically categorized as disposable.
    """
    if disposition not in {'retain', 'discard'}:
        raise ValueError('disposition must be retain or discard')
    rel = _rel(file)
    if not isinstance(note, str) or len(note) > 160 or '\n' in note:
        raise ValueError('note must be one line and at most 160 characters')
    evidence_ids = [] if evidence_ids is None else evidence_ids
    with _locked(repo, case_id, session_id):
        root, archived = _paths(repo, case_id, session_id)
        if archived.exists() or archived.is_symlink():
            raise ValueError('session already finalized')
        workspace._directory(root)
        marker = workspace._marker(root, case_id, session_id)
        if marker.get('state', 'active') != 'active':
            raise ValueError('session is not active')
        item = root / rel
        info = _regular(item, root)
        if disposition == 'retain':
            if (not isinstance(evidence_ids, list) or not evidence_ids or
                len(evidence_ids) > 10 or
                any(not isinstance(eid, str) for eid in evidence_ids)):
                raise ValueError('retained artifacts require 1..10 evidence IDs')
            known = casebook.event_ids(Path(repo), case_id)
            if not set(evidence_ids).issubset(known):
                raise ValueError('retention evidence IDs must exist in this case')
            result = workspace.retain(repo, case_id, session_id, rel, note)
            # Retained evidence rows remain authoritative in the workspace marker.
            marker = workspace._marker(root, case_id, session_id)
            for row in marker['retained']:
                if row['source'] == rel and row['sha256'] == result['sha256']:
                    row['evidence_ids'] = sorted(set(evidence_ids))
                    break
            # A newer version of the same file supersedes earlier snapshots.
            marker['retained'] = [r for r in marker['retained']
                                  if r['source'] != rel or r['sha256'] == result['sha256']]
            marker['disposable'] = [r for r in marker.get('disposable', [])
                                    if r['file'] != rel]
            atomic_json(root / workspace.MARKER, marker)
            return {'file': rel, 'disposition': 'retained', 'sha256': result['sha256'],
                    'case_path': result['path'], 'evidence_count': len(set(evidence_ids))}
        if evidence_ids:
            raise ValueError('discard records may not carry evidence IDs')
        if any(row['source'] == rel for row in marker.get('retained', [])):
            raise ValueError('cannot discard a retained artifact')
        record = {'file': rel, 'sha256': _hash(item), 'size': info.st_size,
                  'note': note}
        rows = [r for r in marker.get('disposable', []) if r['file'] != rel]
        if len(rows) >= MAX_ITEMS:
            raise ValueError('too many registered temporary files')
        rows.append(record)
        marker['disposable'] = rows
        atomic_json(root / workspace.MARKER, marker)
        return {'file': rel, 'disposition': 'discard_on_finalize',
                'sha256': record['sha256']}


def finalize(repo: Path, case_id: str, session_id: str,
             outcome: str = 'completed') -> dict:
    """One bounded, idempotent task-end operation. Never touches remote files."""
    if outcome not in {'completed', 'partial', 'stopped'}:
        raise ValueError('outcome must be completed, partial, or stopped')
    with _locked(repo, case_id, session_id):
        root, archived = _paths(repo, case_id, session_id)
        if archived.exists() or archived.is_symlink():
            return {**status(repo, case_id, session_id), 'already_finalized': True}
        workspace._directory(root)
        marker = workspace._marker(root, case_id, session_id)
        # No file activity or concurrent commands should continue when called.
        # We cannot inspect arbitrary clients' open file descriptors.
        all_files, _, _ = workspace._scan(root)  # rejects symlinks, devices, hardlinks
        names = {str(path.relative_to(root)) for path in all_files}
        retained_rows = marker.get('retained', [])
        retained_sources = {r['source'] for r in retained_rows}
        # A retained copy must exist and match before any scratch removal.
        trusted_retained_dir = casebook.case_dir(Path(repo), case_id) / 'evidence' / 'retained-artifacts'
        if retained_rows:
            workspace._directory(trusted_retained_dir)
        for row in retained_rows:
            saved = row.get('path', '')
            if not isinstance(saved, str) or not saved.startswith(str(trusted_retained_dir.relative_to(Path(repo))) + '/'):
                raise ValueError('retained path is outside this case evidence directory')
            if '..' in PurePosixPath(saved).parts:
                raise ValueError('invalid retained path')
            target = Path(repo) / saved
            _regular(target, trusted_retained_dir)
            if _hash(target) != row['sha256']:
                raise ValueError('retained artifact copy is missing or modified')
            original = root / _rel(row['source'])
            if original.exists() and _hash(original) != row['sha256']:
                raise ValueError('retained source changed; register again before finalization')
        removed = []
        for record in marker.get('disposable', []):
            rel = _rel(record['file'])
            if rel in retained_sources or rel not in names:
                continue
            item = root / rel
            st = _regular(item, root)
            if st.st_size != record['size'] or _hash(item) != record['sha256']:
                continue  # changed files are quarantined, never deleted
            item.unlink()
            removed.append(rel)
        marker['state'] = 'finalized'
        marker['outcome'] = outcome
        marker['finalized_at'] = utc_now()
        marker['discarded_files'] = removed[:MAX_ITEMS]
        marker['quarantined_count'] = max(0, len(all_files) - 1 - len(removed))
        atomic_json(root / workspace.MARKER, marker)
        workspace._directory(archived.parent, create=True)
        # Atomic within same repo filesystem; no deletion of unclassified files.
        os.rename(root, archived)
        return {**status(repo, case_id, session_id), 'already_finalized': False,
                'outcome': outcome}


def restore(repo: Path, case_id: str, session_id: str) -> dict:
    """Explicit recovery of quarantined content; never implicitly reopens it."""
    with _locked(repo, case_id, session_id):
        root, archived = _paths(repo, case_id, session_id)
        workspace._directory(archived)
        marker = workspace._marker(archived, case_id, session_id)
        if root.exists() or root.is_symlink():
            raise ValueError('active workspace already exists')
        workspace._scan(archived)
        marker['state'] = 'active'
        marker.pop('finalized_at', None)
        atomic_json(archived / workspace.MARKER, marker)
        workspace._directory(root.parent, create=True)
        os.rename(archived, root)
        return {'workspace': str(root), 'state': 'active', 'restored': True}


def prune(repo: Path, *, min_age_days: int = QUARANTINE_DAYS) -> dict:
    """Expire only well-formed quarantined sessions, during explicit maintenance.

    No timer, background process or global filesystem deletion.
    """
    if type(min_age_days) is not int or min_age_days < QUARANTINE_DAYS:
        raise ValueError(f'min_age_days must be at least {QUARANTINE_DAYS}')
    home = Path(os.path.abspath(repo)) / 'work' / 'quarantine'
    if not home.exists():
        return {'expired': 0, 'skipped': 0}
    workspace._directory(home)
    expired, skipped = 0, 0
    for case_folder in home.iterdir():
        if case_folder.is_symlink() or not case_folder.is_dir():
            skipped += 1
            continue
        for folder in case_folder.iterdir():
            try:
                case_id, session_id = case_folder.name, folder.name
                with _locked(repo, case_id, session_id):
                    workspace._directory(folder)
                    marker = workspace._marker(folder, case_id, session_id)
                    if marker.get('state') != 'finalized':
                        skipped += 1
                        continue
                    timestamp = datetime.fromisoformat(marker['finalized_at'])
                    if timestamp.tzinfo is None:
                        raise ValueError('invalid finalization timestamp')
                    age = (datetime.now(timezone.utc) - timestamp).total_seconds()/86400
                    if age < min_age_days:
                        skipped += 1
                        continue
                    _, _, newest = workspace._scan(folder)
                    if newest > time.time() - min_age_days*86400:
                        skipped += 1
                        continue
                    # Retained evidence lives outside the quarantine directory.
                    import shutil
                    if not shutil.rmtree.avoids_symlink_attacks:
                        raise ValueError('safe directory deletion unavailable on this platform')
                    shutil.rmtree(folder)
                    expired += 1
            except (ValueError, OSError, KeyError, TimeoutError):
                skipped += 1
    return {'expired': expired, 'skipped': skipped}
