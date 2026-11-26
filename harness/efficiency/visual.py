"""Exact-byte screenshot dedup hints. Never suppresses native view_image calls.

Use only for user-approved local image paths in the current repo; a digest is
not a semantic comparison and cannot prove two visually similar images equal.
"""
from __future__ import annotations

from pathlib import Path
from .common import atomic_json, digest, read_json, safe_id, utc_now

_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp"}
_MAX_BYTES = 30 * 1024 * 1024


def _verified_image(repo: Path, path: str) -> Path:
    root = repo.resolve()
    file = Path(path).expanduser().resolve()
    allowed = [(root / folder).resolve() for folder in ("cases", "work", "outputs", "evidence")]
    allowed = [folder for folder in allowed if folder.is_relative_to(root)]
    if not any(file.is_relative_to(folder) for folder in allowed):
        raise ValueError("image must be inside cases/, work/, outputs/ or evidence/")
    if file.suffix.lower() not in _IMAGE_EXT or not file.is_file():
        raise ValueError("unsupported or missing local image")
    if file.stat().st_size > _MAX_BYTES:
        raise ValueError("image too large for safe hashing (limit 30 MB)")
    return file


def _index_path(repo: Path, case_id: str) -> Path:
    return repo / "work" / "efficiency" / "visual" / f"{safe_id(case_id)}.json"


def inspect(repo: Path, case_id: str, image_path: str, record: bool = False,
            note: str = "") -> dict:
    image = _verified_image(repo, image_path)
    if not isinstance(note, str) or len(note) > 160 or "\n" in note:
        raise ValueError("note must be a single line of up to 160 chars")
    raw = image.read_bytes()
    image_digest = digest(raw)
    path = _index_path(repo, case_id)
    index = read_json(path, {"schema": "oliva-visual-v2", "entries": {}})
    entries = index.get("entries", {})
    matched = entries.get(image_digest)
    # A previously indexed screenshot is NOT a proof that the semantic state is unchanged.
    result = {"case_id": safe_id(case_id), "sha256": image_digest,
              "bytes": len(raw), "known_exact_bytes": matched is not None,
              "has_saved_observation": bool(matched and matched.get("note")),
              "should_review": not bool(matched and matched.get("note")),
              "caution": "Only byte-identical images match. Always review if context changed."}
    if matched and matched.get("note"):
        result["saved_note"] = matched["note"]
    if record:
        entries[image_digest] = {"seen_at": utc_now(), "note": note}
        if len(entries) > 300:
            # Bounded per-case index, evict oldest stored records.
            oldest = sorted(entries, key=lambda k: entries[k].get("seen_at", ""))[:len(entries)-300]
            for key in oldest:
                del entries[key]
        index["entries"] = entries
        atomic_json(path, index)
        result["recorded"] = True
    return result
