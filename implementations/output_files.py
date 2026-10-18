"""
Output Files
Collection and manifest of files a script writes to EPSILON_OUTPUT_DIR.

The manifest format and allowed-type table are a cross-repo contract
(coordinator, job-scheduler and verifier rebuild the same bytes), so keep
them identical everywhere.
"""
import hashlib
import json
import os
import re
import stat
from typing import Any, Dict, List

# Extension (lower-cased, after the last dot) -> content type
ALLOWED_OUTPUT_TYPES = {
    'csv': 'text/csv',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'json': 'application/json',
    'txt': 'text/plain',
    'pdf': 'application/pdf',
}

OUTPUT_FILE_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}')

REJECTED_PREFIX = 'Output files rejected: '


class OutputFilesError(Exception):
    """Raised when the outputs directory violates the output file rules."""


def collect_output_files(output_dir: str, max_files: int, max_total_bytes: int) -> List[Dict[str, Any]]:
    """Read the files a script left in output_dir.

    Returns [{"name", "size", "sha256", "type", "content"}] sorted by name.
    A missing or empty directory yields []. Any rule violation raises
    OutputFilesError; the caller must fail the whole execution.
    """
    if not os.path.lexists(output_dir):
        return []
    if os.path.islink(output_dir) or not os.path.isdir(output_dir):
        raise OutputFilesError('outputs is not a directory')

    entries = []
    for entry in os.scandir(output_dir):
        name = entry.name
        st = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            raise OutputFilesError(f'symlink not allowed: {name!r}')
        if stat.S_ISDIR(st.st_mode):
            raise OutputFilesError(f'subdirectory not allowed: {name!r}')
        if not stat.S_ISREG(st.st_mode):
            raise OutputFilesError(f'not a regular file: {name!r}')
        if not OUTPUT_FILE_NAME_RE.fullmatch(name):
            raise OutputFilesError(f'invalid file name: {name!r}')
        ext = name.rsplit('.', 1)[1].lower() if '.' in name else ''
        if ext not in ALLOWED_OUTPUT_TYPES:
            raise OutputFilesError(f'file type not allowed: {name!r}')
        entries.append((name, ALLOWED_OUTPUT_TYPES[ext], st.st_size))

    if len(entries) > max_files:
        raise OutputFilesError(f'too many files ({len(entries)} > {max_files})')
    total = sum(size for _, _, size in entries)
    if total > max_total_bytes:
        raise OutputFilesError(f'total size too large ({total} > {max_total_bytes} bytes)')

    files = []
    total = 0
    for name, content_type, _ in sorted(entries):
        fd = os.open(os.path.join(output_dir, name), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as f:
            content = f.read(max_total_bytes - total + 1)
        total += len(content)
        if total > max_total_bytes:
            raise OutputFilesError(f'total size too large (> {max_total_bytes} bytes)')
        files.append({
            'name': name,
            'size': len(content),
            'sha256': hashlib.sha256(content).hexdigest(),
            'type': content_type,
            'content': content,
        })
    return files


def build_files_manifest(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Manifest entries {"name", "size", "sha256", "type"} sorted by name."""
    manifest = [
        {'name': f['name'], 'size': f['size'], 'sha256': f['sha256'], 'type': f['type']}
        for f in files
    ]
    return sorted(manifest, key=lambda m: m['name'])


def canonical_manifest_bytes(manifest: List[Dict[str, Any]]) -> bytes:
    """Canonical JSON bytes of the manifest (the exact bytes that get hashed)."""
    return json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')


def files_manifest_sha256(manifest: List[Dict[str, Any]]) -> str:
    """Lowercase hex SHA-256 of the canonical manifest bytes ([] when no files)."""
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()
