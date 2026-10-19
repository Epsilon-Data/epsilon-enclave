"""
Output Files
Collection and manifest of files a script writes to EPSILON_OUTPUT_DIR.

The manifest format, name rule and type table are a cross-repo contract
(coordinator, job-scheduler and verifier rebuild the same bytes), so keep
them identical everywhere.
"""
import hashlib
import json
import os
import re
import stat
from typing import Any, Dict, List, Tuple

# Extension (lower-cased, after the last dot of the last segment) -> content
# type. Any other extension, or none, is DEFAULT_OUTPUT_TYPE. Do not extend:
# the table is part of the attested manifest.
OUTPUT_TYPES = {
    'csv': 'text/csv',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'json': 'application/json',
    'txt': 'text/plain',
    'pdf': 'application/pdf',
}
DEFAULT_OUTPUT_TYPE = 'application/octet-stream'

# Name = path relative to outputs/ with '/' separators: 1-5 segments, each
# matching the segment rule, whole name at most 255 characters.
OUTPUT_FILE_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9][A-Za-z0-9._-]{0,99}){0,4}')
MAX_OUTPUT_FILE_NAME_LEN = 255

REJECTED_PREFIX = 'Output files rejected: '

_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
_DIRECTORY = getattr(os, 'O_DIRECTORY', 0)


class OutputFilesError(Exception):
    """Raised when the outputs directory violates the output file rules."""


def is_valid_output_file_name(name: str) -> bool:
    """True if name satisfies the cross-repo output file name rule."""
    return len(name) <= MAX_OUTPUT_FILE_NAME_LEN and OUTPUT_FILE_NAME_RE.fullmatch(name) is not None


def output_file_type(name: str) -> str:
    """Content type for an output file name (by extension of its last segment)."""
    base = name.rsplit('/', 1)[-1]
    ext = base.rsplit('.', 1)[1].lower() if '.' in base else ''
    return OUTPUT_TYPES.get(ext, DEFAULT_OUTPUT_TYPE)


def _walk(output_dir: str, max_files: int) -> List[Tuple[str, int]]:
    """(name, size) of every regular file under output_dir, without following symlinks."""
    found = []
    stack = ['']
    while stack:
        rel_dir = stack.pop()
        with os.scandir(os.path.join(output_dir, rel_dir) if rel_dir else output_dir) as it:
            for entry in it:
                name = f'{rel_dir}/{entry.name}' if rel_dir else entry.name
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    raise OutputFilesError(f'symlink not allowed: {name!r}')
                if stat.S_ISDIR(st.st_mode):
                    stack.append(name)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    raise OutputFilesError(f'not a regular file: {name!r}')
                if not is_valid_output_file_name(name):
                    raise OutputFilesError(f'invalid file name: {name!r}')
                found.append((name, st.st_size))
                if len(found) > max_files:
                    raise OutputFilesError(f'too many files (> {max_files})')
    return found


def _open_nofollow(output_dir: str, name: str) -> int:
    """Open output_dir/name read-only, refusing a symlink at any path segment."""
    segments = name.split('/')
    dir_fd = os.open(output_dir, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    try:
        for seg in segments[:-1]:
            next_fd = os.open(seg, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        fd = os.open(segments[-1], os.O_RDONLY | _NOFOLLOW, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OutputFilesError(f'not a regular file: {name!r}')
    return fd


def collect_output_files(output_dir: str, max_files: int, max_total_bytes: int) -> List[Dict[str, Any]]:
    """Read the files a script left anywhere under output_dir.

    Returns [{"name", "size", "sha256", "type", "content"}] sorted by name,
    where name is the path relative to output_dir with '/' separators.
    A missing or empty directory (or only empty subdirectories) yields [].
    Any rule violation raises OutputFilesError; the caller must fail the
    whole execution.
    """
    if not os.path.lexists(output_dir):
        return []
    if os.path.islink(output_dir) or not os.path.isdir(output_dir):
        raise OutputFilesError('outputs is not a directory')

    entries = _walk(output_dir, max_files)
    total = sum(size for _, size in entries)
    if total > max_total_bytes:
        raise OutputFilesError(f'total size too large ({total} > {max_total_bytes} bytes)')

    files = []
    total = 0
    for name, _ in sorted(entries):
        try:
            fd = _open_nofollow(output_dir, name)
        except OSError as e:
            raise OutputFilesError(f'cannot read {name!r}: {e.strerror}')
        with os.fdopen(fd, 'rb') as f:
            content = f.read(max_total_bytes - total + 1)
        total += len(content)
        if total > max_total_bytes:
            raise OutputFilesError(f'total size too large (> {max_total_bytes} bytes)')
        files.append({
            'name': name,
            'size': len(content),
            'sha256': hashlib.sha256(content).hexdigest(),
            'type': output_file_type(name),
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
