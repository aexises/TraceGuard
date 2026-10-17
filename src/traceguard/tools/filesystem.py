"""Descriptor-relative filesystem access for the supported POSIX profile."""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from uuid import uuid4


def _parts(raw: str) -> tuple[str, ...]:
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or not path.parts or "\\" in raw:
        raise ValueError(f"path escapes allowed root: {raw}")
    return path.parts


def _directory(parent: int, name: str) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)


@contextmanager
def confined_parent(root: Path, raw: str, *, create: bool = False):
    parts = _parts(raw)
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise ValueError("secure filesystem profile requires POSIX no-follow dirfd support")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in (*root.absolute().parts[1:], *parts[:-1]):
            try:
                child = _directory(descriptor, name)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(name, mode=0o700, dir_fd=descriptor)
                child = _directory(descriptor, name)
            os.close(descriptor)
            descriptor = child
        yield descriptor, parts[-1]
    except OSError as exc:
        raise ValueError("unsafe filesystem alias, object or parent") from exc
    finally:
        os.close(descriptor)


def read_confined(root: Path, raw: str, *, max_bytes: int) -> bytes:
    with confined_parent(root, raw) as (parent, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("only regular non-aliased files may be read")
            if metadata.st_size > max_bytes:
                raise ValueError(f"file exceeds read limit of {max_bytes} bytes")
            chunks = bytearray()
            while len(chunks) <= max_bytes:
                data = os.read(descriptor, min(65536, max_bytes + 1 - len(chunks)))
                if not data:
                    break
                chunks.extend(data)
            if len(chunks) > max_bytes:
                raise ValueError(f"file exceeds read limit of {max_bytes} bytes")
            return bytes(chunks)
        finally:
            os.close(descriptor)


def write_confined(root: Path, raw: str, content: bytes) -> None:
    with confined_parent(root, raw, create=True) as (parent, name):
        try:
            existing = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing and (not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1):
            raise ValueError("only regular non-aliased files may be replaced")
        temporary = f".traceguard-{uuid4().hex}.tmp"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            # Atomic rename never follows a concurrently swapped destination link.
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
