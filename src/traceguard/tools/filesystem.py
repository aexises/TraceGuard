"""Descriptor-relative filesystem access for the supported POSIX profile."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from uuid import uuid4


@dataclass
class CopyBudget:
    """Shared traversal/copy limits, enforced while consuming untrusted inputs."""

    max_entries: int = 1024
    max_bytes: int = 16_777_216
    max_file_bytes: int = 8_388_608
    max_depth: int = 16
    timeout_seconds: float = 5
    entries: int = 0
    bytes: int = 0
    started: float = field(default_factory=time.monotonic)

    def check(self) -> None:
        if time.monotonic() - self.started > self.timeout_seconds:
            raise ValueError("input staging time limit exceeded")
        if self.entries > self.max_entries or self.bytes > self.max_bytes:
            raise ValueError("input staging entry or byte limit exceeded")


def copy_confined(
    root: Path,
    raw: str,
    destination: Path,
    *,
    budget: CopyBudget,
    prohibited: Callable[[str], bool] = lambda _: False,
) -> None:
    """Copy opened regular objects without following names after validation.

    Destination must be a new path inside a private staging directory. No symlinks,
    hardlinked files, special objects or path-based recursive copy are permitted.
    """
    parts = _parts(raw)

    def copy_object(parent: int, name: str, relative: str, target: Path, depth: int) -> None:
        budget.entries += 1
        budget.check()
        if depth > budget.max_depth or prohibited(relative):
            raise ValueError("protected object or input depth limit exceeded")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            if stat.S_ISDIR(before.st_mode):
                target.mkdir(mode=0o700)
                with os.scandir(descriptor) as children:
                    for child in children:
                        copy_object(
                            descriptor,
                            child.name,
                            relative + "/" + child.name,
                            target / child.name,
                            depth + 1,
                        )
                target.chmod(0o555)
            elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                if before.st_size > budget.max_file_bytes:
                    raise ValueError("input staging per-file limit exceeded")
                written = 0
                with target.open("xb") as output:
                    while True:
                        budget.check()
                        chunk = os.read(descriptor, 65_536)
                        if not chunk:
                            break
                        written += len(chunk)
                        budget.bytes += len(chunk)
                        budget.check()
                        if written > budget.max_file_bytes:
                            raise ValueError("input staging per-file limit exceeded")
                        output.write(chunk)
                after = os.fstat(descriptor)
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                    after.st_nlink,
                ):
                    raise ValueError("input object changed while copying")
                target.chmod(0o444)
            else:
                raise ValueError("input must be a regular non-aliased file or directory")
        finally:
            os.close(descriptor)

    with confined_parent(root, raw) as (parent, name):
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        copy_object(parent, name, "/".join(parts), destination, len(parts))


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
