"""Isolated stdlib exporter: bounded no-follow reads from the output tmpfs.

Executed using python -I. Its output is still untrusted and validated by the host.
"""

import base64
import json
import os
import stat
import sys
import time


def collect(root, limits):
    files = []
    total = 0
    entries = 0
    deadline = time.monotonic() + 5

    def visit(parent, relative, depth):
        nonlocal total, entries
        if depth > limits["max_depth"]:
            raise ValueError("artifact depth limit")
        with os.scandir(parent) as children:
            for child in children:
                entries += 1
                if entries > limits["max_entries"] or time.monotonic() > deadline:
                    raise ValueError("artifact traversal limit")
                descriptor = os.open(
                    child.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent,
                )
                try:
                    before = os.fstat(descriptor)
                    path = relative + child.name
                    if stat.S_ISDIR(before.st_mode):
                        visit(descriptor, path + "/", depth + 1)
                    elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                        if len(files) >= limits["max_files"]:
                            raise ValueError("artifact file count")
                        data = bytearray()
                        while True:
                            chunk = os.read(descriptor, 65536)
                            if not chunk:
                                break
                            data.extend(chunk)
                            total += len(chunk)
                            if (
                                len(data) > limits["max_file_bytes"]
                                or total > limits["max_total_bytes"]
                                or time.monotonic() > deadline
                            ):
                                raise ValueError("artifact size/time limit")
                        after = os.fstat(descriptor)
                        if (
                            before.st_size,
                            before.st_mtime_ns,
                            before.st_ctime_ns,
                            before.st_nlink,
                        ) != (
                            after.st_size,
                            after.st_mtime_ns,
                            after.st_ctime_ns,
                            after.st_nlink,
                        ):
                            raise ValueError("artifact changed during export")
                        files.append({"path": path, "data": base64.b64encode(data).decode("ascii")})
                    else:
                        raise ValueError("artifact symbolic-link, hardlink or special object")
                finally:
                    os.close(descriptor)

    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(descriptor, "", 1)
    finally:
        os.close(descriptor)
    return files


if __name__ == "__main__":
    print(json.dumps(collect(sys.argv[1], json.loads(sys.argv[2])), separators=(",", ":")))
