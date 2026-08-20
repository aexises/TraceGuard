"""Regression checks for repository-local README links."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
README_PATH = REPOSITORY_ROOT / "README.md"
LOCAL_LINK_PATTERN = re.compile(r"\[[^]]+\]\(([^)#]+)(?:#[^)]*)?\)")


def test_readme_local_links_target_tracked_files() -> None:
    """Keep README links independent of ignored developer-local documents."""
    targets = LOCAL_LINK_PATTERN.findall(README_PATH.read_text(encoding="utf-8"))

    missing = [target for target in targets if not (REPOSITORY_ROOT / target).is_file()]
    assert not missing, f"README links target missing files: {', '.join(missing)}"

    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", *targets],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "README links must target tracked files, not local-only documents: "
        f"{', '.join(targets)}"
    )
