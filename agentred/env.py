"""Minimal .env loader (no external dependency).

Reads a KEY=VALUE file into os.environ so API keys can live in a local, gitignored
`.env` instead of the shell. Real environment variables always win — the file
never overrides something already set.

Deliberately tiny: `KEY=VALUE` per line, `#` comments and blank lines ignored,
optional surrounding quotes stripped, and an optional leading `export `. For
anything fancier, install python-dotenv; this covers API keys.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | os.PathLike[str] = ".env", *, override: bool = False) -> bool:
    """Load `path` into os.environ. Returns True if the file existed."""
    p = Path(path)
    if not p.is_file():
        return False

    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = value
    return True
