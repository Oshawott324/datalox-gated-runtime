from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

existing = os.environ.get("PYTHONPATH")
paths = [str(SRC)]
if existing:
    paths.extend(path for path in existing.split(os.pathsep) if path and path != str(SRC))
os.environ["PYTHONPATH"] = os.pathsep.join(paths)
