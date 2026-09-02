import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_provider_runtime_report_is_structurally_valid() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/check_provider_runtime_coverage.py",
            "--validate-report",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "49 provider assets" in completed.stdout
