import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_entrypoint_imports():
    result = subprocess.run(
        [sys.executable, "-c", "import asyncio, signal, nonce_monitor; assert hasattr(signal, 'getsignal'); asyncio.run(asyncio.sleep(0))"],
        cwd=ROOT, capture_output=True, text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 0, result.stderr


def test_no_stdlib_shadowing():
    assert not {p.stem for p in ROOT.glob("*.py")} & sys.stdlib_module_names
