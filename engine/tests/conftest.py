import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own state and a file key: it never touches ~/.anonimizador or the Keychain."""
    home = tmp_path / "state"
    monkeypatch.setenv("ANONYMIZER_HOME", str(home))
    monkeypatch.setenv("ANONYMIZER_OUTPUT", str(tmp_path / "anonimizados"))
    return home


@pytest.fixture
def traps(tmp_path):
    output = tmp_path / "sensibles"
    subprocess.run(
        [sys.executable, str(ROOT / "canaries" / "generate.py"), str(output), "--rows", "30",
         "--seed", str(random.randint(0, 10**6))],
        capture_output=True,
        check=True,
    )
    return output


def hook_env(home: Path, sandbox: bool = True) -> dict[str, str]:
    """A hook's environment: a fake HOME with (or without) the `run.sh install` block applied."""
    from anonymizer.settings import block

    fake_home = home.parent / ("home" if sandbox else "home_without_sandbox")
    (fake_home / ".claude").mkdir(parents=True, exist_ok=True)
    (fake_home / ".claude" / "settings.json").write_text(json.dumps(block() if sandbox else {}))
    base = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
    return {**base, "HOME": str(fake_home), "ANONYMIZER_HOME": str(home),
            "ANONYMIZER_OUTPUT": str(home.parent / "anonimizados"),
            "PYTHONPATH": str(ROOT / "engine" / "src")}
