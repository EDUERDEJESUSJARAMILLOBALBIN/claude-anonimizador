import json
import subprocess
import sys
from pathlib import Path

import pytest

from canaries.audit import audit

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def traps(tmp_path_factory):
    output = tmp_path_factory.mktemp("traps")
    result = subprocess.run(
        [sys.executable, str(ROOT / "canaries" / "generate.py"), str(output), "--rows", "30", "--seed", "11"],
        capture_output=True,
        text=True,
        check=True,
    )
    return output, result.stdout


def test_the_generator_prints_no_values(traps):
    output, stdout = traps
    values = json.loads((output / "manifest.json").read_text())["values"]
    assert stdout.startswith(f"{len(values)} canaries")
    assert not any(v in stdout for v in values)


def test_the_auditor_finds_canaries_in_every_format(traps):
    output, _ = traps
    findings = audit(output / "manifest.json", [output])
    files = {Path(where.split("!")[0]).name for where in findings}
    assert files == {"clientes.csv", "clientes_latin1.csv", "clientes.xlsx", "clientes.sql", "clientes.sqlite",
                     "clientes.json", "clientes.yaml"}


@pytest.mark.parametrize(
    "part",
    [
        "xl/worksheets/sheet2.xml",  # hidden sheet
        "xl/worksheets/sheet3.xml",  # very hidden sheet
        "xl/comments/comment1.xml",
        "xl/workbook.xml",  # defined name
        "docProps/core.xml",  # author and title
    ],
)
def test_the_auditor_looks_inside_the_xlsx(traps, part):
    output, _ = traps
    findings = audit(output / "manifest.json", [output / "clientes.xlsx"])
    assert findings.get(f"{output / 'clientes.xlsx'}!{part}", 0) > 0


@pytest.mark.parametrize("file", ["clientes.csv", "clientes_latin1.csv", "clientes.xlsx"])
def test_the_profile_contains_no_canary(traps, tmp_path, file):
    output, _ = traps
    profile = subprocess.run(
        [sys.executable, "-m", "anonymizer", "profile", str(output / file)],
        capture_output=True,
        text=True,
        check=True,
        env={"ANONYMIZER_HOME": str(tmp_path), "PYTHONPATH": str(ROOT / "engine" / "src")},
    ).stdout
    (tmp_path / "profile.json").write_text(profile)
    assert audit(output / "manifest.json", [tmp_path / "profile.json"]) == {}
    columns = {c.get("name"): c["category"] for c in json.loads(profile)["tables"][0]["columns"]}
    assert columns["monto"] == "not_sensitive"


def test_a_clean_folder_gives_zero(traps, tmp_path):
    output, _ = traps
    (tmp_path / "clean.txt").write_text("Customer [REDACTED] from Medellín, amount 120000")
    assert audit(output / "manifest.json", [tmp_path]) == {}
