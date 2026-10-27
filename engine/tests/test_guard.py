import json
import subprocess
import sys

import pytest

from anonymizer import engine, state
from anonymizer.guard import OWN_TOOLS
from conftest import hook_env


def hook(event: str, data: dict, home) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "anonymizer.guard", event],
        input=json.dumps(data),
        capture_output=True,
        text=True,
        cwd=home.parent,
        env=hook_env(home),
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout) if result.stdout.strip() else {}


def decision(response: dict) -> str | None:
    return response.get("hookSpecificOutput", {}).get("permissionDecision")


@pytest.fixture
def protected(traps):
    engine.profile(traps / "clientes.csv")
    return traps / "clientes.csv"


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", lambda p: {"file_path": str(p)}),
        ("Bash", lambda p: {"command": f"cat {p.parent}/../{p.parent.name}/{p.name} | head"}),
        ("Bash", lambda p: {"command": f"cd {p.parent} && python3 -c \"print(open('{p.name}').read())\""}),
        ("Bash", lambda p: {"command": "mdfind canary"}),
        ("Bash", lambda p: {"command": f"head -3 {p.parent}/*.csv"}),
        ("Bash", lambda p: {"command": f"F={p}; cat \"$F\""}),
        ("Bash", lambda p: {"command": f"cp {p} /tmp/copy.csv"}),
        ("Bash", lambda p: {"command": f"mkdir -p /tmp/x && cat {p}"}),
        ("Grep", lambda p: {"pattern": "x", "path": str(p.parent.parent)}),
        ("mcp__plugin_other_fs__read_file", lambda p: {"path": str(p)}),
        ("Edit", lambda p: {"file_path": str(p), "old_string": "a", "new_string": "b"}),
    ],
)
def test_blocks_every_path_to_the_original(protected, isolated_home, tool, tool_input):
    response = hook("pre", {"tool_name": tool, "tool_input": tool_input(protected), "cwd": "/"}, isolated_home)
    assert decision(response) == "deny"


def test_blocks_a_symlink_to_the_original(protected, isolated_home, tmp_path):
    link = tmp_path / "innocent.txt"
    link.symlink_to(protected)
    response = hook("pre", {"tool_name": "Read", "tool_input": {"file_path": str(link)}, "cwd": "/"}, isolated_home)
    assert decision(response) == "deny"


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "/etc/hosts"}),
        ("Bash", {"command": "ls ~/anonimizados"}),
        ("Bash", {"command": "mkdir -p ~/sensibles ~/anonimizados && chmod 700 ~/sensibles"}),
        # The command that blocked the setup skill in the first real test
        ("Bash", {"command": 'mkdir -p ~/sensibles ~/anonimizados && chmod 700 ~/sensibles && ls -ld ~/sensibles '
                             '~/anonimizados; echo "---"; cat ~/.claude/settings.json 2>/dev/null || echo "{}"'}),
        ("Edit", {"file_path": "/tmp/settings.json", "old_string": "{}", "new_string": "Read(~/sensibles/**)"}),
    ],
)
def test_lets_through_what_does_not_touch_originals(protected, isolated_home, tool, tool_input):
    assert decision(hook("pre", {"tool_name": tool, "tool_input": tool_input, "cwd": "/"}, isolated_home)) is None


def test_profile_is_approved_automatically(isolated_home):
    response = hook("pre", {"tool_name": f"{OWN_TOOLS}profile", "tool_input": {"path": "~/sensibles/x.csv"}},
                    isolated_home)
    assert decision(response) == "allow"


def test_apply_asks_the_user_for_approval(isolated_home):
    response = hook("pre", {"tool_name": f"{OWN_TOOLS}apply",
                            "tool_input": {"path": "/x.csv", "plan": {"t1": {"c2": "drop"}}}}, isolated_home)
    assert decision(response) == "ask"


def test_post_blocks_the_whole_output_and_the_session(protected, isolated_home):
    line = protected.read_text().splitlines()[1]
    output = {"stdout": f"ok\n{line}", "stderr": "", "interrupted": False, "isImage": False}
    response = hook("post", {"tool_name": "Bash", "session_id": "s1", "tool_response": output}, isolated_home)
    new = response["hookSpecificOutput"]["updatedToolOutput"]
    assert set(new) == {"stdout", "stderr", "interrupted", "isImage"} and new["interrupted"] is False
    assert new["stdout"] == new["stderr"] == "[BLOCKED BY ANONYMIZER]"  # not even the "ok"
    after = hook("pre", {"tool_name": "Read", "session_id": "s1", "tool_input": {"file_path": "/etc/hosts"}}, isolated_home)
    assert decision(after) == "deny"
    other = hook("pre", {"tool_name": "Read", "session_id": "s2", "tool_input": {"file_path": "/etc/hosts"}}, isolated_home)
    assert decision(other) is None


def test_post_leaves_clean_outputs_alone(protected, isolated_home):
    assert hook("post", {"tool_name": "Bash", "tool_response": {"stdout": "total 3"}}, isolated_home) == {}


def test_prompt_blocks_an_at_mention_of_the_original(protected, isolated_home):
    response = hook("prompt", {"prompt": f"analyze @{protected}", "cwd": "/"}, isolated_home)
    assert response["decision"] == "block"
    assert response["hookSpecificOutput"]["suppressOriginalPrompt"] is True


def test_prompt_blocks_pasted_data(protected, isolated_home):
    pasted = "\n".join(protected.read_text().splitlines()[1:4])
    assert hook("prompt", {"prompt": f"look at this:\n{pasted}", "cwd": "/"}, isolated_home)["decision"] == "block"


def test_a_normal_prompt_goes_through(protected, isolated_home):
    assert hook("prompt", {"prompt": "anonymize ~/Downloads/sales.xlsx", "cwd": "/"}, isolated_home) == {}


def test_end_warns_when_the_transcript_has_values(protected, isolated_home, tmp_path):
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(json.dumps({"content": protected.read_text().splitlines()[2]}))
    result = subprocess.run([sys.executable, "-m", "anonymizer.guard", "end"],
                            input=json.dumps({"transcript_path": str(transcript)}),
                            capture_output=True, text=True, env=hook_env(isolated_home))
    assert "values from protected originals" in result.stderr
    assert "alerts.log" in result.stderr and (state.home() / "alerts.log").exists()


# --- Allowlist: no data file outside ~/anonimizados, profiled or not ---

@pytest.fixture
def unknown(tmp_path):
    path = tmp_path / "downloads" / "never_profiled.csv"
    path.parent.mkdir()
    path.write_text("nombre,cedula\nAna Ruiz,1023456789\n")
    return path


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", lambda p: {"file_path": str(p)}),
        ("Bash", lambda p: {"command": f"python3 -c \"import csv; print(list(csv.reader(open('{p}'))))\""}),
        ("Bash", lambda p: {"command": f"cd {p.parent} && head *.csv"}),
        ("Grep", lambda p: {"pattern": "Ana", "path": str(p.parent), "glob": "*.csv"}),
        ("Grep", lambda p: {"pattern": "Ana", "path": str(p.parent)}),  # outside the project and without a glob
        ("Edit", lambda p: {"file_path": str(p), "old_string": "Ana", "new_string": "X"}),
        ("Write", lambda p: {"file_path": str(p), "content": "x"}),  # overwriting an original
    ],
)
def test_a_never_profiled_data_file_is_closed(unknown, isolated_home, tool, tool_input, tmp_path):
    project = tmp_path / "project"  # Claude works in another project; the file is in "downloads"
    response = hook("pre", {"tool_name": tool, "tool_input": tool_input(unknown), "cwd": str(project)}, isolated_home)
    assert decision(response) == "deny"


def test_recursive_bash_is_covered_by_the_sandbox(isolated_home, tmp_path):
    # With the sandbox configured, rg cannot open data files: the operating system prevents it
    data = {"tool_name": "Bash", "tool_input": {"command": "rg -n Ana"}, "cwd": str(tmp_path)}
    assert decision(hook("pre", data, isolated_home)) is None


def test_grep_inside_the_project_excludes_data_files(isolated_home, tmp_path):
    response = hook("pre", {"tool_name": "Grep", "tool_input": {"pattern": "def "}, "cwd": str(tmp_path)}, isolated_home)
    output = response["hookSpecificOutput"]
    assert output["permissionDecision"] == "allow"
    assert output["updatedInput"]["pattern"] == "def " and ".csv" not in output["updatedInput"]["glob"].split("{")[0]
    assert "csv" in output["updatedInput"]["glob"] and output["updatedInput"]["glob"].startswith("!")


def test_the_anonymized_copy_can_be_read(isolated_home, tmp_path):
    copy = tmp_path / "anonimizados" / "x.anon.csv"
    for tool, tool_input in [("Read", {"file_path": str(copy)}),
                             ("Bash", {"command": f"python3 -c \"import csv; csv.reader(open('{copy}'))\""})]:
        assert decision(hook("pre", {"tool_name": tool, "tool_input": tool_input, "cwd": "/"}, isolated_home)) is None


def test_creating_a_new_csv_is_allowed(isolated_home, tmp_path):
    tool_input = {"file_path": str(tmp_path / "result.csv"), "content": "a,b"}
    assert decision(hook("pre", {"tool_name": "Write", "tool_input": tool_input, "cwd": "/"}, isolated_home)) is None


def test_prompt_blocks_an_at_mention_of_any_data_file(unknown, isolated_home):
    response = hook("prompt", {"prompt": f"summarize @{unknown}", "cwd": "/"}, isolated_home)
    assert response["decision"] == "block"
