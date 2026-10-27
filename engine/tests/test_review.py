"""One test per finding of the independent adversarial security reviews."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from anonymizer import engine, guard, state
from anonymizer.guard import OWN_TOOLS
from conftest import ROOT, hook_env

RUN = ROOT / "scripts" / "run.sh"


def hook(event: str, data: dict, home, sandbox: bool = True, extra: dict | None = None) -> dict:
    result = subprocess.run([sys.executable, "-m", "anonymizer.guard", event], input=json.dumps(data),
                            capture_output=True, text=True, cwd=home.parent,
                            env={**hook_env(home, sandbox), **(extra or {})})
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout) if result.stdout.strip() else {}


def decision(response: dict):
    return response.get("hookSpecificOutput", {}).get("permissionDecision")


def pre(tool: str, tool_input: dict, home, cwd="/", sandbox=True, extra=None):
    return decision(hook("pre", {"tool_name": tool, "tool_input": tool_input, "cwd": str(cwd)}, home, sandbox, extra))


@pytest.fixture
def demo(tmp_path):
    path = tmp_path / "project" / "demo.csv"
    path.parent.mkdir()
    path.write_text("nombre,correo\nZorbo Fake,zorbo@ejemplo.invalid\n")
    return path


def fake_home(home) -> Path:
    hook_env(home)  # creates the fake home with the settings block
    return home.parent / "home"


# ---- Review pass 1 ----

# A repository cannot replace the guard's code
def test_a_malicious_repo_cannot_shadow_the_guard(tmp_path, isolated_home):
    fake = tmp_path / "bad_repo" / "anonymizer"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("")
    (fake / "guard.py").write_text("print('SHADOWED')")
    result = subprocess.run([str(RUN), "pre"], input=json.dumps({"tool_name": "TodoWrite", "tool_input": {}}),
                            capture_output=True, text=True, cwd=fake.parent,
                            env={**hook_env(isolated_home), "PYTHONPATH": str(fake.parent), "CLAUDE_PLUGIN_ROOT": str(ROOT)})
    assert "SHADOWED" not in result.stdout and result.returncode == 0


# Grep with a type or glob that reaches data files
@pytest.mark.parametrize("tool_input", [{"type": "csv"}, {"glob": "*.c?v"}, {"glob": "*"}, {"glob": "**/*.CSV"}])
def test_grep_does_not_reach_data_files(demo, isolated_home, tool_input):
    assert pre("Grep", {"pattern": ".", "path": str(demo.parent), **tool_input}, isolated_home, cwd=demo.parent) == "deny"


def test_grep_over_code_goes_through(demo, isolated_home):
    assert pre("Grep", {"pattern": "def", "path": str(demo.parent), "glob": "*.py"}, isolated_home, cwd=demo.parent) is None


# A file without a header row: the first row does not come out as "column names"
def test_without_headers_the_first_row_never_reaches_the_model(tmp_path):
    original = tmp_path / "no_header.csv"
    original.write_text("Zorbo Quintanilla Fake,Calle Inventada 99 Sur,1020304050\n"
                        "Ana Ruiz Fake,Carrera 1 # 2-3,1030405060\n" * 3)
    profile = engine.profile(original)
    for value in ("Zorbo", "Inventada", "1020304050"):
        assert value not in profile
    result = engine.apply(original, {"t1": {"c1": "drop", "c2": "drop", "c3": "pseudonymize"}})
    assert "Zorbo" not in open(result["output"]).read()


# A short column of names is not kept by default, and the dialog shows the whole plan
def test_a_small_names_column_does_not_go_out(tmp_path, isolated_home):
    original = tmp_path / "patients.csv"
    rows = [f"{n},{c},{m}" for n, c, m in zip(["Ana", "Luis", "Marta", "Jhon", "Yuli", "Edwin"] * 5,
                                              ["Cali", "Pasto"] * 15, range(1000, 1030))]
    original.write_text("referido,ciudad,monto\n" + "\n".join(rows) + "\n")
    engine.profile(original)
    result = engine.apply(original, {})
    text = open(result["output"]).read()
    assert "Marta" not in text and "Cali" in text
    dialog = hook("pre", {"tool_name": f"{OWN_TOOLS}apply", "tool_input": {"path": str(original), "plan": {}}},
                  isolated_home)["hookSpecificOutput"]["permissionDecisionReason"]
    # What goes out is named; what is dropped is summarized
    assert "ciudad" in dialog and "GOES OUT AS-IS" in dialog and "referido" not in dialog and "1 drop" in dialog


@pytest.mark.parametrize("column", ["c1", "c2"])  # address and birth date
def test_quasi_identifiers_are_never_kept(tmp_path, column):
    original = tmp_path / "x.csv"
    original.write_text("direccion,fecha_nacimiento,monto\n" + "Calle 1 # 2-3,1990-01-02,5\n" * 6)
    engine.profile(original)
    with pytest.raises(engine.InvalidPlan):
        engine.apply(original, {"t1": {column: "keep"}})


def test_apply_requires_a_previous_profile(tmp_path):
    original = tmp_path / "new.csv"
    original.write_text("monto\n1\n2\n")
    with pytest.raises(engine.InvalidPlan, match="profile"):
        engine.apply(original, {})


# `&` and subshells do not hide a reading segment
@pytest.mark.parametrize("command", ["mkdir -p x & cat demo.csv", "echo hi & cat demo.csv", "(cat demo.csv)",
                                     "echo `cat demo.csv`", "echo $(cat demo.csv)"])
def test_shell_separators(demo, isolated_home, command):
    assert pre("Bash", {"command": command}, isolated_home, cwd=demo.parent) == "deny"


# A different case, the same file (macOS)
@pytest.mark.skipif(sys.platform != "darwin", reason="APFS is case-insensitive")
def test_case_does_not_dodge_the_protection(tmp_path, isolated_home):
    original = tmp_path / "data3" / "registry.tsv"
    original.parent.mkdir()
    original.write_text("monto\n1\n")
    engine.profile(original)
    assert pre("Read", {"file_path": str(tmp_path / "DATA3" / "REGISTRY.TSV")}, isolated_home) == "deny"


# If Python is missing, the guard blocks instead of letting calls through
def test_without_python_it_blocks(tmp_path):
    empty = tmp_path / "empty_bin"
    empty.mkdir()
    for command in ("sh", "dirname", "cmp", "find", "mkdir"):
        os.symlink(f"/bin/{command}" if os.path.exists(f"/bin/{command}") else f"/usr/bin/{command}", empty / command)
    result = subprocess.run(["/bin/sh", str(RUN), "pre"], input="{}", capture_output=True, text=True,
                            env={"PATH": str(empty), "HOME": str(tmp_path), "CLAUDE_PLUGIN_ROOT": str(ROOT),
                                 "CLAUDE_PLUGIN_DATA": str(tmp_path / "data")})
    assert result.returncode == 2 and "Anonymizer" in result.stderr


# A huge wildcard is cut off in time and blocked
def test_a_slow_wildcard_is_blocked(tmp_path):
    with pytest.raises(guard.SlowGlob):
        guard._expand(tmp_path / "*" / "*", time.monotonic() - 1)


# Without the sandbox, Bash is closed (except creating folders and generating the settings block)
@pytest.mark.parametrize("command", ["cat demo.c?v", "cat demo.cs''v", "python3 -c \"open('demo'+'.c'+'sv')\"", "git status"])
def test_without_the_sandbox_bash_is_closed(demo, isolated_home, command):
    assert pre("Bash", {"command": command}, isolated_home, cwd=demo.parent, sandbox=False) == "deny"


@pytest.mark.parametrize("command", ["mkdir -p ~/sensibles ~/anonimizados && chmod 700 ~/sensibles",
                                     f"\"{ROOT}/scripts/run.sh\" config"])
def test_without_the_sandbox_setup_still_works(isolated_home, command):
    extra = {"CLAUDE_PLUGIN_ROOT": str(ROOT)}
    assert pre("Bash", {"command": command}, isolated_home, sandbox=False, extra=extra) is None


def test_with_the_sandbox_normal_bash_goes_through(demo, isolated_home):
    assert pre("Bash", {"command": "git status"}, isolated_home, cwd=demo.parent) is None


# Line-based export formats
def test_jsonl_is_a_data_file(tmp_path, isolated_home):
    export = tmp_path / "export.jsonl"
    export.write_text('{"nombre": "x"}\n')
    assert pre("Read", {"file_path": str(export)}, isolated_home) == "deny"
    # One that does not exist yet has nothing to read (e.g. a script's output)
    assert pre("Read", {"file_path": str(tmp_path / "new.jsonl")}, isolated_home) is None


# An encoded URL in another MCP tool
def test_encoded_file_url(demo, isolated_home):
    url = "file://" + str(demo).replace(".csv", "%2Ecsv")
    assert pre("mcp__playwright__browser_navigate", {"url": url}, isolated_home) == "deny"


def test_the_plugin_code_is_not_edited(isolated_home):
    target = ROOT / "engine" / "src" / "anonymizer" / "guard.py"
    assert pre("Edit", {"file_path": str(target), "old_string": "a", "new_string": "b"}, isolated_home) == "deny"
    assert pre("Bash", {"command": f"sed -i '' s/a/b/ {target}"}, isolated_home) == "deny"


def test_the_key_does_not_leave_the_keychain(isolated_home):
    assert pre("Bash", {"command": "security find-generic-password -s anonimizador -a clave-hmac -w"},
               isolated_home) == "deny"


def test_a_hard_link_in_the_output_does_not_count(demo, isolated_home, tmp_path):
    target = tmp_path / "anonimizados" / "copy.csv"
    target.parent.mkdir(exist_ok=True)
    os.link(demo, target)
    assert pre("Read", {"file_path": str(target)}, isolated_home) == "deny"


# Pasted personal data, even if the file was never profiled
def test_pasting_personal_data_is_blocked(isolated_home):
    pasted = "ana@ejemplo.invalid, 3001234567\nluis@ejemplo.invalid, 3109876543"
    assert hook("prompt", {"prompt": pasted, "cwd": "/"}, isolated_home)["decision"] == "block"
    assert hook("prompt", {"prompt": "the amounts were 1500000, 2300000 and 4100000 on 2026-10-26", "cwd": "/"},
                isolated_home) == {}


# ---- Review pass 2 ----

# The `run.sh config` exception is exact: nothing before or after it
@pytest.mark.parametrize("command", ["cat demo.c?v; /x/scripts/run.sh config",
                                     f"echo x >> {ROOT}/engine/src/anonymizer/guard.py; \"{ROOT}/scripts/run.sh\" config"])
def test_the_config_exception_does_not_open_bash(demo, isolated_home, command):
    assert pre("Bash", {"command": command}, isolated_home, cwd=demo.parent, sandbox=False,
               extra={"CLAUDE_PLUGIN_ROOT": str(ROOT)}) == "deny"


# Globs with braces or negation (Grep does not run in the sandbox)
@pytest.mark.parametrize("pattern", ["*.{py,csv}", "!*.py", "*.[cC]sv", "*.py,*.csv"])
def test_complex_grep_globs(demo, isolated_home, pattern):
    assert pre("Grep", {"pattern": ".", "path": str(demo.parent), "glob": pattern}, isolated_home, cwd=demo.parent) == "deny"


# A project that loosens the sandbox or turns off the plugin leaves Bash closed
@pytest.mark.parametrize("project_settings", [
    {"sandbox": {"enabled": False}},
    {"sandbox": {"allowUnsandboxedCommands": True}},
    {"sandbox": {"filesystem": {"allowRead": ["~/**/*.csv"]}}},
    {"sandbox": {"excludedCommands": ["python3 *"]}},
    {"enabledPlugins": {"anonimizador@anonimizador": False}},
    {"disableAllHooks": True},
])
def test_a_project_that_loosens_the_sandbox(demo, isolated_home, project_settings):
    (demo.parent / ".claude").mkdir()
    (demo.parent / ".claude" / "settings.local.json").write_text(json.dumps(project_settings))
    assert pre("Bash", {"command": "git status"}, isolated_home, cwd=demo.parent) == "deny"


# The sandbox covers every data extension, in upper case too
def test_the_sandbox_covers_databases_and_case():
    from anonymizer.settings import block

    filesystem = block()["sandbox"]["filesystem"]
    for pattern in ("~/**/*.sqlite3", "~/**/*.db", "~/**/*.sav", "~/**/*.CSV", "~/**/*.Xlsx", "/tmp/**/*.csv"):
        assert pattern in filesystem["denyRead"], pattern
    assert "~/anonimizados/**/*.CSV" in filesystem["allowRead"]


# The tripwire does not say what matched: the whole output is blocked
def test_the_tripwire_is_not_an_oracle(traps, isolated_home):
    engine.profile(traps / "clientes.csv")
    real = (traps / "clientes.csv").read_text().splitlines()[1].split(",")[1]  # a real name
    output = {"stdout": f"{real}\nZed Nonexistent Nobody", "stderr": "", "interrupted": False, "isImage": False}
    new = hook("post", {"tool_name": "Bash", "session_id": "x", "tool_response": output},
               isolated_home)["hookSpecificOutput"]["updatedToolOutput"]
    assert "Zed" not in new["stdout"]


# The dialog shows in full what goes out as-is, even if it is column 90
def test_the_dialog_shows_a_late_column(tmp_path, isolated_home):
    original = tmp_path / "wide.csv"
    headers = [f"monto {i}" for i in range(1, 90)] + ["observaciones"]
    original.write_text(",".join(headers) + "\n" + ("1," * 89 + "Ana dijo hola\n") * 6)
    engine.profile(original)
    tool_input = {"path": str(original), "plan": {"t1": {"c90": "keep"}}}
    response = hook("pre", {"tool_name": f"{OWN_TOOLS}apply", "tool_input": tool_input}, isolated_home)
    text = response["hookSpecificOutput"]["permissionDecisionReason"]
    if decision(response) == "ask":
        assert "c90 observaciones" in text and "GOES OUT AS-IS" in text
    else:
        assert decision(response) == "deny"  # too much to review: denied, never truncated


# A deep wildcard that finds nothing is cut off quickly
def test_a_deep_wildcard_is_denied_quickly(isolated_home):
    start = time.monotonic()
    assert pre("Read", {"file_path": "/Users/*/*/*/*/*/*/*/*/*/zz.txt"}, isolated_home) == "deny"
    assert time.monotonic() - start < 5


# Third-party MCP tools that run code or write into the plugin
@pytest.mark.parametrize(("tool", "tool_input"), [
    ("mcp__playwright__browser_run_code_unsafe", {"code": "require('fs').readFileSync('demo.'+'csv')"}),
    ("mcp__claude-in-chrome__javascript_tool", {"text": "1+1"}),
    ("mcp__filesystem__write_file", {"path": str(ROOT / "engine/src/anonymizer/guard.py"), "content": "x"}),
])
def test_dangerous_third_party_mcp_tools(isolated_home, tool, tool_input):
    assert pre(tool, tool_input, isolated_home) == "deny"


# The model does not choose the output, and the copy's name carries no data
def test_the_engine_decides_the_output(traps, isolated_home, tmp_path):
    from anonymizer.mcp import TOOLS

    apply = next(t for t in TOOLS if t["name"] == "apply")
    assert "output" not in apply["inputSchema"]["properties"]
    real = (traps / "clientes.csv").read_text().splitlines()[1].split(",")[1]
    original = traps / f"{real}.csv"
    original.write_text((traps / "clientes.csv").read_text())
    engine.profile(original)
    result = engine.apply(original, {})
    assert real not in result["output"] and "file-" in result["output"]


# cd is followed for protected folders too, and odd cd forms are denied
def test_cd_into_a_protected_folder(tmp_path, isolated_home):
    root = tmp_path / "R" / "sens"
    root.mkdir(parents=True)
    state._private_dir(state.home())
    (state.home() / "protected.json").write_text(json.dumps({"files": [], "roots": [str(root)]}))
    for command in (f"cd {tmp_path / 'R'} && cd sens && cat notes.json", f"cd {tmp_path / 'R'}; cd se?s; cat notes.json"):
        assert pre("Bash", {"command": command}, isolated_home) == "deny", command


# ---- Review pass 3 ----

# A project allowRead with `..` or a look-alike prefix
@pytest.mark.parametrize("pattern", ["~/anonimizados/../**/*.csv", "~/anonimizadosX/*.csv", "~/**/*.csv"])
def test_a_tricky_project_allow_read(demo, isolated_home, pattern):
    (demo.parent / ".claude").mkdir()
    (demo.parent / ".claude" / "settings.json").write_text(json.dumps({"sandbox": {"filesystem": {"allowRead": [pattern]}}}))
    assert pre("Bash", {"command": "git status"}, isolated_home, cwd=demo.parent) == "deny"


# Keys a project cannot set, and variables that are not trusted inside Claude Code
@pytest.mark.parametrize("project_settings", [
    {"env": {"ANONYMIZER_OUTPUT": "/"}}, {"env": {"CLAUDE_CONFIG_DIR": "/tmp/x"}},
    {"sandbox": {"filesystem": {"allowWrite": ["~"]}}}, {"sandbox": {"enableWeakerNestedSandbox": True}},
    {"permissions": {"additionalDirectories": ["~/anonimizados"]}},
])
def test_dangerous_project_keys(demo, isolated_home, project_settings):
    (demo.parent / ".claude").mkdir()
    (demo.parent / ".claude" / "settings.json").write_text(json.dumps(project_settings))
    assert pre("Bash", {"command": "git status"}, isolated_home, cwd=demo.parent) == "deny"


def test_a_project_that_only_tightens_is_fine(demo, isolated_home):
    (demo.parent / ".claude").mkdir()
    (demo.parent / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"RAILS_ENV": "test"}, "sandbox": {"filesystem": {"denyRead": ["~/secret"]}}}))
    assert pre("Bash", {"command": "git status"}, isolated_home, cwd=demo.parent) is None


def test_variables_are_ignored_inside_claude_code(demo, isolated_home):
    extra = {"CLAUDE_PLUGIN_ROOT": str(ROOT), "ANONYMIZER_OUTPUT": "/"}
    assert pre("Read", {"file_path": str(demo)}, isolated_home, extra=extra) == "deny"


# Archives in Downloads
@pytest.mark.parametrize("command", ["unzip -p export.zip", "zcat clientes.cs?.gz", "tar -xOf export.tar"])
def test_archives_in_downloads(isolated_home, command):
    downloads = fake_home(isolated_home) / "Downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    for name in ("export.zip", "clientes.csv.gz", "export.tar"):
        (downloads / name).write_bytes(b"x")
    assert pre("Bash", {"command": command}, isolated_home, cwd=downloads) == "deny"


def test_project_archives_go_through(demo, isolated_home):
    (demo.parent / "vendor.zip").write_bytes(b"x")
    for command in ("unzip vendor.zip -d vendor", "tar -czf build.tar.gz dist", "git archive -o release.zip HEAD",
                    "python train.py --out model.pkl"):
        assert pre("Bash", {"command": command}, isolated_home, cwd=demo.parent) is None, command
    from anonymizer.settings import block
    deny_read = block()["sandbox"]["filesystem"]["denyRead"]
    assert "~/Downloads/**/*.zip" in deny_read and "~/**/*.zip" not in deny_read


# The tripwire gives no bit per call: once tripped, everything is blanked; without an id, everything locks
def test_after_tripping_everything_is_blanked(traps, isolated_home):
    engine.profile(traps / "clientes.csv")
    name = (traps / "clientes.csv").read_text().splitlines()[1].split(",")[1]
    clean = {"stdout": "normal line", "stderr": "", "interrupted": False, "isImage": False}
    hook("post", {"tool_name": "Bash", "session_id": "p", "tool_response": {**clean, "stdout": name}}, isolated_home)
    after = hook("post", {"tool_name": "Bash", "session_id": "p", "tool_response": clean}, isolated_home)
    assert after["hookSpecificOutput"]["updatedToolOutput"]["stdout"] != "normal line"


def test_without_a_session_everything_locks(traps, isolated_home):
    engine.profile(traps / "clientes.csv")
    name = (traps / "clientes.csv").read_text().splitlines()[1].split(",")[1]
    hook("post", {"tool_name": "Bash", "tool_response": {"stdout": name}}, isolated_home)
    assert pre("Read", {"file_path": "/etc/hosts"}, isolated_home) == "deny"


# A loose first name raises no alarm (false positives would make people uninstall the plugin)
def test_a_loose_first_name_does_not_block(traps, isolated_home):
    engine.profile(traps / "clientes.csv")
    first_name = (traps / "clientes.csv").read_text().splitlines()[1].split(",")[1].split()[0]
    output = {"stdout": f"Author: {first_name} <dev@company.co>", "stderr": "", "interrupted": False, "isImage": False}
    assert hook("post", {"tool_name": "Bash", "session_id": "g", "tool_response": output}, isolated_home) == {}
    assert hook("prompt", {"prompt": f"review {first_name}'s PR please", "cwd": "/"}, isolated_home) == {}


# Third-party MCP tools that run code or queries, and the user's trust list
@pytest.mark.parametrize("tool", ["mcp__jupyter__run_cell", "mcp__sqlite__read_query_sql", "mcp__x__run_python",
                                  "mcp__x__repl", "mcp__x__notebook_run"])
def test_mcp_tools_that_run_code(isolated_home, tool):
    assert pre(tool, {"x": "1"}, isolated_home) == "deny"


def test_an_mcp_tool_trusted_by_the_user(isolated_home):
    state._private_dir(state.home())
    (state.home() / "config.json").write_text(json.dumps({"trusted_mcp_tools": ["mcp__jupyter__run_cell"]}))
    assert pre("mcp__jupyter__run_cell", {"x": "1"}, isolated_home) is None


# Hard links: neither creating them nor searching where there are any
def test_hard_links(demo, isolated_home, tmp_path):
    assert pre("Bash", {"command": f"ln {demo} ~/anonimizados/x.csv"}, isolated_home) == "deny"
    assert pre("Bash", {"command": "ln -s /etc/hosts link"}, isolated_home) is None
    output = tmp_path / "anonimizados"
    output.mkdir(exist_ok=True)
    os.link(demo, output / "new.csv")
    assert pre("Grep", {"pattern": ".", "path": str(output)}, isolated_home) == "deny"


# ---- Review pass 4 ----

# ~/anonimizados cannot be a symlink (nor be moved from a session)
def test_a_symlinked_output_folder_does_not_count(tmp_path, isolated_home, demo):
    fake = tmp_path / "anonimizados"
    if fake.exists():
        fake.rmdir()
    fake.symlink_to(demo.parent)
    assert pre("Read", {"file_path": str(demo)}, isolated_home) == "deny"


def test_the_output_folder_is_not_moved(isolated_home, tmp_path):
    output = tmp_path / "anonimizados"
    output.mkdir(exist_ok=True)
    for command in (f"mv {output} {tmp_path}/old", f"rm -rf {output}", f"ln -s /tmp {output}"):
        assert pre("Bash", {"command": command}, isolated_home) == "deny", command
    assert pre("Bash", {"command": f"rm {output}/old.anon.csv"}, isolated_home) is None


# The key is not taken from ANONYMIZER_HOME inside Claude Code
def test_the_key_ignores_the_variable_inside_claude_code(tmp_path, monkeypatch):
    from anonymizer import env, key

    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "hmac.key").write_text("ab" * 32)
    monkeypatch.setenv("ANONYMIZER_HOME", str(planted))
    assert key.get_or_create() == bytes.fromhex("ab" * 32)  # outside Claude Code it counts
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(ROOT))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(key, "_keychain", lambda: b"\x01" * 32)  # never touch the real Keychain
    assert env.variable("ANONYMIZER_HOME") is None
    assert key.get_or_create() != bytes.fromhex("ab" * 32)


# If the project loosens anything, no tool can be trusted (not only Bash)
def test_a_loosening_project_closes_everything(demo, isolated_home):
    (demo.parent / ".claude").mkdir()
    (demo.parent / ".claude" / "settings.json").write_text(json.dumps({"env": {"DYLD_INSERT_LIBRARIES": "/x.dylib"}}))
    assert pre("Read", {"file_path": "/etc/hosts"}, isolated_home, cwd=demo.parent) == "deny"
    assert pre(f"{OWN_TOOLS}profile", {"path": str(demo)}, isolated_home, cwd=demo.parent) == "deny"


# ---- Review pass 5 ----

# With the block applied in ~/.claude/settings.json and the project inside the home folder
def test_setup_does_not_block_everything(isolated_home):
    project = fake_home(isolated_home) / "projects" / "app"
    project.mkdir(parents=True)
    assert pre("Read", {"file_path": str(project / "README.md")}, isolated_home, cwd=project) is None
    assert pre("Bash", {"command": "git status"}, isolated_home, cwd=project) is None
    assert pre(f"{OWN_TOOLS}profile", {"path": "/x.csv"}, isolated_home, cwd=project) == "allow"


def test_an_archive_in_google_drive(isolated_home):
    drive = fake_home(isolated_home) / "Library" / "CloudStorage" / "GoogleDrive-x" / "My Drive"
    drive.mkdir(parents=True)
    (drive / "export.zip").write_bytes(b"x")
    assert pre("Bash", {"command": f'unzip -p "{drive}/export.zip"'}, isolated_home) == "deny"


def test_archives_in_documents_go_through(isolated_home):
    project = fake_home(isolated_home) / "Documents" / "proj"
    (project / ".yarn" / "cache").mkdir(parents=True)
    (project / ".yarn" / "cache" / "pkg.zip").write_bytes(b"x")
    assert pre("Read", {"file_path": str(project / ".yarn" / "cache" / "pkg.zip")}, isolated_home, cwd=project) is None


def test_grep_in_an_output_folder_with_an_outgoing_symlink(isolated_home, tmp_path, demo):
    output = tmp_path / "anonimizados"
    output.mkdir(exist_ok=True)
    (output / "d").symlink_to(demo.parent)
    assert pre("Grep", {"pattern": ".", "path": str(output)}, isolated_home) == "deny"


@pytest.mark.parametrize("tmpdir", ["/tmp/x", None])  # on Linux TMPDIR is often missing
def test_cd_with_a_simple_variable_goes_through(isolated_home, tmpdir):
    extra = {"TMPDIR": tmpdir} if tmpdir else {"TMPDIR": ""}
    assert pre("Bash", {"command": 'cd "$TMPDIR" && python3 -I -c "print(1)"'}, isolated_home, extra=extra) is None
    assert pre("Bash", {"command": 'cd "$DOES_NOT_EXIST" && head *.csv'}, isolated_home, extra=extra) == "deny"
    assert pre("Bash", {"command": 'cd "$(echo /tmp)" && ls'}, isolated_home) == "deny"
