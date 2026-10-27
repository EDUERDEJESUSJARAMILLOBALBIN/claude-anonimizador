"""JSON, JSONL and YAML: the same flow as a table (value-free profile, plan, verified copy)."""

import json

import pytest
import yaml

from anonymizer import engine
from anonymizer.structured import InvalidFile
from test_review import fake_home, pre

NAMES = ["Zorbo Quintanilla Fake", "Ximena Pradera Falsa", "Brayan Cuchilla Ficticio",
         "Leidy Arboleda Simulada", "Duvan Ensueño Inventado", "Marleny Espejo Irreal"]


def document() -> dict:
    return {
        "empresa": "Comercializadora Nubosa SAS",
        "clientes": [
            {
                "id_cliente": f"CL-{i:03d}",
                "nombre": name,
                "contacto": {"correo": f"cliente{i}.fake@ejemplo.invalid", "celular": f"30012345{i:02d}"},
                "telefonos": [f"31098765{i:02d}"],
                "ciudad": ["Cali", "Pasto", "Quibdó"][i % 3],
                "monto": 1_000_000 + i * 12_345,
                "pedidos": [{"fecha": f"2026-0{i % 9 + 1}-1{i}", "valor": 50_000 + i}],
            }
            for i, name in enumerate(NAMES)
        ],
    }


def sensitive() -> list[str]:
    d = document()
    return [d["empresa"], *[v for c in d["clientes"]
                            for v in (c["nombre"], c["contacto"]["correo"], c["contacto"]["celular"], c["telefonos"][0])]]


@pytest.fixture(params=["json", "yaml", "jsonl"])
def original(request, tmp_path):
    file_format = request.param
    path = tmp_path / f"export.{file_format}"
    if file_format == "json":
        path.write_text(json.dumps(document(), ensure_ascii=False))
    elif file_format == "yaml":
        path.write_text(yaml.safe_dump(document(), allow_unicode=True))
    else:
        path.write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in document()["clientes"]))
    return path


def test_profile_by_paths_without_values(original):
    profile = json.loads(engine.profile(original))
    # The JSONL root table ("[]") has no known words, so the profile shows only its alias
    customers = next(t for t in profile["tables"] if any(c.get("name") == "nombre" for c in t["columns"]))
    categories = {c.get("name"): c["category"] for c in customers["columns"]}
    assert categories["contacto.correo"] == "email" and categories["contacto.celular"] == "phone"
    assert categories["nombre"] == "name" and categories["ciudad"] == "not_sensitive"
    assert categories["id_cliente"] == "identifier"
    text = json.dumps(profile, ensure_ascii=False)
    assert not any(v in text for v in sensitive())


def test_a_copy_with_the_same_shape_and_no_personal_data(original, tmp_path):
    engine.profile(original)
    result = engine.apply(original, {})
    text = _copy(result, tmp_path)
    assert not any(v in text for v in sensitive())
    if original.suffix == ".jsonl":
        customers = [json.loads(line) for line in text.splitlines()]
    else:
        copy = json.loads(text) if original.suffix == ".json" else yaml.safe_load(text)
        customers = copy["clientes"]
        assert "empresa" not in copy  # unclassified text: it does not go out unless someone approves it
    assert len(customers) == len(NAMES)
    first = customers[0]
    assert first["id_cliente"].startswith("ID_") and first["ciudad"] == "Cali" and first["monto"] == 1_000_000
    assert "nombre" not in first and "correo" not in first.get("contacto", {})
    assert first["pedidos"][0]["valor"] == 50_000  # the nested table is still there, with what is not personal


def test_a_nested_email_cannot_be_kept(original):
    profile = json.loads(engine.profile(original))
    table = next(t for t in profile["tables"] if any(c.get("name") == "contacto.correo" for c in t["columns"]))
    column = next(c["alias"] for c in table["columns"] if c.get("name") == "contacto.correo")
    with pytest.raises(engine.InvalidPlan, match="email"):
        engine.apply(original, {table["alias"]: {column: "keep"}})


@pytest.mark.parametrize("text", [
    "a: &x [1, 2]\nb: *x\n",  # aliases: the basis of YAML "bombs"
    "!!python/object/apply:os.system ['echo hello']\n",  # running code on load
])
def test_dangerous_yaml_is_rejected(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text)
    with pytest.raises(InvalidFile):
        engine.profile(path)


def test_json_nested_too_deeply(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 200 + "]" * 200)
    with pytest.raises(InvalidFile):
        engine.profile(path)


def _copy(result: dict, tmp_path) -> str:
    return (tmp_path / "anonimizados" / result["output"].rsplit("/", 1)[1]).read_text()


def test_keys_that_are_data_leave_as_aliases(tmp_path):
    # A map keyed by person: emails, user names and ID numbers used as keys
    keys = [f"person{i}.fake@ejemplo.invalid" for i in range(3)] + ["zorbo_quintanilla", "CC1020304050",
                                                                     "ximena_pradera"]
    path = tmp_path / "by_person.json"
    path.write_text(json.dumps({"clientes": {k: {"ciudad": "Cali", "monto": i, "notas_internas": {"x": "y"}}
                                             for i, k in enumerate(keys)}}))
    engine.profile(path)
    text = _copy(engine.apply(path, {}), tmp_path)
    assert not any(k in text for k in keys)
    copy = json.loads(text)
    assert sorted(copy["clientes"]) == ["k1", "k2", "k3", "k4", "k5", "k6"]
    assert copy["clientes"]["k1"]["ciudad"] == "Cali"


def test_objects_inside_a_list_of_values_are_not_copied_through(tmp_path):
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps([{"id_cliente": [f"A{i}", {"nota": f"Zorbo Quintanilla{i} vive en Calle {i}"}],
                                 "ciudad": "Cali"} for i in range(6)]))
    engine.profile(path)
    assert "id_cliente" not in json.loads(_copy(engine.apply(path, {}), tmp_path))[0]  # dropped by default
    text = _copy(engine.apply(path, {"t1": {"c1": "pseudonymize"}}), tmp_path)
    assert "Zorbo" not in text and "Calle" not in text
    first = json.loads(text)[0]
    assert all(str(v).startswith("ID_") for v in first["id_cliente"])


def test_an_object_emptied_by_the_drops_goes_too(original, tmp_path):
    engine.profile(original)
    text = _copy(engine.apply(original, {}), tmp_path)
    customers = [json.loads(line) for line in text.splitlines()] if original.suffix == ".jsonl" else (
        json.loads(text) if original.suffix == ".json" else yaml.safe_load(text))["clientes"]
    assert "contacto" not in customers[0]  # both email and phone were dropped


def test_a_file_changed_after_the_profile_is_rejected(original):
    engine.profile(original)
    original.write_text(original.read_text().replace("Cali", "Lima"))
    with pytest.raises(engine.InvalidPlan, match="changed"):
        engine.apply(original, {})


def test_json_and_yaml_closed_in_downloads_open_in_projects(isolated_home):
    home = fake_home(isolated_home)
    downloads, project = home / "Downloads", home / "projects" / "app"
    downloads.mkdir(parents=True)
    project.mkdir(parents=True)
    (downloads / "export.json").write_text("{}")
    (project / "package.json").write_text("{}")
    assert pre("Read", {"file_path": str(downloads / "export.json")}, isolated_home) == "deny"
    assert pre("Read", {"file_path": str(project / "package.json")}, isolated_home, cwd=project) is None
    assert pre("Grep", {"pattern": "x", "path": str(project), "glob": "*.json"}, isolated_home, cwd=project) is None
    assert pre("Grep", {"pattern": "x", "path": str(downloads), "glob": "*.json"}, isolated_home, cwd=project) == "deny"
    from anonymizer.settings import block
    deny_read = block()["sandbox"]["filesystem"]["denyRead"]
    assert "~/Downloads/**/*.json" in deny_read and "~/**/*.json" not in deny_read


def test_the_mcp_server_announces_json_and_yaml():
    from anonymizer.mcp import TOOLS

    assert ".json" in TOOLS[0]["inputSchema"]["properties"]["path"]["description"]


def test_index_search_mcp_tools_and_claude_config_writes_are_closed(isolated_home):
    home = fake_home(isolated_home)
    project = home / "projects" / "app"
    (project / ".claude").mkdir(parents=True)
    assert pre("mcp__codebase__search_code", {"pattern": "x"}, isolated_home, cwd=project) == "deny"
    assert pre("mcp__files__read_multiple_files", {"paths": ["a"]}, isolated_home, cwd=project) == "deny"
    assert pre("mcp__browser__get_page_text", {"tabId": 1}, isolated_home, cwd=project) is None
    for target in (".claude/settings.local.json", ".mcp.json", ".claude/hooks/x.sh", ".claude/skills/s/SKILL.md"):
        assert pre("Write", {"file_path": str(project / target), "content": "{}"}, isolated_home, cwd=project) == "deny"
    assert pre("Edit", {"file_path": str(project / "CLAUDE.md"), "old_string": "a", "new_string": "b"},
               isolated_home, cwd=project) is None


def test_objects_inside_a_neutral_list_are_not_kept(tmp_path):
    path = tmp_path / "tags.json"
    path.write_text(json.dumps([{"categoria": ["A", {"nombre": f"Zorbo Quintanilla{i}"}], "monto": i}
                                for i in range(6)]))
    profile = json.loads(engine.profile(path))
    column = next(c for c in profile["tables"][0]["columns"] if c.get("name") == "categoria[]")
    assert column["suggested_action"] != "keep"
    assert "Zorbo" not in _copy(engine.apply(path, {}), tmp_path)
    with pytest.raises(engine.InvalidPlan, match="objects inside a list"):
        engine.apply(path, {"t1": {column["alias"]: "keep"}})


def test_dates_used_as_keys_do_not_reach_the_profile(tmp_path):
    path = tmp_path / "by_date.yaml"
    days = [f"1985-03-1{i}" for i in range(6)]
    path.write_text(yaml.safe_dump({"pacientes": {d: {"ciudad": "Cali"} for d in days}}))
    text = engine.profile(path)
    assert not any(d in text for d in days)
    assert not any(d in _copy(engine.apply(path, {}), tmp_path) for d in days)


def test_digits_next_to_an_identifying_word_are_not_a_header():
    from anonymizer.detect import is_known_header

    assert not is_known_header("tarjeta_4242") and not is_known_header("cuenta_9876")
    assert is_known_header("ventas_2026") and is_known_header("monto")


def test_keys_that_collide_as_text_are_rejected(tmp_path):
    path = tmp_path / "collide.yaml"
    path.write_text("- {1: 10, '1': 20, ciudad: Cali}\n" * 6)
    with pytest.raises(InvalidFile):
        engine.profile(path)


def test_third_party_mcp_tools_cannot_write_claude_config(isolated_home):
    home = fake_home(isolated_home)
    project = home / "projects" / "app"
    project.mkdir(parents=True)
    assert pre("mcp__files__write_file", {"path": str(home / ".claude.json"), "content": "{}"},
               isolated_home, cwd=project) == "deny"
    assert pre("mcp__files__move_file", {"source": "a.txt", "destination": ".claude/hooks/run.sh"},
               isolated_home, cwd=project) == "deny"
    assert pre("mcp__search__full_text_search", {"q": "x"}, isolated_home, cwd=project) == "deny"


def test_objects_in_a_root_list_of_values_are_not_kept(tmp_path):
    path = tmp_path / "root.json"
    path.write_text(json.dumps(["x"] * 6 + [{"nombre": f"Zorbo Quintanilla{i}"} for i in range(6)]))
    profile = json.loads(engine.profile(path))
    assert profile["tables"][0]["columns"][0]["suggested_action"] != "keep"
    assert "Zorbo" not in _copy(engine.apply(path, {"t1": {"c1": "pseudonymize"}}), tmp_path)
    with pytest.raises(engine.InvalidPlan, match="objects inside a list"):
        engine.apply(path, {"t1": {"c1": "keep"}})


def test_claude_config_folders_cannot_be_moved_into_place(isolated_home):
    home = fake_home(isolated_home)
    project = home / "projects" / "app"
    project.mkdir(parents=True)
    for destination in (".claude", ".claude/skills", str(home / ".claude" / "agents")):
        assert pre("mcp__files__move_file", {"source": "prepared", "destination": destination},
                   isolated_home, cwd=project) == "deny"
    assert pre("Write", {"file_path": str(home / ".claude" / "projects" / "m" / "memory" / "a.md"), "content": "x"},
               isolated_home, cwd=project) is None
