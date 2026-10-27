import json
import subprocess
import sys

from canaries.audit import audit
from conftest import hook_env


def test_the_whole_protocol_without_values(traps, isolated_home, tmp_path):
    original = traps / "clientes.xlsx"
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "profile", "arguments": {"path": str(original)}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "apply", "arguments": {
            "path": str(original), "plan": {"t2": "omit", "t3": "omit"}}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "apply", "arguments": {
            "path": str(original), "plan": {"t1": {"c3": "keep"}}}}},
    ]
    process = subprocess.run(
        [sys.executable, "-m", "anonymizer.mcp"],
        input="\n".join(json.dumps(m) for m in messages) + "\n",
        capture_output=True, text=True, env=hook_env(isolated_home), check=True,
    )
    (tmp_path / "stdout.jsonl").write_text(process.stdout)
    responses = {r["id"]: r for r in map(json.loads, process.stdout.splitlines())}

    assert set(responses) == {1, 2, 3, 4, 5}  # the notification gets no response
    assert responses[1]["result"]["protocolVersion"] == "2025-06-18"
    # No "verify" tool: counting matches against any file was a way to guess values
    assert {t["name"] for t in responses[2]["result"]["tools"]} == {"profile", "apply"}
    profile = json.loads(responses[3]["result"]["content"][0]["text"])
    assert profile["hidden_findings"]["hidden_sheets"] == 2
    assert json.loads(responses[4]["result"]["content"][0]["text"])["verification"]["matches"] == 0
    assert responses[5]["result"]["isError"] and "document" in responses[5]["result"]["content"][0]["text"]
    # Nothing the server told the "model" contains a canary
    assert audit(traps / "manifest.json", [tmp_path / "stdout.jsonl"]) == {}
