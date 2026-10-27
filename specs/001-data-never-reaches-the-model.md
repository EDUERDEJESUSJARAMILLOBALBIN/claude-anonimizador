# Spec 001 — Real data never enters the model's context

Status: in progress · Reference Claude Code: 2.1.311 · Date: 2026-10-26

## Problem

Whoever works with Claude Code on an Excel, CSV or SQL dump with personal data hands the whole
content to the model as soon as they ask "analyze this". Claude Code has no command to anonymize
first, and an instruction like "do not read the file" is not a control: the model can make a mistake
or be induced by other text.

## Guarantee the plugin offers

> No value from the original file enters the model's context through any path Claude Code controls,
> and every session can be audited to prove it.

The guarantee rests on deterministic controls outside the model. Instructions to the model (skills,
CLAUDE.md) only improve the experience; they protect nothing.

## Architecture

1. **Single door.** Only the plugin's MCP server reads the originals. It runs outside the Bash
   sandbox (Docker with `--network none` is future work).
2. **Value-free API.** The MCP server exposes `profile` and `apply`. No answer can contain a cell
   value: answers are validated against a closed schema (`engine/src/anonymizer/profile.py`).
3. **Containment layers** so the model cannot reach the original some other way:

| # | Layer | Claude Code mechanism |
|---|---|---|
| 1 | Permissions | `Read(~/sensibles/**)` deny (best effort in Grep, Glob, `@` and the IDE) |
| 2 | Hook PreToolUse | matcher `*`, includes MCP and subagents; allowlist of data files, resolving symlinks and hard links |
| 3 | OS sandbox | `filesystem.denyRead` per extension, `allowUnsandboxedCommands: false`, `failIfUnavailable: true` |
| 4 | DLP PostToolUse | HMAC fingerprints + `updatedToolOutput`; tripwire locks the session; backup only |
| 5 | UserPromptSubmit | blocks `@` to data files and pasted text with fingerprints |
| 6 | Audit | SessionEnd + `canaries/audit.py` over transcripts and caches |

## Known Claude Code gaps (a plugin cannot close them)

- `!` commands: no hooks and no sandbox, and their output enters the context.
- `@file`: it is not documented whether UserPromptSubmit runs before the file is attached.
- Telemetry and the transcript store the original output before PostToolUse.
- A plugin cannot declare deny rules or sandbox settings; they go in user or managed settings.

## Acceptance criteria

- [x] `profile.validate()` rejects any field outside the schema and any count below 5.
- [x] Fingerprints detect national IDs with or without separators, emails and names of 1 to 4 words.
- [x] The canary generator hides values in hidden sheets, comments, defined names, metadata, headers,
      validations, formulas, `COPY`, views and nested JSON. (Missing: pivot tables.)
- [x] The auditor finds 100 % of the canaries in a raw file and 0 in a clean directory, without ever
      printing a value.
- [x] JSON, JSONL and YAML are profiled by path and rebuilt with the same shape without dropped keys;
      YAML aliases and tags are rejected. Keys outside the known vocabulary leave as aliases, and
      objects inside lists of values are never copied through.
- [x] `apply` rejects a file that changed after its profile (the dialog and the copy describe the
      same content).
- [ ] The adversarial sessions (`canaries/attacks.py`; 1 run in default mode: 4/4 blocked, 0 canaries)
      in default, acceptEdits, auto and plan modes end with zero canaries in `~/.claude/projects`,
      `file-history` and `paste-cache`.
