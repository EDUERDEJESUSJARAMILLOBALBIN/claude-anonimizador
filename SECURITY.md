# Security

This plugin exists for a single promise: **the values in your data files do not reach the model**.
A failure of that promise is a security failure, and we treat it as one.

## How to report a vulnerability

Do not open a public issue. Use **Security → Report a vulnerability** in this repository (GitHub
private reporting). Include:

- the exact tool or command that let a value through (with synthetic data, never real data);
- the Claude Code version (`claude --version`), the operating system and the permission mode;
- whether you had run `/anonimizador:setup` (sandbox on or off).

We answer within 7 days. When there is a fix, a new version is released and the reporter is
credited, if they wish.

## Why open source does not weaken the protection

Security does not depend on the code being secret. It depends on:

1. **Deterministic controls outside the model**: Claude Code hooks and the operating system sandbox.
   Knowing how they work does not let anyone skip them: the kernel enforces the sandbox.
2. **One key per machine**: pseudonyms and fingerprints use HMAC-SHA256 with a random key stored in
   the macOS Keychain (or in `~/.anonimizador/hmac.key`, 0600, on Linux). Without that key, an `ID_…`
   or a fingerprint reveals nothing.
3. **Output verification**: every copy is checked against the original's fingerprints before it is
   delivered; if a value is left, it is erased.

Anyone being able to read the code is what lets holes be found and closed.

## Trust model

| Threat | What stops it |
|---|---|
| The model makes a mistake or is induced to read a data file | Hooks (Read, Grep, MCP) and the OS sandbox (Bash) |
| A command builds the path piece by piece (`'data'+'.c'+'sv'`) | Sandbox: the kernel enforces it, not the command text |
| An output carries data from an original through an unforeseen path | Tripwire: the whole output is blocked and the session is locked |
| A repository tries to loosen the sandbox from its `.claude/settings*.json` | The plugin detects it and closes Bash |
| The model writes a project hook, skill or MCP server that would run outside the plugin | The guard denies writes to `.claude/settings*.json`, `.claude/{hooks,skills,commands,agents}/` and `.mcp.json` |
| A repository turns the plugin off from its settings | **No plugin can defend against this.** Use managed settings (`run.sh config managed`) |
| A repository injects environment variables that run code when a hook's shell starts | **Neither.** Only managed settings with `allowManagedHooksOnly` |

## Known limits (not vulnerabilities)

- JSON, YAML and XML are closed only in the folders where files arrive (Downloads, cloud drives,
  Mail, external drives) and in `~/sensibles`; TXT is not covered.
- Commands the user types with `!` go through neither hooks nor sandbox.
- Whatever the user approves keeping in the copy is seen by the model.
- On native Windows, Claude Code has no sandbox; use WSL2.
- The engine does not run in a network-less container yet.
