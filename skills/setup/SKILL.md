---
name: setup
description: Turn on, on this computer, the protections a plugin cannot turn on by itself (the operating system sandbox and read rules). A single command the user runs.
disable-model-invocation: true
---

# Set up the Anonymizer

You do not edit any file or run any command in this step: the user runs a single one. A plugin
cannot turn on the sandbox, and with the sandbox on you could not even write to `~/.claude`. Besides,
a security change should be executed by the person.

Answer in the user's language with exactly this, in this order and nothing else:

1. One line: "This turns on the operating system sandbox so no command can open data files (.csv,
   .xlsx, .sql, .sqlite, .sav…) outside `~/anonimizados`, and creates the folders `~/sensibles`
   (originals) and `~/anonimizados` (clean copies). It backs up your settings and deletes nothing
   of yours."

2. The command, in a block, for them to type in this same chat:

   ```
   ! "${CLAUDE_PLUGIN_ROOT}/scripts/run.sh" install
   ```

3. Two things to know, one line each:
   - Claude Code will ask for permission the first time a command uses a new network domain.
   - If one of their projects reads CSV, `.sql` or SQLite files without personal data (fixtures,
     `structure.sql`, `development.sqlite3`), they can open it with
     `/anonimizador:allow <project folder>`.

4. One final line: "Then restart Claude Code and confirm with `/sandbox`. To undo it:
   `! "${CLAUDE_PLUGIN_ROOT}/scripts/run.sh" uninstall`."

If the user asks about teams or untrusted repositories: the managed-settings block comes out of
`"${CLAUDE_PLUGIN_ROOT}/scripts/run.sh" config managed` and whoever administers the computer
installs it in `/Library/Application Support/ClaudeCode/managed-settings.json`.
