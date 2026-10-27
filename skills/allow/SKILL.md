---
name: allow
description: Let Claude read data files (test CSVs, .sql, SQLite) inside a project folder that has no personal data.
disable-model-invocation: true
argument-hint: <project folder>
---

# Allow a project folder

Requested folder: $ARGUMENTS

You do not run the command: opening a folder is the user's security decision. Answer in the user's
language.

1. If no folder was given, ask for the project's path (not `~`, not Downloads, not `~/sensibles`:
   the command rejects those).
2. Remind them in one line: "Do this only if that folder has no personal data; from then on Claude
   can read its CSV, `.sql` and SQLite files."
3. Give them the command in a block to type in this chat:

   ```
   ! "${CLAUDE_PLUGIN_ROOT}/scripts/run.sh" allow <folder>
   ```

4. One line: "Restart Claude Code so the sandbox picks it up."
