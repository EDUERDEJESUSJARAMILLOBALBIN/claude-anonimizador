---
name: anonymize
description: Anonymize an Excel (.xlsx, .xlsm), CSV, TSV, JSON, JSONL or YAML file locally before analyzing it, so personal data never reaches the model. Use it ALWAYS when the user asks to open, read, analyze, summarize or join a data file that may contain people (customers, employees, patients, sales, payroll, receivables, surveys), or types /anonymize.
argument-hint: <file path> [what the analysis is for]
---

# Anonymize before analyzing

Arguments: $ARGUMENTS

Talk to the user in their own language. The original is **never read**: not with Read, not with
Bash, not through a subagent. The only door is the plugin's MCP server (`profile` and `apply`). If a
tool answers "Anonymizer: …", that is the plugin's guard: do not work around it.

No data file (.csv, .xlsx, .sql…) outside `~/anonimizados/` is readable for you, profiled or not.
Write the results you produce (tables, summary CSVs) to `~/anonimizados/` too, so you can read them
back.

## Steps

1. **Absolute path.** If the user did not give it, ask for it. Expand `~`. Do not check that it
   exists with `ls` or `test`: `profile` will tell you.

2. **Profile.** Call `profile` with the path. If it fails on the contract, retry with
   `strict: true` (it also hides sheet and column names).

3. In JSON and YAML every list of objects is a table (`customers[]`, `customers[].orders[]`) and
   every path is a column (`contact.email`, `phones[]`); the root is the `$` table. The copy
   keeps the same structure without the dropped keys, and any key that is not known vocabulary
   leaves as an alias (`k1`, `k2`…).

4. **Show the profile** in a short table: alias, name (if present), category, confidence and
   suggested action. Below it, in one line, the hidden content it found (`hidden_findings`: hidden
   sheets, comments, metadata…). That content never goes to the copy.

5. **Ask what the analysis is for**, if the user did not say. With that answer, propose the plan
   column by column. The rule: whatever the analysis does not need is dropped.
   - Documents, emails, phones, addresses, cards, bank accounts, plates: **drop**. If they are
     needed to count people or join tables, **pseudonymize** (same value → same `ID_…` code across
     all of the user's files).
   - Names: drop; pseudonymize only when counting per person.
   - Birth date: **generalize** (10-year age ranges).
   - Amounts, quantities, categories, transaction dates, city: **keep**, or generalize amounts into
     ranges if they are salaries.
   - Free text (notes, comments): **drop** unless the analysis needs it. If it is kept, warn that
     the verification may reject the copy if it carries names or phone numbers.
   - Document, email, phone, name, address, birth date, card, bank account, ip and plate cannot be
     kept: the engine rejects it.
   - `unclassified` columns (text without a known header) are dropped unless the user says what
     they are and asks to keep them.

6. **Confirm with AskUserQuestion** (multiSelect) which sensitive columns the user wants
   pseudonymized or generalized instead of dropped. Offer the recommendation first.

7. **Apply.** Call `apply` with `{"t1": {"c3": "pseudonymize", …}}`. Columns you do not mention take
   the suggested action, "review" is dropped and hidden sheets are omitted unless you name them.
   Claude Code will show the user the whole plan, column by column and with what goes out as-is, for
   approval. If the verification fails, explain that the copy had values from the original and
   propose dropping or pseudonymizing the free-text column.

8. **Work with the copy.** From here on use only the `output` path (in `~/anonimizados/`) with Read,
   Bash or whatever the analysis needs. At the end, say in one line that the original never went
   through the conversation.

## If the user asks to see a value from the original

Tell them the plugin does not allow it by design and that they can open the file themselves
outside Claude. Do not try to recover it with another tool.
