---
name: agentussagefolder
description: Use before and after ANY code change in a git repo (bug fix, feature, refactor, rename, signature change). Shows the blast radius first (importers, callers, tests, co-changed files, the project's own check commands), then proves the edit did not break callers, invent imports/names/keywords, weaken tests, silence errors or leak secrets. In-place, no branches or commits, tiny output. Use it instead of grepping or cat-ing files to find usages, and before claiming a change is done.
---

# agentussagefolder: change code safely, read less

`A` = `python3 agentussagefolder/agent.py` (run from the repo root). In-place: it never branches, commits, stashes or resets.

## Size the ceremony to the task
- **Trivial** (typo, comment, one-liner, no signature touched): edit, then `A review`, then run the tests. Skip `begin`.
- **Normal**: the loop below.
- **Refactor, rename, API change**: the loop plus `--touch` and `--run-baseline`.

## Loop
1. **Brief**: `A brief FILE [--symbol NAME]` gives outline, importers, callers (CONFIRMED / PROBABLE / POSSIBLE), tests, co-changed files and `GATES` (the project's own checks). Read it instead of grep/cat. Bare filenames work.
2. **Read little**: `A slice FILE Class.method` (or `FILE 40-80`), `A outline FILE`.
3. **Begin**: `A begin --task NAME --auto-check [--touch Sym ...] [--run-baseline] FILE...`
   `--auto-check` = pytest over the tests that import your files; otherwise `--check '["cmd","arg"]'` (JSON argv, never a shell string). `--touch` = existing functions you intend to change; other logic changes get flagged. `--run-baseline` runs the checks now, so you know what was already red.
4. **Edit minimally.** Never edit `agentussagefolder/` or `.state/`.
5. **Review** after each edit round: `A review --task NAME`. Fix every finding. Callers outside scope: `A widen --task NAME PATH...`.
6. **Verify**: `A verify --task NAME` runs the static gate, then your checks fresh. `CHECKS_PASSED` means those commands passed, not that the code is correct. Read `warn`.
7. **Self-review**: `A diff --task NAME` shows only your changes. Undo one file exactly: `A restore --task NAME PATH` (keeps the user's earlier uncommitted edits; never `git checkout` a dirty file).
8. **Finish**: `A close --task NAME` (or `abandon`). After a context reset: `A list`, `A status --task NAME`.

## Do not distort the project
- Smallest diff that solves the task. Reuse existing helpers (outline first), match local style, no drive-by edits or reformatting.
- Never turn tests green by weakening them: no deleted tests or assertions, skips, `noqa`, `type: ignore`, empty `except`. If a test must change, say why in your summary.
- Run the project's own gates, not only your test. Failures that were already red at `begin` are not yours; do not fix them unless asked.
- Leave nothing behind: debug code, unused imports, TODOs, secrets.

## Reading the output
- **E** proved from the AST (fix). **L** likely invented name (confirm). **P** outside your `--touch`, or a secret. **SMELLS** hints that you may be distorting something: fix or justify. **POSSIBLE / ?** name match or dynamic module: check by hand. Unknown stays unknown; never present a guess as fact.
- BLOCKED reasons end with `-> fix`. Do not delete `.state/`. Use `--no-static` only when review is clean and you can say why.
- Preserve the user's uncommitted work: no stash, reset or clean.
- Not covered: third-party APIs, runtime behaviour, cross-service contracts, non-Python symbols (JS/TS: relative imports only). "No findings" is not "safe". Tests stay the ground truth; if `brief` says `TESTS: NONE`, add or pick one first.
- Python 3.9+ and git, stdlib only. `policy.json` (see `policy.example.json`) is the user's file, not yours. Details: `A <command> -h`.
