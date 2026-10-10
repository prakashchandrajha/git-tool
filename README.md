# Git-Tools

Git-Tools is a safety and intelligence layer for AI agents changing real Git repositories. It does not write code for the agent or claim that a green test suite means “correct.” It makes the agent establish evidence before it changes code, preserve the user’s existing work, and leave a reproducible verification receipt afterwards.

The runnable engine is `agent.py` (the historic directory name in the skill is `agentussagefolder`). It is stdlib-only and works in place: no branch, commit, stash, reset, or checkout is created.

## What it adds

- Maps blast radius before an edit: importers, resolved Python callers, test reachability, co-change, and discovered project gates.
- Uses Git history as evidence: prior fixes, explicit reverts, files that usually change together, and tests added alongside past fixes.
- Compares each declared check with its own pre-edit baseline. A command that previously ran tests but now reports zero tests blocks verification even when it exits successfully.
- Detects broken Python callers/imports, changed signatures, removed names, unintended symbol edits, test weakening, error suppression, debug leftovers, and high-confidence secrets.
- Reserves a task’s exact scope; records a signed baseline; can show or restore only the agent’s delta without erasing pre-existing user edits.
- Stores optional per-repository knowledge as signed facts with explicit evidence. Facts are re-checked and become stale instead of silently becoming “truth.”

## Agent workflow

Run from the target repository after copying this toolkit into it (or pass the appropriate path to `agent.py`):

```bash
A='python3 agentussagefolder/agent.py'
$A brief path/to/file.py --symbol function_name
$A history path/to/file.py
$A begin --task fix-name --check '["python3","-m","pytest","-q"]' --run-baseline path/to/file.py
# make the smallest change
$A review --task fix-name
$A verify --task fix-name
$A diff --task fix-name
$A close --task fix-name
```

For Python, `--auto-check` selects tests that import the scoped files. For every other language, declare the repository’s real compiler, test, lint, or integration command using repeatable JSON `--check` arguments. `brief` discovers likely commands but never executes one implicitly.

Read [SKILL.md](SKILL.md) for the agent-facing protocol and run `python3 selftest.py` after copying the toolkit into another project.

## Evidence, not theatre

`CHECKS_PASSED` means only that fresh, declared commands passed while the watched worktree remained unchanged. It is not approval, a security audit, proof of runtime behavior, or coverage of remote services, databases, feature flags, generated code, third-party APIs, or production data.

History findings deliberately do not become automatic verdicts: a current change may intentionally reintroduce behavior that was once reverted. Git-Tools names the exact commit so the agent must inspect and explain the decision. Missing evidence stays unknown.

Never put tokens, passwords, production data, or keys in source, task receipts, command lines, or durable memory.
