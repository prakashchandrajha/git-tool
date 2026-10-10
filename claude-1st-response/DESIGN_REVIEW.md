# agentussagefolder v2: design review

For you, not for the agents. Agents read only `agentussagefolder/SKILL.md` (about 950 tokens). Keep this file outside the folder you paste into projects.

## 1. What the project is

v1 is a **guardrail kernel** for AI coding agents, and a good one:

| Piece | Role |
|---|---|
| `agent.py` | Reserves exact paths in the *current* worktree, snapshots only what git says changed, runs the JSON-argv checks the agent declares, and writes HMAC-signed receipts. Fails closed. |
| `context.py` | Bounded read-only context: target facts, nearby rules/manifests, git co-change. |
| `radar.sh`, `enforce_workflow.sh`, `check_vault.sh`, `git_logical_coupling.sh` | Compatibility adapters for older agent instructions. |
| `semantic_airlock.py` | Legacy structural "capsule" API. Its `ok` is a structural pass, never approval. |

Its philosophy is right and I kept all of it: no branches, commits or stashes; unknown stays unknown; `CHECKS_PASSED` never claims correctness; fresh verification beats pasted results.

**What it could not do:** answer "if I change this, what else breaks?" It could confirm that *scope was respected* and *commands passed*. It had no idea who calls what, so it could not stop the most common collateral damage.

## 2. Why "one change breaks something else"

| Root cause | v1 | v2 |
|---|---|---|
| Unknown blast radius | `--symbol` grepped **only inside the target file**, so "0 references" read like "no callers" | `brief --symbol`: AST-confirmed callers repo-wide, resolved through aliases and re-exports |
| Signature drift (new required arg, renamed kwarg) | invisible | `review`/`verify` check every resolvable call site against the real signature |
| Removed or renamed names | invisible | every importer is checked; deleted modules are resolved in a "ghost world" |
| Invented imports, attributes, names, keywords | invisible until runtime | caught statically, with did-you-mean (`max_notional` -> `max_notional_usd`) |
| Collateral inside the same file | file-level scope only | symbol-level fingerprints; `--touch` declares intent, anything else is flagged |
| Behaviour change hidden behind a green test run | `CHECKS_PASSED` | plus `UNTESTED` / `TESTS: NONE` warnings |
| Clobbering the user's uncommitted work | detected, but no way to undo exactly | baseline content stored; `diff --task` and `restore` work on *your* delta only |
| Token waste | long SKILL.md, whole-file reads, big logs | terse outputs, `slice`/`outline`, failure tails |

## 3. The 50 cross-questions

Asked as the agent about to edit code. **Built** = new in v2. **Kept** = v1 behaviour retained. **Limit** = honest boundary.

### A. Understanding the task and its blast radius

| # | Question | Finding -> decision |
|---|---|---|
| 1 | I'm told to change `f`. Who calls it? | v1 only searched the target file. **Built:** `brief --symbol` gives CONFIRMED (AST-proved), PROBABLE (method name in a file that imports the module) and POSSIBLE (word match) tiers. |
| 2 | Which files import this module? | **Built:** import graph with absolute, relative, `src/` layout, package-aware roots; JS/TS relative imports. |
| 3 | Which tests exercise it? | v1: filename guesses. **Built:** reverse import closure (direct / "via X"), filename fallback, and an explicit `TESTS: NONE reach this file`. |
| 4 | What usually changes together? | **Built:** co-change shown as `k/n` of commits that touched the target; hidden when n < 2; deleted files dropped. |
| 5 | I know a symbol name, not the file or line. | **Built:** `outline`, `slice FILE Class.method`, basename lookup. |
| 6 | What conventions apply? | **Kept** (AGENTS.md, CLAUDE.md, ...) and added `GEMINI.md`. |
| 7 | My guessed path doesn't exist. | **Built:** unique-suffix and basename lookup; close-match suggestions instead of a dead end. |
| 8 | Is this edit risky? | No invented "risk score" (v1 correctly removed it). **Built:** facts only: importer count, tests reaching it, co-change, uncommitted-edits flag. |
| 9 | Is the file editable at all? | **Kept** fail-closed on private/generated paths; **Built:** `policy.json` per project, lockfiles no longer treated as runtime locks. |
| 10 | The user already has uncommitted edits in it. | **Built:** flagged in `brief`; baseline content kept so you never blame or destroy it. |

### B. Hallucination

| # | Question | Finding -> decision |
|---|---|---|
| 11 | Does the function I'm calling exist with these arguments? | **Built:** `E-CALL` checks arity, keywords, `*args`/`**kw`, positional-only, class `__init__`. |
| 12 | Did I import something that doesn't exist? | **Built:** `E-IMPORT` / `E-NAME` with did-you-mean. |
| 13 | Did I use an attribute an internal module doesn't have? | **Built:** `E-ATTR`. Dunder attributes are exempt (`__file__`). |
| 14 | Did I use an undefined variable or helper? | **Built:** `L-UNDEF` from `compile()` + `symtable`, *introduced-by-you only*, honours `# noqa`. |
| 15 | Did I invent a keyword argument? | **Built:** "unexpected keyword `quantity`, did you mean `qty`?" |
| 16 | Is a deliberately wrong call inside `assertRaises` / `pytest.raises` a bug? | Found on Django's own tests. **Built:** exempt. |
| 17 | Does the file even compile? | **Built:** `compile()` on changed files -> `E-SYNTAX`. |
| 18 | Third-party APIs? | **Limit:** not verifiable without your environment. Declare `mypy`/`pyright` as a `--check`. |
| 19 | Can the *tool* hallucinate? | **Built:** three confidence tiers; unprovable cases (dynamic modules) are reported as POSSIBLE with the reason, never silently passed. See section 5 for measured false-positive rates. |
| 20 | JS/TS? | **Limit:** relative-import resolution and importers only; no symbol-level analysis. |

### C. Using git wisely

| # | Question | Finding -> decision |
|---|---|---|
| 21 | Should the tool branch, commit or stash for safety? | **Kept: no.** History belongs to you; branch juggling is itself a collateral-damage source. |
| 22 | How do I separate my edits from the user's pre-existing dirt without a commit? | **Built:** sha256-addressed baseline blobs inside `.state/`, not git objects or refs. |
| 23 | How do I see only what *I* changed? | **Built:** `diff --task` compares against baseline content, not HEAD. |
| 24 | How do I undo exactly? | **Built:** `restore` returns bytes as of `begin` (user's edits included), backs up current content first, refuses private/special paths. It is the only command that writes project files. |
| 25 | Someone committed or staged mid-task. | **Kept:** HEAD/index drift detected; v2 hints say `abandon` then `begin`. |
| 26 | Fast reference search that respects `.gitignore`? | **Built:** `git grep -w -F --untracked` narrows candidates; the AST confirms. |
| 27 | Avoid re-reading the repo every call? | **Built:** `status`-driven change set; parse cache keyed by git-blob SHA-1 of content, so an entry cannot be stale. |
| 28 | Where does the "before" version come from? | **Built:** `git cat-file blob HEAD:path`, or the stored blob. |
| 29 | Unmerged paths, submodules, assume-unchanged, sparse checkout? | **Kept:** blocked with an explanation. **Built:** repos with no commits yet now work. |
| 30 | Renames and deletions? | **Built:** treated as delete + add; importers of the old path are found in a ghost world. |

### D. Verification quality

| # | Question | Finding -> decision |
|---|---|---|
| 31 | Which tests should I run? | **Built:** `begin --auto-check` = pytest over tests that import your files. Otherwise declare `--check`. **Limit:** pytest only. |
| 32 | Why run slow tests when static analysis already knows it's broken? | **Built:** static gate fast-fails before any check runs. |
| 33 | A failing test costs a rerun just to read the error. | **Built:** `verify` returns a 30-line / 3 KB `failure` tail. |
| 34 | Green tests that don't cover my change? | **Built:** `UNTESTED` warning; `TESTS: NONE` in `brief`. |
| 35 | Behaviour changed without a signature change? | **Built:** per-symbol AST fingerprints (logic / signature / cosmetic). Only tests judge behaviour, and the output says so. |
| 36 | Collateral inside the same file? | **Built:** `--touch Class.method` declares intent; other logic changes become `P-TOUCH` blocks. Typos in `--touch` are caught at `begin`. |
| 37 | Formatting noise? | **Built:** comment/docstring/format-only changes are AST-identical, reported as "cosmetic". |
| 38 | A check that modifies files? | **Kept:** watched-state change blocks. |
| 39 | Dependency updates? | **Built:** `poetry.lock`, `uv.lock`, `Cargo.lock`, ... are scopable. |
| 40 | Does a pass overclaim? | **Kept** the wording; **Built:** `warn`, and `--no-static` is recorded as skipped. |

### E. Tokens

| # | Question | Finding -> decision |
|---|---|---|
| 41 | Where do agents burn tokens? | Whole-file reads, repeated greps, giant logs/diffs, long instructions. Each has a feature below. |
| 42 | Instruction size? | SKILL.md rewritten: 588 words (about 950 tokens) after the v2.1 additions (v1 was roughly 850 words). Detail lives behind `-h`. |
| 43 | Output format? | Terse text with `+N more` caps; `--json` available. Findings carry the fix. |
| 44 | Reading a big file? | `outline` / `slice` / `brief`. See the table in section 5 (30,500 tokens vs 94). |
| 45 | Logs and diffs? | Failure tail capped; `diff` capped at 70 lines per file, 220 total. |

### F. Many projects, many agents

| # | Question | Finding -> decision |
|---|---|---|
| 46 | Pasting into projects with different layouts and private dirs? | **Built:** package-aware import roots; optional `policy.json`; ignored tool dirs (`.idea`, `.terraform`, ...) no longer block. |
| 47 | Different agents read different instruction files? | One 3-line snippet (section 6). |
| 48 | Agent crashes or loses context mid-task? | **Built:** `list`, `status`, `abandon`, idempotent `begin`, errors that say what to do. |
| 49 | Prevention instead of detection? | **Built:** `guard` + optional Claude Code PreToolUse hook. |
| 50 | Windows, Python versions, upgrades? | **Built:** `selftest.py`; Python 3.9+ confirmed with `vermin`. **Limit:** Windows shims are written but **untested**. |

## 4. How git is used

| Primitive | Used for |
|---|---|
| `status --porcelain=v1 -z --ignored=matching` | the changed set, without walking the tree |
| `ls-files -z --cached --others --exclude-standard` | file inventory for the import graph |
| `ls-files --stage -v` | HEAD/index identity, assume-unchanged, submodules |
| `cat-file blob HEAD:path` | exact "before" content for symbol-level diffs |
| `grep -w -F -I --untracked` | narrow candidate files and word hits (config files included, lockfiles excluded) |
| `log --name-only -z` (last 100) | co-change `k/n`, bulk commits skipped |
| `check-ignore` | do not flag generated or ignored files |
| blob-style SHA-1 of file content | cache key for parsed facts |

Never used: `branch`, `commit`, `stash`, `reset`, `checkout`, `worktree`, `add`.

## 5. Evidence

**Self-test:** 114 checks in 21 scenarios, about 20 seconds (`python3 agentussagefolder/selftest.py`).

**Real code, not just my fixtures.** I ran the whole-repo audit on 7 open-source projects (3,477 Python files: requests, click, flask, jinja, httpx, rich, django). The first pass found real flaws in my own checker, all fixed:

| Flaw found | Cause |
|---|---|
| `import typing` resolved to the repo's own `typing.py` | files inside a package never resolve absolute imports against their own directory |
| `requests.packages.urllib3` flagged | module aliases submodules through `sys.modules` |
| `django.__file__` flagged | implicit module attributes |
| `BaseConstraint()` flagged | deliberate misuse inside `assertRaises` |
| `self` "undefined" in `rich/_stack.py` | CPython's `symtable` treats any function *named* `top` as module scope |
| Invented import silently passed (a false **negative**) | I had over-broadened "dynamic module"; now reported as POSSIBLE with the reason |

After the fixes, every remaining finding was a genuine defect: a stale `from flask import Module`, three deliberately broken Django fixtures, and two undefined names in rich example/demo code. Zero false positives observed.

**Seeded faults on real code (click):** wrong keyword, new required argument, undefined name, invented import, renamed function. All five surfaced: three as proved findings, two as POSSIBLE because `click/utils.py` defines a module-level `__getattr__` and genuinely cannot be proved either way.

**Speed:** 37-213 file repos 0.5-1.7 s. Django (2,933 files) `brief` 1.2 s warm; the full audit takes 17 s. Large first runs stop at a 10 s indexing budget and say how many files are pending.

**Tokens (Django `query.py`, 3,138 lines):**

| Action | Tokens |
|---|---|
| read the whole file | about 30,500 |
| `outline` | about 970 |
| `brief` | about 630 |
| `slice QuerySet.filter` | about 94 |

Fixture loop outputs: `status` 33, `verify` (pass) 54, `review` 185, `brief` 203 tokens.

## 6. Adopting it

1. **Copy.** `cp -r agentussagefolder/. <project>/agentussagefolder/` overlays new files. **Never delete the folder to upgrade:** it holds `.state/` with open tasks. Keep your existing `semantic_airlock.py`; I did not touch it and did not re-emit it, to avoid any transcription risk.
2. **Check it works there.** `python3 agentussagefolder/selftest.py`
3. **Tell the agent.** Paste into `AGENTS.md` (Codex reads it; Antigravity reads it since v1.20.3, and `GEMINI.md` takes precedence there), and into `CLAUDE.md` for Claude Code:

```markdown
## Code-change protocol (agentussagefolder)
Before editing code: `python3 agentussagefolder/agent.py brief <file> [--symbol <name>]` (callers, importers, tests; use it instead of grep/cat).
Then begin -> edit minimally -> review -> verify -> close, as in agentussagefolder/SKILL.md (read it once).
Never call a change done without a fresh `verify`. Unknown means unknown: say so.
```

4. **Optional per-project tuning.** Copy `policy.example.json` to `policy.json` (you edit it, not the agent). Examples: `private_dirs_remove: ["database"]`, `private_suffixes_remove: [".csv"]`, `ignored_dirs: "block"` for the original strict behaviour.
5. **Optional edit-time guard for Claude Code** (format checked against the hooks docs; exit code 2 blocks the edit and feeds stderr back). `.claude/settings.json`:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Edit|Write|MultiEdit",
  "hooks": [ { "type": "command",
    "command": "python3 \"$CLAUDE_PROJECT_DIR\"/agentussagefolder/agent.py guard --hook" } ] } ] } }
```

It fails open on any error, and blocks only paths outside every open task's scope.

## 7. Limits you should know

- **Static analysis proves some breakage, never correctness.** Tests remain the ground truth. The tool tells the agent when nothing covers a file.
- **Symbol-level precision is Python only.** JS/TS get relative-import resolution and importers; other languages get word matches.
- **Method calls cannot be proved** (receiver type unknown). v2 reports the exact argument mismatch at probable call sites as POSSIBLE when the method name is unique in the repo.
- **Dynamic modules** (`__getattr__`, writes to `globals()`/`sys.modules`) are reported as unknown, not guessed.
- **Third-party packages** are not checked. **`--auto-check`** assumes pytest.
- **One writer per worktree.** As in v1, another agent's edits to unrelated files will block your `verify`. Use separate clones or worktrees for parallel agents.
- **Windows is untested** (shims for `fcntl`, `O_NOFOLLOW`, `killpg`, permission checks exist). The `.sh` adapters need Git Bash or WSL; use `python` instead of `python3`.
- **Static gate can be wrong.** Escape hatch: `verify --no-static`, recorded in the receipt and echoed as a warning.
- **Receipts are accident protection, not attestation:** the HMAC key sits beside them.

## 8. What changed, by file

| File | Change |
|---|---|
| `agent.py` | Kernel kept. Added: `brief`, `outline`, `slice`, `review`, `diff`, `restore`, `widen`, `abandon`, `guard`; static gate inside `verify`; failure tails; `--auto-check`, `--touch`; baseline blobs; `policy.json`; unborn HEAD; ignored-dir handling; lock waiting; Windows shims; fix hints on every BLOCKED reason; no tracebacks. |
| `pyintel.py` (new) | Import graph, symbol resolver, AST fingerprints, call-compat, hallucination checks, content-addressed cache. |
| `context.py` | Honest scope note on `--symbol`; `GEMINI.md`; unborn HEAD; co-change drops deleted files. |
| `radar.sh` | Now routes to `brief`. |
| `enforce_workflow.sh` | Also passes `--touch` / `--auto-check`. |
| `SKILL.md` | Rewritten; sizes the ceremony to the task and adds the do-not-distort rules. |
| `selftest.py`, `policy.example.json` (new) | Verification and per-project tuning. |
| `pyintel.py` / `agent.py` (v2.1) | Quality signals (tests weakened, skips, suppressions, swallowed exceptions, debug leftovers, unused imports, duplicates), secret detection, `GATES` discovery, `begin --run-baseline`, config/docs/template word hits. See section 9. |
| `check_vault.sh`, `git_logical_coupling.sh`, `.gitignore` | Unchanged. |
| `semantic_airlock.py` | Untouched; keep your copy. |

## 9. Round two: the agent's own view

You asked what problems I actually face as the agent, on projects from trivial to huge, whether this tool helps on any repo, and how to stop agents from *distorting* a project while changing it. This is the honest answer.

### 9.1 The 50 questions

Verdict: **solved** = the tool addresses it directly. **partly** = it narrows or warns. **no** = it cannot help; the agent must be careful, or you must provide something else.

**Simple projects (scripts, small apps)**

| # | Problem I face | Verdict | What the tool does about it |
|---|---|---|---|
| 1 | "Make it better" is ambiguous; I guess the intent | no | Nothing. Ask, or state assumptions. `--touch` at least forces an explicit declaration. |
| 2 | No tests at all; how do I know I broke nothing? | partly | Static checks plus a loud `TESTS: NONE`. No behavioural proof. |
| 3 | I cannot run it (API keys, DB, network) | no | |
| 4 | Wrong runtime or missing dependencies, so my fix never runs | partly | `begin --run-baseline` shows the checks already failing before I touch anything. |
| 5 | It depends on files, paths or env that only the user has | no | |
| 6 | I rewrite more than needed because rewriting is easy | partly | Scope reservation, `diff`, and a `NET +a/-b` line. |
| 7 | I reformat while editing | partly | "cosmetic only" is detected when the AST is identical. |
| 8 | I leave debug code and unused imports | **solved** | `LEFTOVER` smells (breakpoint/pdb/console.log/debugger, new TODOs, unused imports I added). |
| 9 | I guess a file or function name that does not exist | **solved** | Basename lookup, did-you-mean, `slice` suggestions. |
| 10 | The ceremony costs more than a one-line change | partly | "Size the ceremony": trivial edits use only `review` + tests. |

**Normal apps with tests (services, libraries)**

| # | Problem I face | Verdict | What the tool does about it |
|---|---|---|---|
| 11 | Who else uses what I am changing? | **solved** (Python); partly (JS/TS) | AST-resolved callers and importers; JS/TS import paths only. |
| 12 | Method callers: I cannot prove the receiver type | partly | Exact argument mismatch reported as POSSIBLE when the method name is unique in the repo. |
| 13 | A rename misses strings, YAML, templates, docs, entry points | partly | Word hits across source, config, docs, templates and SQL (lockfiles and the toolkit excluded). |
| 14 | I copy a legacy pattern because I do not know the conventions | partly | Rules files and co-change. It cannot tell me which pattern is current. |
| 15 | I re-implement a helper that already exists | partly | `DUP`: exact-body duplicates and near-identical names only. |
| 16 | Framework magic (signals, DI, fixtures, decorators) hides usage | partly | Name matches as POSSIBLE; dynamic modules reported as unknown. |
| 17 | The suite was already red; I blame myself or "fix" unrelated tests | **solved** | `--run-baseline`; a later failure is marked `also_failed_at_begin` with both tails. |
| 18 | Tests pass but nothing covers my change | **solved** | `UNTESTED` on verify, `TESTS: NONE` in brief. |
| 19 | I turn tests green by editing or deleting them | partly | `TEST` smell, **net-aware** (moved tests are fine); skips, xfail and `.only` flagged. It cannot judge whether a new assertion is meaningful. |
| 20 | I silence errors (`except: pass`, `noqa`, `type: ignore`) | **solved** | `SILENCE` smells on anything newly added. |
| 21 | "My test passes" is not "CI passes" | partly | `GATES` lists the project's own checks from CI files, Makefile, package.json, pyproject. Detected, not executed. |
| 22 | Behaviour changed without a signature or test change | partly | Logic vs signature vs cosmetic fingerprints. Only tests judge behaviour. |
| 23 | I invent an internal import, attribute or keyword | **solved** | `E-IMPORT/NAME/ATTR/CALL` with did-you-mean. |
| 24 | I use a third-party API from memory | no | Run a type-checker or the real tests. |
| 25 | I hardcode a secret | **solved** | `SECRET` blocks verify (7 high-confidence patterns, values never echoed, documented example keys ignored). |

**Large and complex projects**

| # | Problem I face | Verdict | What the tool does about it |
|---|---|---|---|
| 26 | The repo does not fit my context; I read the wrong files | **solved** | `brief` / `outline` / `slice`. |
| 27 | Cross-service contracts (REST, gRPC, queues, shared schemas) | no | |
| 28 | Schema migrations and data changes | no | |
| 29 | Generated code (protobuf, OpenAPI) | partly | Generated and ignored trees are never touched. Knowing to regenerate is not covered. |
| 30 | Python-JS-SQL boundaries | no | Word hits only. |
| 31 | Plugins, entry points, `importlib` by string | partly | POSSIBLE plus config word hits. |
| 32 | Legacy code, no tests, tangled globals | partly | Honest `TESTS: NONE`. I would still have to write characterization tests. |
| 33 | Slow CI and heavy build systems | partly | Impacted-test selection (Python). Declared checks run as-is. |
| 34 | Tests need services (Docker, DB, GPU) | no | |
| 35 | Concurrency, timing, async races | no | |
| 36 | Performance regressions | no | |
| 37 | Security-sensitive logic (authz, injection, deserialization) | no | Secrets only. |
| 38 | Feature flags and prod config differences | no | |
| 39 | Typed languages: the compiler would catch it | partly | Only if declared as a check; `GATES` suggests it. |
| 40 | A 30-file refactor I cannot finish in one session | **solved** | Tasks, `widen`, `diff`, `restore`, `list`, `status` survive context resets. |
| 41 | Humans commit or rebase while I work | partly | Drift is detected and blocks. One writer per worktree. |
| 42 | Notebooks, data files, configs as code | no | Private or unsupported by design. |

**My own failure modes (any size)**

| # | Problem I face | Verdict | What the tool does about it |
|---|---|---|---|
| 43 | I say "done" or "tests pass" without running | **solved** | Fresh runs only; a pasted PASS counts for nothing. |
| 44 | I fix the symptom, not the cause | no | `diff` makes it visible; judging it is on me. |
| 45 | I over-engineer | no | Only the diff size is visible. |
| 46 | I fail to ask a needed question, or ask too many | no | |
| 47 | My mental model goes stale after many edits | **solved** | `slice`, `outline`, `diff` are cheap re-reads. |
| 48 | I over-trust the tool | partly | Every clean result says it is "static only: behaviour, third-party APIs and contracts NOT checked". |
| 49 | A false positive blocks me and I am tempted to bypass | partly | Zero false errors on the real history below. The escape hatch is recorded, never silent. |
| 50 | I misread a long failing log and patch around it | partly | 30-line failure tail, plus the pre-existing marker from #17. |

**Scorecard: 12 solved, 22 partly, 16 not at all.** Everything in the "not at all" column needs judgment, a runnable environment, or visibility into other systems. A static tool cannot supply those.

### 9.2 Is it useful on any repo?

- **Yes, a lot:** Python repos with an import graph (blast radius, hallucination checks, impacted tests); *any* repo for the workflow discipline (scope, baseline, exact undo, fresh verification, cheap reading); every repo for the new "did I distort it?" hints.
- **Modestly:** JS/TS (import paths only), compiled languages (the compiler is the better gate; the tool contributes scope, receipts, `GATES`).
- **Not at all:** intent, runtime behaviour, other services, and anything that needs an environment.
- **It can make things worse** if the agent treats "no findings" as "safe", runs the full ceremony on a one-line edit, or reflexively bypasses a finding. The wording, the size-the-ceremony rule and the recorded `--no-static` exist to blunt exactly those three.

### 9.3 What I changed in this round (v2.1)

| Problem | Change |
|---|---|
| Tests weakened to get green | `TEST` smell, net-aware across all changed files; skip/xfail/`.only` |
| Errors silenced | `SILENCE` smell: new `noqa` / `type: ignore` / `eslint-disable`, empty `except`/`catch` |
| Junk left behind | `LEFTOVER` smell: breakpoint/pdb/console.log/debugger, new TODOs, **unused imports I added** |
| Reinvented helpers | `DUP` smell: exact-body duplicates and near-identical names |
| Secrets | `SECRET` **blocks** verify; value never echoed; documented example keys ignored |
| "What does CI run?" | `GATES` line in `brief` |
| Already-red suites | `begin --run-baseline`; `also_failed_at_begin` on later failures; a check that writes files during the baseline run is rejected |
| Renames missing docs/config | Word hits now include md, rst, html/jinja, sql and config files |
| Over-trust | Honest caveat on every clean `review`; partial audits now say **INCOMPLETE** on the RESULT line |
| Wrong line numbers | Undefined-name lines are now scoped to the flagged scope |

### 9.4 Evidence from real history

I replayed **156 real commits** (requests, click, flask, jinja, httpx, rich, django) through `review`. Those commits were merged upstream (normally after CI), so any error reported on them is a probable false alarm.

| Result | Value |
|---|---|
| Commits / changed files replayed | 156 / 404 |
| Commits that changed signatures, removed symbols or deleted files (so the delta logic was really exercised) | 26 (10 signature changes, 18 removals, 1 deletion; some overlap) |
| **False errors** | **0** |
| Real latent bugs found | 2, both in rich: `import zlib` moved into one function while a module-level helper still used it (`NameError` at runtime), and the same pattern with `EMOJI` in a `__main__` block. Both landed in upstream history. |
| `TEST` smell | 15 commits (10%) show a net drop in tests or assertions. The click revert and the flask rewrite I checked by hand were genuine; I did not inspect the 4 Django ones. A jinja commit that only *moved* tests was a false alarm until the rule became net-aware. |
| `SILENCE` smell | 7 commits (4%); the ones I read were genuine added `type: ignore` / `noqa` comments |
| Secrets, duplicates | 0 spurious hits |

Limits of this evidence: 10 signature-change commits is a small sample, the repos are all Python libraries, and replaying human commits is not the same as replaying agent mistakes.

### 9.5 Rule of thumb for the agent (and for you when reviewing its work)

1. Read less (`brief`, `slice`), edit less (smallest diff), prove more (`review`, `verify`).
2. A change is not done until a fresh `verify` passes **and** the summary mentions every SMELL, POSSIBLE and UNTESTED line it left standing.
3. Anything in the "no" column of the scorecard needs a human look or a different tool, whatever the toolkit prints.
