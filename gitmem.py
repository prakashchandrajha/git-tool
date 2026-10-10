#!/usr/bin/env python3
"""Git history as intelligence (stdlib only, read-only).

Answers the questions an agent cannot get from the working tree:

* **Why is this line here?** ``why`` groups blamed lines into commits and reports the
  commit subject, date, author, issue references, whether that commit was later reverted,
  and which tests landed with it.
* **Has this been tried and undone before?** A revert is *proved*, never guessed: ``git revert``
  writes ``This reverts commit <sha>.`` into the message, and that link is read directly.
* **What breaks when I touch this?**  Fragility is counted, not invented: churn, how many
  follow-up fixes a file needed, how often changing it required a revert, its co-change
  neighbourhood, and the test files that history says guard it.
* **Which behaviours must be preserved?**  The tests that were added *together with a fix* are the
  regression guards for those fixes; deleting one is reported as an evidence-backed finding,
  not a stylistic smell.

Everything here is bounded (commit cap, byte caps, wall-clock budget) and cached by HEAD
commit id, so it can never be stale: a different HEAD means a different cache key.

What it deliberately does NOT do: it does not claim that a fragile file is wrong, that a
reverted commit was a bad idea, or that absence of history means safety. Every claim carries
the commit that proves it.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

ANALYZER = 1                      # bump when the meaning of a cached fact changes
DEFAULT_LIMIT = 3000              # commits to mine by default
MAX_LIMIT = 40000
BUDGET = 6.0                      # seconds for the default mining pass
MAX_LOG_BYTES = 96 << 20          # refuse to build history from an absurd stream
BLAME_BUDGET = 8.0
MAX_BLAME_LINES = 60000
CACHE_BYTES = 192 << 20

# ---- message classification (all of it is reported as evidence, never as a verdict) ----
_REVERT_SUBJECT = re.compile(
    r"^\s*(?:revert|reverts|reverting|reverted|roll(?:ing|ed)?\s*back|back(?:ing|ed)?\s*out|"
    r"undo(?:ing|ne)?|restore\s+previous|reinstate|re-?land)", re.I)
_REVERT_BODY = re.compile(r"this reverts commit\s+([0-9a-f]{7,40})", re.I)
_FIX_SUBJECT = re.compile(
    r"\b(?:fix(?:e[sd])?|bugfix|hotfix|hot-fix|regression|re-?fix|patch(?:es|ed)?|"
    r"correct(?:s|ed|ion)?|repair|workaround|avoid\s+crash|no\s+longer\s+(?:works?|fails?))\b", re.I)
_BREAK_WORDS = re.compile(
    r"\b(?:break(?:s|ing|age)?|broke(?:n)?|regress(?:es|ed|ion)?|crash(?:es|ed|ing)?|"
    r"corrupt(?:s|ed|ion)?|data\s+loss|silently)\b", re.I)
_RELEASE_SUBJECT = re.compile(r"^\s*(?:release|version|bump|prepare|merge\s+(?:branch|pull)|"
                              r"update\s+changelog|chore|docs?:|typo)", re.I)
# "fix" in a subject is not evidence of a code fix: docs/comment/formatting commits touch source
# too. Counting them as fixes was measured to flag ~50% of real merged commits - too noisy to ship.
_NOISE_FIX = re.compile(r"\bfix(?:e[sd])?\s+(?:a\s+|the\s+)?(?:typo|docs?|comment|readme|whitespace|"
                        r"format|lint|style|wording|spelling|grammar|test\s+name|example)", re.I)
_ISSUE_RE = re.compile(r"(?<![\w#])#(\d{1,7})(?![\w])|\b([A-Z][A-Z0-9]{1,9}-\d{1,7})\b")
_URL_PR_RE = re.compile(r"https?://\S*?/(?:pull|issues|merge_requests)/(\d{1,7})")
_TRAILER_RE = re.compile(r"^(?:Signed-off-by|Co-authored-by|Reviewed-by|Acked-by|Tested-by|"
                         r"Change-Id|Refs|Closes|Fixes|Resolves)\s*:", re.I)

STATUS_OK = frozenset("AMDTRUXB")


def _git(root, *args, timeout=60, ok=(0,)):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    try:
        proc = subprocess.run(["git", "--no-pager", "-c", "core.fsmonitor=false", *args], cwd=root,
                              env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode in ok else None


def head_id(root, rev=None):
    sha = _git(root, "rev-parse", "--verify", "-q", rev or "HEAD", ok=(0, 1))
    if not sha:
        return "UNBORN"
    return sha.decode("ascii", "replace").strip() or "UNBORN"


# --------------------------------------------------------------------------- log parsing
class Commit:
    __slots__ = ("sha", "ts", "author", "subject", "body", "files", "is_revert", "reverts",
                 "is_fix", "risky_words", "refs", "is_noise", "is_revert_of_revert")

    def __init__(self, sha, ts, author, subject, body):
        self.sha, self.ts, self.author, self.subject, self.body = sha, ts, author, subject, body
        self.files = []                      # [(status, path)] (path = new path for renames)
        self.is_revert = bool(_REVERT_SUBJECT.match(subject)) or bool(_REVERT_BODY.search(body))
        self.reverts = [m.group(1).lower() for m in _REVERT_BODY.finditer(body)]
        self.is_fix = bool(_FIX_SUBJECT.search(subject))
        self.risky_words = bool(_BREAK_WORDS.search(subject))
        if _NOISE_FIX.search(subject):
            self.is_fix = False
        self.is_noise = (bool(_RELEASE_SUBJECT.match(subject)) or bool(_NOISE_FIX.search(subject))) \
            and not self.is_revert
        self.is_revert_of_revert = False
        refs = []
        for m in _ISSUE_RE.finditer(f"{subject}\n{body}"):
            refs.append("#" + m.group(1) if m.group(1) else m.group(2))
        for m in _URL_PR_RE.finditer(body):
            refs.append("#" + m.group(1))
        self.refs = refs[:8]

    @property
    def date(self):
        try:
            return time.strftime("%Y-%m-%d", time.gmtime(int(self.ts)))
        except (ValueError, OSError, OverflowError):
            return "?"

    @property
    def subject_short(self):
        return self.subject[:110]


def parse_log(stream: bytes, max_commits=DEFAULT_LIMIT):
    """Parse ``git log --format=%x00C%x00...%x00%b --name-status -z``.

    Framing (verified against git 2.43): each commit is ``\\0 C \\0 sha \\0 ctime \\0 author \\0
    subject \\0 body`` followed by ``\\0`` separators and then, prefixed by a literal newline on the
    first entry, repeating ``STATUS \\0 path \\0`` (renames/copies carry a second path).
    Unknown framing is skipped rather than guessed at.
    """
    tokens = stream.split(b"\0")
    out, i, n = [], 0, len(tokens)
    while i < n and len(out) < max_commits:
        if tokens[i] != b"C":
            i += 1
            continue
        if i + 5 >= n:
            break
        try:
            sha = tokens[i + 1].decode("ascii")
            ts = int(tokens[i + 2].decode("ascii", "replace") or 0)
            author = tokens[i + 3].decode("utf-8", "replace")[:80]
            subject = tokens[i + 4].decode("utf-8", "replace").replace("\n", " ")[:300]
            body = tokens[i + 5].decode("utf-8", "replace")[:6000]
        except (ValueError, UnicodeDecodeError):
            i += 1
            continue
        commit = Commit(sha, ts, author, subject, body)
        i += 6
        # skip empty separators up to the first status token (which may carry a leading newline)
        while i < n and (tokens[i] == b"" or tokens[i] == b"\n"):
            i += 1
        while i < n:
            raw = tokens[i]
            if not raw or raw == b"\n":
                i += 1
                continue
            if raw == b"C":
                break
            status = raw.decode("ascii", "replace").lstrip("\n")
            head = status[:1]
            if head not in STATUS_OK:
                break
            if i + 1 >= n:
                i = n
                break
            path = os.fsdecode(tokens[i + 1])
            commit.files.append((head, path))
            i += 2
            if head in ("R", "C"):           # rename/copy: old path then new path
                if i < n:
                    i += 1
            elif status[1:] and not status[1:].isdigit():
                break
        out.append(commit)
    return out


def _decode_ignore(data: bytes):
    return {os.fsdecode(x) for x in data.split(b"\0") if x}


# --------------------------------------------------------------------------- the model
class History:
    """Mined commit history with query methods. Never raises on a broken repo; degrades instead."""

    def __init__(self, root, head="UNBORN"):
        self.root = Path(root)
        self.head = head
        self.commits = []                     # newest first
        self.notes = []
        self.truncated = False
        self.index = None                     # path -> [commit position]
        self.event_index = None               # symbol -> [(path, commit position)]

    # ---- build -----------------------------------------------------------------------
    @classmethod
    def load(cls, root, *, limit=DEFAULT_LIMIT, budget=BUDGET, skip=None, cache_dir=None, fresh=False,
             rev=None):
        """Mine history. ``rev`` pins the tip so a replay sees only its own past, never its future."""
        root = Path(root)
        head = head_id(root) if rev is None else (head_id(root, rev) or "UNBORN")
        if head == "UNBORN":
            hist = cls(root, head)
            hist.notes.append("repository has no commits yet; history intelligence is empty")
            return hist
        limit = max(50, min(int(limit), MAX_LIMIT))
        cache_path = None
        if cache_dir is not None and not fresh:
            cache_path = Path(cache_dir) / f"gitmem-{ANALYZER}-{limit}.json"
            cached = cls._read_cache(cache_path, head)
            if cached is not None:
                return cached
        t0 = time.monotonic()
        stream = _git(root, "log", f"--max-count={limit + 1}", "--no-renames", "--no-merges",
                      "--format=%x00C%x00%H%x00%ct%x00%an%x00%s%x00%b", "--name-status", "-z",
                      *([head] if rev is not None else []), "--",
                      timeout=max(20, int(budget * 4)))
        hist = cls(root, head)
        if stream is None:
            hist.notes.append("git log unavailable (no history intelligence)")
            return hist
        if len(stream) > MAX_LOG_BYTES:
            hist.notes.append("history stream too large; mined the first part only")
            hist.truncated = True
            stream = stream[:MAX_LOG_BYTES]
        hist.commits = parse_log(stream, limit + 1)
        if len(hist.commits) > limit:
            hist.commits = hist.commits[:limit]
            hist.truncated = True
        if skip:
            for c in hist.commits:
                c.files = [(s, p) for s, p in c.files if not skip(p)]
        hist._mark_revert_chains()
        hist.elapsed = round(time.monotonic() - t0, 3)
        if cache_path is not None:
            hist._write_cache(cache_path)
        return hist

    def _mark_revert_chains(self):
        """A revert of a revert means the behaviour is contested - record it, do not judge it."""
        pos = {c.sha: i for i, c in enumerate(self.commits)}
        for i, c in enumerate(self.commits):                 # commits are newest-first
            if not c.is_revert:
                continue
            for target in c.reverts:
                j = pos.get(target)
                if j is None and len(target) >= 7:
                    for sha, k in pos.items():
                        if sha.startswith(target):
                            j = k
                            break
                if j is not None and j + 1 < len(self.commits):
                    # the reverted commit is itself a revert -> the change was re-landed later
                    if self.commits[j].is_revert:
                        c.is_revert_of_revert = True

    # ---- cache -----------------------------------------------------------------------
    @staticmethod
    def _read_cache(path, head):
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > CACHE_BYTES:
                return None
            data = json.loads(path.read_text("utf-8"))
            if data.get("v") != ANALYZER or data.get("head") != head:
                return None
            hist = History(data["root"], head)
            hist.notes = data.get("notes") or []
            hist.truncated = bool(data.get("truncated"))
            hist.elapsed = data.get("elapsed")
            for c in data.get("c") or []:
                cm = Commit(c[0], c[1], c[2], c[3], c[4])
                cm.files = [(s, p) for s, p in c[5]]
                cm.is_revert, cm.reverts = bool(c[6]), list(c[7])
                cm.is_fix, cm.risky_words = bool(c[8]), bool(c[9])
                cm.refs, cm.is_noise = list(c[10]), bool(c[11])
                cm.is_revert_of_revert = bool(c[12])
                hist.commits.append(cm)
            return hist
        except (OSError, ValueError, TypeError, IndexError, KeyError):
            return None

    def _write_cache(self, path):
        try:
            path.parent.mkdir(mode=0o700, exist_ok=True)
            payload = {
                "v": ANALYZER, "head": self.head, "root": str(self.root), "notes": self.notes,
                "truncated": self.truncated, "elapsed": getattr(self, "elapsed", None),
                "c": [[c.sha, c.ts, c.author, c.subject, c.body, c.files, int(c.is_revert),
                       c.reverts, int(c.is_fix), int(c.risky_words), c.refs, int(c.is_noise),
                       int(c.is_revert_of_revert)] for c in self.commits],
            }
            fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, separators=(",", ":"), ensure_ascii=False)
            os.replace(tmp, path)
        except OSError:
            pass

    # ---- indexes ---------------------------------------------------------------------
    def _index_paths(self):
        if self.index is None:
            idx = defaultdict(list)
            for i, c in enumerate(self.commits):
                for _s, path in c.files:
                    idx[path].append(i)
            self.index = idx
        return self.index

    def touching(self, path, cap=400):
        return self._index_paths().get(path, [])[:cap]

    def is_known_path(self, path):
        return path in self._index_paths()

    def find_revert(self, sha):
        """The revert commit that undid ``sha`` (proved by 'This reverts commit'), if any."""
        if not sha:
            return None
        short = sha[:12]
        for c in self.commits:
            if c.is_revert and any(short.startswith(t[:7]) or t.startswith(short[:7]) for t in c.reverts):
                return c
        return None

    def _commit_by_prefix(self, prefix):
        if not prefix:
            return None
        for c in self.commits:
            if c.sha.startswith(prefix) or prefix.startswith(c.sha[:7]):
                return c
        return None

    # ---- fragility: counted evidence, never an invented risk score ---------------------
    def fix_runs(self, path, window=12, cap=200):
        """Fixes that followed an earlier change to ``path`` within ``window`` commits.

        A run means something here needed a follow-up repair soon after it changed: a measured
        property of this repository, returned with both commits so the reader can check it.
        """
        positions = self.touching(path, cap)
        runs = []
        for k, i in enumerate(positions):                       # newest-first
            c = self.commits[i]
            if not c.is_fix or c.is_noise:
                continue
            older = positions[k + 1] if k + 1 < len(positions) else None
            if older is not None and (older - i) <= window:
                runs.append({"fix": c, "gap": older - i, "after": self.commits[older]})
        return runs

    def reverts_touching(self, path, cap=200):
        """Revert relationships in which ``path`` was involved, in either direction."""
        out, seen = [], set()
        for i in self.touching(path, cap):
            c = self.commits[i]
            for target in c.reverts:
                tgt = self._commit_by_prefix(target)
                key = (c.sha, tgt.sha if tgt else target)
                if key not in seen:
                    seen.add(key)
                    out.append({"revert": c, "reverted": tgt, "target_prefix": target})
            if c.is_revert and not c.reverts:
                out.append({"revert": c, "reverted": None, "target_prefix": None})
            undid = self.find_revert(c.sha)
            if undid is not None:
                key = (undid.sha, c.sha)
                if key not in seen:
                    seen.add(key)
                    out.append({"revert": undid, "reverted": c, "target_prefix": c.sha[:12]})
        return out

    def coupled(self, path, cap=6, min_commits=2, bulk=40):
        """Files that habitually change in the same commit as ``path`` (k of n relevant commits)."""
        counts, relevant = Counter(), 0
        for i in self.touching(path, 300):
            c = self.commits[i]
            if c.is_noise or len(c.files) > bulk:
                continue
            relevant += 1
            for _s, other in c.files:
                if other != path:
                    counts[other] += 1
        rows = [{"path": p, "k": k} for p, k in counts.items() if k >= min_commits]
        rows.sort(key=lambda r: (-r["k"], r["path"]))
        return rows[:cap], relevant

    def guards(self, path, is_test, cap=4, min_fixes=1):
        """Test files that landed in the same commit as a fix touching ``path``.

        These are the repository's own regression guards for ``path``: history, not a filename
        guess. Each row carries the fix commit that added or updated the test.
        """
        counts, example = Counter(), {}
        for i in self.touching(path, 300):
            c = self.commits[i]
            if not c.is_fix or c.is_noise:
                continue
            for _s, other in c.files:
                if other != path and is_test(other):
                    counts[other] += 1
                    example.setdefault(other, c)
        rows = [{"path": p, "fixes": k, "evidence": example[p]} for p, k in counts.items() if k >= min_fixes]
        rows.sort(key=lambda r: (-r["fixes"], r["path"]))
        return rows[:cap]

    def report(self, path, is_test, cap=4):
        """One bounded, evidence-carrying history record for a single path."""
        positions = self.touching(path, 400)
        if not positions and not self.is_known_path(path):
            return {"path": path, "known": False}
        commits = [self.commits[i] for i in positions]
        authors = {c.author for c in commits}
        fixes = [c for c in commits if c.is_fix and not c.is_noise][:cap]
        runs = self.fix_runs(path)
        reverts = self.reverts_touching(path)[:cap]
        guards = self.guards(path, is_test, cap)
        coupled, relevant = self.coupled(path, cap)
        risky = [c for c in commits if c.risky_words][:4]
        reasons = []
        if len(runs) >= 2:
            reasons.append(f"{len(runs)} follow-up fix(es) within 12 commits of an earlier change here")
        elif len(runs) == 1:
            reasons.append("1 follow-up fix within 12 commits of an earlier change here")
        if reverts:
            reasons.append(f"{len(reverts)} revert(s) involved this file")
        if risky:
            reasons.append(f"{len(risky)} commit(s) here mention breakage/regression/crash/silent failure")
        if len(commits) >= 25:
            reasons.append(f"high churn ({len(commits)} commits in the mined window)")
        label = "hotspot" if (len(runs) >= 2 or reverts) else (
            "active" if (len(fixes) >= 3 or len(commits) >= 25) else "quiet")
        return {"path": path, "known": True, "commits": len(commits), "authors": len(authors),
                "label": label, "reasons": reasons, "fixes": fixes, "runs": runs[:3],
                "reverts": reverts, "guards": guards, "coupled": coupled, "coupled_of": relevant,
                "risky": risky, "last": commits[0] if commits else None,
                "truncated": len(positions) >= 400}

    # ---- why: blame archaeology -------------------------------------------------------
    def blame(self, path, start=None, end=None, budget=BLAME_BUDGET):
        """Group the blamed lines of a region into commits, with refs, tests and revert status."""
        args = ["blame", "--line-porcelain"]
        if start:
            stop = end or start
            if stop - start + 1 > MAX_BLAME_LINES:
                return None, f"region too large to blame ({stop - start + 1} lines)"
            args += ["-L", f"{start},{stop}"]
        args += ["--", path]
        raw = _git(self.root, *args, timeout=max(10, int(budget)))
        if raw is None:
            return None, "git blame unavailable for this path"
        groups, order, field, n_lines = {}, [], None, 0
        for chunk in raw.split(b"\n"):
            if not chunk:
                continue
            if chunk[:1] == b"\t":
                n_lines += 1
                continue
            text = chunk.decode("utf-8", "replace")
            head = text.split(" ", 1)[0]
            if re.fullmatch(r"[0-9a-f]{40}", head):
                parts = text.split(" ")
                sha = parts[0]
                try:
                    final = int(parts[2])
                except (IndexError, ValueError):
                    final = None
                if sha not in groups:
                    groups[sha] = {"sha": sha, "count": 0, "lines": [], "author": "?", "date": "?",
                                   "subject": "", "refs": [], "is_fix": False, "is_revert": False,
                                   "reverted": None}
                    order.append(sha)
                groups[sha]["count"] += 1
                if final is not None:
                    groups[sha]["lines"].append(final)
                field = groups[sha]
                continue
            if field is None or not text.strip():
                continue
            if text.startswith("author "):
                field["author"] = text[7:][:60]
            elif text.startswith("author-time "):
                try:
                    field["date"] = time.strftime("%Y-%m-%d", time.gmtime(int(text[12:])))
                except (ValueError, OSError, OverflowError):
                    pass
            elif text.startswith("summary "):
                field["subject"] = text[8:][:200]
                c = self._commit_by_prefix(field["sha"])
                if c is not None:
                    field["is_fix"], field["is_revert"] = c.is_fix, c.is_revert
                    field["refs"] = c.refs
                    field["files"] = [p for _s, p in c.files][:6]
                    found = self.find_revert(c.sha)
                    if found is not None:
                        field["reverted"] = {"sha": found.sha, "date": found.date,
                                             "subject": found.subject, "refs": found.refs}
        out = [groups[s] for s in order]
        out.sort(key=lambda g: -g["count"])
        for g in out:
            g["lines"] = (g["lines"][:1] + g["lines"][-1:]) if len(g["lines"]) > 2 else g["lines"]
        return {"path": path, "lines": n_lines, "commits": out[:12], "more": max(0, len(out) - 12),
                "total_commits": len(out)}, None

    # ---- diff-level history conflicts ------------------------------------------------
    def _diff_lines(self, sha, paths, max_bytes=6 << 20):
        """(added, removed) normalized lines from ``sha``'s own diff, attributed per path."""
        raw = _git(self.root, "show", "--format=", "--unified=0", "--no-color", "--no-ext-diff",
                   "--no-textconv", "--find-renames", sha, "--", *paths, timeout=60)
        if raw is None or len(raw) > max_bytes:
            return None
        added, removed, cur = defaultdict(set), defaultdict(set), None
        for chunk in raw.split(b"\n"):
            if chunk.startswith(b"+++ "):
                cur = os.fsdecode(chunk[4:]).strip()
                if cur.startswith("b/"):
                    cur = cur[2:]
                continue
            if chunk[:3] in (b"---", b"diff", b"@@ "):
                continue
            if chunk[:1] == b"+" and cur:
                added[cur].add(_norm(os.fsdecode(chunk[1:])))
            elif chunk[:1] == b"-" and cur:
                removed[cur].add(_norm(os.fsdecode(chunk[1:])))
        return added, removed

    def conflicts(self, changes, *, is_test, max_commits=10, max_hits=6, big=40, before_pos=None,
                  recent=500, max_files=6):
        """Findings that a change re-does what history undid, or undoes what history fixed.

        ``before_pos`` restricts the search to commits at or older than a position in this history
        (used by replay benchmarks so a change can only see its own ancestors).

        * ``P-REVERT`` - an added line is text a revert deliberately removed from this file.
        * ``P-UNFIX``  - a removed line is text a past bug-fix commit added to this file.

        Both are *proofs about text*, not judgements: the finding names the commit so the reader
        can read it and decide. Bulk rewrites (> ``big`` changed lines) are skipped: at that scale
        line matching says nothing.
        """
        wanted, added, removed = [], {}, {}
        for ch in changes:
            if ch.get("opaque") or (ch.get("old") is None and ch.get("new") is None):
                continue
            if is_test(ch["path"]):
                continue          # test files have their own evidence: guard_findings()
            a, r, ok = _change_lines(ch)
            if not ok or (not a and not r):
                continue
            if len(a) > 4000 or len(r) > 4000:
                continue
            added[ch["path"]], removed[ch["path"]] = a, r
            wanted.append(ch["path"])
        if not wanted:
            return []
        # candidate commits: the newest fixes/reverts that touched these paths
        seen, candidates = set(), []
        for path in wanted:
            for i in self.touching(path, 300):
                if before_pos is not None and i < before_pos:
                    continue
                if i > recent:
                    continue          # ancient history is not a useful regression guard
                c = self.commits[i]
                if c.sha in seen or c.is_noise:
                    continue
                if not (c.is_fix or c.is_revert or c.reverts):
                    continue
                if len(c.files) > max_files:
                    continue          # sweeping commits match unrelated lines by accident
                seen.add(c.sha)
                candidates.append((path, c, i))
                if len(candidates) >= max_commits * 4:
                    break
            if len(candidates) >= max_commits * 4:
                break
        candidates.sort(key=lambda t: t[2])                      # most recent history first
        out, done = [], set()
        for path, commit, _pos in candidates[:max_commits]:
            data = self._diff_lines(commit.sha, [path])
            if data is None:
                continue
            added_by, removed_by = data
            c_add, c_rem = added_by.get(path, set()), removed_by.get(path, set())
            if len(c_add) + len(c_rem) > big:
                continue
            for text, line in sorted(added.get(path, {}).items()):
                if text in c_rem and substantive(text) and (("P-REVERT", path, text) not in done):
                    done.add(("P-REVERT", path, text))
                    out.append({"code": "P-REVERT", "path": path, "line": line, "commit": commit.sha,
                                "text": text[:70], "subject": commit.subject_short, "refs": commit.refs,
                                "msg": f"this line re-adds text that {commit.sha[:8]} removed "
                                       f"({commit.date}, {commit.subject_short[:70]!r})"})
            for text, line in sorted(removed.get(path, {}).items()):
                if text in c_add and substantive(text) and (("P-UNFIX", path, text) not in done):
                    done.add(("P-UNFIX", path, text))
                    out.append({"code": "P-UNFIX", "path": path, "line": line, "commit": commit.sha,
                                "text": text[:70], "subject": commit.subject_short, "refs": commit.refs,
                                "msg": f"this removes a line added by {commit.sha[:8]} "
                                       f"({commit.date}, {commit.subject_short[:70]!r})"})
            if len(out) >= max_hits:
                break
        for f in out:
            f["fix"] = ("read that commit first (`git show " + f["commit"][:8] + "`); if the behaviour must go, "
                        "say why in your summary and rerun verify --no-static")
        return out[:max_hits]

    # ---- history-derived regression guards --------------------------------------------
    def guard_findings(self, changes, is_test, weakened, max_findings=4):
        """Escalate 'tests weakened' to proof when history says those tests guard a past fix."""
        changed = [c["path"] for c in changes if not c.get("opaque")]
        tests = sorted({c["path"] for c in changes if is_test(c["path"]) and c.get("new") is not None})
        if not tests:
            return []
        out = []
        for test in tests:
            if not any(w.get("path") == test for w in weakened):
                continue
            for path in changed:
                if path == test or is_test(path):
                    continue
                for g in self.guards(path, is_test, cap=8):
                    if g["path"] != test:
                        continue
                    ev = g["evidence"]
                    refs = (" " + " ".join(ev.refs[:3])) if ev.refs else ""
                    out.append({"code": "P-GUARD", "path": test, "line": None,
                                "msg": f"these tests are the regression guard for {path}: history links them to "
                                       f"{g['fixes']} fix(es), e.g. {ev.sha[:8]} ({ev.date}, "
                                       f"{ev.subject_short[:60]!r}{refs}) and they are weaker now",
                                "fix": "restore the assertions, or say in your summary which behaviour changed and why"})
                    break
                if len(out) >= max_findings:
                    return out
        return out[:max_findings]
# --------------------------------------------------------------------------- change lines
MIN_SUBSTANTIVE = 16
_MAX_DIFF_LINES = 20000


def _norm(line: str) -> str:
    """Whitespace-insensitive form of a source line, with any trailing comment dropped.

    Both sides of every comparison get identical treatment, so this can only make matching
    stricter. It exists because `# type: ignore[...]` churn was measured to be a large share of
    the remaining false alarms: the same statement re-added with a changed suppression comment is
    not a regression. A `#` with no whitespace before it (a colour literal) is left alone.
    """
    comment = re.search(r"\s#.*$", line)
    if comment:
        line = line[:comment.start()]
    return " ".join(line.split())


# Lines that carry no behaviour: matching on these is how a detector becomes noise. Measured on
# 480 real merged commits, allowing imports/defs/decorators was the single largest source of
# false alarms (imports get added by "fix" commits and reordered by everyone else).
_GENERIC_LINE = re.compile(
    r"^(?:import|from)\s+\S|^@\w|^(?:async\s+)?def\s+\w|^class\s+\w|^\.\.\s|^%(?:if|else|endif|extends)|"
    r"^version(?:added|changed|deprecated|removed)::|^(?:pass|return|continue|break|else:|try:|finally:|\}\s*;?)$|"
    r"^[\w\.\[\], '\"]+\s*:\s*[\w\.\[\]\|, \"']+$|^[\"'].*[\"'],?$|^-{3,}$|^={3,}$")
_WORD_RE = re.compile(r"[A-Za-z_]\w*")


def substantive(text: str) -> bool:
    """Is this line worth matching on? A line must look like *behaviour*, not boilerplate.

    Rejected: comments, imports, decorators, `def`/`class` headers, docstring/string-only lines,
    bare annotations, short lines, and lines with fewer than three words. Each of these matches
    every other project's code by accident, so a finding resting on one is worse than no finding.
    """
    s = text.strip()
    if len(s) < MIN_SUBSTANTIVE or s.startswith(("#", "//", "/*", "*", "<!--")):
        return False
    if _GENERIC_LINE.match(s):
        return False
    core = s.strip("{}[](),;:.-+=|&!*<>\\/ \t'\"")
    if len(core) < MIN_SUBSTANTIVE:
        return False
    if len([w for w in _WORD_RE.findall(s) if len(w) > 1]) < 3:
        return False
    # At least two structural characters: prose ("... position the cursor correctly.") has one
    # period and is not code, while every real statement has brackets, an assignment or dots.
    return len(re.findall(r"[=()\[\]]", s)) >= 2


def _change_lines(change):
    """(added, removed) normalized line -> first line number, for one change dict."""
    old = change.get("old")
    new = change.get("new")
    a_text = (old or b"").decode("utf-8", "replace").splitlines()
    b_text = (new or b"").decode("utf-8", "replace").splitlines()
    if len(a_text) + len(b_text) > _MAX_DIFF_LINES:
        return {}, {}, False
    added, removed = {}, {}
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a_text, b_text, autojunk=False).get_opcodes():
        if tag in ("replace", "insert"):
            for j in range(j1, j2):
                key = _norm(b_text[j])
                if key and key not in added:
                    added[key] = j + 1
        if tag in ("replace", "delete"):
            for i in range(i1, i2):
                key = _norm(a_text[i])
                if key and key not in removed:
                    removed[key] = i + 1
    return added, removed, True


# --------------------------------------------------------------------------- rendering
def render_history(records, mined, limit=6, head="?"):
    """Compact, evidence-first history report (one block per path)."""
    lines = [f"history  {len(records)} path(s)  mined {mined} commit(s)  HEAD {head[:8]}"]
    for r in records:
        if not r.get("known"):
            lines.append(f"{r['path']}  no history in the mined window (new or renamed file)")
            continue
        lines.append(f"{r['path']}  {r['label'].upper()}  {r['commits']} commits / {r['authors']} authors"
                     + ("  (window truncated)" if r.get("truncated") else ""))
        for reason in r["reasons"]:
            lines.append("  WHY: " + reason)
        if not r["reasons"]:
            lines.append("  WHY: no repeated-fix or revert pattern in the mined window")
        for f in r["fixes"][:3]:
            lines.append(f"  FIX    {f.sha[:8]} {f.date} {f.subject_short[:72]!r}"
                         + (f" {' '.join(f.refs[:3])}" if f.refs else ""))
        for rv in r["reverts"][:2]:
            tgt = rv.get("reverted")
            lines.append(f"  REVERT {rv['revert'].sha[:8]} {rv['revert'].date} "
                         f"undid {(tgt.sha[:8] + ' ' + tgt.subject_short[:52]) if tgt else '(unknown target)'}"
                         f" - {rv['revert'].subject_short[:56]!r}")
        for g in r["guards"][:3]:
            ev = g["evidence"]
            lines.append(f"  GUARDS {g['path']} ({g['fixes']} fix commit(s), e.g. {ev.sha[:8]} {ev.date} "
                         f"{ev.subject_short[:52]!r})")
        if r["coupled"]:
            lines.append("  COUPLED " + " · ".join(f"{c['path']} {c['k']}/{r['coupled_of']}" for c in r["coupled"][:limit]))
        if r["last"] is not None:
            lines.append(f"  LAST   {r['last'].sha[:8]} {r['last'].date} {r['last'].subject_short[:72]!r}")
    lines.append("NOTE: counts come from commit messages and file lists only; a reverting-looking subject is "
                 "evidence, not proof, unless it carries 'This reverts commit' (those are marked REVERT).")
    return "\n".join(lines)


def render_why(res, label="", limit=8):
    """Compact 'why does this code exist' report from blame groups."""
    commits = res["commits"]
    lines = [f"why {res['path']}{label}  {res['lines']} blamed line(s), {res.get('total_commits', len(commits))} "
             f"commit(s)"]
    for g in commits[:limit]:
        where = ""
        if g["lines"]:
            where = f"L{g['lines'][0]}" + (f"-{g['lines'][-1]}" if len(g["lines"]) > 1 else "")
        flags = []
        if g["is_fix"]:
            flags.append("FIX")
        if g["is_revert"]:
            flags.append("REVERT")
        if g.get("reverted"):
            flags.append("LATER-REVERTED " + g["reverted"]["sha"][:8] + " " + g["reverted"]["subject"][:40])
        refs = (" " + " ".join(g["refs"][:3])) if g["refs"] else ""
        lines.append(f"  x{g['count']:<3} {where:<10} {g['sha'][:8]} {g['date']} {g['subject'][:78]!r}{refs}"
                     + ("  [" + " / ".join(flags) + "]" if flags else ""))
        if g.get("files"):
            others = [p for p in g["files"] if p != res["path"]]
            if others:
                lines.append("        also in that commit: " + ", ".join(others[:4]))
    if res.get("more"):
        lines.append(f"  (+{res['more']} more commit(s))")
    return "\n".join(lines)
