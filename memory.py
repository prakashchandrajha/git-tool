#!/usr/bin/env python3
"""Durable, tamper-evident knowledge for AI agents across sessions (stdlib only).

An agent that loses its context re-derives everything it had learned - or worse, re-derives it
wrongly. This module is the honest store that survives a context reset:

* **Facts carry evidence.** Every fact names the commit, file hash, test name or command result
  that justifies it. A fact with no evidence is allowed, but it must say ``confidence:
  hypothesis``, and confidence is never upgraded automatically.
* **Staleness is checked, never assumed.** A fact about ``src/x.py`` is re-checked against the
  file's current hash; a fact about a commit is checked for ancestry of HEAD; a fact about a test
  is checked for that test still existing. Anything that no longer holds comes back ``STALE`` with
  the reason.
* **Contradictions are kept, not resolved.** Two active facts with the same key and different text
  are both marked ``disputed``; a memory that silently overwrites is a memory that lies.
* **Tamper-evident.** The store is HMAC-signed with the same private key as the task receipts.

What it does NOT do: it never claims a fact is true because it is stored, never ranks facts by age
or repetition, and never lets a stale fact be used as if it were fresh.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

SCHEMA = 1
MAX_BYTES = 8 << 20
MAX_FACTS = 2000
KINDS = ("invariant", "guard", "decision", "gotcha", "dependency", "contract", "verified", "todo")
CONFIDENCE = ("proved", "reported", "hypothesis")
TEST_NAME_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test_\w+)", re.M)


class MemoryError_(Exception):
    """Expected, reportable memory failure."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def file_sha256(path):
    """SHA-256 of a file's current bytes, or None when it is missing/unreadable."""
    try:
        with open(path, "rb") as stream:
            hasher = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1 << 16), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return None


def fact_id(kind, key, text):
    core = {"k": kind, "key": key, "t": text}
    return hashlib.sha256(_canonical(core)).hexdigest()[:16]


class Memory:
    """The on-disk fact store. One instance per process; mutate through the methods below."""

    def __init__(self, root, path, key):
        self.root = Path(root)
        self.path = Path(path)
        self.key = key
        self.facts = []
        self.notes = []
        self.loaded_from_disk = False

    # ---- persistence ---------------------------------------------------------------
    @classmethod
    def open(cls, root, key, path=None):
        root = Path(root)
        store = Path(path) if path else root / ".state" / "memory.json"
        mem = cls(root, store, key)
        mem._load()
        return mem

    def _load(self):
        if self.path.is_symlink():
            self.notes.append("memory file is a symlink; refusing to read it")
            return
        if not self.path.is_file():
            return
        try:
            if self.path.stat().st_size > MAX_BYTES:
                self.notes.append("memory file exceeds the size limit; ignoring it")
                return
            record = json.loads(self.path.read_bytes())
            payload = record["payload"]
            mac = hmac.new(self.key, _canonical(payload), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, record["mac"]):
                self.notes.append("memory file failed its integrity check; refusing to trust it")
                return
            if payload.get("schema") != SCHEMA:
                self.notes.append("memory file has an unknown schema version; ignoring it")
                return
            # A toolkit can serve several repositories.  A valid, signed memory from a
            # different repository is still the wrong evidence, so do not accidentally
            # mix their facts if a caller supplied the wrong path.
            if payload.get("root") != str(self.root):
                self.notes.append("memory belongs to a different repository; refusing to mix evidence")
                return
            self.facts = payload.get("facts") or []
            self.loaded_from_disk = True
        except (OSError, ValueError, KeyError, TypeError):
            self.notes.append("memory file is unreadable; starting empty")
            self.facts = []

    def save(self):
        """Atomic, fsynced, HMAC-signed write: never leave a half-written store behind."""
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        if self.path.is_symlink():
            raise MemoryError_("memory path must not be a symlink")
        payload = {"schema": SCHEMA, "root": str(self.root), "facts": self.facts[-MAX_FACTS:]}
        record = {"payload": payload,
                  "mac": hmac.new(self.key, _canonical(payload), hashlib.sha256).hexdigest()}
        fd, tmp = tempfile.mkstemp(prefix=".mem-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(_canonical(record) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ---- writing -------------------------------------------------------------------
    def remember(self, kind, key, text, evidence=(), confidence="reported", tags=(), actor="agent",
                 task=None, now=None):
        """Add one fact. Duplicates are idempotent; contradictions are recorded, not overwritten."""
        kind = (kind or "").strip().lower()
        if kind not in KINDS:
            raise MemoryError_("kind must be one of: " + ", ".join(KINDS))
        confidence = (confidence or "").strip().lower()
        if confidence not in CONFIDENCE:
            raise MemoryError_("confidence must be one of: " + ", ".join(CONFIDENCE))
        text = " ".join((text or "").split())
        if not text:
            raise MemoryError_("a fact needs text")
        if len(text) > 1200:
            raise MemoryError_("fact text is too long (1200 characters max)")
        evidence = [item for item in (evidence or []) if isinstance(item, dict)]
        if not evidence and confidence == "proved":
            raise MemoryError_("confidence 'proved' needs at least one piece of evidence")
        fid = fact_id(kind, key, text)
        for existing in self.facts:
            if existing["id"] == fid and existing.get("status") != "superseded":
                existing["checked"] = self._check(existing)
                return {"fact": existing, "duplicate": True}
        fact = {"id": fid, "kind": kind, "key": (key or "")[:160], "text": text,
                "evidence": evidence[:8], "confidence": confidence,
                "tags": sorted({t for t in tags if t})[:12], "actor": (actor or "agent")[:60],
                "task": task, "created": now or time.time(), "status": "active",
                "superseded_by": None, "history": []}
        self._flag_contradictions(fact)
        self.facts.append(fact)
        return {"fact": fact, "duplicate": False}

    def _flag_contradictions(self, new):
        """Same key, different text, both active: mark both disputed and keep both."""
        for other in self.facts:
            if (other["id"] != new["id"] and other["status"] == "active"
                    and other["kind"] == new["kind"] and other["key"] == new["key"]
                    and other["text"] != new["text"]):
                for victim in (other, new):
                    if victim["status"] != "disputed":
                        victim["status"] = "disputed"
                        victim.setdefault("history", []).append(
                            {"at": time.time(), "what": "disputed by " + new["id"]})

    def forget(self, fid, reason="", actor="agent"):
        """Supersede a fact; it stays in the store as an audit trail."""
        for fact in self.facts:
            if fact["id"] == fid or fact["id"].startswith(fid):
                if fact["status"] == "superseded":
                    return {"fact": fact, "already": True}
                fact["status"] = "superseded"
                fact["superseded_by"] = ((actor + ": " + reason) if reason else actor)[:200]
                fact.setdefault("history", []).append(
                    {"at": time.time(), "what": "superseded: " + reason[:120]})
                return {"fact": fact, "already": False}
        raise MemoryError_("no fact with id " + fid)

    # ---- verification --------------------------------------------------------------
    def _git(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
        try:
            proc = subprocess.run(["git", "--no-pager", *args], cwd=str(self.root), env=env,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout if proc.returncode == 0 else None

    def _check_commit(self, sha):
        if not sha:
            return "stale: no commit recorded"
        if self._git("merge-base", "--is-ancestor", sha, "HEAD") is not None:
            return "fresh"
        exists = self._git("cat-file", "-e", str(sha) + "^{commit}")
        if exists is not None:
            return "stale: that commit is not an ancestor of HEAD (history was rewritten?)"
        return "stale: that commit does not exist any more"

    def _check_file(self, path, sha):
        current = file_sha256(self.root / path)
        if current is None:
            return "stale: " + str(path) + " no longer exists"
        if sha and current != sha:
            return "stale: " + str(path) + " has changed since this was recorded"
        return "fresh"

    def _check_test(self, path, name):
        try:
            data = (self.root / path).read_text("utf-8", "replace")
        except OSError:
            return "stale: " + str(path) + " is gone"
        if name and name not in set(TEST_NAME_RE.findall(data)):
            return "stale: test " + str(name) + " is no longer in " + str(path)
        return "fresh"

    def _check(self, fact, now=None):
        """Re-verify a fact's evidence against the current worktree. Never raises."""
        detail, worst = [], "fresh"
        for evidence in fact.get("evidence") or []:
            kind = evidence.get("type")
            if kind == "commit":
                status = self._check_commit(evidence.get("sha"))
            elif kind == "file":
                status = self._check_file(evidence.get("path", ""), evidence.get("sha256"))
            elif kind == "test":
                status = self._check_test(evidence.get("path", ""), evidence.get("name", ""))
            elif kind == "command":
                status = "unverified: a past command result cannot be re-checked without running it"
            else:
                status = "unknown evidence type"
            detail.append({"type": kind, "status": status})
            if status.startswith("stale"):
                worst = "stale"
            elif status.startswith("unverified") and worst == "fresh":
                worst = "unverified"
        return {"at": now or time.time(), "result": worst, "detail": detail}

    def recall(self, tags=(), kinds=(), query=None, key=None, limit=8, include_stale=True,
               include_superseded=False, recheck=True, now=None):
        """Fresh facts first, each with its evidence, confidence and staleness verdict."""
        want_tags = {t.lower() for t in tags}
        want_kinds = {k.lower() for k in kinds}
        needle = (query or "").lower().strip()
        rows = []
        for fact in self.facts:
            if fact["status"] == "superseded" and not include_superseded:
                continue
            if want_kinds and fact["kind"] not in want_kinds:
                continue
            if key and fact["key"] != key:
                continue
            if want_tags and not want_tags.issubset({t.lower() for t in fact.get("tags") or []}):
                continue
            haystack = fact["text"] + " " + fact["key"] + " " + " ".join(fact["tags"])
            if needle and needle not in haystack.lower():
                continue
            checked = self._check(fact, now) if recheck else (fact.get("checked") or {"result": "unchecked"})
            fact["checked"] = checked
            if checked["result"] == "stale" and not include_stale:
                continue
            row = dict(fact)
            row["checked"] = checked
            rows.append(row)
        order = {"fresh": 0, "unverified": 1, "unknown": 2, "unchecked": 2, "stale": 3}
        rows.sort(key=lambda r: (order.get(r["checked"]["result"], 4), -r["created"]))
        return rows[:limit]

    def stats(self, now=None):
        counts, stale = {}, 0
        for fact in self.facts:
            counts[fact["status"]] = counts.get(fact["status"], 0) + 1
            if self._check(fact, now)["result"] == "stale":
                stale += 1
        return {"facts": len(self.facts), "by_status": counts, "stale": stale,
                "path": str(self.path), "notes": self.notes}


# --------------------------------------------------------------------------- rendering
def _ago(ts, now=None):
    delta = max(0, int((now or time.time()) - float(ts or 0)))
    if delta < 3600:
        return str(delta // 60) + "m"
    if delta < 86400:
        return str(delta // 3600) + "h"
    return str(delta // 86400) + "d"


def render_recall(rows, now=None, limit=8):
    if not rows:
        return "recall  nothing remembered matches (an empty memory is not evidence of safety)"
    lines = ["recall  " + str(len(rows)) + " fact(s)"]
    for fact in rows[:limit]:
        verdict = fact["checked"]["result"].upper()
        lines.append("[" + verdict + "] " + fact["id"] + " " + fact["kind"] + "/" + (fact["key"] or "-")
                     + " (" + fact["confidence"] + ", " + _ago(fact["created"], now) + " ago, "
                     + fact["actor"] + ")"
                     + ("  DISPUTED" if fact["status"] == "disputed" else ""))
        lines.append("    " + fact["text"][:300])
        for detail in fact["checked"].get("detail", []):
            if detail["status"] != "fresh":
                lines.append("    ! " + detail["status"])
        for evidence in fact["evidence"]:
            kind = evidence.get("type")
            if kind == "commit":
                lines.append("    evidence: commit " + str(evidence.get("sha"))[:8] + " "
                             + str(evidence.get("subject") or "")[:60])
            elif kind == "file":
                lines.append("    evidence: file " + str(evidence.get("path")) + " sha:"
                             + str(evidence.get("sha256"))[:8])
            elif kind == "test":
                lines.append("    evidence: test " + str(evidence.get("name")) + " in "
                             + str(evidence.get("path")))
            elif kind == "command":
                argv = " ".join(str(a) for a in (evidence.get("argv") or []))[:80]
                lines.append("    evidence: command " + argv + " -> " + str(evidence.get("result")))
    if len(rows) > limit:
        lines.append("(+" + str(len(rows) - limit) + " more)")
    lines.append("NOTE: a stored fact is not a verified fact; act on FRESH facts backed by proof, "
                 "re-check STALE ones, and never let 'hypothesis' become a decision.")
    return "\n".join(lines)
