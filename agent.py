#!/usr/bin/env python3
"""In-place task receipts + blast-radius intelligence for AI coding agents (stdlib only).

Kernel: reserves exact paths in the current worktree, runs only the JSON argv checks the agent
declares, and re-snapshots watched paths before/after each check.  ``CHECKS_PASSED`` means only
that those commands passed without changing the watched state - not code correctness, review
approval or a sandbox.  An authorized check can still touch the network or external files.

It never creates a branch, worktree, clone, commit, reset or stash.  The only automatic writes
go to the private ``.state`` directory.  ``restore`` is the one command that writes project
files: explicit, only to a task's recorded baseline, current content backed up first.
Credentials, databases, logs, runtime data, symlinks and special files are never read.

Intelligence (pyintel.py): ``brief`` before editing, ``review`` after, ``outline``/``slice`` to
read less, ``diff`` for your own changes only, ``guard`` as an edit-time scope check.
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import hmac
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

try:  # POSIX
    import fcntl
except ImportError:  # Windows
    fcntl = None

VERSION = "2.2"
IS_WIN = os.name == "nt"
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_BINARY = getattr(os, "O_BINARY", 0)

TOOLKIT = Path(__file__).resolve().parent
STATE = TOOLKIT / ".state"
BLOBS = STATE / "blobs"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
MEMORY_NAME = re.compile(r"memory\.[0-9a-f]{16}\.json\Z")
PRUNE = {".venv", ".venv_test", "venv", "env", "node_modules", "build", "dist",
         "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
         ".tox", ".nox", "coverage", ".cache", "htmlcov"}
PRIVATE_DIRS = {"logs", "runtime", "data", "database", ".ssh", ".aws",
                ".gnupg", ".kube"}
# Ephemeral/tooling trees: contents are never evidence and are never read.
GENERATED_DIRS = PRUNE | {".agents", ".omnirush", ".kilo", "scratch", "research", ".idea", ".vscode",
                          ".gradle", ".next", ".nuxt", ".terraform", ".turbo", ".svelte-kit",
                          ".parcel-cache", ".ipynb_checkpoints", ".eggs", ".dart_tool", ".angular",
                          ".serverless", ".docusaurus"}
PRIVATE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".log", ".pid", ".lock", ".pem",
                    ".key", ".p12", ".pfx", ".csv", ".parquet", ".pkl", ".pickle",
                    ".zip", ".gz", ".so", ".pyc", ".pyo", ".shm"}
# Dependency lockfiles are plain source-like text, not runtime locks.
LOCKFILES = {"poetry.lock", "pipfile.lock", "uv.lock", "cargo.lock", "yarn.lock", "pdm.lock",
             "gemfile.lock", "composer.lock", "flake.lock", "bun.lock"}
MAX_FILE, MAX_TOTAL, MAX_ENTRIES = 16 << 20, 256 << 20, 50000
MAX_STATUS_BYTES, TAIL = 16 << 20, 8192
MAX_BLOBS = 64 << 20
SOURCE_SUFFIXES = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".c", ".h", ".cc",
                   ".cpp", ".hpp", ".rs", ".go", ".java", ".rb", ".sh", ".sql"}
POLICY = {"ignored_dirs": "scan", "protect": ["tests/invariants"]}
POLICY_ERROR = None
_MODULES = {}


def _apply_policy():
    """Optional per-project overrides in agentussagefolder/policy.json (unknown keys are errors)."""
    global POLICY_ERROR
    path = TOOLKIT / "policy.json"
    try:
        if path.is_symlink() or not path.is_file():
            return
        data = json.loads(path.read_text("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("root must be a JSON object")
        known = {"private_dirs_add", "private_dirs_remove", "private_suffixes_add", "private_suffixes_remove",
                 "generated_dirs_add", "protect", "ignored_dirs"}
        for key, value in data.items():
            if key.startswith("_"):
                continue
            if key not in known:
                raise ValueError(f"unknown key {key!r}; known: {', '.join(sorted(known))}")
            if key == "ignored_dirs":
                if value not in ("scan", "block"):
                    raise ValueError("ignored_dirs must be 'scan' or 'block'")
                POLICY[key] = value
                continue
            if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
                raise ValueError(f"{key} must be a list of non-empty strings")
            if key == "protect":
                POLICY["protect"] = [x.strip("/") for x in value]
            elif key.startswith("private_dirs"):
                (PRIVATE_DIRS.update if key.endswith("add") else PRIVATE_DIRS.difference_update)(x.lower() for x in value)
            elif key.startswith("private_suffixes"):
                fixed = [x.lower() if x.startswith(".") else "." + x.lower() for x in value]
                (PRIVATE_SUFFIXES.update if key.endswith("add") else PRIVATE_SUFFIXES.difference_update)(fixed)
            else:
                GENERATED_DIRS.update(value)
    except (OSError, ValueError) as exc:
        POLICY_ERROR = f"policy.json invalid: {exc}"


_apply_policy()


class Blocked(Exception):
    pass


def load_module(name):
    if name not in _MODULES:
        spec = importlib.util.spec_from_file_location("agentussage_" + name, TOOLKIT / f"{name}.py")
        if spec is None or spec.loader is None:
            raise Blocked(f"toolkit file missing: {name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _MODULES[name] = module
    return _MODULES[name]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def guard(info):
    return [info.st_mode, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def file_hash(path, maximum=MAX_FILE):
    """Never use a stat-based content cache; reject races and symlink reads."""
    fd = os.open(path, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_BINARY)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise Blocked(f"unsupported file size/type: {path}")
        hasher, count = hashlib.sha256(), 0
        for chunk in iter(lambda: stream.read(65536), b""):
            count += len(chunk)
            if count > maximum:
                raise Blocked(f"file grew past snapshot limit: {path}")
            hasher.update(chunk)
        after = os.fstat(stream.fileno())
    if guard(before) != guard(after):
        raise Blocked(f"file changed while hashing: {path}")
    return hasher.hexdigest()


def read_regular(path, maximum=MAX_FILE):
    fd = os.open(path, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_BINARY)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise Blocked(f"unsupported file size/type: {path}")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(data) > maximum or guard(before) != guard(after):
        raise Blocked(f"file changed while reading: {path}")
    return data


def _read_opt(path):
    try:
        return read_regular(path)
    except (Blocked, OSError):
        return None


def environment():
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GIT_"):
            del env[key]
    env.update(GIT_OPTIONAL_LOCKS="0", PYTHONDONTWRITEBYTECODE="1")
    env["PYTEST_ADDOPTS"] = env.get("PYTEST_ADDOPTS", "") + " -p no:cacheprovider"
    return env


def git(root, *args, data=None, allowed=(0,)):
    try:
        result = subprocess.run(["git", "--no-pager", "-c",
                                 "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
                                cwd=root, input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment(), timeout=30, check=False)
    except subprocess.TimeoutExpired:
        raise Blocked("git " + args[0] + " timed out") from None
    if len(result.stdout) > MAX_STATUS_BYTES:
        raise Blocked("Git result exceeds the bounded output limit")
    if result.returncode not in allowed:
        raise Blocked("git " + args[0] + " failed: " +
                      result.stderr.decode(errors="replace").strip()[:300])
    return result.stdout


def git_blob(root, rev, rel):
    if not rev or rev == "UNBORN":
        return None
    try:
        result = subprocess.run(["git", "--no-pager", "cat-file", "blob", f"{rev}:{rel}"], cwd=root,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment(),
                                timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 and len(result.stdout) <= MAX_FILE else None


def ignored(root, names):
    if not names:
        return set()
    output = git(root, "check-ignore", "--no-index", "-z", "--stdin",
                 data=b"\0".join(os.fsencode(x) for x in names) + b"\0", allowed=(0, 1))
    return {os.fsdecode(x) for x in output.split(b"\0") if x}


def private(path):
    parts, name = Path(path).parts, Path(path).name.lower()
    # src/database is source, whereas top-level/project database trees are data.
    data_dir = any(p.lower() in PRIVATE_DIRS and
                   not (p.lower() == "database" and i and parts[i - 1].lower() == "src")
                   for i, p in enumerate(parts[:-1]))
    if name in LOCKFILES:
        return data_dir
    return (data_dir or name in {".kite_session", ".netrc", ".npmrc", ".pypirc",
                                "credentials", "credentials.json",
                                "secrets.json", "secrets.yml", "secrets.yaml"}
            or name.startswith(("id_rsa", "id_ed25519", "id_ecdsa"))
            or (name.startswith(".env") and name not in
                {".env.example", ".env.sample", ".env.template"})
            or Path(name).suffix in PRIVATE_SUFFIXES
            or any(name.endswith(x) for x in (".db-wal", ".db-shm", ".sqlite-wal")))


def git_state(root):
    entries = git(root, "ls-files", "--stage", "-v", "-z")
    if any(record[:1].islower() for record in entries.split(b"\0") if record):
        raise Blocked("assume-unchanged tracked files are unsupported; clear the flag first")
    if any(record[2:].startswith(b"160000 ") for record in entries.split(b"\0")):
        raise Blocked("submodules require their own verified boundary; unsupported here")
    if git(root, "ls-files", "--unmerged", "-z"):
        raise Blocked("unmerged index entries must be resolved first")
    head = git(root, "rev-parse", "--verify", "-q", "HEAD", allowed=(0, 1)).decode().strip() or "UNBORN"
    return {"head": head,
            "ref": git(root, "symbolic-ref", "-q", "HEAD", allowed=(0, 1)).decode().strip(),
            "index": hashlib.sha256(entries).hexdigest()}


def _status_paths(root, boundary=None):
    """Return Git's changed paths without walking clean or ignored trees."""
    raw = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all",
              "--ignored=matching", "--ignore-submodules=none")
    if len(raw) > MAX_STATUS_BYTES:
        raise Blocked("too many changed paths for a bounded receipt")
    boundary_rel = None
    if boundary is not None:
        boundary_rel = Path(boundary).relative_to(root).as_posix().rstrip("/")
        if boundary_rel == ".":
            boundary_rel = ""
    records, index = [], 0
    parts = raw.split(b"\0")
    while index < len(parts):
        item = parts[index]
        index += 1
        if not item:
            continue
        if len(item) < 4 or item[2:3] != b" ":
            raise Blocked("Git returned an unsupported porcelain status record")
        code, encoded = os.fsdecode(item[:2]), os.fsdecode(item[3:])
        records.append((code, encoded))
        if code[0] in "RC" or code[1] in "RC":
            if index >= len(parts) or not parts[index]:
                raise Blocked("Git returned an incomplete rename record")
            records.append((code, os.fsdecode(parts[index])))
            index += 1
    if boundary_rel:
        records = [(code, rel) for code, rel in records
                   if rel == boundary_rel or rel.startswith(boundary_rel + "/")]
    if len(records) > MAX_ENTRIES:
        raise Blocked("changed-path limit exceeded")
    return records


def _opaque(path):
    info = path.lstat()
    return {"kind": "opaque", "guard": guard(info), "mode": stat.S_IMODE(info.st_mode)}


def _state_relative(root):
    try:
        return STATE.relative_to(root).as_posix()
    except ValueError:
        return None


def _ignored_dir(root, path, rel):
    """Unknown ignored directory: strict mode blocks; default mode only cares if it hides source."""
    if POLICY["ignored_dirs"] == "block":
        raise Blocked("ignored directory is not an approved generated/private tree: " + rel)
    if (path / "pyvenv.cfg").exists() or rel.endswith(".egg-info"):
        return None
    found, seen, stack = [], 0, [(path, 0)]
    while stack and seen < 2000 and not found:
        folder, depth = stack.pop()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    seen += 1
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if depth < 4 and entry.name not in GENERATED_DIRS:
                            stack.append((Path(entry.path), depth + 1))
                    elif Path(entry.name).suffix.lower() in SOURCE_SUFFIXES:
                        found.append(entry.path)
        except OSError:
            continue
    if not found:
        return None  # source-free ignored tree (IDE/tool state): never evidence, never read
    result = _opaque(path)
    result["reason"] = "ignored tree containing source (not evidence, not read)"
    return {"code": "!!", **result}


def _path_record(root, code, rel):
    """Hash one changed path; never read private, generated, symlink or special data."""
    rel = rel.rstrip("/") if rel not in ("", ".") else rel
    if not rel or rel == "." or rel == ".git" or rel.startswith(".git/"):
        raise Blocked("Git returned an unsafe changed path")
    state_rel = _state_relative(root)
    if state_rel and (rel == state_rel or rel.startswith(state_rel + "/")):
        return None
    path = root / rel
    try:
        info = path.lstat()
    except FileNotFoundError:
        if private(rel):
            return {"code": code, "kind": "opaque", "reason": "private/runtime deletion"}
        return {"code": code, "kind": "deleted"}
    parts = set(Path(rel).parts)
    if code == "!!" and (parts & GENERATED_DIRS or rel.endswith(".egg-info")):
        return None
    if stat.S_ISDIR(info.st_mode):
        if code == "!!":
            if private(rel) or Path(rel).name in PRIVATE_DIRS:
                result = _opaque(path)
                result["reason"] = "private/runtime tree"
                return {"code": code, **result}
            return _ignored_dir(root, path, rel)
        return {"code": code, "kind": "directory", "guard": guard(info)}
    if code == "!!" and path.suffix.lower() in SOURCE_SUFFIXES:
        if POLICY["ignored_dirs"] == "block":
            raise Blocked("ignored executable source is outside the evidence boundary: " + rel)
        result = _opaque(path)
        result["reason"] = "ignored source file (not evidence, not read)"
        return {"code": code, **result}
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return {"code": code, "kind": "opaque", "guard": guard(info), "reason": "symlink/special"}
    if private(rel):
        result = _opaque(path)
        result["reason"] = "private/runtime file"
        return {"code": code, **result}
    if info.st_size > MAX_FILE:
        raise Blocked("changed file exceeds snapshot limit: " + rel)
    return {"code": code, "kind": "file", "mode": stat.S_IMODE(info.st_mode),
            "sha256": file_hash(path)}


def snapshot(root, boundary=None):
    """Snapshot Git state and only paths Git says are changed.

    Clean source files are protected by HEAD/index; dirty files alone are freshly hashed.
    """
    before = git_state(root)
    files = {}
    for code, rel in _status_paths(root, boundary):
        record = _path_record(root, code, rel)
        if record is not None:
            files[rel.rstrip("/")] = record
    after = git_state(root)
    if before != after:
        raise Blocked("HEAD/index changed during snapshot")
    return {"git": after, "files": files}


def contains(spec, rel):
    return (rel == spec["path"] or spec["directory"] and
            (not spec["path"] or rel.startswith(spec["path"] + "/")))


def validate_path(project, root, text):
    raw = Path(text)
    if (not text or raw.is_absolute() or ".." in raw.parts or
            any(c in text for c in "*?[]{}\0") or ".git" in raw.parts):
        raise Blocked(f"invalid relative literal path: {text!r}")
    path = project / raw
    try:
        path.relative_to(root)
    except ValueError:
        raise Blocked(f"target is outside the Git root: {text}") from None
    for ancestor in [path, *path.parents]:
        if ancestor == root:
            break
        if ancestor.is_symlink():
            raise Blocked(f"symlink target: {text}")
    rel = path.relative_to(root).as_posix().rstrip("/")
    if rel == ".":
        rel = ""
    state_rel = STATE.relative_to(root).as_posix() if STATE.is_relative_to(root) else None
    if ((state_rel and (rel == state_rel or rel.startswith(state_rel + "/"))) or
            STATE in path.parents or private(rel) or path.name in PRIVATE_DIRS):
        raise Blocked(f"private/runtime target: {text} "
                      "(if this is real source/fixture, ask the user to allow it in agentussagefolder/policy.json)")
    if rel in ignored(root, [rel] if rel else []):
        raise Blocked(f"ignored target: {text}")
    if path.exists() and not (path.is_file() or path.is_dir()):
        raise Blocked(f"unsupported target: {text}")
    return {"path": rel, "directory": path.is_dir() or text.endswith("/") or text == "."}


def protections(project, root, extra):
    specs = [validate_path(project, root, item) for item in extra]
    for item in POLICY["protect"]:  # protect these even when not yet created
        specs.append({"path": (project / item).relative_to(root).as_posix(), "directory": True})
    return sorted({canonical(x): x for x in specs}.values(), key=lambda x: x["path"])


def problems(plan, current):
    reasons, baseline = [], plan["baseline"]
    if current["git"] != baseline["git"]:
        reasons.append("initial HEAD/ref/index changed")
    for rel in sorted(baseline["files"].keys() | current["files"].keys()):
        old, new = baseline["files"].get(rel), current["files"].get(rel)
        if old == new:
            continue
        if any(contains(p, rel) for p in plan["protect"]) or "/tests/invariants/" in "/" + rel + "/":
            reasons.append("protected path changed: " + rel)
        elif any(x and x["kind"] in {"opaque", "unsupported"} for x in (old, new)):
            reasons.append("unsupported/private/runtime delta: " + rel)
        elif not any(contains(s, rel) for s in plan["scope"]):
            reasons.append("outside-scope delta (baseline dirty files included): " + rel)
    if plan["unknown"]:
        reasons.append("unresolved unknown claims: " + "; ".join(plan["unknown"]))
    return reasons


HINTS = (
    ("outside-scope delta", "agent.py restore --task {t} {p}; or, if it is a legitimate dependent of your change, "
                            "agent.py widen --task {t} {p}"),
    ("protected path changed", "agent.py restore --task {t} {p}; protected paths are never editable"),
    ("initial HEAD/ref/index changed", "git state moved (commit/checkout/stage); agent.py abandon --task {t}, begin again"),
    ("unsupported/private/runtime delta", "a private/runtime file changed; agent.py restore --task {t} {p}; never edit data/logs/.env"),
    ("unresolved unknown claims", "resolve the --unknown claim(s), then begin again"),
    ("proof debt:", "run `agent.py proof --task {t}`; add/select the cited test, then abandon and begin again if the check set must change"),
    ("check failed", "read `failure`, fix the cause, rerun verify"),
    ("check changed watched files", "the check modified files; make it read-only or use temp dirs"),
    ("static:", "agent.py review --task {t}; fix the findings; rerun verify"),
)


def hinted(task, reasons):
    out = []
    for reason in reasons:
        path = reason.rsplit(": ", 1)[-1] if ": " in reason else "PATH"
        fix = next((h.format(t=task, p=path) for k, h in HINTS if reason.startswith(k)), None)
        out.append(reason + (" -> " + fix if fix else ""))
    return out


# ------------------------------------------------------------------ receipts / state
def load(path, key):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 << 20:
        raise Blocked(f"invalid task receipt: {path.name}")
    try:
        record = json.loads(path.read_bytes())
        payload = record["payload"]
        signature = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, record["mac"]) or payload["version"] != 1:
            raise ValueError("receipt integrity/version mismatch")
        return payload
    except (ValueError, KeyError, TypeError) as exc:
        raise Blocked(f"invalid task receipt: {path.name}") from exc


def _fsync_dir(directory):
    try:
        fd = os.open(directory, os.O_RDONLY | O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def save(path, payload, key):
    record = {"payload": payload, "mac": hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()}
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=STATE)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_dir(STATE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def blob_put(data):
    sha = hashlib.sha256(data).hexdigest()
    target = BLOBS / sha
    if target.exists():
        return sha
    BLOBS.mkdir(mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=BLOBS)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return sha


def blob_get(sha):
    if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
        return None
    path = BLOBS / sha
    try:
        if path.is_symlink() or not path.is_file():
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return data if hashlib.sha256(data).hexdigest() == sha else None


def gc_blobs(key):
    """Drop stored baseline/backup content no open task still references."""
    if not BLOBS.is_dir() or BLOBS.is_symlink():
        return
    keep = set()
    for path in STATE.glob("task.*.json"):
        try:
            plan = load(path, key)
        except Blocked:
            continue
        if plan.get("closed") is True:
            continue
        keep.update(r["sha256"] for r in plan["baseline"]["files"].values() if r.get("sha256"))
        keep.update((plan.get("backups") or {}).values())
    for item in BLOBS.iterdir():
        if item.name not in keep and not item.name.startswith(".tmp-"):
            try:
                item.unlink()
            except OSError:
                pass


def state_guard(key, lock_fd):
    if STATE.is_symlink():
        raise Blocked("state directory/lock changed")
    if not IS_WIN and (STATE / ".lock").lstat().st_ino != os.fstat(lock_fd).st_ino:
        raise Blocked("state directory/lock changed")
    for path in STATE.iterdir():
        if path.is_symlink():
            raise Blocked(f"unsupported runtime state entry: {path.name}")
        if path.name in {"blobs", "cache"}:
            if not path.is_dir():
                raise Blocked(f"unsupported runtime state entry: {path.name}")
            continue
        if not path.is_file():
            raise Blocked(f"unsupported runtime state entry: {path.name}")
        if (path.name in {".key", ".lock"} or path.name.startswith((".write-", ".tmp-", ".mem-"))
                or MEMORY_NAME.fullmatch(path.name)):
            continue
        if not re.fullmatch(r"task\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.json", path.name):
            raise Blocked(f"unexpected runtime state entry: {path.name}")
        load(path, key)  # No source/evidence file can acquire an exclusion by its name.
    if (STATE / ".key").read_bytes() != key:
        raise Blocked("receipt key changed")


def _flock(fd):
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    else:  # Windows
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)


def ensure_state():
    if STATE.is_symlink():
        raise Blocked("state directory must not be a symlink")
    STATE.mkdir(mode=0o700, exist_ok=True)


@contextlib.contextmanager
def locked(wait=None):
    if wait is None:
        wait = float(os.environ.get("AGENT_LOCK_WAIT") or 15.0)
    ensure_state()
    state_info = STATE.lstat()
    if not stat.S_ISDIR(state_info.st_mode) or (not IS_WIN and stat.S_IMODE(state_info.st_mode) & 0o077):
        raise Blocked("toolkit state directory must be a private 0700 directory")
    fd = os.open(STATE / ".lock", os.O_CREAT | os.O_RDWR | O_NOFOLLOW | O_BINARY, 0o600)
    try:
        lock_info = os.fstat(fd)
        if not stat.S_ISREG(lock_info.st_mode) or (not IS_WIN and stat.S_IMODE(lock_info.st_mode) & 0o077):
            raise Blocked("invalid state lock")
        deadline = time.monotonic() + wait
        while True:
            try:
                _flock(fd)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise Blocked("another task operation holds the toolkit lock (waited "
                                  f"{int(wait)}s; a verify may be running) - retry shortly") from None
                time.sleep(0.25)
        key_path = STATE / ".key"
        if not key_path.exists() and not key_path.is_symlink():
            key_fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | O_BINARY, 0o600)
            with os.fdopen(key_fd, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
        key_info = key_path.lstat()
        if (key_path.is_symlink() or not stat.S_ISREG(key_info.st_mode) or
                (not IS_WIN and stat.S_IMODE(key_info.st_mode) & 0o077) or key_info.st_size != 32):
            raise Blocked("invalid receipt key")
        key = key_path.read_bytes()
        state_guard(key, fd)
        yield key, fd
    finally:
        os.close(fd)


def read_plan(task):
    """Lock-free receipt read for read-only commands (receipts are replaced atomically)."""
    if not NAME.fullmatch(task):
        raise Blocked("invalid task name")
    key_path, path = STATE / ".key", STATE / f"task.{task}.json"
    if not key_path.is_file() or not path.is_file():
        raise Blocked("task does not exist: " + task)
    return load(path, key_path.read_bytes())


# ------------------------------------------------------------------ checks
def check_argv(raw):
    try:
        argv = json.loads(raw)
    except ValueError as exc:
        raise Blocked("--check must be a JSON argv array") from exc
    if (not isinstance(argv, list) or not argv or len(argv) > 128 or
            not all(isinstance(s, str) and "\0" not in s and len(s) <= 8000 for s in argv)
            or not argv[0].strip()):
        raise Blocked("--check requires a nonempty JSON array of string arguments")
    if re.fullmatch(r"python(?:3(?:\.\d+)?)?", argv[0]):
        argv[0] = sys.executable
    executable = Path(argv[0]).name.lower()
    shell_flags = {"-c", "-command", "/c", "/command"}
    if executable in {"sh", "bash", "dash", "zsh", "fish", "ksh", "cmd", "powershell", "pwsh"} and any(
            item.lower() in shell_flags for item in argv[1:]):
        raise Blocked("shell-string checks are not supported; pass an executable argv directly")
    return argv


def identity(project, checks, env):
    executables = []
    for argv in checks:
        command = argv[0]
        found = str(project / command) if "/" in command else shutil.which(command, path=env.get("PATH"))
        if not found or not Path(found).is_file() or not os.access(found, os.X_OK):
            raise Blocked(f"check executable missing/not executable: {command}")
        path = Path(found).resolve(strict=True)
        executables.append({"requested": command, "path": str(path), "sha256": file_hash(path, 128 << 20)})
    python = Path(sys.executable).resolve()
    selected = {name: env.get(name, "") for name in (
        "PATH", "PYTHONPATH", "VIRTUAL_ENV", "CONDA_PREFIX", "PYTEST_ADDOPTS",
        "TRADING_MODE", "NODE_PATH", "JAVA_HOME", "RUSTUP_TOOLCHAIN", "GOPATH",
        "LANG", "LC_ALL")}
    return {"python": {"executable": sys.executable, "resolved": str(python),
                        "sha256": file_hash(python, 128 << 20), "version": sys.version,
                        "prefix": sys.prefix, "base_prefix": sys.base_prefix},
            "platform": platform.platform(), "executables": executables,
            "environment_sha256": digest(selected)}


def command_env(project):
    env = environment()
    env["PWD"] = str(project)
    return env


def _kill_tree(process):
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


def run_check(argv, project, env, timeout, capture_limit=TAIL):
    """Drain both streams with bounded tails; kill the process group on timeout."""
    output = {name: {"bytes": 0, "tail": b"", "hash": hashlib.sha256()}
              for name in ("stdout", "stderr")}
    record = {"argv": argv, "cwd": str(project), "timeout_seconds": timeout,
              "exit_code": None, "timed_out": False}

    def drain(stream, target):
        try:
            for chunk in iter(lambda: stream.read(65536), b""):
                target["hash"].update(chunk)
                target["bytes"] += len(chunk)
                target["tail"] = (target["tail"] + chunk)[-capture_limit:]
        finally:
            stream.close()

    try:
        process = subprocess.Popen(argv, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, start_new_session=True)
        threads = [threading.Thread(target=drain, args=(getattr(process, name), output[name]), daemon=True)
                   for name in output]
        for thread in threads:
            thread.start()
        try:
            record["exit_code"] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
        if record["timed_out"]:
            # Only kill a group after a timeout; never signal a recycled group
            # after a normally completed check.
            _kill_tree(process)
            try:
                record["exit_code"] = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                record["error"] = "process group did not exit after timeout"
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            record["error"] = "output pipes still open; check descendants may have escaped the process group"
    except OSError as exc:
        record["error"] = str(exc)[:300]
    for name, result in output.items():
        record[name] = {"bytes": result["bytes"], "sha256": result["hash"].hexdigest(),
                        "tail": result["tail"].decode("utf-8", errors="replace")}
    if capture_limit > TAIL:
        record["_stdout_raw"] = output["stdout"]["tail"]
    return record


def report(task, state, reasons=(), **extra):
    return {"task": task, "state": state, "reasons": list(reasons), **extra}


# ------------------------------------------------------------------ intelligence plumbing
def _toolkit_rel(root):
    try:
        return TOOLKIT.relative_to(root).as_posix()
    except ValueError:
        return None


def is_toolkit_path(root, rel):
    tk = _toolkit_rel(root)
    return bool(tk and (rel == tk or rel.startswith(tk + "/")))


def build_world(root, budget=10.0):
    intel = load_module("pyintel")
    ensure_state()
    return intel.World.build(root, skip=lambda rel: private(rel) or is_toolkit_path(root, rel),
                             budget=budget, cache_dir=STATE / "cache")


def memory_file(root):
    """A separate signed memory ledger per repository, kept with the toolkit state.

    The filename deliberately contains only a stable digest of the absolute Git root.  This lets
    one installed toolkit serve many repositories without leaking facts from one into another or
    requiring the target project to track a private state file.
    """
    return STATE / ("memory." + digest({"root": str(root)})[:16] + ".json")


def open_memory(root, key):
    module = load_module("memory")
    return module.Memory.open(root, key, path=memory_file(root))


def _memory_evidence(raw):
    """Parse deliberately small, structured evidence supplied by an agent.

    Memory is a knowledge ledger, not a place for command output or secrets.  The memory module
    re-checks recognized evidence types; this boundary constrains what enters the signed store.
    """
    if raw is None:
        return []
    try:
        items = json.loads(raw)
    except ValueError as exc:
        raise Blocked("--evidence must be a JSON array of evidence objects") from exc
    if not isinstance(items, list) or len(items) > 8 or not all(isinstance(item, dict) for item in items):
        raise Blocked("--evidence must be a JSON array containing at most 8 objects")
    allowed = {"commit", "file", "test", "command"}
    out = []
    for item in items:
        kind = item.get("type")
        if kind not in allowed:
            raise Blocked("evidence type must be one of: " + ", ".join(sorted(allowed)))
        # Bound recursive/untrusted JSON before it is signed and persisted.  The memory verifier
        # intentionally treats command evidence as historical, never as fresh proof.
        if len(canonical(item)) > 2400:
            raise Blocked("one evidence object is too large")
        out.append(item)
    return out


def _history_findings(root, changes, weakened, is_test):
    """Attach evidence-only history findings to a review result.

    These findings are never merged into static errors: matching a reverted/fixed line proves a
    relationship to an earlier decision, not that the current change is wrong.  It is surfaced
    prominently so an agent must read the cited commit before deciding to proceed.
    """
    if not changes:
        return [], []
    try:
        history = load_module("gitmem").History.load(root, cache_dir=STATE / "cache")
        findings = history.conflicts(changes, is_test=is_test)
        findings += history.guard_findings(changes, is_test, weakened)
        notes = list(history.notes)
        if history.truncated:
            notes.append("history mining reached its commit cap; older evidence was not considered")
        return findings[:8], notes[:4]
    except Exception as exc:  # noqa: BLE001 - history must never turn an analysis failure into a pass or crash
        if os.environ.get("AGENT_DEBUG"):
            raise
        return [], [f"history intelligence unavailable ({type(exc).__name__}: {str(exc)[:100]})"]


def add_history_intelligence(result, root, changes, intel):
    """Mutate a normal static-review result with bounded, cited Git-history evidence."""
    findings, notes = _history_findings(root, changes, result.get("smells") or [], intel.is_test_path)
    result["history"] = findings
    if notes:
        result.setdefault("notes", []).extend(notes)
    return result


def _proof_sources(plan, root, project, changes, world, intel):
    """Turn changed/scoped source paths into test and Git-history evidence candidates."""
    changed = [row["path"] for row in (changes or []) if not row.get("opaque") and not intel.is_test_path(row["path"])
               and Path(row["path"]).suffix.lower() in SOURCE_SUFFIXES]
    # `proof --task` before an edit is still useful: assess the intended scope.  During verify,
    # use only source files that actually changed so an untouched neighbour cannot create debt.
    if not changed:
        changed = [rel for rel in world.files if Path(rel).suffix.lower() in SOURCE_SUFFIXES
                   and not intel.is_test_path(rel) and any(contains(scope, rel) for scope in plan["scope"])]
    changed = sorted(set(changed))[:80]
    history = None
    history_notes = []
    try:
        history = load_module("gitmem").History.load(root, cache_dir=STATE / "cache")
        history_notes = list(history.notes)
    except Exception as exc:  # noqa: BLE001 - insufficient history is an unknown, not a crash
        history_notes = [f"history guards unavailable ({type(exc).__name__})"]
    sources = []
    for rel in changed:
        tests = []
        for test, (_depth, _via) in world.tests_for([rel]):
            tests.append({"path": test, "project_path": os.path.relpath(root / test, project).replace(os.sep, "/")})
        guards = []
        if history is not None:
            for guard_row in history.guards(rel, intel.is_test_path, cap=8):
                test = guard_row["path"]
                guards.append({"path": test, "project_path": os.path.relpath(root / test, project).replace(os.sep, "/")})
        sources.append({"path": rel, "python": rel.endswith((".py", ".pyi")), "tests": tests, "guards": guards})
    return sources, history_notes


def proof_matrix(plan, project, root, changes=None):
    """Evidence matrix: changed code -> known tests/guards -> declared check selection."""
    intel, proof = load_module("pyintel"), load_module("proof")
    world = build_world(root)
    sources, notes = _proof_sources(plan, root, project, changes, world, intel)
    result = proof.assess(sources, plan["checks"])
    result["notes"] = notes
    if world.partial:
        result["notes"].append(f"test graph is partial ({world.partial} source file(s) pending); proof is incomplete")
    return result


def baseline_bytes(root, plan, rel):
    """Content of ``rel`` at ``begin`` time -> (bytes|None, how)."""
    base = plan["baseline"]
    rec = base["files"].get(rel)
    if rec is None:  # clean at begin: identical to HEAD
        return git_blob(root, base["git"]["head"], rel), "head"
    if rec["kind"] == "file":
        data = blob_get(rec["sha256"])
        if data is not None:
            return data, "blob"
        return git_blob(root, base["git"]["head"], rel), "approx"
    return None, rec["kind"]


def collect_changes(root, project, plan=None):
    """Readable deltas: only the agent's own (vs begin) when a plan is given, else worktree vs HEAD."""
    out = []
    if plan is None:
        seen = {}
        for code, rel in _status_paths(root):
            rel = rel.rstrip("/")
            if code == "!!" or not rel or is_toolkit_path(root, rel):
                continue
            seen[rel] = code
        for rel in sorted(seen):
            if private(rel):
                out.append({"path": rel, "opaque": True, "old": None, "new": None, "in_scope": None})
                continue
            new, old = _read_opt(root / rel), git_blob(root, "HEAD", rel)
            if old != new:
                out.append({"path": rel, "old": old, "new": new, "in_scope": None})
        return out
    base, cur = plan["baseline"], snapshot(root)
    for rel in sorted(base["files"].keys() | cur["files"].keys()):
        old_rec, new_rec = base["files"].get(rel), cur["files"].get(rel)
        if old_rec == new_rec:
            continue
        in_scope = any(contains(s, rel) for s in plan["scope"])
        if any(x and x["kind"] in {"opaque", "unsupported"} for x in (old_rec, new_rec)):
            out.append({"path": rel, "opaque": True, "old": None, "new": None, "in_scope": in_scope})
            continue
        if any(x and x["kind"] == "directory" for x in (old_rec, new_rec)):
            continue
        old, how = baseline_bytes(root, plan, rel)
        new = _read_opt(root / rel)
        if old != new:
            out.append({"path": rel, "old": old, "new": new, "in_scope": in_scope, "approx": how == "approx"})
    return out


def static_gate(plan, project, root):
    try:
        intel = load_module("pyintel")
        changes = collect_changes(root, project, plan)
        world = build_world(root)
        scope = plan["scope"]
        result = intel.review(world, changes, touch=plan.get("touch") or [],
                              in_scope=lambda rel: any(contains(s, rel) for s in scope))
        return add_history_intelligence(result, root, changes, intel)
    except Blocked:
        raise
    except Exception as exc:  # noqa: BLE001 - an analyzer bug must never masquerade as a pass
        if os.environ.get("AGENT_DEBUG"):
            raise
        return {"files": [], "errors": [], "likely": [], "possible": [], "policy": [], "tests": [], "untested": [],
                "smells": [], "history": [], "warnings": [],
                "notes": [f"static analysis unavailable ({type(exc).__name__}: {str(exc)[:100]}) - NOT a pass"],
                "partial": 0}


def failure_info(last, plan=None):
    before = {json.dumps(b["argv"]): b for b in (plan or {}).get("baseline_run") or []}
    for run in last.get("runs", []):
        if run["exit_code"] != 0 or run["timed_out"] or run.get("error"):
            text = "\n".join(x for x in (run["stdout"]["tail"].rstrip(), run["stderr"]["tail"].rstrip()) if x)
            info = {"cmd": run["argv"], "exit": run["exit_code"], "timed_out": run["timed_out"],
                    "tail": "\n".join(text.splitlines()[-30:])[-3000:]}
            base = before.get(json.dumps(run["argv"]))
            if base and (base["exit"] != 0 or base["timed_out"]):
                info["also_failed_at_begin"] = True
                info["begin_tail"] = base["tail"][-300:]
                info["note"] = ("this check was already failing BEFORE your change; compare begin_tail with tail - "
                                "if the failures are the same they are not yours (do not 'fix' unrelated tests unless asked)")
            return info
    return None


# ------------------------------------------------------------------ task lifecycle
def auto_check(project, root, scope):
    world = build_world(root)
    intel = load_module("pyintel")
    chosen = {}
    for rel in sorted(p for p in world.files if p.endswith(".py") and any(contains(s, p) for s in scope)):
        if intel.is_test_path(rel):
            chosen.setdefault(rel, 0)
        for path, (depth, _via) in world.tests_for([rel]):
            if path.endswith(".py"):
                chosen[path] = min(chosen.get(path, 9), depth)
    tests = [p for p, _ in sorted(chosen.items(), key=lambda kv: (kv[1], kv[0]))][:40]
    if not tests:
        raise Blocked("--auto-check found no impacted Python tests (JS/other languages unsupported); "
                      "pass --check with the project's real test command")
    rels = [os.path.relpath(root / t, project).replace(os.sep, "/") for t in tests]
    return [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *rels], tests


def store_baseline(root, baseline):
    total, complete = 0, True
    for rel, rec in baseline["files"].items():
        if rec.get("kind") != "file":
            continue
        data = read_regular(root / rel)
        if hashlib.sha256(data).hexdigest() != rec["sha256"]:
            raise Blocked("file changed during begin; retry: " + rel)
        if total + len(data) > MAX_BLOBS:
            complete = False
            continue
        blob_put(data)
        total += len(data)
    return complete


def validate_touch(root, scope, touch):
    """Declared symbols must exist already (new symbols never need declaring) - catches typos early."""
    if not touch:
        return
    world = build_world(root)
    defs = {rel: f["d"] for rel, f in world.files.items() if "d" in f and any(contains(s, rel) for s in scope)}
    if not defs:
        raise Blocked("--touch needs existing Python files in the scope (symbol intent is Python-only)")
    every = {q for d in defs.values() for q in d}
    for item in touch:
        path, _, q = item.rpartition("::")
        if q in ("*", "<module>"):
            continue
        if path and path not in defs:
            raise Blocked(f"--touch {item}: {path} is not an existing Python file in the scope")
        names = set(defs[path]) if path else every
        if q not in names and not any(n.startswith(q + ".") for n in names):
            near = difflib.get_close_matches(q, sorted(names), 3, 0.5)
            raise Blocked(f"--touch {item}: no such symbol in the scope files" +
                          (f"; did you mean {', '.join(near)}?" if near else "; run `outline FILE` to see names"))


def run_baseline(checks, project, root, env, timeout):
    """Run the declared checks once BEFORE any edit so pre-existing failures are never blamed on (or 'fixed' by) the agent."""
    before, runs = snapshot(root), []
    for argv in checks:
        result = run_check(argv, project, env, timeout)
        output_tail = "\n".join(x for x in (result["stdout"]["tail"].rstrip(), result["stderr"]["tail"].rstrip()) if x)
        # Keep enough of the exact same command's terminal output to compare framework
        # summaries later.  This is bounded by run_check's tail cap and is not a claimed test
        # result; unparseable output simply produces no inference.
        runs.append({"argv": argv, "exit": result["exit_code"], "timed_out": result["timed_out"],
                     "tail": output_tail[-600:], "summary": output_tail[-TAIL:]})
    if snapshot(root) != before:
        raise Blocked("a check modified the worktree during the baseline run; make the check read-only first")
    return runs


def baseline_deltas(plan, runs):
    """Evidence-only comparison of a declared check with its own pre-edit output.

    A command can pass after its test selection silently shrinks.  ``checkdiff`` parses only
    well-known summaries and returns no result for any ambiguous output.  A zero-test collapse is
    treated as a verification failure; lesser count changes remain warnings because a task may
    legitimately replace or retire tests.
    """
    previous = {json.dumps(row.get("argv")): row for row in plan.get("baseline_run") or []}
    if not previous:
        return []
    compare = load_module("checkdiff").compare
    warnings = []
    for run in runs:
        base = previous.get(json.dumps(run.get("argv")))
        if not base:
            continue
        old_text = base.get("summary") or base.get("tail") or ""
        new_text = "\n".join(x for x in (run.get("stdout", {}).get("tail", "").rstrip(),
                                          run.get("stderr", {}).get("tail", "").rstrip()) if x)
        for finding in compare(old_text, new_text):
            finding["argv"] = run.get("argv")
            warnings.append(finding)
    return warnings


def begin(args, project, root, key):
    scope = sorted({canonical(x): x for x in
                    (validate_path(project, root, p) for p in args.paths)}.values(), key=lambda x: x["path"])
    protect = protections(project, root, args.protect)
    for s in scope:
        if any(contains(p, s["path"]) or contains(s, p["path"]) for p in protect):
            raise Blocked("scope overlaps a protected path: " + s["path"])
    validate_touch(root, scope, sorted(set(args.touch)))
    checks = [check_argv(raw) for raw in args.check]
    auto = None
    if args.auto_check:
        argv, auto = auto_check(project, root, scope)
        if argv not in checks:
            checks.append(argv)
    invariants = project / "tests/invariants"
    if invariants.exists():
        validate_path(project, root, "tests/invariants")
        required = [sys.executable, "-m", "pytest", "tests/invariants", "-q", "-p", "no:cacheprovider"]
        if required not in checks:
            checks.append(required)
    if not checks:
        raise Blocked("declare at least one --check (JSON argv) or --auto-check; no implicit verification exists")
    if args.timeout < 1 or args.timeout > 3600:
        raise Blocked("timeout must be between 1 and 3600 seconds")
    configuration = {"version": 1, "project": str(project), "root": str(root), "scope": scope,
                     "protect": protect, "checks": checks, "timeout": args.timeout,
                     "unknown": sorted(set(args.unknown)), "touch": sorted(set(args.touch)),
                     "require_proof": bool(args.require_proof)}
    path = STATE / f"task.{args.task}.json"
    env_id = identity(project, checks, command_env(project))
    baseline = snapshot(root)
    if path.exists():
        previous = load(path, key)
        if (all(previous.get(k, [] if k == "touch" else None) == v for k, v in configuration.items()) and
                previous["baseline"] == baseline and previous["environment"] == env_id):
            return status(args.task, previous, baseline, env_id)
        raise Blocked(f"task '{args.task}' already exists and its baseline is fixed. Continue it with "
                      f"`verify --task {args.task}` / `status`, or `abandon --task {args.task}` then begin again")
    for other_path in sorted(STATE.glob("task.*.json")):
        other = load(other_path, key)
        if other.get("closed") is True:
            continue  # closed receipts remain audit records, not reservations
        if other["root"] != str(root) or other["baseline"]["git"]["head"] != baseline["git"]["head"]:
            continue
        if any(contains(s, o["path"]) or contains(o, s["path"])
               for s in scope for o in other["scope"]):
            raise Blocked("overlapping task reservation: " + other_path.name[5:-5] +
                          f" (finish it, or `abandon --task {other_path.name[5:-5]}` if it is dead)")
    plan = {**configuration, "baseline": baseline, "environment": env_id,
            "last": None, "closed": False, "blobs_complete": store_baseline(root, baseline)}
    if args.run_baseline:
        plan["baseline_run"] = run_baseline(checks, project, root, command_env(project), args.timeout)
    save(path, plan, key)
    result = status(args.task, plan, baseline, env_id)
    if args.run_baseline:
        red = [r for r in plan["baseline_run"] if r["exit"] != 0 or r["timed_out"]]
        result["baseline"] = ("all declared checks were green before you started" if not red else
                              [{"check": r["argv"][-3:], "exit": r["exit"], "tail": r["tail"][-200:]} for r in red])
        if red:
            result["note"] = ("RED before you started: those failures are not yours; do not 'fix' unrelated tests unless asked, "
                              "and tell the user the project was already failing")
    if auto:
        result["auto_check"] = auto[:10] + ([f"+{len(auto) - 10} more"] if len(auto) > 10 else [])
    return result


def status(task, plan, current, env_id):
    if plan.get("closed") is True:
        if plan.get("abandoned"):
            return report(task, "ABANDONED", meaning="Reservation released; nothing was verified.")
        last = plan.get("last") or {}
        if last.get("post") == current and last.get("environment") == env_id:
            return report(task, "CLOSED", checks=len(last.get("runs", [])),
                          meaning="Archived receipt; checks passed, not correctness or review approval.")
        return report(task, "CLOSED_STALE", ["receipt was closed before the current worktree changed"])
    failures = problems(plan, current)
    last = plan["last"]
    if failures:
        return report(task, "BLOCKED", hinted(task, failures))
    if last is None:
        return report(task, "READY" if current == plan["baseline"] else "UNVERIFIED",
                      checks=len(plan["checks"]))
    if last.get("post") != current or last.get("environment") != env_id:
        return report(task, "STALE", ["snapshot or check environment differs from the latest attempt "
                                      f"-> rerun: agent.py verify --task {task}"])
    if last["state"] != "CHECKS_PASSED":
        return report(task, "BLOCKED", hinted(task, last.get("reasons") or ["verification incomplete/interrupted"]))
    return report(task, "CHECKS_PASSED", checks=len(last["runs"]),
                  meaning="Recorded commands passed; not correctness or review approval.")


def close_task(args, plan, project, root, key):
    current = snapshot(root)
    env_id = identity(project, plan["checks"], command_env(project))
    if plan.get("closed") is True:
        return status(args.task, plan, current, env_id)
    if not plan.get("last") or plan["last"].get("state") != "CHECKS_PASSED":
        raise Blocked("only a fresh CHECKS_PASSED receipt can be closed (or `abandon --task "
                      f"{args.task}` to release without verification)")
    if plan["last"].get("post") != current or plan["last"].get("environment") != env_id:
        raise Blocked("receipt is stale; run verify again before closing")
    if problems(plan, current):
        raise Blocked("current worktree no longer matches the verified receipt")
    plan["closed"] = True
    save(STATE / f"task.{args.task}.json", plan, key)
    gc_blobs(key)
    return status(args.task, plan, current, env_id)


def widen_task(args, plan, project, root, key):
    """Add paths to a task's scope on the SAME baseline (e.g. callers review says must change)."""
    if plan.get("closed") is True:
        raise Blocked("task is closed")
    added = sorted({canonical(x): x for x in (validate_path(project, root, p) for p in args.paths)}.values(),
                   key=lambda x: x["path"])
    for s in added:
        if any(contains(p, s["path"]) or contains(s, p["path"]) for p in plan["protect"]):
            raise Blocked("path overlaps a protected path: " + s["path"])
    for other_path in sorted(STATE.glob("task.*.json")):
        name = other_path.name[5:-5]
        other = load(other_path, key)
        if name == args.task or other.get("closed") is True or other["root"] != plan["root"]:
            continue
        if any(contains(s, o["path"]) or contains(o, s["path"]) for s in added for o in other["scope"]):
            raise Blocked("overlapping task reservation: " + name)
    merged = {canonical(x): x for x in plan["scope"] + added}
    plan["scope"] = sorted(merged.values(), key=lambda x: x["path"])
    plan.setdefault("widened", []).extend(x["path"] for x in added)
    plan["last"] = None  # earlier verification covered a narrower scope
    save(STATE / f"task.{args.task}.json", plan, key)
    current = snapshot(root)
    result = status(args.task, plan, current, identity(project, plan["checks"], command_env(project)))
    result["widened"] = [x["path"] for x in added]
    return result


def abandon_task(args, plan, key):
    if plan.get("closed") is not True:
        plan["closed"], plan["abandoned"] = True, True
        save(STATE / f"task.{args.task}.json", plan, key)
        gc_blobs(key)
    return report(args.task, "ABANDONED", meaning="Reservation released; nothing was verified. "
                  "Edits stay in the worktree - use `diff` to review them.")


def verify(args, plan, project, root, key, lock_fd):
    path, env = STATE / f"task.{args.task}.json", command_env(project)
    before, env_id = snapshot(root), identity(project, plan["checks"], env)
    failures = problems(plan, before)
    if failures:
        return report(args.task, "BLOCKED", hinted(args.task, failures))
    intel = load_module("pyintel")
    skipped = bool(getattr(args, "no_static", False))
    static = None if skipped else static_gate(plan, project, root)
    blocking = (static["errors"] + static["likely"] + static["policy"]) if static else []
    if blocking:
        last = {"state": "BLOCKED", "pre": before, "post": before, "environment": env_id, "runs": [],
                "reasons": [f"static: {len(blocking)} definite finding(s); checks not run (fast-fail)"],
                "static": {"e": len(static["errors"]), "l": len(static["likely"]), "p": len(static["policy"])}}
        plan["last"] = last
        save(path, plan, key)
        result = status(args.task, plan, before, env_id)
        result["static"] = intel.render_short(static)
        return result
    # Always replace a cached pass with a running receipt before executing.
    last = {"state": "RUNNING", "pre": before, "post": before,
            "environment": env_id, "runs": [], "reasons": [],
            "static": {"e": 0, "l": 0, "p": 0, "skipped": skipped}}
    plan["last"] = last
    save(path, plan, key)
    for argv in plan["checks"]:
        pre = snapshot(root)
        if pre != before or identity(project, plan["checks"], env) != env_id:
            last["reasons"].append("snapshot/environment changed before a check")
            break
        result = run_check(argv, project, env, plan["timeout"])
        try:
            post = snapshot(root)
        except Blocked as exc:
            post = pre
            result["snapshot_error"] = str(exc)
        result.update(environment=env_id, snapshot_pre=digest(pre), snapshot_post=digest(post))
        last["runs"].append(result)
        last["post"] = post
        if (result["exit_code"] != 0 or result["timed_out"] or result.get("error") or
                result.get("snapshot_error")):
            last["reasons"].append("check failed/timed out: " + json.dumps(argv))
        if pre != post or identity(project, plan["checks"], env) != env_id:
            last["reasons"].append("check changed watched files, HEAD/index, or executable identity")
        last["reasons"].extend(problems(plan, post))
        state_guard(key, lock_fd)
        save(path, plan, key)
        if last["reasons"]:
            break
    if len(last["runs"]) != len(plan["checks"]):
        last["reasons"].append("not all planned checks completed")
    # Compare only a command with exactly itself, and only when the agent explicitly recorded a
    # pre-edit baseline.  This catches the particularly dangerous case where discovery falls to
    # zero while the command still exits 0.  Other deltas are surfaced as evidence, not guessed
    # failures: deleting/replacing a test can be intentional.
    last["baseline_warnings"] = baseline_deltas(plan, last["runs"])
    if any(f.get("code") == "W-SILENT" for f in last["baseline_warnings"]):
        last["reasons"].append("baseline comparison: a declared check ran zero tests after it previously ran tests")
    last["state"] = "BLOCKED" if last["reasons"] else "CHECKS_PASSED"
    state_guard(key, lock_fd)
    save(path, plan, key)
    result = status(args.task, plan, snapshot(root), identity(project, plan["checks"], env))
    if last.get("baseline_warnings"):
        # Keep structured, command-specific proof in the receipt output even when a zero-test
        # collapse turns verification into BLOCKED.
        result["baseline_warnings"] = last["baseline_warnings"]
    if result["state"] == "BLOCKED":
        info = failure_info(last, plan)
        if info:
            result["failure"] = info
    elif result["state"] == "CHECKS_PASSED" and static:
        warn = []
        for finding in last.get("baseline_warnings") or []:
            if finding.get("code") != "W-SILENT":
                warn.append(f"{finding.get('code')}: {finding.get('msg')}")
        if static["untested"]:
            warn.append("UNTESTED (no test imports them; a green run says nothing about): " + ", ".join(static["untested"][:4]))
        if static["possible"]:
            warn.append(f"{len(static['possible'])} POSSIBLE usage(s) of removed/changed names not provable - see review")
        smells = static.get("smells") or []
        if smells:
            warn.append(f"{len(smells)} SMELL(S) - fix or justify in your summary: " +
                        "; ".join(f"[{x['code'][2:]}] {x['path']}: {x['msg']}" for x in smells[:3]))
        history = static.get("history") or []
        if history:
            warn.append(f"{len(history)} HISTORY finding(s) cite prior fixes/reverts; read the cited commit before claiming this is safe")
        warn += static["notes"]
        if warn:
            result["warn"] = warn
    elif result["state"] == "CHECKS_PASSED" and skipped:
        result["warn"] = ["static analysis was skipped (--no-static)"]
    return result


def restore_task(args, plan, project, root, key):
    """Put paths back to their exact content at ``begin`` (user's pre-existing edits included)."""
    if plan.get("closed") is True:
        raise Blocked("task is closed; nothing to restore")
    base, cur = plan["baseline"], snapshot(root)
    deltas = {rel for rel in base["files"].keys() | cur["files"].keys()
              if base["files"].get(rel) != cur["files"].get(rel)}
    wanted, notes = set(), []
    for text in args.paths:
        spec = validate_path(project, root, text)
        hit = {rel for rel in deltas if contains(spec, rel)}
        if not hit:
            notes.append(f"{text}: unchanged since begin")
        wanted |= hit
    done, refused = [], []
    backups = plan.setdefault("backups", {})
    for rel in sorted(wanted):
        old, new = base["files"].get(rel), cur["files"].get(rel)
        if any(x and x["kind"] in {"opaque", "unsupported", "directory"} for x in (old, new)):
            refused.append(f"{rel}: private/special path is never touched")
            continue
        target = root / rel
        if old is None:
            if cur["git"] != base["git"]:
                refused.append(f"{rel}: HEAD/index changed since begin")
                continue
            data = git_blob(root, base["git"]["head"], rel)
        elif old["kind"] == "file":
            data = blob_get(old["sha256"])
            if data is None:
                refused.append(f"{rel}: baseline content was not stored (file was large or store pruned)")
                continue
        else:
            data = None  # did not exist at begin
        try:
            current_bytes = read_regular(target) if target.exists() else None
        except (Blocked, OSError) as exc:
            refused.append(f"{rel}: cannot back up current content ({exc})")
            continue
        if target.is_symlink() or target.is_dir():
            refused.append(f"{rel}: not a regular file")
            continue
        if current_bytes is not None:
            backups[rel] = blob_put(current_bytes)
        if data is None:
            if target.exists():
                target.unlink()
            done.append(f"{rel}: removed (did not exist at begin)")
        else:
            mode = (old or {}).get("mode") or (stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o644)
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".restore-", dir=target.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                os.chmod(temporary, mode)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            done.append(f"{rel}: restored to its content at begin")
    save(STATE / f"task.{args.task}.json", plan, key)
    state = "RESTORED" if done and not refused else ("PARTIAL" if done else "NOCHANGE")
    return report(args.task, state, refused + notes, restored=done,
                  next=f"agent.py verify --task {args.task}" if done else None)


# ------------------------------------------------------------------ read-only commands
def project_and_root(value):
    project = Path(value or Path.cwd()).absolute()
    if not project.exists() or not project.is_dir():
        raise Blocked("project directory does not exist: " + str(project))
    if any(path.is_symlink() for path in (project, *project.parents)):
        raise Blocked("project path may not contain symlinks")
    raw = git(project, "rev-parse", "--show-toplevel")
    root = Path(raw.decode().strip()).absolute()
    try:
        project.relative_to(root)
    except ValueError:
        raise Blocked("project is not inside its Git root") from None
    return project, root


def load_plan(task, key):
    if not NAME.fullmatch(task):
        raise Blocked("invalid task name")
    path = STATE / f"task.{task}.json"
    if not path.exists():
        raise Blocked("task does not exist: " + task)
    return path, load(path, key)


def plan_project(plan, requested):
    stored = Path(plan["project"])
    if requested is not None and Path(requested).absolute() != stored:
        raise Blocked("requested project differs from the task receipt")
    project, root = project_and_root(stored)
    if str(project) != plan["project"] or str(root) != plan["root"]:
        raise Blocked("repository/project identity changed")
    return project, root


def output(value, pretty=False):
    print(json.dumps(value, sort_keys=True, indent=2 if pretty else None,
                     separators=None if pretty else (",", ":")))


def _runner(project):
    target = TOOLKIT / "agent.py"
    rel = os.path.relpath(target, project).replace(os.sep, "/")
    # A relative path is concise for a copied-in toolkit.  For a centrally installed toolkit
    # serving another checkout, an absolute path is less surprising and cannot be misread as a
    # repository path in the agent's next command.
    return f"python3 {target}" if rel == ".." or rel.startswith("../") else f"python3 {rel}"


def _locate_all(world, project, root, specs):
    intel = load_module("pyintel")
    cwd_rel = project.relative_to(root).as_posix()
    cwd_rel = "" if cwd_rel == "." else cwd_rel
    found, notes = [], []
    for spec in specs:
        rel, cands = intel.locate(world.all_paths, spec, cwd_rel)
        if rel is None:
            if spec.strip("/") in world.dirs:
                notes.append(f"{spec}: is a directory; pass files")
            else:
                notes.append(f"{spec}: not found" + (f"; did you mean: {', '.join(cands)}" if cands else ""))
        elif private(rel):
            notes.append(f"{rel}: private/runtime path (never read)")
        elif rel not in found:
            found.append(rel)
    return found, notes


def cmd_brief(args, project, root):
    intel, context = load_module("pyintel"), load_module("context")
    world = build_world(root)
    targets, notes = _locate_all(world, project, root, args.paths)
    if not targets:
        raise Blocked("; ".join(notes) or "no valid target")
    ctx = context.inspect_context(project, [str(root / t) for t in targets], history=not args.no_history,
                                  limit=min(max(args.limit, 1), 32))
    tk = _toolkit_rel(root)
    if tk and ctx.get("dirty"):
        ctx["dirty"]["paths"] = [e for e in ctx["dirty"].get("paths", [])
                                 if not (e["path"].rstrip("/") == tk or e["path"].startswith(tk + "/"))]
    data = intel.brief(world, targets, args.symbol, ctx, args.limit)
    data["notes"] += notes + ([f"index partial: {world.partial} file(s) pending; rerun to complete"] if world.partial else [])
    if args.json:
        return data, 0
    text = intel.render_brief(data, args.limit, _runner(project))
    return text + "".join("\nNOTE: " + n for n in data["notes"]), 0


def cmd_outline(args, project, root):
    intel = load_module("pyintel")
    world = build_world(root)
    targets, notes = _locate_all(world, project, root, [args.file])
    if not targets:
        raise Blocked("; ".join(notes))
    rel = targets[0]
    data = intel.read_small(root / rel)
    if data is None:
        raise Blocked(f"{rel}: unreadable or larger than 1 MiB")
    head = f"{rel}  {len(data.splitlines())}L  sha:{intel.blob_sha(data)[:7]}"
    if not rel.endswith(".py"):
        return head + "\n(no symbol outline for this language; use `slice FILE START-END`)", 0
    facts = world.files.get(rel) or intel.analyze(data)
    if "d" not in facts:
        return head + f"\n[BROKEN: {facts.get('err')}]", 0
    return "\n".join([head] + intel.outline_lines(facts, 10 ** 6 if args.all else 80)), 0


def cmd_slice(args, project, root):
    intel = load_module("pyintel")
    world = build_world(root)
    targets, notes = _locate_all(world, project, root, [args.file])
    if not targets:
        raise Blocked("; ".join(notes))
    data = intel.read_small(root / targets[0])
    if data is None:
        raise Blocked(f"{targets[0]}: unreadable or larger than 1 MiB")
    text, err = intel.slice_view(targets[0], data, args.target, args.context, args.max_lines)
    if err:
        raise Blocked(err)
    return text, 0


def cmd_review(args, project, root, plan=None):
    intel = load_module("pyintel")
    world = build_world(root)
    if args.all:
        everything = intel.audit(world, args.limit * 25)
        found = [f for f in everything if not f["code"].startswith("?")]
        unprovable = [f for f in everything if f["code"].startswith("?")]
        if args.json:
            return {"findings": found, "unprovable": unprovable, "files_indexed": len(world.files),
                    "partial": world.partial}, 1 if found else 0
        lines = [f"audit  {len(world.files)} source file(s) indexed" + (f", {world.partial} not checked yet (time budget; rerun continues)" if world.partial else "")]
        lines += ["  " + intel.finding_line(f, f"E{i}") for i, f in enumerate(found[:args.limit * 3], 1)]
        if unprovable:
            lines.append(f"NOTE: {len(unprovable)} imported name(s) live in dynamic modules (__getattr__/globals) and cannot be "
                         f"proved either way, e.g. {unprovable[0]['path']}:{unprovable[0]['line']}")
        lines.append(f"RESULT: {len(found)} finding(s)" + (f" (showing {args.limit * 3})" if len(found) > args.limit * 3 else "")
                     + (f"  *** INCOMPLETE: {world.partial} file(s) not checked yet (time budget) - rerun to finish ***" if world.partial else ""))
        return "\n".join(lines), 1 if found else 0
    changes = collect_changes(root, project, plan)
    scope = plan["scope"] if plan else None
    res = intel.review(world, changes, touch=(plan or {}).get("touch") or [],
                       in_scope=(lambda rel: any(contains(s, rel) for s in scope)) if scope else None)
    add_history_intelligence(res, root, changes, intel)
    bad = len(res["errors"]) + len(res["likely"]) + len(res["policy"])
    outside = sorted({f["path"] for f in res["errors"] + res["likely"]
                      if scope and not any(contains(s, f["path"]) for s in scope)})
    if args.json:
        res["widen"] = outside
        return res, 1 if bad else 0
    text = intel.render_review(res, args.task, args.limit, "agent.py")
    if outside:
        text = text.replace("\nRESULT:", "\nOUTSIDE SCOPE (must change too): agent.py widen --task "
                            f"{args.task} " + " ".join(outside[:12]) + "\nRESULT:")
    return text, 1 if bad else 0


def cmd_diff(args, project, root, plan=None):
    changes = collect_changes(root, project, plan)
    lines, adds, dels, shown = [], 0, 0, 0
    for ch in changes:
        path = ch["path"]
        if args.file and path != args.file:
            continue
        if ch.get("opaque"):
            lines.append(f"=== {path}  private/opaque change (content never shown)")
            continue
        a, b = ch["old"], ch["new"]
        if (a and b"\0" in a[:8000]) or (b and b"\0" in b[:8000]):
            lines.append(f"=== {path}  binary")
            continue
        al = a.decode("utf-8", "replace").splitlines() if a is not None else []
        bl = b.decode("utf-8", "replace").splitlines() if b is not None else []
        body = list(difflib.unified_diff(al, bl, "a/" + path, "b/" + path, n=args.context, lineterm=""))[2:]
        add = sum(1 for x in body if x.startswith("+"))
        rem = sum(1 for x in body if x.startswith("-"))
        adds, dels = adds + add, dels + rem
        tag = "" if ch.get("in_scope") is None else ("[scope]" if ch["in_scope"] else "[OUT-OF-SCOPE]")
        kind = " (new)" if a is None else (" (deleted)" if b is None else "")
        lines.append(f"=== {path} {tag}{kind} +{add}/-{rem}" + ("  [baseline approximated from HEAD]" if ch.get("approx") else ""))
        cap = 10 ** 6 if args.file else 70
        for x in body[:cap]:
            if shown >= args.max_lines:
                break
            lines.append(x)
            shown += 1
        if len(body) > cap:
            lines.append(f"... +{len(body) - cap} more lines (agent.py diff --file {path})")
        if shown >= args.max_lines:
            lines.append(f"... output capped at {args.max_lines} lines; use --file PATH for one file")
            break
    head = (f"diff  agent changes since begin ({args.task})" if plan else "diff  worktree vs HEAD") + \
           f"  {len(changes)} file(s) +{adds}/-{dels}"
    return head + ("\n" + "\n".join(lines) if lines else "\n(no changes)"), 0


def cmd_history(args, project, root):
    """Read bounded Git evidence for a path or a precise line range, never a risk score."""
    intel, gitmem = load_module("pyintel"), load_module("gitmem")
    world = build_world(root)
    targets, notes = _locate_all(world, project, root, args.paths)
    if not targets:
        raise Blocked("; ".join(notes) or "no valid target")
    if args.lines and len(targets) != 1:
        raise Blocked("--lines needs exactly one file")
    history = gitmem.History.load(root, limit=args.commits, cache_dir=STATE / "cache")
    if args.lines:
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", args.lines)
        if not match:
            raise Blocked("--lines must be LINE or START-END")
        start, end = int(match.group(1)), int(match.group(2) or match.group(1))
        if start < 1 or end < start:
            raise Blocked("--lines must be a positive ascending range")
        blamed, error = history.blame(targets[0], start, end)
        if error:
            raise Blocked(error)
        text = gitmem.render_why(blamed, f":{start}-{end}", args.limit)
    else:
        records = [history.report(path, intel.is_test_path, args.limit) for path in targets]
        text = gitmem.render_history(records, len(history.commits), args.limit, history.head)
    extras = notes + history.notes
    if history.truncated:
        extras.append("history window is truncated; older commits were not considered")
    return text + "".join("\nNOTE: " + item for item in extras[:6]), 0


def cmd_memory(args, project, root, key):
    """Maintain a per-repository, signed evidence ledger for context resets and handoffs."""
    memory = open_memory(root, key)
    action = args.memory_action
    if action == "remember":
        evidence = _memory_evidence(args.evidence)
        result = memory.remember(args.kind, args.fact_key, args.text, evidence=evidence,
                                 confidence=args.confidence, tags=args.tag, actor=args.actor,
                                 task=args.fact_task)
        memory.save()
        fact = dict(result["fact"])
        fact["checked"] = memory._check(fact)
        return report("memory", "REMEMBERED", memory.notes, duplicate=result["duplicate"], fact=fact)
    if action == "forget":
        result = memory.forget(args.fact_id, args.reason, args.actor)
        memory.save()
        return report("memory", "FORGOTTEN", memory.notes, fact=result["fact"], already=result["already"])
    if action == "recall":
        rows = memory.recall(tags=args.tag, kinds=args.kind, query=args.query, key=args.fact_key,
                             limit=args.limit, include_stale=not args.fresh)
        return report("memory", "READY", memory.notes, facts=rows, stats=memory.stats())
    return report("memory", "READY", memory.notes, stats=memory.stats())


def cmd_guard(args):
    paths, cwd = list(args.paths), None
    if args.hook:
        try:
            payload = json.load(sys.stdin)
            tool_input = payload.get("tool_input") or {}
            target = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path")
            cwd = payload.get("cwd")
        except (ValueError, AttributeError):
            return 0
        if not target:
            return 0
        paths = [target]
    try:
        project, root = project_and_root(args.project or os.environ.get("CLAUDE_PROJECT_DIR") or cwd)
        plans = []
        key_path = STATE / ".key"
        if key_path.is_file():
            key = key_path.read_bytes()
            for path in sorted(STATE.glob("task.*.json")):
                try:
                    plan = load(path, key)
                except Blocked:
                    continue
                if plan.get("closed") is not True and plan.get("root") == str(root):
                    plans.append(plan)
        bad = []
        for text in paths:
            p = Path(text)
            p = p if p.is_absolute() else project / p
            try:
                rel = p.relative_to(root).as_posix()
            except ValueError:
                continue  # outside the repository: not our business
            tk = _toolkit_rel(root)
            if tk and rel.startswith(tk + "/.state"):
                bad.append(f"{rel}: toolkit state is never editable")
            elif any(contains(s, rel) for pl in plans for s in pl["protect"]):
                bad.append(f"{rel}: protected path")
            elif plans and not any(contains(s, rel) for pl in plans for s in pl["scope"]):
                bad.append(f"{rel}: outside every open task's scope - add it with a new begin, or abandon the task")
            elif not plans and args.require_task:
                bad.append(f"{rel}: no open task; run agent.py begin --task NAME ... first")
    except (Blocked, OSError, ValueError):
        if args.hook:
            return 0  # fail open inside a hook: a broken guard must not wedge the agent
        raise
    if args.hook:
        if bad:
            print("agentussagefolder guard: " + "; ".join(bad), file=sys.stderr)
            return 2
        return 0
    output({"state": "BLOCKED" if bad else "OK", "reasons": bad})
    return 1 if bad else 0


def command_probe(args, project):
    """Compatibility probe: exact stdout, bounded, no shell."""
    script = Path(args.script)
    if not script.is_absolute():
        script = project / script
    if not script.is_file() or script.is_symlink():
        raise Blocked("probe script must be a regular local file")
    try:
        script.relative_to(project)
    except ValueError:
        raise Blocked("probe script must be inside the project") from None
    if any(parent.is_symlink() for parent in (script, *script.parents) if parent != project):
        raise Blocked("probe script may not traverse a symlink")
    script_rel = script.relative_to(project).as_posix()
    if private(script_rel) or script_rel.startswith(".git/"):
        raise Blocked("probe script is private/runtime data")
    result = run_check([args.python or sys.executable, str(script)], project,
                       command_env(project), args.timeout, capture_limit=MAX_FILE)
    if result["timed_out"] or result.get("error") or result["exit_code"] != 0:
        raise Blocked("probe failed: " + json.dumps(result, sort_keys=True))
    output_bytes = result.pop("_stdout_raw").replace(b"\r", b"")
    if result["stdout"]["bytes"] > MAX_FILE:
        raise Blocked("probe stdout exceeds the bounded artifact limit")
    destination = args.baseline or args.verify_path
    if not destination:
        return report("probe", "CHECKS_PASSED", stdout_sha256=result["stdout"]["sha256"])
    target = Path(destination)
    if not target.is_absolute():
        target = project / target
    try:
        target.relative_to(project)
    except ValueError:
        raise Blocked("probe artifact must remain inside the project") from None
    if any(parent.is_symlink() for parent in (target, *target.parents) if parent != project):
        raise Blocked("probe artifact may not traverse a symlink")
    if args.baseline:
        if target.exists() and target.is_symlink():
            raise Blocked("probe baseline may not be a symlink")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(output_bytes)
        return report("probe", "BASELINE_SAVED", path=str(target.relative_to(project)))
    if not target.is_file() or target.read_bytes() != output_bytes:
        return report("probe", "BLOCKED", ["probe output changed"], path=str(target))
    return report("probe", "CHECKS_PASSED", path=str(target),
                  stdout_sha256=result["stdout"]["sha256"])


# ------------------------------------------------------------------ CLI
def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pretty", action="store_true", help="format JSON for a human")
    parser.add_argument("--version", action="version", version="agentussagefolder " + VERSION)
    subs = parser.add_subparsers(dest="command", required=True)

    def task_cmd(name, help_text):
        sub = subs.add_parser(name, help=help_text)
        sub.add_argument("--task", required=True)
        sub.add_argument("--project", type=Path)
        return sub

    b = subs.add_parser("begin", help="reserve paths and record a baseline")
    b.add_argument("--task", required=True)
    b.add_argument("--project", type=Path)
    b.add_argument("--check", action="append", default=[], help="JSON argv array; repeat for independent checks")
    b.add_argument("--auto-check", action="store_true", help="add pytest over the tests that import the scope files")
    b.add_argument("--touch", action="append", default=[], metavar="SYMBOL",
                   help="declare the functions/classes you intend to change (Python); other logic changes are flagged")
    b.add_argument("--run-baseline", action="store_true",
                   help="run the checks once now, before any edit, to learn what is already failing")
    b.add_argument("--protect", action="append", default=[])
    b.add_argument("--unknown", action="append", default=[])
    b.add_argument("--timeout", type=int, default=300)
    b.add_argument("paths", nargs="+")

    v = task_cmd("verify", "static gate, then run the declared checks fresh")
    v.add_argument("--no-static", action="store_true", help="skip the static gate (recorded as skipped)")
    task_cmd("status", "show the receipt state")
    task_cmd("close", "close a fresh CHECKS_PASSED receipt")
    task_cmd("abandon", "release a task's reservation without verifying")
    r = task_cmd("restore", "put paths back to their exact content at begin")
    r.add_argument("paths", nargs="+")
    w = task_cmd("widen", "add paths to a task's scope (same baseline), e.g. callers review says must change")
    w.add_argument("paths", nargs="+")

    d = subs.add_parser("diff", help="compact diff of YOUR changes (--task) or worktree vs HEAD")
    d.add_argument("--task")
    d.add_argument("--project", type=Path)
    d.add_argument("--file")
    d.add_argument("--max-lines", type=int, default=220)
    d.add_argument("-U", "--context", type=int, default=1)

    rv = subs.add_parser("review", help="static review: touched symbols, broken callers, invented imports/names")
    rv.add_argument("--task")
    rv.add_argument("--project", type=Path)
    rv.add_argument("--all", action="store_true", help="audit the whole repo instead of a change set")
    rv.add_argument("--limit", type=int, default=12)
    rv.add_argument("--json", action="store_true")

    br = subs.add_parser("brief", help="one-shot pre-edit briefing: outline, importers, refs, tests, co-change")
    br.add_argument("--project", type=Path)
    br.add_argument("--symbol")
    br.add_argument("--limit", type=int, default=6)
    br.add_argument("--no-history", action="store_true")
    br.add_argument("--json", action="store_true")
    br.add_argument("paths", nargs="+")

    hist = subs.add_parser("history", help="Git evidence: prior fixes, reverts, guards and coupling for paths")
    hist.add_argument("--project", type=Path)
    hist.add_argument("--lines", help="explain why one line or START-END exists (uses git blame)")
    hist.add_argument("--commits", type=int, default=3000, help="bounded history window (50-40000)")
    hist.add_argument("--limit", type=int, default=6)
    hist.add_argument("paths", nargs="+")

    o = subs.add_parser("outline", help="symbols with line ranges and signatures (read less)")
    o.add_argument("--project", type=Path)
    o.add_argument("--all", action="store_true")
    o.add_argument("file")

    s = subs.add_parser("slice", help="print one symbol (or START-END lines) with line numbers")
    s.add_argument("--project", type=Path)
    s.add_argument("--context", type=int, default=0)
    s.add_argument("--max-lines", type=int, default=150)
    s.add_argument("file")
    s.add_argument("target", help="Class.method | function | START-END")

    g = subs.add_parser("guard", help="edit-time check: is PATH inside an open task's scope? (hook-friendly)")
    g.add_argument("--project", type=Path)
    g.add_argument("--hook", action="store_true", help="read a Claude Code PreToolUse JSON payload on stdin")
    g.add_argument("--require-task", action="store_true")
    g.add_argument("paths", nargs="*")

    mem = subs.add_parser("memory", help="signed, evidence-backed repository knowledge across agent sessions")
    mem.add_argument("--project", type=Path)
    memsubs = mem.add_subparsers(dest="memory_action", required=True)
    ms = memsubs.add_parser("status", help="show ledger health and stale-fact count")
    mr = memsubs.add_parser("recall", help="recall facts; every recognized evidence item is re-checked")
    mr.add_argument("--tag", action="append", default=[])
    mr.add_argument("--kind", action="append", default=[])
    mr.add_argument("--key", dest="fact_key")
    mr.add_argument("--query")
    mr.add_argument("--limit", type=int, default=8)
    mr.add_argument("--fresh", action="store_true", help="hide stale facts instead of treating them as current")
    mw = memsubs.add_parser("remember", help="write one bounded fact with explicit evidence/confidence")
    mw.add_argument("--kind", required=True)
    mw.add_argument("--key", dest="fact_key", default="")
    mw.add_argument("--text", required=True)
    mw.add_argument("--evidence", help="JSON evidence array: commit/file/test/command objects")
    mw.add_argument("--confidence", choices=("proved", "reported", "hypothesis"), default="reported")
    mw.add_argument("--tag", action="append", default=[])
    mw.add_argument("--actor", default="agent")
    mw.add_argument("--task", dest="fact_task")
    mf = memsubs.add_parser("forget", help="supersede a fact without deleting its audit trail")
    mf.add_argument("fact_id")
    mf.add_argument("--reason", default="")
    mf.add_argument("--actor", default="agent")

    listing = subs.add_parser("list", help="list local task receipts")
    listing.add_argument("--project", type=Path)

    inspect = subs.add_parser("inspect", help="legacy bounded context (prefer brief)")
    inspect.add_argument("--project", type=Path)
    inspect.add_argument("--history", action="store_true")
    inspect.add_argument("--symbol")
    inspect.add_argument("--limit", type=int, default=8)
    inspect.add_argument("paths", nargs="*")

    probe = subs.add_parser("probe", help="run a legacy deterministic stdout probe")
    probe.add_argument("--project", type=Path)
    probe.add_argument("--script", required=True)
    probe.add_argument("--baseline")
    probe.add_argument("--verify", dest="verify_path")
    probe.add_argument("--python")
    probe.add_argument("--timeout", type=int, default=300)
    return parser


TEXT_COMMANDS = {"brief", "outline", "slice", "review", "diff", "history"}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "timeout", 300) < 1 or getattr(args, "timeout", 300) > 3600:
        output(report("tool", "BLOCKED", ["timeout must be between 1 and 3600 seconds"]), args.pretty)
        return 2
    try:
        if POLICY_ERROR:
            raise Blocked(POLICY_ERROR)
        command = args.command
        if command == "inspect":
            project, _ = project_and_root(args.project)
            module = load_module("context")
            result = module.inspect_context(project, args.paths, history=args.history,
                                            symbol=args.symbol, limit=args.limit)
            output(result, args.pretty)
            return 2 if result["errors"] else 0
        if command == "probe":
            project, _ = project_and_root(args.project)
            if args.baseline and args.verify_path:
                raise Blocked("probe accepts only --baseline or --verify")
            result = command_probe(args, project)
            output(result, args.pretty)
            return 0 if result["state"] != "BLOCKED" else 1
        if command == "guard":
            return cmd_guard(args)
        if command in TEXT_COMMANDS:
            plan = None
            if command in {"review", "diff"} and args.task:
                plan = read_plan(args.task)
                project, root = plan_project(plan, args.project)
            else:
                project, root = project_and_root(getattr(args, "project", None))
            if command == "review" and args.task and args.all:
                raise Blocked("--all audits the whole repo; do not combine it with --task")
            handler = {"brief": cmd_brief, "outline": cmd_outline, "slice": cmd_slice,
                       "review": cmd_review, "diff": cmd_diff, "history": cmd_history}[command]
            payload, code = handler(args, project, root, plan) if command in {"review", "diff"} else handler(args, project, root)
            if isinstance(payload, str):
                print(payload)
            else:
                output(payload, args.pretty)
            return code

        with locked() as (key, lock_fd):
            if command == "begin":
                if not NAME.fullmatch(args.task):
                    raise Blocked("invalid task name")
                project, root = project_and_root(args.project)
                result = begin(args, project, root, key)
            elif command in {"verify", "status", "close", "abandon", "restore", "widen", "memory"}:
                if command == "memory":
                    project, root = project_and_root(args.project)
                    result = cmd_memory(args, project, root, key)
                else:
                    _, plan = load_plan(args.task, key)
                    project, root = plan_project(plan, args.project)
                    if command == "verify":
                        result = verify(args, plan, project, root, key, lock_fd)
                    elif command == "close":
                        result = close_task(args, plan, project, root, key)
                    elif command == "abandon":
                        result = abandon_task(args, plan, key)
                    elif command == "restore":
                        result = restore_task(args, plan, project, root, key)
                    elif command == "widen":
                        result = widen_task(args, plan, project, root, key)
                    else:
                        current = snapshot(root)
                        env_id = identity(project, plan["checks"], command_env(project))
                        result = status(args.task, plan, current, env_id)
            else:  # list
                project, root = project_and_root(args.project)
                rows = []
                for path in sorted(STATE.glob("task.*.json")):
                    task = path.name[5:-5]
                    plan = load(path, key)
                    if (plan.get("root") == str(root) and
                            (args.project is None or plan.get("project") == str(project))):
                        state = ("ABANDONED" if plan.get("abandoned") else "CLOSED") if plan.get("closed") \
                            else (plan.get("last") or {}).get("state", "READY")
                        rows.append({"task": task, "state": state, "scope": plan.get("scope", [])})
                result = {"state": "READY", "tasks": rows}
        output(result, args.pretty)
        return 0 if result.get("state") not in {"BLOCKED", "STALE", "CLOSED_STALE"} else 1
    except BrokenPipeError:
        raise
    except (Blocked, OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        output(report(getattr(args, "task", None) or "tool", "BLOCKED", [str(exc)]), args.pretty)
        return 2
    except Exception as exc:  # noqa: BLE001 - never dump a traceback into an agent's context
        if os.environ.get("AGENT_DEBUG"):
            raise
        output(report(getattr(args, "task", None) or "tool", "BLOCKED",
                      [f"internal error {type(exc).__name__}: {str(exc)[:160]} (set AGENT_DEBUG=1 for a traceback)"]), args.pretty)
        return 2


if __name__ == "__main__":
    try:
        code = main()
        sys.stdout.flush()
    except BrokenPipeError:  # `... | head`: exit quietly instead of a traceback
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        code = 1
    raise SystemExit(code)
