#!/usr/bin/env python3
"""Verification-adequacy evidence for a code-change task (stdlib only).

Passing a command is weaker than proving it was relevant.  This module connects three facts that
agents otherwise keep separate:

1. a source file actually changed;
2. the repository names tests that reach it now, or that historically guarded a fix there;
3. one of the *declared JSON-argv checks* plausibly selects each of those tests.

The output is a proof matrix, not coverage measurement.  It never claims a broad suite executed
one particular test, and it never treats a missing import graph for another language as a failed
test.  Those become ``UNKNOWN``.  ``DEBT`` is reserved for stronger evidence: a Python source
file with no reaching test, or a current/history guard that the declared test command clearly
does not select.
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath

MAX_ROWS = 80


def _norm(path):
    return str(PurePosixPath(path.replace("\\", "/"))).lstrip("./")


def _looks_like_test_path(arg):
    path = _norm(arg)
    name = path.rsplit("/", 1)[-1].lower()
    return ("test" in name or "/test" in "/" + path.lower() or "/spec" in "/" + path.lower()
            or name.endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts")))


def _runner(argv):
    text = " ".join(argv).lower()
    first = PurePosixPath(argv[0]).name.lower() if argv else ""
    if "pytest" in text or first in {"pytest", "py.test"}:
        return "pytest"
    if first in {"npm", "yarn", "pnpm", "bun"} and "test" in text:
        return "js-test"
    if first == "cargo" and "test" in argv[1:]:
        return "cargo"
    if first == "go" and "test" in argv[1:]:
        return "go"
    if first in {"gradle", "gradlew", "mvn", "mvnw"} and "test" in text:
        return "jvm-test"
    if first == "dotnet" and "test" in argv[1:]:
        return "dotnet"
    if "unittest" in text:
        return "unittest"
    return None


def _explicit(argv, test):
    test = _norm(test)
    base = test.rsplit("/", 1)[-1]
    args = {_norm(arg) for arg in argv if arg and not arg.startswith("-")}
    return test in args or (base in args and sum(1 for arg in args if arg == base) == 1)


def _broad_test_arg(arg):
    path = _norm(arg).rstrip("/").lower()
    return path in {".", "test", "tests", "spec", "specs", "__tests__"} or path.endswith(
        ("/test", "/tests", "/spec", "/specs", "/__tests__"))


def coverage_for(checks, test, project_test=None):
    """How the declared checks select ``test``: explicit, suite, missed, or unknown.

    ``suite`` is deliberately modest: it means the runner's normal project-wide form was
    declared, not that the tool measured coverage.  ``missed`` is emitted only for a recognizable
    test runner whose argv explicitly targets other test paths.  Everything else stays unknown.
    """
    test = _norm(test)
    alternatives = {test}
    if project_test:
        alternatives.add(_norm(project_test))
    seen_runner, targeted = False, False
    for argv in checks:
        if not argv:
            continue
        if any(_explicit(argv, candidate) for candidate in alternatives):
            return "explicit"
        runner = _runner(argv)
        if not runner:
            continue
        seen_runner = True
        test_args = [arg for arg in argv[1:] if _looks_like_test_path(arg)]
        if any(_broad_test_arg(arg) for arg in test_args):
            return "suite"
        if test_args:
            targeted = True
            continue
        # A project-wide runner invocation is credible selection evidence.  This applies to
        # test runner commands only; lint/build commands remain unknown by design.
        if runner in {"pytest", "js-test", "cargo", "go", "jvm-test", "dotnet", "unittest"}:
            return "suite"
    if seen_runner and targeted:
        return "missed"
    return "unknown"


def assess(sources, checks):
    """Build a bounded proof matrix from source/test/history facts supplied by the caller.

    ``sources`` rows use ``path``, ``python`` and optional ``tests`` / ``guards`` lists.  Test
    entries can be a path string or ``{path, project_path}``.  The pure model makes the policy
    testable without a Git repository or a particular language runtime.
    """
    rows, debts, unknown = [], [], []
    for source in sources[:MAX_ROWS]:
        path, is_python = source["path"], bool(source.get("python"))
        candidates = {}
        for item in source.get("tests") or []:
            row = item if isinstance(item, dict) else {"path": item}
            candidates.setdefault(row["path"], {**row, "origin": "reachability"})
        for item in source.get("guards") or []:
            row = item if isinstance(item, dict) else {"path": item}
            present = candidates.setdefault(row["path"], {**row, "origin": "history"})
            if present["origin"] != "history":
                present["origin"] = "reachability+history"
        if not candidates:
            if is_python:
                debts.append({"kind": "NO_TEST", "path": path,
                              "msg": "no repository test reaches this changed Python source file"})
            else:
                unknown.append({"kind": "NO_GRAPH", "path": path,
                                "msg": "no language-aware test reachability is available; declared checks are command evidence only"})
            continue
        for test, item in sorted(candidates.items()):
            coverage = coverage_for(checks, test, item.get("project_path"))
            row = {"source": path, "test": test, "origin": item["origin"], "coverage": coverage}
            rows.append(row)
            if coverage == "missed":
                debts.append({"kind": "MISSED_TEST", "path": test,
                              "msg": f"{item['origin']} test for {path} is not selected by a declared test command"})
            elif coverage == "unknown":
                unknown.append({"kind": "UNKNOWN_SELECTION", "path": test,
                                "msg": f"cannot prove a declared command selects this {item['origin']} test for {path}"})
    summary = {"sources": len(sources), "tests": len(rows), "covered": sum(r["coverage"] in {"explicit", "suite"} for r in rows),
               "debts": len(debts), "unknown": len(unknown)}
    return {"summary": summary, "rows": rows[:MAX_ROWS], "debts": debts[:MAX_ROWS], "unknown": unknown[:MAX_ROWS]}


def render(result, limit=12):
    """Small, action-oriented representation suitable for an agent context window."""
    summary = result["summary"]
    lines = [f"proof  {summary['sources']} changed source file(s) · {summary['tests']} linked test(s) · "
             f"{summary['covered']} selected · {summary['debts']} debt(s) · {summary['unknown']} unknown"]
    for row in result["rows"][:limit]:
        lines.append(f"  {row['coverage'].upper():<8} {row['source']} <- {row['test']} [{row['origin']}]")
    for debt in result["debts"][:limit]:
        lines.append(f"  DEBT [{debt['kind']}] {debt['path']}  {debt['msg']}")
    for item in result["unknown"][:max(0, limit - len(result["debts"]))]:
        lines.append(f"  UNKNOWN {item['path']}  {item['msg']}")
    hidden = len(result["rows"]) + len(result["debts"]) + len(result["unknown"]) - (len(lines) - 1)
    if hidden > 0:
        lines.append(f"  (+{hidden} more; use --json for the evidence matrix)")
    lines.append("NOTE: selected means the declared argv names the test or is a project-wide test runner; it is not coverage measurement.")
    return "\n".join(lines)
