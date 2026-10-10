#!/usr/bin/env python3
"""Compare a check's own output before and after a change (stdlib only, no execution).

A green run is not evidence that nothing broke: a check goes green when tests are deleted, when
collection silently collapses to zero, or when a new failure hides inside an already-red suite.
This module reads the *text of the same command* at two points in time - recorded before the edit
and again after it - and reports only what the numbers prove:

* ``W-SILENT``     the check ran no tests at all now, when it ran some before
* ``W-COUNT``      the check ran fewer tests than before (deleted, skipped or deselected)
* ``W-REGRESSION`` tests are failing that were not failing before, or fewer tests pass

Nothing is inferred when the numbers cannot be parsed: an unparsable tail produces no warning,
because a guess here would be worse than silence. Only the same command (identical argv) is ever
compared with itself.
"""

from __future__ import annotations

import re

MAX_TEXT = 40000
_FAILED_NAME_CAP = 40

# pytest: "1 failed, 205 passed, 3 skipped in 1.23s"
_PYTEST_COUNT = re.compile(r"(\d+)\s+(failed|passed|error|errors|skipped|xfailed|xpassed|deselected)\b")
# pytest failure list (-q / short summary): "FAILED tests/test_x.py::test_y - AssertionError"
_PYTEST_FAILED = re.compile(r"^(?:FAILED|ERROR)\s+(\S+)", re.M)
# unittest: "Ran 12 tests in 0.003s" and "FAILED (failures=2, errors=1)" / "OK (skipped=1)"
_UNITTEST_TOTAL = re.compile(r"^Ran (\d+) tests? in ", re.M)
_UNITTEST_RESULT = re.compile(r"^(?:FAILED|OK)\b(.*)$", re.M)
_UNITTEST_KV = re.compile(r"(failures|errors|skipped|expected failures|unexpected successes)=(\d+)")
_UNITTEST_NAME = re.compile(r"^(?:FAIL|ERROR):\s+(\S+)", re.M)
# jest: "Tests: 1 failed, 2 passed, 3 total"
_JEST_TOTAL = re.compile(r"Tests:\s+(.*)", re.M)
# go: "--- FAIL: TestName" / "ok  pkg  0.1s"
_GO_FAILED = re.compile(r"^\s*--- FAIL:\s+(\S+)", re.M)
# cargo: "test result: FAILED. 3 passed; 1 failed; 0 ignored"
_CARGO = re.compile(r"test result:.*?(\d+) passed;\s*(\d+) failed", re.M)


def _counts_from_pytest(text):
    found = {}
    for number, label in _PYTEST_COUNT.findall(text):
        key = {"error": "errors", "errors": "errors"}.get(label, label)
        found[key] = found.get(key, 0) + int(number)
    if not found:
        return None
    total = sum(found.get(k, 0) for k in ("passed", "failed", "errors", "skipped", "xfailed", "xpassed"))
    if total == 0:
        return None
    return {"passed": found.get("passed", 0), "failed": found.get("failed", 0),
            "errors": found.get("errors", 0), "skipped": found.get("skipped", 0), "total": total,
            "engine": "pytest"}


def _counts_from_unittest(text):
    total = _UNITTEST_TOTAL.search(text)
    if not total:
        return None
    counts = {"passed": None, "failed": 0, "errors": 0, "skipped": 0, "total": int(total.group(1)),
              "engine": "unittest"}
    result = _UNITTEST_RESULT.search(text)
    if result:
        for key, value in _UNITTEST_KV.findall(result.group(1)):
            key = {"expected failures": "skipped", "unexpected successes": "skipped"}.get(key, key)
            counts[key] = counts.get(key, 0) + int(value)
    counts["passed"] = max(0, counts["total"] - counts["failed"] - counts["errors"] - counts["skipped"])
    counts["skipped"] = counts.get("skipped", 0)
    return counts


def _counts_from_jest(text):
    match = _JEST_TOTAL.search(text)
    if not match:
        return None
    found = {}
    for number, label in re.findall(r"(\d+)\s+(failed|passed|errors|skipped|total)\b", match.group(1)):
        found[label] = found.get(label, 0) + int(number)
    if "total" not in found:
        return None
    return {"passed": int(found.get("passed", 0)), "failed": int(found.get("failed", 0)),
            "errors": int(found.get("errors", 0)), "skipped": int(found.get("skipped", 0)),
            "total": int(found["total"]), "engine": "jest"}


def _counts_from_cargo(text):
    match = _CARGO.search(text)
    if not match:
        return None
    passed, failed = int(match.group(1)), int(match.group(2))
    return {"passed": passed, "failed": failed, "errors": 0, "skipped": 0,
            "total": passed + failed, "engine": "cargo"}


def parse_counts(text):
    """(counts|None, failed_names) parsed from a check's own summary output."""
    if not text:
        return None, set()
    text = text[-MAX_TEXT:]
    names = set()
    for pattern in (_PYTEST_FAILED, _UNITTEST_NAME, _GO_FAILED):
        names.update(match.strip() for match in pattern.findall(text))
    # Jest's ``Tests:`` line also contains ``N passed`` and would otherwise look like
    # a one-line pytest summary.  Try its distinctive grammar first.
    for builder in (_counts_from_jest, _counts_from_pytest, _counts_from_unittest, _counts_from_cargo):
        counts = builder(text)
        if counts:
            return counts, set(sorted(names)[:_FAILED_NAME_CAP])
    return None, set(sorted(names)[:_FAILED_NAME_CAP])


def _warning(code, msg, fix):
    return {"code": code, "line": None, "path": "-", "msg": msg, "fix": fix}


def compare(before_text, after_text):
    """Warnings proved by comparing the same command's summary at two points in time."""
    before, before_names = parse_counts(before_text)
    after, after_names = parse_counts(after_text)
    if not before or not after:
        return []                      # cannot compare: say nothing rather than guess
    out = []
    if after["total"] == 0 and before["total"] > 0:
        out.append(_warning("W-SILENT", f"this check ran 0 tests now (it ran {before['total']} before): "
                                        "collection collapsed - import error, wrong path, or everything deselected",
                            "run the check directly and read its output before believing a green result"))
        return out
    if after["total"] < before["total"]:
        out.append(_warning("W-COUNT", f"this check ran {before['total'] - after['total']} fewer test(s) "
                                       f"({after['total']} now, {before['total']} before)",
                            "restore what was skipped/deselected/removed, or say in your summary why it is gone"))
    new_failures = sorted(name for name in (after_names - before_names))[:4]
    grew = after["failed"] + after["errors"] > before["failed"] + before["errors"]
    if new_failures:
        out.append(_warning("W-REGRESSION", "test(s) failing now that were not failing before: "
                                            + ", ".join(new_failures),
                            "these are probably yours; read the failure tail"))
    elif grew:
        out.append(_warning("W-REGRESSION", f"this check reports more failures than at baseline "
                                            f"({after['failed'] + after['errors']} now, "
                                            f"{before['failed'] + before['errors']} before)",
                            "compare the two failure lists; do not assume the extra one is pre-existing"))
    elif (before["passed"] is not None and after["passed"] is not None
          and after["passed"] < before["passed"]):
        out.append(_warning("W-REGRESSION", f"fewer tests pass than at baseline ({after['passed']} now, "
                                            f"{before['passed']} before) with no new failure names reported",
                            "find out which tests stopped passing"))
    return out
