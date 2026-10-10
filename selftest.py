#!/usr/bin/env python3
"""Self-test for agentussagefolder: builds throwaway git repos and drives the toolkit end to end.

    python3 agentussagefolder/selftest.py        # stdlib only, no network, ~1 minute
    python3 agentussagefolder/selftest.py -k guard   # run scenarios whose name contains "guard"

Exit code 0 = every check passed.  Run it once after pasting the folder into a new project.
"""
from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import checkdiff

HERE = Path(__file__).resolve().parent
PY = sys.executable
PASSES, FAILS = 0, []
UNITTEST = json.dumps(["python3", "-m", "unittest", "discover", "-s", "tests", "-t", "."])

FILES = {
    ".gitignore": ".idea/\nscratch2/\n",
    "pkg/__init__.py": "",
    "pkg/util.py": "def helper(a, b):\n    return a + b\n\n\nclass Box:\n    def __init__(self, size, color=\"red\"):\n"
                   "        self.size = size\n        self.color = color\n\n\n"
                   "def summarize(rows):\n    total = 0\n    count = 0\n    for row in rows:\n        if row is None:\n"
                   "            continue\n        total += row\n        count += 1\n    if count == 0:\n        return 0\n"
                   "    return total / count\n",
    "pkg/risk.py": "def max_notional_usd(x):\n    return x * 2\n",
    "pkg/orders.py": "from pkg import risk\nfrom pkg.util import Box, helper\n\n\nclass OrderBook:\n"
                     "    def place_order(self, side, qty, px=None):\n        return helper(qty, 1) + risk.max_notional_usd(qty)\n\n\n"
                     "def cancel(order_id):\n    box = Box(3)\n    return helper(order_id, box.size)\n",
    "app.py": "from pkg.orders import OrderBook, cancel\nfrom pkg.util import helper\n\n"
              "print(helper(1, 2), cancel(5), OrderBook().place_order(\"b\", 1))\n",
    "tests/__init__.py": "",
    "tests/test_orders.py": "import unittest\n\nfrom pkg.orders import OrderBook, cancel\nfrom pkg.util import helper\n\n\n"
                           "class T(unittest.TestCase):\n    def test_place(self):\n"
                           "        self.assertEqual(OrderBook().place_order(\"b\", 2), 7)\n\n    def test_helper(self):\n"
                           "        self.assertEqual(helper(1, 2), 3)\n\n    def test_cancel(self):\n"
                           "        self.assertEqual(cancel(5), 8)\n",
    "web/a.ts": "export const a = 1;\n",
    "web/b.ts": "import { a } from './a';\nexport const b = a + 1;\n",
    "web/c.ts": "import { a } from './a';\nexport const c = a;\n",
    ".idea/workspace.xml": "<project/>\n",
}


def check(name, cond, detail=""):
    global PASSES
    if cond:
        PASSES += 1
    else:
        FAILS.append(f"{name} {detail}"[:400])
        print(f"    FAIL  {name}  {str(detail)[:220]}")


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


class Repo:
    def __init__(self, files=FILES, commit=True, commit_toolkit=False, toolkit=True):
        self.root = Path(tempfile.mkdtemp(prefix="agentselftest-"))
        git(self.root, "init", "-q", ".")
        git(self.root, "config", "user.email", "t@t")
        git(self.root, "config", "user.name", "t")
        for rel, text in files.items():
            self.write(rel, text)
        if commit:
            git(self.root, "add", "-A")
            git(self.root, "commit", "-qm", "init")
        if toolkit:
            dest = self.root / "agentussagefolder"
            # When the toolkit is developed from a checkout, do not accidentally copy that
            # checkout's .git directory into the throwaway project: Git then records it as an
            # embedded repository/submodule rather than testing a normal tracked toolkit.
            shutil.copytree(HERE, dest, ignore=shutil.ignore_patterns(".state", "__pycache__", "policy.json", ".git"))
            if commit_toolkit:
                git(self.root, "add", "-A")
                git(self.root, "commit", "-qm", "toolkit")

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def read(self, rel):
        return (self.root / rel).read_text(encoding="utf-8")

    def sub(self, rel, old, new, count=1):
        text = self.read(rel)
        assert old in text, (rel, old)
        self.write(rel, text.replace(old, new, count))

    def run(self, *args, stdin=None, env=None):
        e = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        e.update(env or {})
        p = subprocess.run([PY, str(self.root / "agentussagefolder" / "agent.py"), *args], cwd=self.root,
                           capture_output=True, text=True, input=stdin, env=e, timeout=120)
        return p.returncode, p.stdout, p.stderr

    def js(self, *args, **kw):
        code, out, err = self.run(*args, **kw)
        try:
            return code, json.loads(out)
        except ValueError:
            return code, {"state": "UNPARSEABLE", "reasons": [out[:300], err[:300]]}

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


SCENARIOS = []


def scenario(fn):
    SCENARIOS.append(fn)
    return fn


@scenario
def brief_outline_slice():
    r = Repo()
    code, out, _ = r.run("brief", "pkg/orders.py", "--symbol", "place_order")
    check("brief ok", code == 0, out[:200])
    check("brief shows importers", "app.py" in out and "tests/test_orders.py" in out, out)
    check("brief shows probable method caller", "PROBABLE" in out and "app.py:4" in out, out)
    check("brief shows tests", "TESTS:" in out and "tests/test_orders.py" in out, out)
    code, out, _ = r.run("brief", "orders.py")
    check("brief locates by basename", code == 0 and "TARGET pkg/orders.py" in out, out[:200])
    code, out, _ = r.run("brief", "pkg/orderz.py")
    check("brief suggests close paths", code == 2 and "pkg/orders.py" in out, out)
    code, data = r.js("brief", "pkg/util.py", "--symbol", "helper", "--json")
    refs = data.get("refs", {})
    files = {c[0] for c in refs.get("confirmed", [])}
    check("confirmed refs repo-wide", {"app.py", "pkg/orders.py", "tests/test_orders.py"} <= files, refs)
    code, out, _ = r.run("outline", "pkg/orders.py")
    check("outline", "class OrderBook" in out and "def cancel(order_id)" in out, out)
    code, out, _ = r.run("slice", "pkg/orders.py", "OrderBook.place_order")
    check("slice symbol", code == 0 and "def place_order" in out and "return helper" in out, out)
    code, out, _ = r.run("slice", "pkg/orders.py", "place_ordr")
    check("slice typo suggests", code == 2 and "place_order" in out, out)
    code, out, _ = r.run("slice", "pkg/orders.py", "1-3")
    check("slice range", code == 0 and "from pkg import risk" in out, out)
    r.cleanup()


@scenario
def collateral_damage_loop():
    r = Repo()
    code, d = r.js("begin", "--task", "t1", "--check", UNITTEST, "pkg/util.py")
    check("begin READY", d.get("state") == "READY", d)
    code, d2 = r.js("begin", "--task", "t1", "--check", UNITTEST, "pkg/util.py")
    check("begin idempotent", d2.get("state") == "READY", d2)
    code, d3 = r.js("begin", "--task", "t1", "--check", UNITTEST, "pkg/risk.py")
    check("begin conflicting redo explains", d3.get("state") == "BLOCKED" and "abandon" in json.dumps(d3), d3)
    r.sub("pkg/util.py", "def helper(a, b):\n    return a + b", "def helper(a, b, c):\n    return a + b + c")
    code, out, _ = r.run("review", "--task", "t1")
    check("review flags broken callers", code == 1 and out.count("[CALL]") >= 3, out)
    check("review suggests widen", "agent.py widen --task t1" in out, out)
    code, d = r.js("verify", "--task", "t1")
    check("verify fast-fails on static", d.get("state") == "BLOCKED" and any("static" in x for x in d.get("reasons", [])), d)
    check("verify lists findings", any("[CALL]" in x for x in d.get("static", [])), d)
    code, d = r.js("widen", "--task", "t1", "app.py", "pkg/orders.py", "tests/test_orders.py")
    check("widen ok", "widened" in d and d.get("state") in ("READY", "UNVERIFIED"), d)
    r.sub("app.py", "helper(1, 2)", "helper(1, 2, 0)")
    r.sub("pkg/orders.py", "helper(qty, 1)", "helper(qty, 1, 0)")
    r.sub("pkg/orders.py", "helper(order_id, box.size)", "helper(order_id, box.size, 0)")
    r.sub("tests/test_orders.py", "helper(1, 2)", "helper(1, 2, 0)")
    code, out, _ = r.run("review", "--task", "t1")
    check("review clean after fixes", code == 0 and "no definite findings" in out, out)
    code, d = r.js("verify", "--task", "t1")
    check("verify passes", d.get("state") == "CHECKS_PASSED", d)
    code, d = r.js("status", "--task", "t1")
    check("status passed", d.get("state") == "CHECKS_PASSED", d)
    r.sub("pkg/util.py", "return a + b + c", "return a + b + c  # touched again")
    code, d = r.js("status", "--task", "t1")
    check("status stale after edit", d.get("state") == "STALE", d)
    code, d = r.js("verify", "--task", "t1")
    check("verify again passes", d.get("state") == "CHECKS_PASSED", d)
    code, d = r.js("close", "--task", "t1")
    check("close", d.get("state") == "CLOSED", d)
    r.cleanup()


@scenario
def hallucination_detection():
    r = Repo()
    r.js("begin", "--task", "h", "--check", UNITTEST, "pkg/orders.py")
    r.sub("pkg/orders.py", "from pkg import risk\n", "from pkg import risk\nfrom pkg.risk import max_notional\nfrom pkg.riskk import x\n")
    r.sub("pkg/orders.py", "return helper(qty, 1) + risk.max_notional_usd(qty)",
          "tmp = normalise(qty)\n        return helper(qty, 1, mode=2) + risk.max_notional(qty) + Box(1, colour=1).size")
    code, out, _ = r.run("review", "--task", "h")
    check("hallucinated name import", "`max_notional` is not defined in pkg/risk.py" in out and "max_notional_usd" in out, out)
    check("hallucinated module import", "no module `pkg.riskk`" in out, out)
    check("hallucinated attribute", "risk.max_notional" in out and "has no `max_notional`" in out, out)
    check("undefined name", "undefined name `normalise`" in out, out)
    check("wrong keyword suggests", "unexpected keyword `mode`" in out and "unexpected keyword `colour`" in out and "did you mean `color`" in out, out)
    check("review blocks", code == 1, code)
    code, d = r.js("verify", "--task", "h")
    check("verify blocked by static", d.get("state") == "BLOCKED", d)
    code, d = r.js("verify", "--task", "h", "--no-static")
    check("--no-static is explicit", d.get("state") in ("BLOCKED", "CHECKS_PASSED") and "static" not in d, d)
    r.cleanup()


@scenario
def removed_symbol_and_deleted_module():
    r = Repo()
    r.js("begin", "--task", "rm", "--check", UNITTEST, "pkg/util.py", "pkg/risk.py")
    r.sub("pkg/util.py", "def helper(a, b):\n    return a + b", "def helper2(a, b):\n    return a + b")
    (r.root / "pkg" / "risk.py").unlink()
    code, out, _ = r.run("review", "--task", "rm")
    check("removed name breaks importers", "`helper` was removed/renamed in pkg/util.py" in out, out)
    check("deleted module breaks importers", "pkg/orders.py:1  imports pkg/risk.py, which was deleted" in out, out)
    r.cleanup()


@scenario
def scope_restore_and_diff():
    r = Repo()
    r.js("begin", "--task", "s", "--check", UNITTEST, "pkg/util.py")
    r.sub("pkg/util.py", "self.color = color", "self.color = color  # ok")
    r.sub("pkg/risk.py", "x * 2", "x * 3")
    code, d = r.js("verify", "--task", "s")
    check("out-of-scope blocks", d.get("state") == "BLOCKED" and any("outside-scope" in x for x in d.get("reasons", [])), d)
    check("hint offers restore/widen", any("restore --task s pkg/risk.py" in x and "widen" in x for x in d.get("reasons", [])), d)
    code, out, _ = r.run("diff", "--task", "s")
    check("diff marks out-of-scope", "[OUT-OF-SCOPE]" in out and "pkg/risk.py" in out and "[scope]" in out, out)
    code, d = r.js("restore", "--task", "s", "pkg/risk.py")
    check("restore ok", d.get("state") == "RESTORED", d)
    check("restore exact", r.read("pkg/risk.py") == FILES["pkg/risk.py"])
    code, d = r.js("verify", "--task", "s")
    check("verify passes after restore", d.get("state") == "CHECKS_PASSED", d)
    r.write("pkg/new_file.py", "x = 1\n")
    code, d = r.js("status", "--task", "s")
    check("new out-of-scope file blocks", d.get("state") == "BLOCKED", d)
    code, d = r.js("restore", "--task", "s", "pkg/new_file.py")
    check("restore removes agent-created file", d.get("state") == "RESTORED" and not (r.root / "pkg/new_file.py").exists(), d)
    r.cleanup()


@scenario
def preexisting_dirty_work_is_preserved():
    r = Repo()
    user_version = FILES["pkg/risk.py"] + "# USER'S UNCOMMITTED WORK\n"
    r.write("pkg/risk.py", user_version)
    code, d = r.js("begin", "--task", "dirty", "--check", UNITTEST, "pkg/risk.py", "pkg/util.py")
    check("begin with dirty file", d.get("state") == "READY", d)
    r.sub("pkg/util.py", "self.size = size", "self.size = size  # agent")
    r.sub("pkg/risk.py", "x * 2", "x * 5")
    code, out, _ = r.run("diff", "--task", "dirty")
    check("diff shows only agent hunk in dirty file",
          "+    return x * 5" in out and "-    return x * 2" in out and "+# USER" not in out and "-# USER" not in out, out)
    code, d = r.js("restore", "--task", "dirty", "pkg/risk.py")
    check("restore goes to user's version, not HEAD", d.get("state") == "RESTORED" and r.read("pkg/risk.py") == user_version, d)
    code, out, _ = r.run("review")
    check("review (no task) vs HEAD sees user work", "pkg/risk.py" in out, out)
    r.cleanup()


@scenario
def symbol_intent_touch():
    r = Repo()
    code, d = r.js("begin", "--task", "typo", "--check", UNITTEST, "--touch", "OrderBok.place_order", "pkg/orders.py")
    check("--touch typo is caught with suggestion", d.get("state") == "BLOCKED" and "OrderBook.place_order" in json.dumps(d), d)
    code, d = r.js("begin", "--task", "tc", "--check", UNITTEST, "--touch", "OrderBook.place_order", "pkg/orders.py")
    check("begin with --touch", d.get("state") == "READY", d)
    r.sub("pkg/orders.py", "return helper(order_id, box.size)", "return helper(order_id, box.size) + 1")
    code, d = r.js("verify", "--task", "tc")
    check("undeclared change blocks", d.get("state") == "BLOCKED" and any("[TOUCH]" in x for x in d.get("static", [])), d)
    r.sub("pkg/orders.py", "return helper(order_id, box.size) + 1", "return helper(order_id, box.size)")
    r.sub("pkg/orders.py", "return helper(qty, 1) +", "return helper(qty, 1) * 1 +")
    code, d = r.js("verify", "--task", "tc")
    check("declared change allowed", d.get("state") in ("BLOCKED", "CHECKS_PASSED") and "static" not in d, d)
    check("declared change passes checks", d.get("state") == "CHECKS_PASSED", d)
    r.cleanup()


@scenario
def method_signature_change_possible_callers():
    r = Repo()
    r.sub("app.py", "OrderBook().place_order(\"b\", 1)", "OrderBook().place_order(\"b\", qty=1)")
    r.js("begin", "--task", "m", "--check", UNITTEST, "pkg/orders.py")
    r.sub("pkg/orders.py", "def place_order(self, side, qty, px=None):\n        return helper(qty, 1) + risk.max_notional_usd(qty)",
          "def place_order(self, side, quantity, px=None):\n        return helper(quantity, 1) + risk.max_notional_usd(quantity)")
    code, out, _ = r.run("review", "--task", "m")
    check("method rename: exact mismatch at probable caller", "app.py:4" in out and "unexpected keyword `qty`" in out
          and "missing `quantity`" in out, out)
    check("method mismatch is POSSIBLE not blocking", "POSSIBLE" in out and code == 0, (code, out))
    r.cleanup()


@scenario
def distortion_smells_and_secrets():
    r = Repo()
    r.js("begin", "--task", "q", "--check", UNITTEST, "pkg/orders.py", "tests/test_orders.py")
    # weaken the tests: delete one test, skip another
    r.write("tests/test_orders.py", "import unittest\n\nfrom pkg.orders import OrderBook, cancel\n\n\nclass T(unittest.TestCase):\n"
            "    @unittest.skip(\"flaky\")\n    def test_place(self):\n        self.assertEqual(OrderBook().place_order(\"b\", 2), 7)\n\n"
            "    def test_cancel(self):\n        self.assertEqual(cancel(5), 8)\n")
    # silence / leave junk / duplicate an existing helper
    r.sub("pkg/orders.py", "from pkg import risk\n", "import os\nfrom pkg import risk\n")
    r.write("pkg/orders.py", r.read("pkg/orders.py") + "\n\ndef debug_me():  # TODO remove\n    breakpoint()\n    try:\n        return 1\n"
            "    except Exception:\n        pass\n    x = 1  # noqa\n\n\n"
            "def summarize_copy(rows):\n    total = 0\n    count = 0\n    for row in rows:\n        if row is None:\n            continue\n"
            "        total += row\n        count += 1\n    if count == 0:\n        return 0\n    return total / count\n\n\n"
            "def summarizes(values):\n    return len(values)\n")
    code, d = r.js("review", "--task", "q", "--json")
    msgs = " | ".join(f"{f['code']} {f['msg']}" for f in d.get("smells", []))
    check("tests weakened detected", "Q-TEST tests weakened: -1 assertion(s), -1 test(s)" in msgs, msgs)
    check("skip detected", "Q-TEST +1 skipped/xfail" in msgs, msgs)
    check("suppression + swallow detected", "Q-SILENCE +1 suppression" in msgs and "Q-SILENCE +1 swallowed" in msgs, msgs)
    check("debug leftover + todo detected", "debug leftover" in msgs and "TODO" in msgs, msgs)
    check("unused import introduced", "unused import `os`" in msgs, msgs)
    check("exact duplicate detected", "`summarize_copy` has exactly the same body as `summarize` in pkg/util.py" in msgs, msgs)
    check("similar name detected", "`summarizes` is very similar to existing `summarize`" in msgs, msgs)
    check("smells never block by themselves", d.get("errors") == [] and d.get("policy") == [], d)
    code, out, _ = r.run("review", "--task", "q")
    check("review prints SMELLS, NET and the honesty caveat", "SMELLS (" in out and "NET +" in out and "tests -1" in out
          and "static only" in out, out)
    code, d = r.js("verify", "--task", "q")
    check("verify passes but warns about smells", d.get("state") == "CHECKS_PASSED" and "SMELL" in json.dumps(d.get("warn", [])), d)
    r.write("pkg/orders.py", r.read("pkg/orders.py") + "\nKEY = \"AKIAABCDEFGHIJKLMNOP\"\n")
    code, d = r.js("verify", "--task", "q")
    check("secret blocks verify", d.get("state") == "BLOCKED" and any("[SECRET]" in x for x in d.get("static", [])), d)
    check("secret value is never echoed", "AKIAABCDEFGHIJKLMNOP" not in json.dumps(d), d)
    r.sub("pkg/orders.py", "KEY = \"AKIAABCDEFGHIJKLMNOP\"", "KEY = \"AKIAIOSFODNN7EXAMPLE\"")
    code, d = r.js("verify", "--task", "q")
    check("documented example keys are not secrets", d.get("state") == "CHECKS_PASSED", d)
    r.cleanup()


@scenario
def project_gates_discovery():
    files = dict(FILES)
    files["pyproject.toml"] = "[tool.ruff]\nline-length = 100\n\n[tool.mypy]\nstrict = true\n"
    files["package.json"] = json.dumps({"scripts": {"test": "jest", "lint": "eslint .", "dev": "vite"}})
    files["Makefile"] = "test:\n\tpytest\n\nclean:\n\trm -rf x\n"
    files[".github/workflows/ci.yml"] = "jobs:\n  t:\n    steps:\n      - run: pip install -e .\n      - run: pytest -q --cov\n      - run: ruff check .\n"
    r = Repo(files=files)
    code, out, _ = r.run("brief", "pkg/util.py")
    gates = next((l for l in out.splitlines() if l.startswith("GATES")), "")
    for want in ("pytest -q", "ruff check .", "mypy .", "npm test", "npm run lint", "make test", "CI: pytest -q --cov"):
        check(f"gate discovered: {want}", want in gates, gates)
    check("irrelevant scripts/targets are not suggested", "vite" not in gates and "clean" not in gates and "pip install" not in gates, gates)
    r.cleanup()


@scenario
def red_baseline_is_not_blamed_on_the_agent():
    r = Repo()
    red = json.dumps(["python3", "-m", "unittest", "no_such_module"])
    code, d = r.js("begin", "--task", "red", "--check", red, "--run-baseline", "pkg/util.py")
    check("begin reports a RED baseline", isinstance(d.get("baseline"), list) and "RED before you started" in d.get("note", ""), d)
    r.sub("pkg/util.py", "self.size = size", "self.size = size  # e")
    code, d = r.js("verify", "--task", "red")
    fail = d.get("failure", {})
    check("failure is marked as pre-existing", fail.get("also_failed_at_begin") is True and "BEFORE your change" in fail.get("note", ""), d)
    code, d = r.js("begin", "--task", "green", "--check", UNITTEST, "--run-baseline", "pkg/risk.py")
    check("green baseline says so", d.get("baseline") == "all declared checks were green before you started", d)
    mutator = json.dumps(["python3", "-c", "open('stray.txt','w').write('x')"])
    code, d = r.js("begin", "--task", "mut", "--check", mutator, "--run-baseline", "app.py")
    check("a check that writes files is rejected up front", d.get("state") == "BLOCKED" and "modified the worktree" in json.dumps(d), d)
    r.cleanup()


@scenario
def baseline_comparison_catches_silent_test_loss():
    """A green command is unsafe when it now discovers zero tests it used to run."""
    files = dict(FILES)
    files["app.py"] = "MODE = 'covered'\n"
    files["check_count.py"] = (
        "from pathlib import Path\n"
        "covered = \"covered\" in Path('app.py').read_text()\n"
        "print('Ran 2 tests in 0.001s' if covered else 'Ran 0 tests in 0.001s')\n"
        "print('OK')\n"
    )
    r = Repo(files=files)
    command = json.dumps(["python3", "check_count.py"])
    code, d = r.js("begin", "--task", "silent", "--check", command, "--run-baseline", "app.py")
    check("baseline records a test-producing command", d.get("baseline") == "all declared checks were green before you started", d)
    r.sub("app.py", "covered", "empty")
    code, d = r.js("verify", "--task", "silent")
    warnings = d.get("baseline_warnings", [])
    check("zero-test collapse blocks a green command", d.get("state") == "BLOCKED" and
          any(x.get("code") == "W-SILENT" for x in warnings), d)
    r.cleanup()


@scenario
def check_summary_parsers_are_conservative_and_cover_jest():
    check("jest summary parses", checkdiff.parse_counts("Tests: 2 passed, 2 total")[0] ==
          {"passed": 2, "failed": 0, "errors": 0, "skipped": 0, "total": 2, "engine": "jest"})
    codes = {f["code"] for f in checkdiff.compare("Tests: 2 passed, 2 total", "Tests: 1 passed, 1 total")}
    check("jest count regression is evidence", "W-COUNT" in codes)
    check("unknown check output produces no invented warning", checkdiff.compare("all fine", "still fine") == [])


@scenario
def history_revert_and_memory_are_evidence_not_guesses():
    """Exercise the new history and durable-memory paths against a real temporary Git history."""
    files = dict(FILES)
    files["app.py"] = (
        "def validate_order(order, limits):\n"
        "    return order <= limits\n\n\n"
        "def execute(order, limits):\n"
        "    return order\n"
    )
    r = Repo(files=files)
    r.write("app.py", r.read("app.py").replace("    return order\n", "    return validate_order(order, limits)\n"))
    git(r.root, "add", "app.py")
    git(r.root, "commit", "-qm", "fix: validate orders before execution")
    fixed = git(r.root, "rev-parse", "HEAD").strip()
    r.write("app.py", r.read("app.py").replace("    return validate_order(order, limits)\n", "    return order\n"))
    git(r.root, "add", "app.py")
    git(r.root, "commit", "-qm", 'Revert "fix: validate orders before execution"',
        "-m", "This reverts commit " + fixed + ".")
    # This uncommitted edit is an agent attempt to put back exactly what the revert removed.
    r.write("app.py", r.read("app.py").replace("    return order\n", "    return validate_order(order, limits)\n"))
    code, out, _ = r.run("review")
    check("re-adding reverted behaviour is cited with its commit", "HISTORY (" in out and "[REVERT]" in out, out)
    code, out, _ = r.run("history", "app.py")
    check("history report proves the revert relationship", code == 0 and "REVERT" in out and fixed[:8] in out, out)
    sha = hashlib.sha256(r.read("pkg/risk.py").encode()).hexdigest()
    evidence = json.dumps([{"type": "file", "path": "pkg/risk.py", "sha256": sha}])
    code, d = r.js("memory", "remember", "--kind", "invariant", "--key", "risk", "--text",
                   "Risk sizing remains bounded by max_notional_usd.", "--evidence", evidence,
                   "--confidence", "proved", "--tag", "risk")
    check("memory stores fresh evidence-backed fact", d.get("state") == "REMEMBERED" and
          d.get("fact", {}).get("checked", {}).get("result") == "fresh", d)
    r.sub("pkg/risk.py", "return x * 2", "return x * 3")
    code, d = r.js("memory", "recall", "--tag", "risk", "--fresh")
    check("stale memory is not returned as current knowledge", d.get("facts") == [] and d.get("stats", {}).get("stale") == 1, d)
    r.cleanup()


@scenario
def docs_and_config_mentions_of_removed_names():
    files = dict(FILES)
    files["docs/risk.md"] = "Call `max_notional_usd` before sending an order.\n"
    files["setup.cfg"] = "[options.entry_points]\nconsole_scripts =\n    risk = pkg.risk:max_notional_usd\n"
    r = Repo(files=files)
    r.js("begin", "--task", "d", "--check", UNITTEST, "pkg/risk.py")
    r.sub("pkg/risk.py", "def max_notional_usd(x):", "def max_notional(x):")
    code, out, _ = r.run("review", "--task", "d")
    check("docs/config mentions surface as POSSIBLE", "docs/risk.md" in out or "setup.cfg" in out, out)
    r.cleanup()


@scenario
def cosmetic_change_detected():
    r = Repo()
    r.js("begin", "--task", "c", "--check", UNITTEST, "pkg/risk.py")
    r.write("pkg/risk.py", "# a comment\ndef max_notional_usd(x):\n    '''doc'''\n    return x*2\n")
    code, out, _ = r.run("review", "--task", "c")
    check("cosmetic recognised", "cosmetic only" in out and "logic:" not in out and "sig:" not in out, out)
    r.cleanup()


@scenario
def ignored_dirs_and_policy():
    r = Repo()
    r.write("scratch2/helper.py", "x = 1\n")  # ignored dir that hides source
    r.write(".idea/other.xml", "<x/>\n")
    code, d = r.js("begin", "--task", "i", "--check", UNITTEST, "pkg/util.py")
    check("ignored dirs do not block by default", d.get("state") == "READY", d)
    r.write("agentussagefolder/policy.json", json.dumps({"ignored_dirs": "block"}))
    code, d = r.js("begin", "--task", "i2", "--check", UNITTEST, "pkg/risk.py")
    check("policy ignored_dirs=block is strict", d.get("state") == "BLOCKED" and "ignored" in json.dumps(d), d)
    r.write("agentussagefolder/policy.json", json.dumps({"bogus_key": 1}))
    code, d = r.js("status", "--task", "i")
    check("bad policy key is an error", d.get("state") == "BLOCKED" and "unknown key" in json.dumps(d), d)
    r.write("agentussagefolder/policy.json", json.dumps({"private_suffixes_remove": [".csv"]}))
    r.write("tests/prices.csv", "a,b\n")
    code, d = r.js("begin", "--task", "i3", "--check", UNITTEST, "tests/prices.csv")
    check("policy can release .csv", d.get("state") == "READY", d)
    os.unlink(r.root / "agentussagefolder" / "policy.json")
    code, d = r.js("begin", "--task", "i4", "--check", UNITTEST, "tests/prices.csv", "poetry.lock")
    check("private csv blocked with policy hint", d.get("state") == "BLOCKED" and "policy.json" in json.dumps(d), d)
    code, d = r.js("begin", "--task", "i5", "--check", UNITTEST, "poetry.lock")
    check("lockfiles are not private", d.get("state") == "READY", d)
    r.cleanup()


@scenario
def abandon_and_overlap():
    r = Repo()
    r.js("begin", "--task", "a", "--check", UNITTEST, "pkg/util.py")
    code, d = r.js("begin", "--task", "b", "--check", UNITTEST, "pkg/util.py")
    check("overlap rejected", d.get("state") == "BLOCKED" and "overlapping" in json.dumps(d), d)
    code, d = r.js("abandon", "--task", "a")
    check("abandon", d.get("state") == "ABANDONED", d)
    code, d = r.js("begin", "--task", "b", "--check", UNITTEST, "pkg/util.py")
    check("begin after abandon", d.get("state") == "READY", d)
    code, d = r.js("list")
    states = {t["task"]: t["state"] for t in d.get("tasks", [])}
    check("list states", states.get("a") == "ABANDONED" and states.get("b") == "READY", d)
    r.cleanup()


@scenario
def guard_command_and_hook():
    r = Repo()
    code, out, _ = r.run("guard", "pkg/orders.py")
    check("guard allows when no task", code == 0, out)
    code, out, _ = r.run("guard", "--require-task", "pkg/orders.py")
    check("guard --require-task blocks", code == 1, out)
    r.js("begin", "--task", "g", "--check", UNITTEST, "pkg/util.py")
    code, out, _ = r.run("guard", "pkg/orders.py")
    check("guard blocks out-of-scope", code == 1 and "outside every open task" in out, out)
    code, out, _ = r.run("guard", "pkg/util.py")
    check("guard allows in-scope", code == 0, out)
    payload = json.dumps({"tool_name": "Edit", "cwd": str(r.root), "tool_input": {"file_path": str(r.root / "pkg" / "orders.py")}})
    code, out, err = r.run("guard", "--hook", stdin=payload)
    check("hook blocks with exit 2 + stderr", code == 2 and "outside every open task" in err, (code, err))
    payload = json.dumps({"cwd": str(r.root), "tool_input": {"file_path": str(r.root / "pkg" / "util.py")}})
    code, out, err = r.run("guard", "--hook", stdin=payload)
    check("hook allows in-scope", code == 0, (code, err))
    code, out, err = r.run("guard", "--hook", stdin="not json")
    check("hook fails open on garbage", code == 0, (code, err))
    r.cleanup()


@scenario
def failure_tail_and_auto_check():
    r = Repo()
    code, d = r.js("begin", "--task", "f", "--check", json.dumps(["python3", "-m", "unittest", "no_such_module"]), "pkg/util.py")
    r.sub("pkg/util.py", "self.size = size", "self.size = size  # e")
    code, d = r.js("verify", "--task", "f")
    check("failing check blocks", d.get("state") == "BLOCKED", d)
    check("failure tail returned", "no_such_module" in json.dumps(d.get("failure", {})), d)
    code, d = r.js("begin", "--task", "ac", "--auto-check", "pkg/orders.py")
    check("auto-check picks impacted tests", "tests/test_orders.py" in d.get("auto_check", []), d)
    code, d = r.js("begin", "--task", "ac2", "--auto-check", "pkg/risk.py")
    check("auto-check refuses when nothing impacted... or finds test", d.get("state") in ("READY", "BLOCKED"), d)
    r.cleanup()


@scenario
def unborn_head_and_untracked_toolkit():
    r = Repo(files={"m.py": "def f():\n    return 1\n"}, commit=False)
    code, d = r.js("begin", "--task", "u", "--check", json.dumps(["python3", "-c", "print(1)"]), "m.py")
    check("begin on repo without commits", d.get("state") == "READY", d)
    r.sub("m.py", "return 1", "return 2")
    code, d = r.js("verify", "--task", "u")
    check("verify on repo without commits", d.get("state") == "CHECKS_PASSED", d)
    r.cleanup()


@scenario
def js_light_support():
    r = Repo()
    code, out, _ = r.run("brief", "web/a.ts")
    check("js importers", "web/b.ts" in out and "web/c.ts" in out, out)
    r.sub("web/c.ts", "'./a'", "'./missing'")
    code, out, _ = r.run("review")
    check("js unresolved relative import", "relative import `./missing`" in out and "web/c.ts" in out, out)
    r.cleanup()


@scenario
def legacy_and_misc():
    r = Repo(commit_toolkit=True)
    code, out, _ = r.run("inspect", "pkg/util.py")
    check("legacy inspect works", code == 0 and "\"sha256\"" in out, out[:200])
    code, out, _ = r.run("--version")
    check("--version", "agentussagefolder" in out, out)
    code, d = r.js("begin", "--task", "x", "--check", UNITTEST, "pkg/util.py")
    check("begin with tracked toolkit", d.get("state") == "READY", d)
    code, out, _ = r.run("brief", "pkg/util.py")
    check("brief ignores toolkit as dirty", "dirty:0" in out, out[:120])
    r.cleanup()


@scenario
def lock_contention_is_graceful():
    if os.name == "nt":
        return
    import fcntl
    r = Repo()
    r.js("begin", "--task", "l", "--check", UNITTEST, "pkg/util.py")
    fd = os.open(str(r.root / "agentussagefolder" / ".state" / ".lock"), os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    t0 = time.monotonic()
    code, d = r.js("status", "--task", "l", env={"AGENT_LOCK_WAIT": "1"})
    check("lock held -> clear message", d.get("state") == "BLOCKED" and "lock" in json.dumps(d), d)
    check("waits instead of failing instantly", time.monotonic() - t0 >= 0.9, time.monotonic() - t0)
    code, out, _ = r.run("review", "--task", "l")
    check("read-only commands ignore the lock", code in (0, 1) and "review" in out, out[:150])
    os.close(fd)
    code, d = r.js("status", "--task", "l")
    check("works after release", d.get("state") in ("READY", "UNVERIFIED"), d)
    r.cleanup()


def main():
    pattern = sys.argv[sys.argv.index("-k") + 1] if "-k" in sys.argv else ""
    t0 = time.monotonic()
    for fn in SCENARIOS:
        if pattern and pattern not in fn.__name__:
            continue
        before = len(FAILS)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a crashing scenario is a failure, not a stop
            FAILS.append(f"{fn.__name__} crashed: {type(exc).__name__}: {exc}")
            print(f"    CRASH {fn.__name__}: {type(exc).__name__}: {exc}")
        print(f"{'ok  ' if len(FAILS) == before else 'FAIL'} {fn.__name__}")
    print(f"\n{PASSES} checks passed, {len(FAILS)} failed  ({time.monotonic() - t0:.0f}s)")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
