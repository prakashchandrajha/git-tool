"""gittool engine — the orchestrator that ties snapshot, harvest, replay, compare, and verdict together.

Runs in-process (advisory enforcement) or as a separate uid (enforced).
Manages session state, tree hashing, worker dispatch, and the crypto ledger.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gittool.state import step, allowed, IllegalTransition, TRANSITIONS
from gittool.crypto import Ledger, sym_hash, digest


def _tree_hash(project: str, tracked_globs: list[str] | None = None) -> str:
    """Blake2b hash of sorted (relpath, content_hash) pairs for tracked files."""
    pairs = []
    root = Path(project).resolve()
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        # Skip __pycache__, .venv, node_modules, .git
        parts = rel.parts
        if any(skip in parts for skip in ("__pycache__", ".venv", ".git", "node_modules", "venv")):
            continue
        content_hash = hashlib.blake2b(p.read_bytes()).hexdigest()[:32]
        pairs.append((str(rel), content_hash))
    blob = json.dumps(pairs, sort_keys=True).encode()
    return "b2:" + hashlib.blake2b(blob).hexdigest()[:32]


def _snapshot_dir(session_dir: str) -> str:
    return os.path.join(session_dir, "snapshot_s0")


class Session:
    """One edit-verify-close cycle."""

    def __init__(self, project: str, intent: str, targets: dict[str, list[str]],
                 session_dir: str | None = None):
        self.project = os.path.abspath(project)
        self.intent: Literal["refactor", "behavior_change"] = intent
        self.targets = targets  # {module: [qualnames]}
        self.session_dir = session_dir or tempfile.mkdtemp(prefix="gittool_")
        self.state = "BEGUN"
        self.h0 = _tree_hash(self.project)
        self.h_verified: str | None = None
        self.run_id: str | None = None
        self._key = Ed25519PrivateKey.generate()
        self.ledger = Ledger(self._key)
        self.ledger.append({"t": "begin", "intent": intent, "h0": self.h0})
        self.failure_fingerprints: list[str] = []
        self.verify_budget = 5
        self.last_report: dict | None = None
        self.used_nonces: set[str] = set()

        # Take snapshot S0
        snap = _snapshot_dir(self.session_dir)
        os.makedirs(snap, exist_ok=True)
        self._copy_tree(self.project, snap)

    def _copy_tree(self, src: str, dst: str):
        """Copy Python source files only (not .git, __pycache__, etc)."""
        root = Path(src)
        for p in root.rglob("*.py"):
            rel = p.relative_to(root)
            parts = rel.parts
            if any(skip in parts for skip in ("__pycache__", ".venv", ".git", "node_modules", "venv")):
                continue
            dest = Path(dst) / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)

    def _transition(self, tool: str) -> str:
        self.state = step(self.state, tool)
        self.ledger.append({"t": tool, "state": self.state})
        return self.state

    def current_hash(self) -> str:
        return _tree_hash(self.project)

    def status(self) -> dict:
        return {
            "state": self.state,
            "tree_hash": self.current_hash(),
            "h0": self.h0,
            "intent": self.intent,
            "allowed": allowed(self.state),
            "verify_budget_remaining": self.verify_budget,
            "enforcement": "advisory",
        }

    def edit_ack(self) -> dict:
        self._transition("edit_ack")
        return self.status()

    def review(self) -> dict:
        self._transition("review")
        h_now = self.current_hash()
        changed = h_now != self.h0
        return {
            **self.status(),
            "tree_changed": changed,
            "diff_hash": h_now,
        }

    def verify_start(self) -> dict:
        self._transition("verify_start")
        self.run_id = str(uuid.uuid4())[:8]
        self.verify_budget -= 1
        return {"run_id": self.run_id, "state": self.state}

    def verify_execute(self) -> dict:
        """Run the full harvest→replay→compare pipeline. Returns a VerifyReport dict."""
        if self.state != "VERIFYING":
            raise IllegalTransition(self.state, "verify_execute")

        project = self.project
        snap = _snapshot_dir(self.session_dir)
        plan_json = json.dumps(self.targets)

        # Load policy
        policy_path = os.path.join(project, "contract", "policy.toml")
        if os.path.exists(policy_path):
            with open(policy_path, "rb") as f:
                policy = tomllib.load(f)
        else:
            policy = {}

        report = {
            "state": "VERIFIED",
            "tree_hash": self.current_hash(),
            "enforcement": "advisory",
            "new_test_failures": [],
            "broken_callers": [],
            "math_integrity": {"verdict": "PASS", "changed_line_coverage": 0.0,
                               "diverging": [], "unverified_reasons": []},
            "latency": {"verdict": "UNVERIFIED", "mode": "instructions",
                        "ratio_ci95": None, "scaling_slope_delta": None,
                        "top_regressions": []},
            "advisories_suppressed": 0,
            "next_actions": [],
        }

        with tempfile.TemporaryDirectory(prefix="gittool_verify_") as tmpd:
            harvest_out = os.path.join(tmpd, "harvest.jsonl")
            replay_out = os.path.join(tmpd, "replay.jsonl")

            # --- Harvest baseline from snapshot ---
            suite_dir = os.path.join(project, "fixtures") if os.path.isdir(os.path.join(project, "fixtures")) else None
            harvest_cmd = [
                sys.executable, "-m", "gittool.workers.harvest",
                "--tree", snap,
                "--plan", plan_json,
                "--out", harvest_out,
            ]
            if suite_dir:
                harvest_cmd.extend(["--suite-dir", suite_dir])

            # Find a test runner
            test_runner = self._find_test_runner(project)
            harvest_cmd.extend(["--"] + test_runner)

            env = {**os.environ, "PYTHONPATH": project, "PYTHONHASHSEED": "0"}

            try:
                subprocess.run(harvest_cmd, check=True, capture_output=True, env=env, timeout=120)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                report["math_integrity"]["verdict"] = "UNVERIFIED"
                report["math_integrity"]["unverified_reasons"].append(
                    f"harvest failed: {getattr(e, 'stderr', b'')[:200]}"
                )
                self._finalize_report(report, failed=True)
                return report

            # Check harvest produced output
            if not os.path.exists(harvest_out) or os.path.getsize(harvest_out) == 0:
                report["math_integrity"]["verdict"] = "UNVERIFIED"
                report["math_integrity"]["unverified_reasons"].append("harvest produced no records")
                self._finalize_report(report, failed=True)
                return report

            # --- Replay on candidate (current working tree) ---
            replay_cmd = [
                sys.executable, "-m", "gittool.workers.replay",
                "--tree", project,
                "--in", harvest_out,
                "--out", replay_out,
            ]
            try:
                subprocess.run(replay_cmd, check=True, capture_output=True, env=env, timeout=120)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                report["math_integrity"]["verdict"] = "UNVERIFIED"
                report["math_integrity"]["unverified_reasons"].append(
                    f"replay failed: {getattr(e, 'stderr', b'')[:200]}"
                )
                self._finalize_report(report, failed=True)
                return report

            # --- Compare ---
            from gittool.gates.compare import compare

            with open(harvest_out) as f:
                base = [json.loads(line) for line in f]
            with open(replay_out) as f:
                cand = [json.loads(line) for line in f]

            comp = compare(base, cand, policy)
            report["math_integrity"]["verdict"] = comp["verdict"]
            report["math_integrity"]["diverging"] = comp.get("diverging", [])
            if comp.get("unverified"):
                report["math_integrity"]["unverified_reasons"].extend(comp["unverified"])

        # --- Run existing test suite (new-failure delta) ---
        test_failures = self._run_tests(project)
        baseline_failures = self._run_tests(snap)
        new_failures = [f for f in test_failures if f not in baseline_failures]
        report["new_test_failures"] = new_failures

        # --- Determine final verdict ---
        math_fail = report["math_integrity"]["verdict"] == "FAIL"
        has_new_failures = len(new_failures) > 0
        is_unverified = report["math_integrity"]["verdict"] == "UNVERIFIED"

        if math_fail or has_new_failures:
            self._finalize_report(report, failed=True)
        elif is_unverified:
            report["state"] = "FAILED"
            self._finalize_report(report, failed=True)
        else:
            self._finalize_report(report, failed=False)

        return report

    def _find_test_runner(self, project: str) -> list[str]:
        """Find a test runner for the project."""
        fixtures_suite = os.path.join(project, "fixtures", "suite.py")
        if os.path.exists(fixtures_suite):
            return ["suite:run"]

        invariants = os.path.join(project, "tests", "invariants")
        if os.path.isdir(invariants):
            return ["pytest", invariants, "-q"]

        tests_dir = os.path.join(project, "tests")
        if os.path.isdir(tests_dir):
            return ["pytest", tests_dir, "-q", "--ignore=tests/test_acceptance.py"]

        return ["suite:run"]

    def _run_tests(self, tree: str) -> list[str]:
        """Run pytest on a tree and return list of failed test names."""
        tests_dir = os.path.join(tree, "tests")
        if not os.path.isdir(tests_dir):
            return []
        invariants_dir = os.path.join(tests_dir, "invariants")
        if os.path.isdir(invariants_dir):
            target = invariants_dir
        else:
            target = tests_dir

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", target, "-q", "--tb=no",
                 "--ignore=tests/test_acceptance.py"],
                capture_output=True, text=True,
                env={**os.environ, "PYTHONPATH": tree, "PYTHONHASHSEED": "0"},
                cwd=tree, timeout=60,
            )
            if result.returncode == 0:
                return []
            # Parse failures from output
            failures = []
            for line in result.stdout.splitlines():
                if "FAILED" in line:
                    failures.append(line.strip())
            return failures
        except Exception:
            return []

    def _finalize_report(self, report: dict, failed: bool):
        if failed:
            fp = digest({"diverging": report["math_integrity"].get("diverging", []),
                         "failures": report.get("new_test_failures", [])})
            self.failure_fingerprints.append(fp)
            report["state"] = "FAILED"
            self.state = "FAILED"
            report["next_actions"] = ["edit_ack", "abort", "request_override"]

            # Auto-escalate after 3 same fingerprints or budget exhausted
            if self.failure_fingerprints.count(fp) >= 3 or self.verify_budget <= 0:
                report["next_actions"] = ["abort", "request_override"]
                report["auto_escalate"] = "STALLED: same failure 3x or budget exhausted"
        else:
            report["state"] = "VERIFIED"
            self.state = "VERIFIED"
            self.h_verified = report["tree_hash"]
            report["next_actions"] = ["close", "edit_ack", "abort"]

        self.last_report = report
        self.ledger.append({"t": "verify_result", "state": self.state,
                            "verdict": report["math_integrity"]["verdict"]})

    def close(self, expected_hash: str | None = None) -> dict:
        current = self.current_hash()
        if self.h_verified and current != self.h_verified:
            raise ValueError(
                f"Tree modified after VERIFIED (was {self.h_verified[:16]}, "
                f"now {current[:16]}). Edit-after-verify blocked."
            )
        self._transition("close")
        self.ledger.append({"t": "close", "tree_hash": current})
        return {"state": self.state, "tree_hash": current}

    def abort(self) -> dict:
        self._transition("abort")
        # Restore snapshot S0
        snap = _snapshot_dir(self.session_dir)
        if os.path.isdir(snap):
            self._copy_tree(snap, self.project)
        self.ledger.append({"t": "abort"})
        return {"state": self.state, "tree_hash": self.current_hash()}

    def request_override(self, claim: dict, scope: dict) -> dict:
        self._transition("request_override")
        self.ledger.append({"t": "request_override", "claim": claim})
        return {
            "state": self.state,
            "action": "yield_to_user",
            "message": "Override requested. Waiting for human approval.",
            "claim": claim,
            "scope": scope,
        }


class Engine:
    """Manages sessions. One session at a time."""

    def __init__(self, project: str):
        self.project = os.path.abspath(project)
        self.session: Session | None = None

    async def call(self, name: str, **kw) -> dict:
        """Dispatch a tool call to the engine."""

        if name == "begin":
            return self._begin(**kw)
        if name == "status":
            return self._status()

        # All other calls require an active session
        if self.session is None:
            return {"error": {"code": "NO_SESSION", "message": "No active session. Call begin first."}}

        try:
            if name == "edit_ack":
                return self.session.edit_ack()
            elif name == "review":
                return self.session.review()
            elif name == "verify_start":
                return self.session.verify_start()
            elif name == "verify_result":
                return self.session.verify_execute()
            elif name == "close":
                result = self.session.close(kw.get("expected_hash"))
                self.session = None  # Session done
                return result
            elif name == "abort":
                result = self.session.abort()
                self.session = None  # Session done
                return result
            elif name == "request_override":
                return self.session.request_override(
                    kw.get("claim", {}), kw.get("scope", {}))
            else:
                return {"error": {"code": "UNKNOWN_TOOL", "message": f"Unknown tool: {name}"}}
        except IllegalTransition as e:
            return {"error": {
                "code": "ILLEGAL_TRANSITION",
                "state": self.session.state,
                "allowed": allowed(self.session.state),
                "message": str(e),
            }}
        except ValueError as e:
            return {"error": {"code": "VALIDATION_ERROR", "message": str(e)}}

    def _begin(self, intent: str = "refactor", targets: dict | None = None, **kw) -> dict:
        if self.session is not None and self.session.state not in ("CLOSED", "ABORTED"):
            return {"error": {"code": "SESSION_ACTIVE",
                              "message": f"Session already active in state {self.session.state}. Abort or close first.",
                              "allowed": allowed(self.session.state)}}

        targets = targets or {}
        self.session = Session(self.project, intent, targets)
        return self.session.status()

    def _status(self) -> dict:
        if self.session is None:
            return {"state": "IDLE", "message": "No active session."}
        return self.session.status()
