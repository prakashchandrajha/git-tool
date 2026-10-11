"""MCP front-end — exposes gittool engine as MCP tools.

Tools: begin, edit_ack, review, verify_start, verify_result, status, close, abort, request_override
"""
from __future__ import annotations
import json
from typing import Literal, Protocol

from pydantic import BaseModel

try:                                               # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server, Context
    from mcp.server.mcpserver.exceptions import ToolError
except ModuleNotFoundError:                        # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server, Context
    from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations


# ── Response models ──

class BrokenCaller(BaseModel):
    caller: str; file: str; line: int
    reason: Literal["ARITY", "UNKNOWN_KWARG", "REMOVED_SYMBOL", "RETURN_SHAPE"]
    witness: str


class Divergence(BaseModel):
    function: str; field: str; kind: Literal["NUMERIC", "STRUCTURAL", "EXCEPTION"]
    max_ulp: int; critical: bool; input_index: int


class MathIntegrity(BaseModel):
    verdict: Literal["PASS", "FAIL", "UNVERIFIED"]
    changed_line_coverage: float
    diverging: list[Divergence] = []
    unverified_reasons: list[str] = []


class Latency(BaseModel):
    verdict: Literal["PASS", "FAIL", "INCONCLUSIVE", "UNVERIFIED"]
    mode: Literal["wall", "instructions"]
    ratio_ci95: tuple[float, float] | None = None
    scaling_slope_delta: float | None = None
    top_regressions: list[dict] = []


class VerifyReport(BaseModel):
    schema_version: Literal["gt.verify/3"] = "gt.verify/3"
    state: str
    tree_hash: str
    enforcement: Literal["enforced", "advisory"]
    new_test_failures: list[str]
    broken_callers: list[BrokenCaller]
    math_integrity: MathIntegrity
    latency: Latency
    advisories_suppressed: int
    next_actions: list[str]


class Started(BaseModel):
    run_id: str
    state: str


class StatusReport(BaseModel):
    state: str
    tree_hash: str | None = None
    h0: str | None = None
    intent: str | None = None
    allowed: list[str] = []
    verify_budget_remaining: int | None = None
    enforcement: str = "advisory"


class SessionStarted(BaseModel):
    state: str
    tree_hash: str
    h0: str
    intent: str
    allowed: list[str]
    verify_budget_remaining: int
    enforcement: str = "advisory"


# ── Engine protocol ──

class Engine(Protocol):
    async def call(self, name: str, **kw) -> dict: ...


def _err(code: str, **extra) -> ToolError:
    return ToolError(json.dumps({"code": code, **extra}, sort_keys=True))


def build_server(engine: Engine) -> _Server:
    mcp = _Server("git-tool")

    async def _engine(name: str, **kw) -> dict:
        try:
            r = await engine.call(name, **kw)
        except ConnectionError as e:
            raise _err("ENGINE_UNREACHABLE", detail=str(e))
        if r.get("error"):
            raise _err(r["error"]["code"], **{k: v for k, v in r["error"].items() if k != "code"})
        return r

    # ── Session lifecycle ──

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
    async def begin(intent: str = "refactor", targets: str = "{}") -> SessionStarted:
        """Start a new edit session. intent='refactor' or 'behavior_change'.
        targets is a JSON dict mapping module names to lists of qualnames to track.
        Example: '{"src.math.trading_calcy": ["calculate_total_charges"]}'"""
        import json as _json
        t = _json.loads(targets) if isinstance(targets, str) else targets
        r = await _engine("begin", intent=intent, targets=t)
        return SessionStarted(**r)

    @mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
    async def edit_ack() -> StatusReport:
        """Acknowledge that edits have been made. Transitions from BEGUN or VERIFIED to EDITING."""
        r = await _engine("edit_ack")
        return StatusReport(**r)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def review() -> dict:
        """Transition to REVIEWED. Returns whether the tree changed from baseline."""
        return await _engine("review")

    @mcp.tool(annotations=ToolAnnotations(idempotentHint=True))
    async def verify_start(expected_state_hash: str = "") -> Started:
        """Start verification of the current tree. Returns a run_id."""
        return Started(**await _engine("verify_start", expected_state_hash=expected_state_hash))

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def verify_result(run_id: str = "") -> VerifyReport:
        """Run the full harvest→replay→compare pipeline and return the report."""
        r = await _engine("verify_result", run_id=run_id)
        return VerifyReport(**r)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def status() -> StatusReport:
        """Get the current session state, tree hash, and allowed transitions."""
        r = await _engine("status")
        return StatusReport(**r)

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
    async def close(expected_hash: str = "") -> dict:
        """Close a VERIFIED session. Fails if tree was modified after verification."""
        return await _engine("close", expected_hash=expected_hash)

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
    async def abort(expected_state_hash: str = "") -> dict:
        """Roll back to the sealed snapshot. Always legal before close."""
        return await _engine("abort", expected_state_hash=expected_state_hash)

    @mcp.tool(annotations=ToolAnnotations(destructiveHint=True))
    async def request_override(claim: str = "{}", scope: str = "{}") -> dict:
        """Request a human override for a FAILED verification. Only from FAILED state."""
        import json as _json
        c = _json.loads(claim) if isinstance(claim, str) else claim
        s = _json.loads(scope) if isinstance(scope, str) else scope
        return await _engine("request_override", claim=c, scope=s)

    return mcp
