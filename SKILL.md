---
name: git-tool
description: "Use before and after ANY code change in a git repo. The Quantitative Anti-Regression Vault: harvests runtime behavior of target functions before edits, replays after edits, and mathematically proves (via ULP-distance, instruction-count, and coverage gates) that no silent regression occurred. Replaces the legacy git-tool/ bash scripts."
---

# gittool v3 — Quantitative Anti-Regression Vault

## Architecture

```
gittool/
├── state.py          # State machine: BEGUN→EDITING→REVIEWED→VERIFYING→VERIFIED→CLOSED
├── crypto.py         # Ed25519 ledger, JCS canonical JSON, sym_hash, waiver validation
├── engine.py         # Orchestrator: session lifecycle, snapshot, pipeline dispatch
├── server.py         # stdio entry point: python -m gittool.server --project PATH
├── mcp_front.py      # MCP server: 9 tools (begin, edit_ack, review, verify_start, etc.)
├── probe/
│   ├── inject.py     # AST-based import hook — wraps target functions at import time
│   └── canon.py      # Lossless, address-free serialization (floats as hex, numpy-aware)
├── workers/
│   ├── harvest.py    # Runs suite on baseline tree, records (args, result, post-state) per call
│   ├── replay.py     # Replays recorded calls on candidate tree, emits JSONL
│   └── bench.py      # Wall-clock and instruction-count benchmarking worker
└── gates/
    ├── compare.py    # Diffs harvest vs replay using per-function ULP policy
    ├── coverage.py   # sys.monitoring-based changed-line coverage
    ├── latency.py    # Bootstrap CI wall-clock + deterministic instruction counting
    └── bench_driver.py # ABBA interleaved benchmark driver

contract/             # HUMAN-OWNED, read-only to agents
├── policy.toml       # Per-function comparison policy (ulp/exact, max_ulp, critical)
├── bench.py          # make_args(target, n) for benchmark inputs
└── invariants/       # (TODO) Hypothesis property tests

fixtures/             # Test fixtures for acceptance suite
```

## How It Works

### The Pipeline
1. **Harvest**: Run the test suite on the *baseline* tree with probes injected. Records every call's `(pre-args, post-args, result, exception)` as JSONL.
2. **Replay**: A fresh process loads the *candidate* tree and replays each recorded call from its pickled pre-state.
3. **Compare**: Diffs the two JSONL streams using per-function policy from `contract/policy.toml`. Floats compared by ULP distance; structures compared exactly.
4. **Coverage**: Checks that changed lines were actually executed (prevents vacuous passes).
5. **Latency**: ABBA-interleaved benchmarks with bootstrap confidence intervals, plus deterministic instruction counting for noisy boxes.

### Key Design Decisions
- **Never load baseline and candidate in one interpreter** — import resolution contamination.
- **Import-hook injection, not sys.settrace** — 1x overhead vs 3-8x.
- **Tri-state verdicts**: `PASS | FAIL | UNVERIFIED(reason)`. `UNVERIFIED` is never green.
- **Per-function ULP policy** — not one global tolerance. `numpy.allclose` would mask millions of ULPs on small values.

## Manual Usage (Until Engine Is Built)

### Harvest baseline
```bash
python -m gittool.workers.harvest \
  --tree . --plan '{"src.math.trading_calcy": ["calculate_total_charges"]}' \
  --out /tmp/baseline.jsonl -- pytest tests/ -q
```

### Replay on candidate
```bash
python -m gittool.workers.replay \
  --tree . --in /tmp/baseline.jsonl --out /tmp/candidate.jsonl
```

### Compare
```python
from gittool.gates.compare import compare
import json, tomllib
base = [json.loads(l) for l in open("/tmp/baseline.jsonl")]
cand = [json.loads(l) for l in open("/tmp/candidate.jsonl")]
policy = tomllib.load(open("contract/policy.toml", "rb"))
result = compare(base, cand, policy)
print(result["verdict"])  # PASS, FAIL, or UNVERIFIED
```

## Status

**Working (13/13 tests pass):**
- Engine orchestrator with full session lifecycle
- State machine, crypto ledger, canonical serialization
- Harvest → Replay → Compare pipeline (driven by Engine)
- ULP-distance comparison with per-function policy
- Changed-line coverage via sys.monitoring
- Deterministic instruction counting
- ABBA benchmark driver
- MCP server with 9 tools (begin, edit_ack, review, verify_start, verify_result, status, close, abort, request_override)
- Edit-after-verify tamper detection
- stdio server entry point

**Not yet built:**
- `contract/invariants/` (Hypothesis property tests for real project code)
- `contract/perf.lock` (golden baseline)
- Hardware counter tier (`perf stat`)
- Z3 algebraic equivalence checker
