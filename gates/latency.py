from __future__ import annotations
import math, sys
import numpy as np

mon = sys.monitoring


def latency_verdict(base, cand, thresh: float = 1.05, B: int = 10_000, seed: int = 0):
    rng = np.random.default_rng(seed)
    base, cand = np.asarray(base, float), np.asarray(cand, float)
    r = np.median(cand[rng.integers(0, len(cand), (B, len(cand)))], 1) / \
        np.median(base[rng.integers(0, len(base), (B, len(base)))], 1)
    lo, hi = (float(x) for x in np.percentile(r, [2.5, 97.5]))
    verdict = "FAIL" if lo > thresh else "PASS" if hi < thresh else "INCONCLUSIVE"
    return verdict, (lo, hi)


def noise_floor(samples) -> float:
    """sd/mean of A/A samples; > ~0.02 means a 5% wall-clock gate is not enforceable on this machine."""
    s = np.asarray(samples, float)
    return float(s.std() / s.mean())


def scaling_slope(sizes, costs) -> float:
    return float(np.polyfit(np.log(sizes), np.log(costs), 1)[0])


def complexity_verdict(base_slope: float, cand_slope: float) -> str:
    if cand_slope - base_slope > 0.3 or (base_slope <= 1.3 and cand_slope >= 1.7):
        return "FAIL"
    return "PASS"


def _free_tool_id() -> int:
    for tid in (4, 3):
        try:
            mon.use_tool_id(tid, "gittool-insn")
            return tid
        except ValueError:
            continue
    raise RuntimeError("no free sys.monitoring tool id")


def codes_in_module(mod) -> list:
    """Code objects of every function and method defined in `mod` (to count callees too)."""
    import types
    out, seen = [], set()
    def add(f):
        c = getattr(f, "__code__", None)
        if c is not None and id(c) not in seen:
            seen.add(id(c)); out.append(c)
    for v in vars(mod).values():
        if isinstance(v, types.FunctionType) and v.__module__ == mod.__name__:
            add(v)
        elif isinstance(v, type) and v.__module__ == mod.__name__:
            for m in vars(v).values():
                add(getattr(m, "__func__", m))
    return out


def count_instructions(fn, *args, codes=None, **kw) -> int:
    """Deterministic count of Python bytecode instructions executed inside `codes`
    (default: fn only). Local events do NOT follow into callees, so pass every callee's code object
    (e.g. codes_in_module(mod)). Blind to work done in C extensions (numpy)."""
    codes = codes or [fn.__code__]
    tid = _free_tool_id()
    n = [0]
    def on_ins(code, offset):
        n[0] += 1                                   # do NOT return DISABLE here, or counting stops
    mon.register_callback(tid, mon.events.INSTRUCTION, on_ins)
    for c in codes:
        mon.set_local_events(tid, c, mon.events.INSTRUCTION)
    try:
        fn(*args, **kw)
    finally:
        for c in codes:
            mon.set_local_events(tid, c, 0)
        mon.register_callback(tid, mon.events.INSTRUCTION, None)
        mon.free_tool_id(tid)
    return n[0]
