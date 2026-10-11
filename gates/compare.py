from __future__ import annotations
from gittool.probe.canon import float_leaves, has_uncanon, skeleton, ulp_dist

BIG = 2**63


def compare(base: list[dict], cand: list[dict], policy: dict) -> dict:
    """base: harvest records (need mod, qual, pre/post/res/exc). cand: replay records, same order.
    Returns {"verdict": PASS|FAIL|UNVERIFIED, "diverging": [...], "unverified": [...]}"""
    if len(base) != len(cand):
        return {"verdict": "UNVERIFIED", "diverging": [], "unverified": [f"record count {len(base)} != {len(cand)}"]}
    worst: dict[tuple, dict] = {}
    unverified: list[str] = []
    for i, (b, c) in enumerate(zip(base, cand)):
        q = b["qual"]; key_pol = f'{b["mod"]}:{q}'
        pol = policy.get(key_pol, {"compare": "exact"})
        for what in ("res", "post"):
            bv, cv = b[what], c[what]
            if has_uncanon(bv) or has_uncanon(cv):
                unverified.append(f"{key_pol} {what}: value not canonicalisable"); continue
            if bv == cv:
                continue
            kind, d = "NUMERIC", 0
            if skeleton(bv) != skeleton(cv):
                kind, d = "STRUCTURAL", BIG
            else:
                bl, cl = list(float_leaves(bv)), list(float_leaves(cv))
                d = max(ulp_dist(x, y) for x, y in zip(bl, cl))
                if pol.get("compare") == "ulp":
                    tol = pol.get("abs_tol", 0.0)
                    if d <= pol.get("max_ulp", 0) or all(abs(x - y) <= tol for x, y in zip(bl, cl)):
                        continue
                # compare == "exact": any difference is a divergence
            k = (key_pol, what)
            if k not in worst or d > worst[k]["max_ulp"]:
                worst[k] = {"function": key_pol, "field": what, "kind": kind, "max_ulp": d,
                            "critical": bool(pol.get("critical", False)), "input_index": i,
                            "baseline": bv if kind == "STRUCTURAL" else list(map(float.hex, float_leaves(bv)))[:4],
                            "candidate": cv if kind == "STRUCTURAL" else list(map(float.hex, float_leaves(cv)))[:4]}
        if b["exc"] != c["exc"]:
            worst[(key_pol, "exc")] = {"function": key_pol, "field": "exc", "kind": "EXCEPTION", "max_ulp": BIG,
                                       "critical": bool(pol.get("critical", False)), "input_index": i,
                                       "baseline": b["exc"], "candidate": c["exc"]}
    div = sorted(worst.values(), key=lambda r: -r["max_ulp"])
    verdict = "FAIL" if div else ("UNVERIFIED" if unverified else "PASS")
    return {"verdict": verdict, "diverging": div, "unverified": sorted(set(unverified))}
