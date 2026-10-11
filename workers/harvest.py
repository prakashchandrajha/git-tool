"""python -m gittool.workers.harvest --tree TREE --plan '{"risk.margin": ["risk_multiplier"]}' --out out.jsonl -- suite:run
   python -m gittool.workers.harvest --tree TREE --plan ... --out ... -- pytest tests -q        (pytest mode: NOT TESTED)
Runs in a fresh process. TREE is put first on sys.path. The target runner must not print to stdout the parent reads."""
import argparse, builtins, contextvars, functools, importlib, json, os, random, sys

ap = argparse.ArgumentParser()
ap.add_argument("--tree", required=True)
ap.add_argument("--plan", required=True)          # JSON {module: [qualnames]}
ap.add_argument("--out", required=True)
ap.add_argument("--suite-dir", default=None)      # extra sys.path entry for the human-owned suite/contract
ap.add_argument("rest", nargs=argparse.REMAINDER)
a = ap.parse_args()
rest = [r for r in a.rest if r != "--"]

sys.path.insert(0, os.path.abspath(a.tree))
if a.suite_dir:
    sys.path.insert(1, os.path.abspath(a.suite_dir))
os.environ.setdefault("PYTHONHASHSEED", "0")
random.seed(0)
try:
    import numpy as np; np.random.seed(0)
except Exception:
    pass

from gittool.probe import inject
from gittool.probe.canon import blob, canon

rec = open(a.out, "w")
busy = contextvars.ContextVar("gt_busy", default=False)


def __gt_probe__(mod, qual):
    def deco(fn):
        @functools.wraps(fn)
        def w(*args, **kw):
            if busy.get():
                return fn(*args, **kw)
            tok = busy.set(True)
            try:
                pre = canon([list(args), kw]); rb = blob([args, kw])
            finally:
                busy.reset(tok)
            exc = None
            try:
                res = fn(*args, **kw)
            except Exception as e:                      # record, then re-raise unchanged
                res, exc = None, repr(e)
            tok = busy.set(True)
            try:
                post = canon([list(args), kw]); r = canon(res)
            finally:
                busy.reset(tok)
            rec.write(json.dumps({"mod": mod, "qual": qual, "pre": pre, "post": post,
                                  "res": r, "exc": exc, "replay": rb}) + "\n")
            if exc:
                raise
            return res
        return w
    return deco


builtins.__gt_probe__ = __gt_probe__
inject.install({m: set(q) for m, q in json.loads(a.plan).items()})

if rest and rest[0] == "pytest":
    import pytest
    code = pytest.main(rest[1:])
else:
    mod, fn = rest[0].split(":")
    getattr(importlib.import_module(mod), fn)()
    code = 0
rec.close()
sys.exit(int(code))
