"""python -m gittool.workers.replay --tree CANDIDATE_TREE --in harvest.jsonl --out replay.jsonl
No probes. Each recorded call is re-run from its own pickled pre-state on the candidate code."""
import argparse, importlib, json, os, sys

ap = argparse.ArgumentParser()
ap.add_argument("--tree", required=True)
ap.add_argument("--in", dest="inp", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()
if os.path.realpath(a.inp) == os.path.realpath(a.out):
    sys.exit("replay: --in and --out must be different files (opening --out would truncate --in)")
sys.path.insert(0, os.path.abspath(a.tree))
os.environ.setdefault("PYTHONHASHSEED", "0")

from gittool.probe.canon import canon, unblob

with open(a.out, "w") as out, open(a.inp) as inp:
    for line in inp:
        r = json.loads(line)
        args, kw = unblob(r["replay"])
        exc = None
        try:
            obj = importlib.import_module(r["mod"])
            for part in r["qual"].split("."):
                obj = getattr(obj, part)
            res = obj(*args, **kw)
        except AttributeError as e:
            res, exc = None, "MISSING_SYMBOL: " + repr(e)
        except Exception as e:
            res, exc = None, repr(e)
        out.write(json.dumps({"qual": r["qual"], "pre": r["pre"], "post": canon([list(args), kw]),
                              "res": canon(res), "exc": exc}) + "\n")
