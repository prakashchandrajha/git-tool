"""python -m gittool.workers.bench --tree T --contract-dir contract --target risk.margin:pair_scan --mode wall|insn --size N --loops L --out FILE"""
import argparse, gc, importlib, os, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--tree", required=True); ap.add_argument("--contract-dir", required=True)
ap.add_argument("--target", required=True); ap.add_argument("--mode", choices=["wall", "insn"], required=True)
ap.add_argument("--size", type=int, required=True); ap.add_argument("--loops", type=int, default=200)
ap.add_argument("--out", required=True)
a = ap.parse_args()
sys.path.insert(0, os.path.abspath(a.tree)); sys.path.insert(1, os.path.abspath(a.contract_dir))

import bench as contract_bench                      # contract/bench.py
modname, qual = a.target.split(":")
mod = importlib.import_module(modname)
fn = mod
for p in qual.split("."):
    fn = getattr(fn, p)
args = contract_bench.make_args(a.target, a.size)
sys.stdout = sys.stderr                              # target code may print; result goes to --out only

if a.mode == "wall":
    try:
        cpus = sorted(os.sched_getaffinity(0)); os.sched_setaffinity(0, {cpus[-1]})
    except Exception:
        pass
    for _ in range(3):
        fn(*args)
    gc.collect(); gc.freeze(); gc.disable()
    t0 = time.perf_counter_ns()
    for _ in range(a.loops):
        fn(*args)
    val = (time.perf_counter_ns() - t0) / a.loops
else:
    from gittool.gates.latency import codes_in_module, count_instructions
    val = count_instructions(fn, *args, codes=codes_in_module(mod))
with open(a.out, "w") as fh:
    fh.write(repr(float(val)))
