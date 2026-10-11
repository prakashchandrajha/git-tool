import os, subprocess, sys, tempfile
import numpy as np


def sample(tree, contract_dir, target, mode, size, loops=200, env=None) -> float:
    with tempfile.NamedTemporaryFile("w+", suffix=".val", delete=False) as f:
        out = f.name
    try:
        subprocess.run([sys.executable, "-m", "gittool.workers.bench", "--tree", tree, "--contract-dir", contract_dir,
                        "--target", target, "--mode", mode, "--size", str(size), "--loops", str(loops), "--out", out],
                       check=True, stdout=subprocess.DEVNULL, env={**os.environ, "PYTHONHASHSEED": "0", **(env or {})})
        with open(out) as fh:
            return float(fh.read().strip())
    finally:
        os.unlink(out)


def abba(tree_a, tree_b, k, **kw):
    A, B = [], []
    for i in range(k):
        order = [(tree_a, A), (tree_b, B), (tree_b, B), (tree_a, A)] if i % 2 == 0 else \
                [(tree_b, B), (tree_a, A), (tree_a, A), (tree_b, B)]
        for tree, sink in order:
            sink.append(sample(tree, **kw))
    return np.array(A), np.array(B)
