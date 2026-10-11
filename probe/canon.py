import base64, math, pickle, struct
from decimal import Decimal

import numpy as np


def canon(x, _seen=None):
    """Lossless, address-free, JSON-friendly encoding. Floats are hex strings (exact, keeps -0.0/nan/inf)."""
    _seen = _seen if _seen is not None else frozenset()
    t = type(x)
    if t is bool: return ["b", x]
    if t is float: return ["f", x.hex()]
    if t in (int, str, type(None)): return x
    if t is bytes: return ["by", x.hex()]
    if t is Decimal: return ["D", str(x)]
    if isinstance(x, np.generic): return ["npg", x.dtype.str, x.tobytes().hex()]
    if isinstance(x, np.ndarray):
        if x.dtype.hasobject: return ["UNCANON", "object-array"]
        return ["nd", x.dtype.str, list(x.shape), x.tobytes().hex()]
    if id(x) in _seen: return ["cycle"]
    _seen = _seen | {id(x)}
    if isinstance(x, (list, tuple)): return [t.__name__, [canon(i, _seen) for i in x]]
    if isinstance(x, (set, frozenset)): return [t.__name__, sorted((canon(i, _seen) for i in x), key=repr)]
    if isinstance(x, dict):
        return ["dict", sorted(([canon(k, _seen), canon(v, _seen)] for k, v in x.items()), key=repr)]
    if hasattr(x, "__dict__"): return ["obj", t.__qualname__, canon(vars(x), _seen)]
    slots = [s for c in t.__mro__ for s in getattr(c, "__slots__", ())]
    if slots:
        return ["obj", t.__qualname__, [[s, canon(getattr(x, s, None), _seen)] for s in sorted(set(slots))]]
    return ["UNCANON", t.__qualname__]


def ulp_dist(a: float, b: float) -> int:
    """Distance in representable doubles. 0.0 vs -0.0 counts as 1; nan==nan is 0; nan vs number is 2**63."""
    if a != a or b != b:
        return 0 if (a != a and b != b) else 2**63
    if a == b == 0.0 and math.copysign(1, a) != math.copysign(1, b):
        return 1
    ia, ib = (struct.unpack("<q", struct.pack("<d", v))[0] for v in (a, b))
    ia = -2**63 - ia if ia < 0 else ia
    ib = -2**63 - ib if ib < 0 else ib
    return abs(ia - ib)


def blob(o) -> str:
    return base64.b64encode(pickle.dumps(o, protocol=5)).decode()


def unblob(s: str):
    return pickle.loads(base64.b64decode(s))


def is_float_leaf(c) -> bool:
    return isinstance(c, (list, tuple)) and len(c) == 2 and c[0] == "f" and isinstance(c[1], str)


def float_leaves(c):
    if is_float_leaf(c):
        yield float.fromhex(c[1])
    elif isinstance(c, (list, tuple)):
        for i in c:
            yield from float_leaves(i)


def skeleton(c):
    """Same structure with every float leaf blanked. Equal skeletons => any difference is purely numeric."""
    if is_float_leaf(c): return ["f", "*"]
    if isinstance(c, (list, tuple)): return [skeleton(i) for i in c]
    return c


def has_uncanon(c) -> bool:
    if isinstance(c, (list, tuple)):
        return (len(c) >= 1 and c[0] == "UNCANON") or any(has_uncanon(i) for i in c)
    return False
