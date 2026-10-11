from __future__ import annotations
import ast, hashlib, json, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def jcs(obj) -> bytes:
    def chk(o):
        if isinstance(o, float):
            raise TypeError("floats forbidden in signed payloads; use float.hex() strings")
        if isinstance(o, dict):
            for k, v in o.items():
                if not (isinstance(k, str) and k.isascii()):
                    raise TypeError("ASCII str keys only")
                chk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                chk(v)
        elif not isinstance(o, (str, int, bool, type(None))):
            raise TypeError(type(o))
    chk(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(obj) -> str:
    return hashlib.sha256(jcs(obj)).hexdigest()


def sym_hash(src: str, name: str) -> str | None:
    """AST hash of a function, ignoring formatting, comments, line numbers and docstrings.
    Reformatting keeps the hash; any logic edit changes it. Use for AST-diff and waiver scoping."""
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            n.body = [b for b in n.body if not (isinstance(b, ast.Expr) and isinstance(getattr(b, "value", None), ast.Constant)
                                                 and isinstance(b.value.value, str))]
            for x in ast.walk(n):
                for a in ("lineno", "end_lineno", "col_offset", "end_col_offset"):
                    if hasattr(x, a):
                        setattr(x, a, 0)
            return hashlib.sha256(ast.dump(n).encode()).hexdigest()[:16]
    return None


def waiver_valid(w: dict, current_symbol_hashes: dict, used_nonces: set, now: int | None = None) -> bool:
    now = int(time.time()) if now is None else now
    return (w["nonce"] not in used_nonces and now <= w["expires"]
            and all(current_symbol_hashes.get(s) == h for s, h in w["symbol_hashes"].items()))


class Ledger:
    """Append-only, hash-chained, every head signed by the engine key."""
    def __init__(self, key: Ed25519PrivateKey):
        self.k, self.rows = key, []

    def append(self, ev: dict):
        prev = self.rows[-1]["h"] if self.rows else "0" * 64
        body = {"prev": prev, "ts": int(time.time()), "ev": ev}
        h = hashlib.sha256(jcs(body)).hexdigest()
        self.rows.append({**body, "h": h, "sig": self.k.sign(h.encode()).hex()})

    def verify(self, pub: Ed25519PublicKey) -> bool:
        prev = "0" * 64
        try:
            for r in self.rows:
                body = {"prev": r["prev"], "ts": r["ts"], "ev": r["ev"]}
                if r["prev"] != prev or hashlib.sha256(jcs(body)).hexdigest() != r["h"]:
                    return False
                pub.verify(bytes.fromhex(r["sig"]), r["h"].encode())
                prev = r["h"]
            return True
        except Exception:
            return False
