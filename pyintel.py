#!/usr/bin/env python3
"""Static intelligence for agentussagefolder (stdlib only, read-only).

Answers from git + AST: who imports this, who calls this, which tests reach it, what did my
edit change at symbol level, and did I just invent an import, name, attribute or call
signature.  Findings are labelled CONFIRMED (proved from the AST) or POSSIBLE (name match);
whatever it cannot prove is reported as unknown, never guessed.

Python is analysed with the AST (precise).  JS/TS gets relative-import resolution only.
Other languages get lexical references.  Parse results are cached by git-blob hash under
``.state/cache`` (content-addressed: a cache entry can never be stale).
"""
from __future__ import annotations

import ast
import builtins
import difflib
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import symtable
import sys
import tempfile
import time
import warnings
from collections import Counter, defaultdict, deque
from pathlib import Path

ANALYZER = 6                      # bump whenever the meaning of a cached fact changes (invalidates cache)
MAX_SRC = 1 << 20
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
JS_RESOLVE = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".vue", ".svelte", ".css", ".scss")
SRC_PATHSPECS = ["*" + s for s in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java",
                                    ".rb", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".kt", ".swift", ".php")]
_STDLIB = getattr(sys, "stdlib_module_names", None) or frozenset((
    "abc argparse array ast asyncio base64 bisect builtins calendar cmd codecs collections concurrent configparser "
    "contextlib copy csv ctypes dataclasses datetime decimal difflib dis email enum errno fnmatch fractions "
    "functools gc getpass glob gzip hashlib heapq hmac html http importlib inspect io ipaddress itertools json "
    "keyword locale logging math multiprocessing numbers operator os pathlib pickle platform pprint queue random "
    "re secrets select shlex shutil signal socket sqlite3 ssl stat statistics string struct subprocess sys "
    "tempfile textwrap threading time timeit token tokenize traceback types typing unicodedata unittest urllib "
    "uuid warnings weakref xml zipfile zlib").split())
CONFIG_PATHSPECS = ["*.yaml", "*.yml", "*.json", "*.toml", "*.cfg", "*.ini", "*.conf", "*.md", "*.rst",
                    "*.html", "*.htm", "*.j2", "*.jinja", "*.sql"]
BENIGN = ("lru_cache", "functools.lru_cache", "cache", "functools.cache")
IMPLICIT = frozenset(("__file__", "__name__", "__doc__", "__package__", "__spec__", "__loader__",
                      "__builtins__", "__path__", "__cached__", "__annotations__", "__qualname__",
                      "__module__", "__class__", "__dict__", "WindowsError", "reveal_type",
                      "reveal_locals", "__debug__", "get_ipython", "display", "__IPYTHON__"))
BUILTINS = frozenset(dir(builtins)) | IMPLICIT
_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef)
_TRY = tuple(getattr(ast, n) for n in ("Try", "TryStar") if hasattr(ast, n))
_REF_RE = re.compile(rb"([^\x00]+)\x00([0-9]+)\x00[^\n]*\n")


# ----------------------------------------------------------------------------- small helpers
def _j(*parts):
    return "/".join(p for p in parts if p)


def _dir(p):
    return p.rpartition("/")[0]


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def read_small(path, maximum=MAX_SRC):
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            return None
        with open(path, "rb") as stream:
            data = stream.read(maximum + 1)
        return data if len(data) <= maximum else None
    except OSError:
        return None


def _git(root, *args, stdin=None, ok=(0,), timeout=30):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    try:
        proc = subprocess.run(["git", "--no-pager", "-c", "core.fsmonitor=false", *args], cwd=root,
                              env=env, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode in ok else None


def _unparse(node, cap=80):
    try:
        return ast.unparse(node)[:cap]
    except Exception:  # noqa: BLE001 - unparse is cosmetic only
        return "?"


def _fp(*nodes):
    h = hashlib.sha1()
    for n in nodes:
        h.update((ast.dump(n) if isinstance(n, ast.AST) else str(n or "")).encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()[:12]


def _strip_doc(body):
    if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        return body[1:]
    return body


def _child_bodies(st):
    for field in ("body", "orelse", "finalbody"):
        v = getattr(st, field, None)
        if isinstance(v, list) and v and isinstance(v[0], ast.stmt):
            yield v
    for h in getattr(st, "handlers", None) or ():
        yield h.body
    for c in getattr(st, "cases", None) or ():
        yield c.body


def _target_names(t, out):
    if isinstance(t, ast.Name):
        out.add(t.id)
    elif isinstance(t, (ast.Tuple, ast.List)):
        for e in t.elts:
            _target_names(e, out)
    elif isinstance(t, ast.Starred):
        _target_names(t.value, out)


def _bound_by_stmt(st, out):
    if isinstance(st, ast.Assign):
        for t in st.targets:
            _target_names(t, out)
    elif isinstance(st, (ast.AnnAssign, ast.AugAssign)):
        _target_names(st.target, out)
    elif isinstance(st, (ast.For, ast.AsyncFor)):
        _target_names(st.target, out)
    elif isinstance(st, (ast.With, ast.AsyncWith)):
        for it in st.items:
            if it.optional_vars is not None:
                _target_names(it.optional_vars, out)


def _is_sys_modules(n):
    return (isinstance(n, ast.Attribute) and n.attr == "modules"
            and isinstance(n.value, ast.Name) and n.value.id == "sys")


def _is_globals_call(n):
    return (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id in ("globals", "locals", "vars") and not n.args)


def _injects(node):
    """Constructs that can define module-level names behind the AST's back (reads are harmless)."""
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name) and f.id == "exec":
            return True
        if (isinstance(f, ast.Name) and f.id == "setattr" and node.args
                and any(_is_sys_modules(x) for x in ast.walk(node.args[0]))):
            return True
        if isinstance(f, ast.Attribute) and f.attr in ("update", "setdefault", "pop", "__setitem__") \
                and _is_globals_call(f.value):
            return True
    elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return _is_sys_modules(node.value) or _is_globals_call(node.value)
    return False


def _catches_import_error(node):
    for h in node.handlers:
        if h.type is None:
            return True
        for n in (h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]):
            if isinstance(n, ast.Name) and n.id in ("ImportError", "ModuleNotFoundError", "Exception", "BaseException"):
                return True
            if isinstance(n, ast.Attribute) and n.attr in ("ImportError", "ModuleNotFoundError"):
                return True
    return False


def is_test_path(p):
    n = posixpath.basename(p)
    return bool((n.startswith("test_") and n.endswith(".py")) or n.endswith("_test.py")
                or re.search(r"\.(test|spec)\.(jsx?|tsx?|mjs|cjs)$", n)
                or ("/__tests__/" in "/" + p and n.endswith(JS)))


# ----------------------------------------------------------------------------- per-file facts
def _sig(node):
    a = node.args
    pos = [x.arg for x in a.posonlyargs] + [x.arg for x in a.args]
    shown = _unparse(a, 400)
    text = "(" + (shown if len(shown) <= 110 else shown[:107] + "...") + ")"
    if node.returns is not None:
        text += " -> " + _unparse(node.returns, 40)
    return {"p": pos, "po": len(a.posonlyargs), "r": len(pos) - len(a.defaults),
            "va": a.vararg.arg if a.vararg else None,
            "ko": [x.arg for x in a.kwonlyargs],
            "kr": [x.arg for x, d in zip(a.kwonlyargs, a.kw_defaults) if d is None],
            "kw": a.kwarg.arg if a.kwarg else None,
            "a": 1 if isinstance(node, ast.AsyncFunctionDef) else 0, "t": text[:160]}


def _sigkey(s):
    return (tuple(s["p"]), s["po"], s["r"], s["va"], tuple(s["ko"]), tuple(s["kr"]), s["kw"])


class _Facts:
    def __init__(self):
        self.names, self.defs, self.imports, self.glob = set(), {}, [], set()
        self.dyn, self.mod, self.all_list, self.seen = False, [], None, set()

    def walk(self, body, prefix="", cls=None, top=True, guard=False):
        for st in body:
            if isinstance(st, _FUNC):
                q = prefix + st.name
                self.add_def(q, st, "m" if cls else "f", cls)
                if top:
                    self.names.add(st.name)
            elif isinstance(st, ast.ClassDef):
                q = prefix + st.name
                self.add_class(q, st, cls)
                if top:
                    self.names.add(st.name)
                self.walk(st.body, q + ".", q, False, guard)
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                self.add_import(st, 1 if (top and cls is None) else 0, guard)
            else:
                if top:
                    _bound_by_stmt(st, self.names)
                if top and cls is None:
                    self.mod.append(st)
                    if (isinstance(st, ast.Assign) and isinstance(st.value, (ast.List, ast.Tuple))
                            and any(isinstance(t, ast.Name) and t.id == "__all__" for t in st.targets)
                            and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in st.value.elts)):
                        self.all_list = [e.value for e in st.value.elts]
                if isinstance(st, _TRY):
                    g = guard or _catches_import_error(st)
                    self.walk(st.body, prefix, cls, top, g)
                    for h in st.handlers:
                        self.walk(h.body, prefix, cls, top, guard)
                    self.walk(st.orelse, prefix, cls, top, guard)
                    self.walk(st.finalbody, prefix, cls, top, guard)
                else:
                    for sub in _child_bodies(st):
                        self.walk(sub, prefix, cls, top, guard)

    def add_import(self, st, t, guard):
        self.seen.add(id(st))
        g = 1 if guard else 0
        if isinstance(st, ast.Import):
            for a in st.names:
                self.imports.append({"m": a.name, "n": None, "a": a.asname, "l": 0, "ln": st.lineno, "t": t, "g": g})
                if t:
                    self.names.add(a.asname or a.name.split(".")[0])
        else:
            if st.module == "__future__":
                return
            for a in st.names:
                self.imports.append({"m": st.module or "", "n": a.name, "a": a.asname, "l": st.level,
                                     "ln": st.lineno, "t": t, "g": g})
                if t and a.name != "*":
                    self.names.add(a.asname or a.name)

    def add_def(self, q, node, kind, cls):
        decs = [_unparse(d, 60) for d in node.decorator_list]
        start = min([node.lineno] + [d.lineno for d in node.decorator_list])
        e = {"k": kind, "l": start, "e": getattr(node, "end_lineno", None) or node.lineno, "s": _sig(node),
             "sz": sum(1 for _ in ast.walk(node)),
             "fp": _fp(*node.decorator_list, node.args, node.returns, *getattr(node, "type_params", ()),
                       *_strip_doc(node.body)), "d": decs, "c": cls}
        if q in self.defs:
            self.defs[q]["dup"] = 1
            self.defs[q]["fp"] = _fp(self.defs[q]["fp"], e["fp"])
        else:
            self.defs[q] = e

    def add_class(self, q, node, cls):
        decs = [_unparse(d, 60) for d in node.decorator_list]
        start = min([node.lineno] + [d.lineno for d in node.decorator_list])
        attrs = [n for n in _strip_doc(node.body) if not isinstance(n, _FUNC + (ast.ClassDef,))]
        e = {"k": "c", "l": start, "e": getattr(node, "end_lineno", None) or node.lineno, "s": None,
             "fp": _fp(*node.decorator_list, *node.bases, *node.keywords, *attrs), "d": decs, "c": cls,
             "b": [_unparse(b, 40) for b in node.bases][:6],
             "mc": 1 if any(k.arg == "metaclass" for k in node.keywords) else 0}
        if q in self.defs:
            self.defs[q]["dup"] = 1
        else:
            self.defs[q] = e

    def sweep(self, tree):
        stack = [(tree, False)]
        while stack:
            node, guard = stack.pop()
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if id(node) not in self.seen:
                    self.add_import(node, 0, guard)
                continue
            if isinstance(node, ast.Global):
                self.glob.update(node.names)
                continue
            if _injects(node):
                self.dyn = True
            if isinstance(node, _TRY):
                g = guard or _catches_import_error(node)
                stack.extend((s, g) for s in node.body)
                for h in node.handlers:
                    stack.extend((s, guard) for s in h.body)
                stack.extend((s, guard) for s in node.orelse + node.finalbody)
                continue
            stack.extend((c, guard) for c in ast.iter_child_nodes(node))


def analyze(data: bytes) -> dict:
    """Facts for one Python source (cacheable, JSON-safe)."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(data)
        body = _strip_doc(tree.body)
        facts = _Facts()
        facts.walk(body)
        facts.sweep(tree)
        names = facts.names | facts.glob
        mods = [s for s in facts.mod if not isinstance(s, (ast.Import, ast.ImportFrom))]
        facts.imports.sort(key=lambda i: i["ln"])
        return {"v": ANALYZER, "n": sorted(names), "o": 1 if ("__getattr__" in names or facts.dyn) else 0, "d": facts.defs,
                "i": facts.imports, "mf": _fp(*mods), "dy": 1 if facts.dyn else 0, "al": facts.all_list,
                "lc": len(data.splitlines())}
    except SyntaxError as exc:
        return {"v": ANALYZER, "err": f"SyntaxError: {exc.msg} (line {exc.lineno})"}
    except (ValueError, RecursionError, MemoryError) as exc:
        return {"v": ANALYZER, "err": f"{type(exc).__name__}: {str(exc)[:80]}"}


_JS_RES = (re.compile(r"""\b(?:import|export)\b[^'";]*?\bfrom\s*['"]([^'"\n]+)['"]"""),
           re.compile(r"""\bimport\s*['"]([^'"\n]+)['"]"""),
           re.compile(r"""\b(?:require|import)\s*\(\s*['"]([^'"\n]+)['"]\s*\)"""))


def analyze_js(data: bytes) -> dict:
    text, seen, out = data.decode("utf-8", "replace"), set(), []
    for rx in _JS_RES:
        for m in rx.finditer(text):
            key = (m.group(1), text.count("\n", 0, m.start()) + 1)
            if key not in seen:
                seen.add(key)
                out.append([key[0], key[1]])
    out.sort(key=lambda x: x[1])
    return {"v": ANALYZER, "js": out[:500]}


def sym_delta(old, new):
    """Symbol-level change list between two fact dicts (None = file absent)."""
    od, nd = (old or {}).get("d") or {}, (new or {}).get("d") or {}
    out = []
    for q in sorted(od.keys() | nd.keys()):
        a, b = od.get(q), nd.get(q)
        if a is None:
            out.append({"q": q, "ch": "added", "new": b["s"]["t"] if b.get("s") else "class"})
        elif b is None:
            out.append({"q": q, "ch": "removed", "old": a["s"]["t"] if a.get("s") else "class"})
        elif a.get("s") and b.get("s") and _sigkey(a["s"]) != _sigkey(b["s"]):
            out.append({"q": q, "ch": "sig", "old": a["s"]["t"], "new": b["s"]["t"]})
        elif a.get("fp") != b.get("fp"):
            out.append({"q": q, "ch": "logic"})
    if old is not None and new is not None and old.get("mf") != new.get("mf"):
        out.append({"q": "<module>", "ch": "logic"})
    return out


def _sigchanged(delta):
    names = set()
    for d in delta:
        if d["ch"] == "sig":
            q = d["q"]
            if q.endswith(".__init__"):
                names.add(q.rsplit(".", 1)[0])
            elif "." not in q:
                names.add(q)
    return names


# ----------------------------------------------------------------------------- scope-aware scan
def _chain(n):
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return tuple(reversed(parts))
    return None


def _bound(fn):
    """Every name bound anywhere inside a function/lambda (deliberately conservative)."""
    a, s = fn.args, set()
    for x in a.posonlyargs + a.args + a.kwonlyargs:
        s.add(x.arg)
    for x in (a.vararg, a.kwarg):
        if x:
            s.add(x.arg)
    for b in (fn.body if isinstance(fn.body, list) else [fn.body]):
        for n in ast.walk(b):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                s.add(n.id)
            elif isinstance(n, _FUNC + (ast.ClassDef,)):
                s.add(n.name)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                s.add(n.name)
            elif isinstance(n, ast.Import):
                s.update((al.asname or al.name).split(".")[0] for al in n.names)
            elif isinstance(n, ast.ImportFrom):
                s.update(al.asname or al.name for al in n.names)
            elif isinstance(n, ast.arg):
                s.add(n.arg)
            elif type(n).__name__ in ("MatchAs", "MatchStar") and getattr(n, "name", None):
                s.add(n.name)
            elif type(n).__name__ == "MatchMapping" and n.rest:
                s.add(n.rest)
    return frozenset(s)


def _module_rebinds(body, out):
    for st in body:
        if isinstance(st, _FUNC + (ast.ClassDef, ast.Import, ast.ImportFrom)):
            continue
        _bound_by_stmt(st, out)
        for sub in _child_bodies(st):
            _module_rebinds(sub, out)


_RAISES = ("raises", "assertRaises", "assertRaisesMessage", "assertRaisesRegex", "assertRaisesRegexp",
           "assertWarns", "assertWarnsMessage", "assertWarnsRegex", "warns", "deprecated_call")


def _is_raises(expr):
    ch = _chain(expr.func) if isinstance(expr, ast.Call) else None
    return bool(ch and ch[-1] in _RAISES)


def scan_source(data: bytes):
    """Every call / name-chain reference with the set of names shadowing it locally.

    Items are (kind, line, chain, extra, shadow_index); kind is "call"/"ref", or "rcall"/"rref"
    inside ``with assertRaises(...)`` / ``pytest.raises(...)`` (deliberate misuse: never reported).
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(data)
        items, shadows, rebound = [], [frozenset()], set()
        _module_rebinds(tree.body, rebound)
        rebound.update(n for g in ast.walk(tree) if isinstance(g, ast.Global) for n in g.names)

        def sub(idx, extra):
            shadows.append(shadows[idx] | extra)
            return len(shadows) - 1

        def visit(node, sh, rs=False):
            if isinstance(node, _FUNC + (ast.Lambda,)):
                for d in list(node.args.defaults) + [x for x in node.args.kw_defaults if x is not None]:
                    visit(d, sh, rs)
                for d in getattr(node, "decorator_list", ()):
                    visit(d, sh, rs)
                new = sub(sh, _bound(node))
                for s in (node.body if isinstance(node.body, list) else [node.body]):
                    visit(s, new, False)
                return
            if isinstance(node, ast.ClassDef):
                for d in node.decorator_list + node.bases + [k.value for k in node.keywords]:
                    visit(d, sh, rs)
                for s in node.body:
                    visit(s, sh, False)
                return
            if isinstance(node, (ast.With, ast.AsyncWith)):
                inner = rs or any(_is_raises(it.context_expr) for it in node.items)
                for it in node.items:
                    visit(it.context_expr, sh, rs)
                for s in node.body:
                    visit(s, sh, inner)
                return
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                names = set()
                for g in node.generators:
                    _target_names(g.target, names)
                new = sub(sh, names)
                for g in node.generators:
                    visit(g.iter, new, rs)
                    for c in g.ifs:
                        visit(c, new, rs)
                for e in ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)):
                    visit(e, new, rs)
                return
            if isinstance(node, ast.Call):
                ch = _chain(node.func)
                extra = (sum(1 for a in node.args if not isinstance(a, ast.Starred)),
                         tuple(k.arg for k in node.keywords if k.arg),
                         any(isinstance(a, ast.Starred) for a in node.args),
                         any(k.arg is None for k in node.keywords))
                if ch:
                    items.append(("rcall" if rs else "call", node.lineno, ch, extra, sh))
                else:
                    if isinstance(node.func, ast.Attribute):  # Foo().bar(...): receiver unknown, args real
                        items.append(("rcall" if rs else "call", node.lineno, ("?", node.func.attr), extra, sh))
                    visit(node.func, sh, rs)
                for a in node.args:
                    visit(a, sh, rs)
                for k in node.keywords:
                    visit(k.value, sh, rs)
                return
            if isinstance(node, (ast.Attribute, ast.Name)) and isinstance(getattr(node, "ctx", None), ast.Load):
                ch = _chain(node)
                if ch:
                    items.append(("rref" if rs else "ref", node.lineno, ch, None, sh))
                    return
                if isinstance(node, ast.Attribute):
                    visit(node.value, sh, rs)
                    return
            for child in ast.iter_child_nodes(node):
                visit(child, sh, rs)

        for st in tree.body:
            visit(st, 0)
        return {"items": items, "shadows": shadows, "rebound": rebound}
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def deep_check(data: bytes, rel="<file>"):
    """compile() + symtable for *changed* files: syntax errors and undefined global names."""
    out = {"err": None, "undef": None}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(data)
            compile(tree, rel, "exec", dont_inherit=True)
    except SyntaxError as exc:
        out["err"] = f"SyntaxError: {exc.msg} (line {exc.lineno})"
        return out
    except (ValueError, RecursionError, MemoryError, OverflowError) as exc:
        out["err"] = f"{type(exc).__name__}: {str(exc)[:80]}"
        return out
    nodes = list(ast.walk(tree))
    if any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in nodes):
        return out
    if any(_injects(n) for n in nodes):
        return out
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            top = symtable.symtable(data.decode("utf-8", "replace"), rel, "exec")
    except (SyntaxError, ValueError, RecursionError):
        return out

    def tables(t):
        yield t
        for c in t.get_children():
            yield from tables(c)

    allt = list(tables(top))
    defined = {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
    for t in allt[1:]:
        defined.update(s.get_name() for s in t.get_symbols() if s.is_declared_global() and s.is_assigned())
    bad = defaultdict(set)  # name -> start lines of the scopes that reference it
    for t in allt:
        for s in t.get_symbols():
            n = s.get_name()
            if n in defined or n in BUILTINS or not s.is_referenced():
                continue
            # NB: Symbol.is_global() is unreliable (CPython treats any table *named* "top" as module scope)
            if s.is_assigned() or s.is_parameter() or s.is_imported() or s.is_namespace() or s.is_free():
                continue
            bad[n].add(0 if t is top else t.get_lineno())
    if bad:
        ranges = {n.lineno: (n.end_lineno or n.lineno) for n in nodes if isinstance(n, _FUNC + (ast.ClassDef,))}
        spans = list(ranges.items())
        loads = defaultdict(list)
        for n in nodes:
            if isinstance(n, ast.Name) and n.id in bad and isinstance(n.ctx, ast.Load):
                loads[n.id].append(n.lineno)

        def in_scope(ln, start):
            if start == 0:  # module scope: only code outside every def/class (they have their own scopes)
                return not any(a <= ln <= b for a, b in spans)
            return start <= ln <= ranges.get(start, start)

        lines = {}
        for name, starts in bad.items():
            scoped = sorted(ln for ln in loads[name] if any(in_scope(ln, st) for st in starts))
            lines[name] = (scoped or sorted(loads[name]))[:3]
        out["undef"] = {k: v for k, v in lines.items() if v}
    else:
        out["undef"] = {}
    return out


def call_problems(sig, skip, np, kws, star, dstar):
    pos = sig["p"][skip:]
    po, req = max(sig["po"] - skip, 0), max(sig["r"] - skip, 0)
    out = []
    if np > len(pos) and not sig["va"]:
        out.append(f"takes at most {len(pos)} positional argument(s), got {np}")
    filled = pos[:np]
    for k in kws:
        if k in filled[po:]:
            out.append(f"multiple values for `{k}`")
        elif k in pos[po:] or k in sig["ko"] or sig["kw"]:
            continue
        elif k in pos[:po]:
            out.append(f"`{k}` is positional-only")
        else:
            near = difflib.get_close_matches(k, pos + sig["ko"], 1, 0.6)
            out.append(f"unexpected keyword `{k}`" + (f" (did you mean `{near[0]}`?)" if near else ""))
    if not dstar:
        miss = [n for n in sig["kr"] if n not in kws]
        if not star:
            miss = [n for i, n in enumerate(pos[:req]) if i >= np and (i < po or n not in kws)] + miss
        if miss:
            out.append("missing " + ", ".join(f"`{m}`" for m in miss))
    return out


def _finding(code, path, line, msg, fix=None, sym=None, tgt=None, cand=None):
    d = {"code": code, "path": path, "line": line, "msg": msg}
    for k, v in (("fix", fix), ("sym", sym), ("tgt", tgt), ("cand", cand)):
        if v:
            d[k] = v
    return d


# ----------------------------------------------------------------------------- cache
def _cache_file(cache_dir):
    return Path(cache_dir) / f"pyindex-{ANALYZER}-{sys.version_info[0]}{sys.version_info[1]}.json"


def _load_cache(cache_dir):
    try:
        p = _cache_file(cache_dir)
        if p.is_symlink() or not p.is_file() or p.stat().st_size > (256 << 20):
            return {}
        data = json.loads(p.read_text("utf-8"))
        return data.get("f", {}) if data.get("v") == ANALYZER else {}
    except (OSError, ValueError):
        return {}


def _save_cache(cache_dir, facts):
    try:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=cache_dir)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"v": ANALYZER, "f": facts}, stream, separators=(",", ":"))
        os.replace(tmp, _cache_file(cache_dir))
    except OSError:
        pass


# ----------------------------------------------------------------------------- the repo world
class World:
    """Repo-wide import graph + symbol resolver built from git's file list."""

    def __init__(self, root):
        self.root = Path(root)
        self.files, self.all_paths, self.dirs = {}, set(), set()
        self.partial = 0
        self._ai, self._ex, self._busy = {}, {}, set()
        self._rev = self._topidx = self._mnames = self._dups = self._fnames = None
        self.skip = None

    @classmethod
    def build(cls, root, *, skip=None, budget=10.0, cache_dir=None):
        w, t0 = cls(root), time.monotonic()
        w.skip = skip
        raw = _git(w.root, "ls-files", "-z", "--cached", "--others", "--exclude-standard") or b""
        cache = _load_cache(cache_dir) if cache_dir else {}
        fresh, keep = {}, {}
        for item in sorted({os.fsdecode(x) for x in raw.split(b"\0") if x}):
            full = w.root / item
            try:
                info = os.lstat(full)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            w.all_paths.add(item)
            d = _dir(item)
            while d and d not in w.dirs:
                w.dirs.add(d)
                d = _dir(d)
            is_py, is_js = item.endswith(".py"), item.endswith(JS)
            if not (is_py or is_js) or info.st_size > MAX_SRC or (skip and skip(item)):
                continue
            data = read_small(full)
            if data is None:
                continue
            key = blob_sha(data)
            facts = cache.get(key)
            if facts is None or facts.get("v") != ANALYZER:
                if time.monotonic() - t0 > budget:
                    w.partial += 1
                    continue
                facts = analyze(data) if is_py else analyze_js(data)
                fresh[key] = facts
            w.files[item], keep[key] = facts, facts
        if cache_dir and fresh:
            _save_cache(cache_dir, keep)
        return w

    # ---- import resolution -------------------------------------------------------------
    def _roots(self, importer):
        """Directories an absolute import may resolve against (Python 3 semantics).

        A module inside a package never resolves absolute imports against its own directory
        (that is how ``import typing`` stays the stdlib next to a ``typing.py``); only plain
        scripts do.  A package's root is the directory above its top-level package.
        """
        d = _dir(importer)
        if _j(d, "__init__.py") in self.all_paths:
            while d and _j(d, "__init__.py") in self.all_paths:
                d = _dir(d)
        out = []
        while True:
            out.append(d)
            if _j(d, "src") in self.dirs:
                out.append(_j(d, "src"))
            if not d:
                break
            d = _dir(d)
        return out

    def _walk(self, cur, parts, definite):
        for i, part in enumerate(parts):
            m, p, d = _j(cur, part + ".py"), _j(cur, part, "__init__.py"), _j(cur, part)
            if i == len(parts) - 1:
                if m in self.all_paths:
                    return ("ok", m)
                if p in self.all_paths:
                    return ("ok", p)
                if d in self.dirs:
                    return ("ns", d)
                return ("missing", d) if definite else ("ext", None)
            if p in self.all_paths or d in self.dirs:
                cur = d
            else:
                return ("missing", m if m in self.all_paths else d) if definite else ("ext", None)
        return ("ns", cur)

    def _guess(self, top):
        if self._topidx is None:
            idx = defaultdict(set)
            for p, f in self.files.items():
                if "d" not in f:
                    continue
                if p.endswith("__init__.py"):
                    if _dir(p):
                        idx[posixpath.basename(_dir(p))].add(_dir(_dir(p)))
                else:
                    idx[posixpath.basename(p)[:-3]].add(_dir(p))
            self._topidx = idx
        roots = self._topidx.get(top)
        return next(iter(roots)) if roots and len(roots) == 1 else None

    def _abs(self, importer, parts):
        top, roots = parts[0], self._roots(importer)
        stdlib = top in _STDLIB
        for r in roots[:1] if stdlib else roots:
            if _j(r, top + ".py") in self.all_paths or _j(r, top, "__init__.py") in self.all_paths:
                return (*self._walk(r, parts, True), False)
        if stdlib:
            return ("ext", None, False)
        for r in roots:
            if _j(r, top) in self.dirs:
                st = self._walk(r, parts, False)
                if st[0] in ("ok", "ns"):
                    return (*st, False)
        g = self._guess(top)
        if g is not None:
            st = self._walk(g, parts, False)
            if st[0] in ("ok", "ns"):
                return (*st, True)
        return ("ext", None, False)

    def _rel(self, importer, level, parts):
        base = _dir(importer)
        for _ in range(level - 1):
            if not base:
                return ("missing", "<above repo root>", False)
            base = _dir(base)
        if not parts:
            p = _j(base, "__init__.py")
            return ("ok", p, False) if p in self.all_paths else ("ns", base, False)
        return (*self._walk(base, parts, True), False)

    def _child(self, st, path, name):
        if st == "ns":
            d = path
        elif path.endswith("__init__.py"):
            d = _dir(path)
        else:
            return None
        for c in (_j(d, name + ".py"), _j(d, name, "__init__.py")):
            if c in self.all_paths:
                return c
        return None

    def imp(self, importer, im):
        key = (importer, im["l"], im["m"], im["n"], im["ln"])
        hit = self._ai.get(key)
        if hit is not None:
            return hit
        parts = im["m"].split(".") if im["m"] else []
        if im["l"]:
            st = self._rel(importer, im["l"], parts)
        elif parts:
            st = self._abs(importer, parts)
        else:
            st = ("ext", None, False)
        r = {"st": st[0], "path": st[1], "guess": st[2]}
        n = im["n"]
        if n and n != "*" and r["st"] in ("ok", "ns"):
            sub = self._child(r["st"], r["path"], n)
            if sub:
                r["sub"] = sub
            elif n.startswith("__") and n.endswith("__"):
                r["ns"] = "ok"
            elif r["st"] == "ok":
                ex, op = self.exports(r["path"])
                if n in ex:
                    r["ns"] = "ok"
                elif op:
                    r["ns"] = "maybe"
                else:
                    r["ns"] = "missing"
                    r["near"] = difflib.get_close_matches(n, sorted(ex), 3, 0.6)
        self._ai[key] = r
        return r

    def exports(self, path):
        if path in self._ex:
            return self._ex[path]
        f = self.files.get(path)
        if not f or "d" not in f:
            return set(), True
        if path in self._busy:
            return set(f["n"]), True
        self._busy.add(path)
        names, open_ = set(f["n"]), bool(f["o"])
        for im in f["i"]:
            if im["n"] == "*" and im["t"]:
                r = self.imp(path, im)
                if r["st"] == "ok":
                    sub_names, sub_open = self.exports(r["path"])
                    src = self.files.get(r["path"], {})
                    names |= set(src["al"]) if src.get("al") is not None else {n for n in sub_names if not n.startswith("_")}
                    open_ |= sub_open
                else:
                    open_ = True
        self._busy.discard(path)
        self._ex[path] = (names, open_)
        return names, open_

    def origin(self, path, name, depth=0):
        f = self.files.get(path)
        if f and "d" in f and name not in f["d"] and depth < 6:
            for im in f["i"]:
                if im["t"] and im["n"] not in (None, "*") and (im["a"] or im["n"]) == name:
                    r = self.imp(path, im)
                    if r.get("sub"):
                        return (r["sub"], None)
                    if r["st"] == "ok":
                        return self.origin(r["path"], im["n"], depth + 1)
        return (path, name)

    def js_target(self, importer, spec):
        if not spec.startswith("."):
            return None
        base = posixpath.normpath(_j(_dir(importer), spec))
        if base.startswith(".."):
            return None
        cands = [base]
        for ext in (".js", ".jsx", ".mjs", ".cjs"):
            if base.endswith(ext):
                cands += [base[:-len(ext)] + e for e in (".ts", ".tsx")]
        cands += [base + e for e in JS_RESOLVE] + [_j(base, "index" + e) for e in JS_RESOLVE]
        for c in cands:
            if c in self.all_paths:
                return c
        return None

    def with_ghosts(self, ghosts):
        """Copy of this world where deleted modules still exist (to find who imported them)."""
        w = World(self.root)
        w.files, w.all_paths, w.dirs = dict(self.files), set(self.all_paths), set(self.dirs)
        w.skip = self.skip
        for path, facts in ghosts.items():
            w.files[path] = facts
            w.all_paths.add(path)
            d = _dir(path)
            while d and d not in w.dirs:
                w.dirs.add(d)
                d = _dir(d)
        return w

    # ---- graph queries -----------------------------------------------------------------
    def rev(self):
        """target path -> [(importer, line, imported name|None, guessed)]"""
        if self._rev is None:
            R = defaultdict(list)
            for rel, f in self.files.items():
                if "js" in f:
                    for spec, ln in f["js"]:
                        t = self.js_target(rel, spec)
                        if t and t != rel:
                            R[t].append((rel, ln, None, False))
                elif "i" in f:
                    for im in f["i"]:
                        r = self.imp(rel, im)
                        for t in ([r["path"]] if r["st"] == "ok" else []) + ([r["sub"]] if r.get("sub") else []):
                            if t != rel:
                                R[t].append((rel, im["ln"], im["n"], r["guess"]))
            self._rev = R
        return self._rev

    def tests_for(self, paths, depth=3, cap=60):
        R, out = self.rev(), {}
        for start in paths:
            seen, queue = {start}, deque([(start, 0, None)])
            while queue and len(seen) < 4000:
                node, d, via = queue.popleft()
                if d >= depth:
                    continue
                for src, _ln, _nm, _g in R.get(node, ()):
                    if src in seen:
                        continue
                    seen.add(src)
                    v = via or src
                    if is_test_path(src):
                        prev = out.get(src)
                        if prev is None or d + 1 < prev[0]:
                            out[src] = (d + 1, None if d == 0 else v)
                    queue.append((src, d + 1, v))
        return sorted(out.items(), key=lambda kv: (kv[1][0], kv[0]))[:cap]

    def heuristic_tests(self, rel):
        stem = posixpath.basename(rel).rsplit(".", 1)[0]
        names = {f"test_{stem}.py", f"{stem}_test.py", f"{stem}.test.ts", f"{stem}.test.js", f"{stem}.spec.ts",
                 f"{stem}.spec.js", f"{stem}.test.tsx", f"{stem}.spec.tsx"}
        return sorted(p for p in self.all_paths if posixpath.basename(p) in names)[:4]

    # ---- bindings & chain resolution ---------------------------------------------------
    def bindings(self, rel, facts):
        out = defaultdict(list)
        for im in facts["i"]:
            if im["n"] == "*":
                continue
            r = self.imp(rel, im)
            if im["n"] is None:
                if im["a"]:
                    out[im["a"]].append(("mod", r["path"], r["guess"]) if r["st"] == "ok" else ("unk",))
                else:
                    top = im["m"].split(".")[0]
                    st = self._abs(rel, [top])
                    out[top].append(("mod", st[1], st[2]) if st[0] == "ok" else ("unk",))
            else:
                local = im["a"] or im["n"]
                if r.get("sub"):
                    out[local].append(("mod", r["sub"], r["guess"]))
                elif r["st"] == "ok":
                    out[local].append(("sym", r["path"], im["n"], r["guess"]))
                else:
                    out[local].append(("unk",))
        for q in facts["d"]:
            if "." not in q:
                out[q].append(("sym", rel, q, False))
        return out

    def _walk_mod(self, cur, rest, guess):
        for i, c in enumerate(rest):
            if c.startswith("__") and c.endswith("__"):
                return None  # __file__/__path__/__name__...: implicit module attributes
            f = self.files.get(cur)
            if f and "d" in f and c in f["n"]:
                org = self.origin(cur, c)
                if org[1] is None:
                    cur = org[0]
                    continue
                return ("sym", org[0], org[1], tuple(rest[i + 1:]), guess)
            sub = self._child("ok", cur, c)
            if sub:
                cur = sub
                continue
            ex, op = self.exports(cur)
            if c in ex or op:
                return None
            return ("missing", cur, c, guess)
        return ("module", cur)

    def resolve(self, chain, shadow, binds, rebound):
        n0 = chain[0]
        if n0 in shadow or n0 in rebound:
            return None
        c = binds.get(n0)
        if not c or len(c) != 1 or c[0][0] == "unk":
            return None
        b = c[0]
        if b[0] == "sym":
            org = self.origin(b[1], b[2])
            if org[1] is None:
                return self._walk_mod(org[0], chain[1:], b[3])
            return ("sym", org[0], org[1], chain[1:], b[3])
        return self._walk_mod(b[1], chain[1:], b[2])

    def callee_sig(self, path, name):
        f = self.files.get(path)
        if not f or "d" not in f:
            return None
        d = f["d"].get(name)
        if not d or d.get("dup"):
            return None
        ok_dec = lambda decs: all(x.startswith(BENIGN) for x in decs)  # noqa: E731
        if d["k"] == "f":
            return (d["s"], 0) if ok_dec(d["d"]) else None
        if d["k"] == "c" and not d["d"] and not d.get("mc"):
            if any(re.search(r"Enum|NamedTuple|TypedDict|Protocol", b) for b in d.get("b", [])):
                return None
            init, new = f["d"].get(name + ".__init__"), f["d"].get(name + ".__new__")
            if init and not new and not init.get("dup") and ok_dec(init["d"]):
                return init["s"], 1
        return None

    def dynamic_ancestor(self, p):
        q = p[:-3] if p.endswith(".py") else p
        while q:
            for cand in (q + ".py", _j(q, "__init__.py")):
                f = self.files.get(cand)
                if f and "d" in f and self.exports(cand)[1]:
                    return True
            q = _dir(q)
        return False

    def near_modules(self, path):
        d, base = _dir(path), posixpath.basename(path)
        base = base[:-3] if base.endswith(".py") else base
        cands = {posixpath.basename(p)[:-3] for p in self.files if _dir(p) == d and p.endswith(".py")}
        cands |= {posixpath.basename(x) for x in self.dirs if _dir(x) == d}
        return difflib.get_close_matches(base, sorted(cands - {"__init__"}), 3, 0.6)

    # ---- static checks on one file -----------------------------------------------------
    def check_file(self, rel, data, facts):
        out = []
        if not facts or "d" not in facts:
            return out
        for im in facts["i"]:
            if im["n"] == "*" or im.get("g"):
                continue
            r = self.imp(rel, im)
            dotted = "." * im["l"] + im["m"]
            if r["st"] == "missing" and not r["guess"]:
                p = r["path"]
                if self.dynamic_ancestor(p):
                    continue
                if p.endswith(".py"):
                    msg = f"`{p[:-3].replace('/', '.')}` is a module, not a package; cannot import `{dotted}`"
                    out.append(_finding("E-IMPORT", rel, im["ln"], msg))
                else:
                    near = self.near_modules(p)
                    out.append(_finding("E-IMPORT", rel, im["ln"], f"no module `{dotted}` in repo (expected {p}.py)",
                                        fix=("did you mean " + ", ".join(near) + "?") if near else None,
                                        cand=[p + ".py", p + "/__init__.py", p]))
            elif im["n"] and r.get("ns") == "maybe" and not r["guess"]:
                out.append(_finding("?-OPEN", rel, im["ln"],
                                    f"`{im['n']}` is not among the names defined in {r['path']}; that module loads names "
                                    "dynamically (__getattr__/globals/star-import), so absence cannot be proved - check it exists",
                                    sym=im["n"], tgt=r["path"]))
            elif im["n"] and r.get("ns") == "missing" and not r["guess"]:
                near = r.get("near") or []
                d = _dir(r["path"])
                out.append(_finding("E-NAME", rel, im["ln"], f"`{im['n']}` is not defined in {r['path']}",
                                    fix=("did you mean " + ", ".join(near) + "?") if near else None,
                                    sym=im["n"], tgt=r["path"],
                                    cand=[_j(d, im["n"] + ".py"), _j(d, im["n"], "__init__.py")]))
        scan = scan_source(data)
        if scan:
            binds = self.bindings(rel, facts)
            for kind, ln, chain, extra, sh in scan["items"]:
                if kind in ("rcall", "rref"):
                    continue
                res = self.resolve(chain, scan["shadows"][sh], binds, scan["rebound"])
                if not res:
                    continue
                if res[0] == "missing" and not res[3]:
                    near = difflib.get_close_matches(res[2], sorted(self.exports(res[1])[0]), 3, 0.6)
                    out.append(_finding("E-ATTR", rel, ln, f"`{'.'.join(chain)}`: {res[1]} has no `{res[2]}`",
                                        fix=("did you mean " + ", ".join(near) + "?") if near else None,
                                        sym=res[2], tgt=res[1]))
                elif kind == "call" and res[0] == "sym" and not res[3] and not res[4]:
                    sig = self.callee_sig(res[1], res[2])
                    if sig:
                        probs = call_problems(sig[0], sig[1], *extra)
                        if probs:
                            out.append(_finding("E-CALL", rel, ln, f"`{'.'.join(chain)}()` " + "; ".join(probs),
                                                fix=f"signature is {res[2]}{sig[0]['t']} ({res[1]})",
                                                sym=res[2], tgt=res[1]))
        seen, uniq = set(), []
        for f in out:
            k = (f["code"], f["line"], f["msg"])
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        return uniq

    def js_missing(self, rel, data):
        out = []
        for spec, ln in analyze_js(data)["js"]:
            if spec.startswith(".") and self.js_target(rel, spec) is None:
                base = posixpath.normpath(_j(_dir(rel), spec))
                if not base.startswith(".."):
                    out.append(_finding("E-IMPORT", rel, ln, f"relative import `{spec}` resolves to no file",
                                        cand=[base] + [base + e for e in JS_RESOLVE] + [_j(base, "index" + e) for e in JS_RESOLVE]))
        return out

    def name_hits(self, name, exclude=(), cap=4):
        raw = _git(self.root, "grep", "-n", "-w", "-F", "-I", "--untracked", "-z", "-e", name, "--",
                   *SRC_PATHSPECS, *CONFIG_PATHSPECS, ok=(0, 1)) or b""
        hits = []
        for m in _REF_RE.finditer(raw):
            path = os.fsdecode(m.group(1))
            if "lock" in posixpath.basename(path).lower():  # lockfiles are noise, never evidence
                continue
            if path not in exclude and path in self.all_paths and not (self.skip and self.skip(path)):
                hits.append((path, int(m.group(2))))
        return hits[:cap], len(hits)

    def dup_index(self):
        if self._dups is None:
            idx = defaultdict(list)
            for path, f in self.files.items():
                for q, d in f.get("d", {}).items():
                    if d["k"] in ("f", "m") and d.get("sz", 0) >= 40 and not d.get("dup"):
                        idx[d["fp"]].append((path, q))
            self._dups = idx
        return self._dups

    def func_names(self):
        if self._fnames is None:
            names = {}
            for path, f in self.files.items():
                for q, d in f.get("d", {}).items():
                    if d["k"] == "f" and "." not in q and not q.startswith(("test", "_")):
                        names.setdefault(q, (path, q))
            self._fnames = names
        return self._fnames

    def method_names(self):
        """simple method name -> number of classes defining it (uniqueness makes name-based call checks safer)"""
        if self._mnames is None:
            counts = defaultdict(int)
            for f in self.files.values():
                for q, d in f.get("d", {}).items():
                    if d["k"] == "m":
                        counts[q.rsplit(".", 1)[-1]] += 1
            self._mnames = counts
        return self._mnames

    def drop_ignored(self, findings):
        """Remove import findings whose expected file is merely gitignored/generated."""
        cands = sorted({c for f in findings for c in f.get("cand", ())})
        if not cands:
            return findings
        raw = _git(self.root, "check-ignore", "-z", "--no-index", "--stdin",
                   stdin=b"\0".join(os.fsencode(c) for c in cands) + b"\0", ok=(0, 1)) or b""
        ignored = {os.fsdecode(x) for x in raw.split(b"\0") if x}
        return [f for f in findings if not (set(f.get("cand", ())) & ignored)]


# ----------------------------------------------------------------------------- locate / outline / slice
def locate(paths, spec, cwd_rel=""):
    s = spec.replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    if s in paths:
        return s, []
    if cwd_rel and _j(cwd_rel, s) in paths:
        return _j(cwd_rel, s), []
    suffix = [p for p in paths if p.endswith("/" + s)]
    if len(suffix) == 1:
        return suffix[0], []
    base = posixpath.basename(s)
    cands = suffix or [p for p in paths if posixpath.basename(p) == base]
    if len(cands) == 1:
        return cands[0], []
    if cands:
        return None, sorted(cands, key=lambda p: (len(p), p))[:6]
    names = {}
    for p in sorted(paths):
        names.setdefault(posixpath.basename(p), p)
    return None, [names[c] for c in difflib.get_close_matches(base, list(names), n=4, cutoff=0.6)]


def outline_lines(facts, limit=60):
    if not facts or "d" not in facts:
        return []
    items = sorted(facts["d"].items(), key=lambda kv: (kv[1]["l"], kv[0]))
    out = []
    for q, d in items[:limit]:
        name = q.rsplit(".", 1)[-1]
        if d["k"] == "c":
            label = f"class {name}" + (f"({', '.join(d['b'])})" if d.get("b") else "")
        else:
            label = ("async " if d["s"]["a"] else "") + f"def {name}{d['s']['t']}"
        deco = (" @" + ",".join(x.split("(")[0] for x in d["d"])) if d["d"] else ""
        out.append(f"{d['l']}-{d['e']} {'  ' * q.count('.')}{label[:140]}{deco}")
    if len(items) > limit:
        out.append(f"(+{len(items) - limit} more; use `outline --all`)")
    return out


def slice_view(rel, data, target, context=0, max_lines=150):
    lines = data.decode("utf-8", "replace").splitlines()
    sha, m = blob_sha(data)[:7], re.fullmatch(r"(\d+)(?:-(\d+))?", target)
    label = ""
    if m:
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
    else:
        facts = analyze(data)
        if "d" not in facts:
            return None, f"{rel}: {facts.get('err', 'cannot parse')}; slice by line range instead (e.g. 10-40)"
        defs = facts["d"]
        d = defs.get(target)
        if d is None:
            hits = [q for q in defs if q.rsplit(".", 1)[-1] == target]
            if len(hits) == 1:
                target, d = hits[0], defs[hits[0]]
            elif hits:
                return None, f"`{target}` is ambiguous in {rel}: " + ", ".join(sorted(hits)[:8])
            else:
                near = difflib.get_close_matches(target, list(defs), 4, 0.5)
                return None, f"no symbol `{target}` in {rel}" + (f"; closest: {', '.join(near)}" if near else "")
        a, b, label = d["l"], d["e"], f"  {target}"
        if d["k"] == "c" and b - a + 1 > max_lines:
            members = [x for x in sorted(defs.items(), key=lambda kv: kv[1]["l"]) if x[1].get("c") == target]
            head = [f"{i:>5}| {lines[i - 1]}" for i in range(a, min(a + 3, len(lines)) + 1)]
            body = [f"      | {x[0].rsplit('.', 1)[-1]}{x[1]['s']['t'][:90] if x[1]['s'] else ''}   [{x[1]['l']}-{x[1]['e']}]"
                    for x in members]
            return "\n".join([f"{rel}:{a}-{b}{label}  sha:{sha}  (large class: members listed; slice `{target}.<name>`)"]
                             + head + body), None
    a2, b2 = max(1, a - context), min(len(lines), b + context)
    note = ""
    if b2 - a2 + 1 > max_lines:
        b2, note = a2 + max_lines - 1, f"\n      | ... truncated at {max_lines} lines; use a line range for more"
    head = f"{rel}:{a2}-{b2}{label}  sha:{sha}"
    return head + "\n" + "\n".join(f"{i:>5}| {lines[i - 1]}" for i in range(a2, b2 + 1)) + note, None


# ----------------------------------------------------------------------------- brief
def brief(world, targets, symbol=None, ctx=None, limit=6):
    ctx = ctx or {}
    out = {"repo": ctx.get("repo") or {}, "dirty": ctx.get("dirty") or {}, "targets": [], "notes": []}
    dirty = {e["path"] for e in (out["dirty"].get("paths") or [])}
    R = world.rev()
    for rel in targets:
        data = read_small(world.root / rel)
        facts = world.files.get(rel) or (analyze(data) if data and rel.endswith(".py") else None)
        t = {"path": rel, "lines": len(data.splitlines()) if data is not None else None,
             "sha": blob_sha(data)[:7] if data is not None else None, "dirty": rel in dirty,
             "outline": outline_lines(facts, limit=max(limit * 6, 30)),
             "err": facts.get("err") if facts else None}
        groups = defaultdict(list)
        for src, ln, nm, g in R.get(rel, []):
            groups[src].append((ln, nm, g))
        t["importers"] = [{"path": s, "line": min(x[0] for x in v), "names": sorted({x[1] for x in v if x[1]}),
                           "guess": all(x[2] for x in v)} for s, v in sorted(groups.items())]
        t["tests"] = [{"path": p, "depth": d, "via": via} for p, (d, via) in world.tests_for([rel])]
        t["heuristic_tests"] = [] if t["tests"] else world.heuristic_tests(rel)
        out["targets"].append(t)
    if symbol and out["targets"]:
        out["refs"] = symbol_refs(world, out["targets"][0]["path"], symbol, limit * 4)
    out["gates"] = discover_gates(world)
    out["cochange"] = (ctx.get("history") or {})
    out["pointers"] = ctx.get("pointers") or {}
    return out


def discover_gates(world):
    """The project's own quality gates (what CI / the maintainers run), best effort and never executed."""
    root, paths = world.root, world.all_paths
    gates, seen = [], set()

    def add(cmd, src):
        if cmd not in seen:
            seen.add(cmd)
            gates.append((cmd, src))

    def rd(rel):
        data = read_small(root / rel, 300000) if rel in paths else None
        return data.decode("utf-8", "replace") if data else ""

    pj = rd("package.json")
    if pj:
        try:
            scripts = json.loads(pj).get("scripts") or {}
        except (ValueError, AttributeError):
            scripts = {}
        for k in ("test", "lint", "typecheck", "type-check", "check", "build"):
            if isinstance(scripts, dict) and k in scripts:
                add("npm test" if k == "test" else f"npm run {k}", "package.json")
    for m in re.finditer(r"^(test|lint|check|typecheck|ci|verify)\s*:", rd("Makefile"), re.M):
        add(f"make {m.group(1)}", "Makefile")
    cfg = "\n".join(rd(f) for f in ("pyproject.toml", "setup.cfg", "tox.ini", "pytest.ini"))
    if re.search(r"\[tool\.pytest|\[pytest\]|\[tool:pytest\]", cfg) or any(is_test_path(p) and p.endswith(".py") for p in paths):
        add("pytest -q", "pytest")
    for rx, cmd in ((r"\[tool\.ruff", "ruff check ."), (r"\[tool\.mypy|\[mypy\]", "mypy ."),
                    (r"\[tool\.black", "black --check ."), (r"\[tool\.pyright", "pyright"), (r"\[flake8\]", "flake8")):
        if re.search(rx, cfg):
            add(cmd, "config")
    if "tsconfig.json" in paths:
        add("npx tsc --noEmit", "tsconfig.json")
    if any("/" not in p and re.match(r"(\.eslintrc|eslint\.config)", p) for p in paths):
        add("npx eslint .", "eslint config")
    if "go.mod" in paths:
        for c in ("go build ./...", "go vet ./...", "go test ./..."):
            add(c, "go.mod")
    if "Cargo.toml" in paths:
        for c in ("cargo check", "cargo clippy", "cargo test"):
            add(c, "Cargo.toml")
    tools = re.compile(r"\b(pytest|ruff|mypy|flake8|black|pyright|tox|nox|npm|yarn|pnpm|tsc|eslint|go|cargo|make|gradle|mvn|dotnet)\b")
    for wf in sorted(p for p in paths if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")))[:6]:
        for line in rd(wf).splitlines():
            m = re.match(r"\s*-?\s*run:\s*(?![|>])(.+)$", line)
            if m and tools.search(m.group(1)) and "install" not in m.group(1) and len(m.group(1)) < 90:
                add("CI: " + m.group(1).strip(), posixpath.basename(wf))
    return gates[:8]


def symbol_refs(world, path, symbol, cap=24, budget=4.0):
    """CONFIRMED (AST-resolved) / PROBABLE (method name in an importing file) / POSSIBLE (word match).

    Only files in the import-graph neighbourhood of ``path`` (importers, then importers of
    re-exporters) can hold a confirmed reference, so only those are parsed - nearest first.
    """
    facts = world.files.get(path)
    res = {"symbol": symbol, "kind": None, "confirmed": [], "probable": [], "possible": [], "total_possible": 0,
           "scanned": 0, "partial": False}
    if not facts or "d" not in facts:
        res["kind"] = "non-python"
    else:
        defs = facts["d"]
        if symbol in defs:
            res["kind"] = defs[symbol]["k"]
        else:
            hits = [q for q in defs if q.rsplit(".", 1)[-1] == symbol]
            res["kind"] = "method" if hits else "unknown"
            res["qual"] = hits[:3]
    name = symbol.rsplit(".", 1)[-1]
    raw = _git(world.root, "grep", "-l", "-z", "-w", "-F", "-I", "--untracked", "-e", name,
               "--", "*.py", ok=(0, 1)) or b""
    texty = {os.fsdecode(x) for x in raw.split(b"\0") if x}
    R, depth, frontier = world.rev(), {path: 0}, {path}
    for d in (1, 2):
        nxt = {s for t in frontier for s, _l, _n, _g in R.get(t, ())} - set(depth)
        depth.update({s: d for s in nxt})
        frontier = nxt
    direct = {s for s, d in depth.items() if d == 1}
    cands = sorted((c for c in texty if c in depth), key=lambda c: (depth[c], c))
    done, t0 = set(), time.monotonic()
    for c in cands[:200]:
        if time.monotonic() - t0 > budget:
            res["partial"] = True
            break
        f = world.files.get(c)
        data = read_small(world.root / c) if f and "d" in f else None
        scan = scan_source(data) if data is not None else None
        if not scan:
            continue
        res["scanned"] += 1
        binds = world.bindings(c, f)
        for kind, ln, chain, _extra, sh in scan["items"]:
            if name not in chain:
                continue
            r = world.resolve(chain, scan["shadows"][sh], binds, scan["rebound"])
            if r and r[0] == "sym" and r[1] == path:
                rest = r[3]
                if (r[2] == symbol and not rest) or (r[2] + "." + ".".join(rest) == symbol) or (not rest and r[2] == name):
                    res["confirmed"].append((c, ln, kind.lstrip("r") if kind in ("rcall", "rref") else kind))
                    done.add((c, ln))
                    continue
            if (c, ln) not in done and chain[-1] == name and len(chain) > 1 and c in direct and c != path:
                res["probable"].append((c, ln, "call" if kind in ("call", "rcall") else "ref"))
                done.add((c, ln))
    hits, total = world.name_hits(name, exclude={path}, cap=cap + 20)
    seen_files = {x[0] for x in res["confirmed"]}
    res["possible"] = [(p, ln) for p, ln in hits if (p, ln) not in done and p not in seen_files][:6]
    res["total_possible"] = total
    for k in ("confirmed", "probable"):
        res[k] = sorted(set(res[k]))[:cap]
    return res


def _short(items, n):
    shown = [f"{p}:{ln}" for p, ln, *_ in items[:n]]
    more = len(items) - n
    return " · ".join(shown) + (f" (+{more})" if more > 0 else "")


def render_brief(d, limit=6, runner="python3 agentussagefolder/agent.py"):
    r, L = d["repo"], []
    dn = len((d["dirty"] or {}).get("paths") or [])
    L.append(f"brief  HEAD {(r.get('head') or 'none')[:7]}  {r.get('branch') or 'detached'}  dirty:{dn}"
             + ("+" if (d["dirty"] or {}).get("truncated") else ""))
    for t in d["targets"]:
        L.append(f"TARGET {t['path']}  {t['lines']}L  sha:{t['sha']}"
                 + ("  [UNCOMMITTED EDITS - user work, preserve]" if t["dirty"] else "")
                 + (f"  [BROKEN: {t['err']}]" if t["err"] else ""))
        L += ["  " + x for x in t["outline"]]
        imps = t["importers"]
        if imps:
            L.append(f"IMPORTED-BY({len(imps)}): " + " · ".join(
                f"{i['path']}:{i['line']}" + ("~" if i["guess"] else "") for i in imps[:limit])
                + (f" (+{len(imps) - limit})" if len(imps) > limit else ""))
        else:
            L.append("IMPORTED-BY: none found (entry point, dynamic import, or non-Python caller)")
        if t["tests"]:
            L.append("TESTS: " + " · ".join(f"{x['path']}" + (f" (via {x['via']})" if x["via"] else "")
                                            for x in t["tests"][:limit]) + (f" (+{len(t['tests']) - limit})" if len(t["tests"]) > limit else ""))
        elif t["heuristic_tests"]:
            L.append("TESTS: " + " · ".join(t["heuristic_tests"]) + "  (filename match only; no import link)")
        else:
            L.append("TESTS: NONE reach this file (no import link, no filename match) - nothing will catch a regression; "
                     "choose or add a test before editing")
    refs = d.get("refs")
    if refs:
        s = refs["symbol"]
        if refs["kind"] == "unknown":
            L.append(f"REFS {s}: not defined in {d['targets'][0]['path']} (check spelling; see outline)")
        else:
            kind = {"f": "function", "c": "class", "m": "method"}.get(refs["kind"], refs["kind"])
            L.append(f"REFS {s} ({kind}{' ' + ','.join(refs.get('qual', [])) if refs.get('qual') else ''}):")
            L.append("  CONFIRMED: " + (_short(refs["confirmed"], 10) or "none (AST-proved callers/uses)"))
            if refs["kind"] in ("method", "non-python") or refs["probable"]:
                L.append("  PROBABLE (method name in a file that imports the module; receiver type unknown): "
                         + (_short(refs["probable"], 10) or "none"))
            L.append("  POSSIBLE (word match only): " + (_short(refs["possible"], 6) or "none")
                     + (f" of {refs['total_possible']}" if refs["total_possible"] > 6 else ""))
            if refs.get("partial"):
                L.append(f"  (partial: scanned {refs['scanned']} neighbouring files before the time budget; "
                         "narrow with a more specific symbol)")
    co = d.get("cochange") or {}
    rows = co.get("cochanges") or []
    n = co.get("target_commits") or 0
    if rows and n >= 2:
        L.append(f"CO-CHANGE (last {co.get('commits_scanned', '?')} commits, {n} touched the target"
                 + (", small sample" if n < 5 else "") + "): "
                 + " · ".join(f"{x['path']} {x['count']}/{n}" for x in rows[:limit]))
    ptr = d.get("pointers") or {}
    rules = (ptr.get("rules") or {}).get("paths") or []
    if rules:
        L.append("RULES: " + " · ".join(rules[:4]))
    if d.get("gates"):
        L.append("GATES (this project's own checks, detected not verified; declare real ones via --check '[\"cmd\",\"arg\"]'): "
                 + " · ".join(c for c, _src in d["gates"]))
    L.append(f"NEXT: {runner} begin --task NAME --auto-check [--touch SYMBOL] "
             + " ".join(t["path"] for t in d["targets"]))
    return "\n".join(L)


# ----------------------------------------------------------------------------- "did I distort the project?" signals
CODE_SUFFIXES = (".py",) + JS + (".go", ".rs", ".java", ".rb", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".kt", ".swift", ".php")
_SUPPRESS_RE = re.compile(r"#\s*noqa\b|#\s*type:\s*ignore|#\s*pylint:\s*disable|#\s*pragma:\s*no\s*cover|#\s*nosec\b"
                          r"|//\s*eslint-disable|/\*\s*eslint-disable|//\s*@ts-(?:ignore|nocheck)")
_TODO_RE = re.compile(r"\b(?:TODO|FIXME|XXX|HACK)\b")
_JS_SIGNALS = {
    "debug": re.compile(r"\bdebugger\s*;|\bconsole\.log\("),
    "skip": re.compile(r"\b(?:xit|xdescribe|xtest)\(|\b(?:it|test|describe)\.(?:skip|todo)\("),
    "only": re.compile(r"\b(?:it|test|describe)\.only\(|\b(?:fit|fdescribe)\("),
    "swallow": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    "assert": re.compile(r"\bexpect\(|\bassert\w*\("),
    "test": re.compile(r"\b(?:it|test)\(\s*['\"`]"),
}
_GENERIC_ASSERT = re.compile(r"\bassert\w*\(|\bexpect\(|\bt\.(?:Error|Fatal)f?\(")
_GENERIC_TEST = re.compile(r"^\s*func\s+Test\w+|#\[test\]|@Test\b", re.M)
_SECRETS = ((re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
            (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "private key"),
            (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
            (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
            (re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}"), "Stripe live key"),
            (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
            (re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b"), "GitLab token"))


def _py_signals(data):
    sig = Counter()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(data)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return sig
    nodes = list(ast.walk(tree))
    decorators = {id(d) for n in nodes if isinstance(n, _FUNC + (ast.ClassDef,)) for d in n.decorator_list}
    for n in nodes:
        if isinstance(n, ast.Assert):
            sig["assert"] += 1
        elif isinstance(n, ast.Call):
            ch = _chain(n.func)
            if ch:
                last = ch[-1]
                if last.startswith("assert") or last in ("raises", "warns"):
                    sig["assert"] += 1
                if last in ("skip", "xfail", "skipTest") and id(n) not in decorators:  # decorators are counted below
                    sig["skip"] += 1
                if last == "breakpoint" or ch[-2:] in (("pdb", "set_trace"), ("ipdb", "set_trace")):
                    sig["debug"] += 1
        elif isinstance(n, _FUNC + (ast.ClassDef,)):
            if isinstance(n, _FUNC) and n.name.startswith("test"):
                sig["test"] += 1
            for d in n.decorator_list:
                low = _unparse(d, 60).lower()
                if "skip" in low or "xfail" in low:
                    sig["skip"] += 1
        elif isinstance(n, ast.ExceptHandler):
            if all(isinstance(b, ast.Pass) or (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))
                   for b in n.body):
                sig["swallow"] += 1
        elif isinstance(n, ast.Import):
            if any(a.name.split(".")[0] in ("pdb", "ipdb") for a in n.names):
                sig["debug"] += 1
    return sig


def signals(rel, data):
    sig = Counter()
    if data is None or b"\0" in data[:4096]:
        return sig
    text = data.decode("utf-8", "replace")
    sig["suppress"] = len(_SUPPRESS_RE.findall(text))
    sig["todo"] = len(_TODO_RE.findall(text))
    if rel.endswith(".py"):
        sig.update(_py_signals(data))
    elif rel.endswith(JS):
        for key, rx in _JS_SIGNALS.items():
            sig[key] = len(rx.findall(text))
    else:
        sig["assert"] = len(_GENERIC_ASSERT.findall(text))
        sig["test"] = len(_GENERIC_TEST.findall(text))
    return sig


def unused_imports(data, rel):
    """{name: line} of imports never referenced (conservative: any word in any string counts as a use)."""
    if rel.endswith("__init__.py"):
        return {}
    facts = analyze(data)
    if "i" not in facts or facts.get("al") is not None:
        return {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(data)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return {}
    used = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            used.add(n.id)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 400:
            used.update(re.findall(r"[A-Za-z_]\w*", n.value))
    lines = data.decode("utf-8", "replace").splitlines()
    out = {}
    for im in facts["i"]:
        if im["n"] == "*" or im.get("g"):
            continue
        local = im["a"] or (im["n"] if im["n"] else im["m"].split(".")[0])
        if local not in used and not _noqa(lines, im["ln"], "F401"):
            out[local] = im["ln"]
    return out


def _noqa(src_lines, ln, code="F821"):
    if not ln or ln > len(src_lines):
        return False
    m = re.search(r"#\s*noqa(?:\s*:\s*([A-Za-z0-9_, ]+))?", src_lines[ln - 1], re.I)
    return bool(m and (not m.group(1) or code in m.group(1).upper().replace(" ", "").split(",")))


def _diff(old, new):
    """(added, removed, [(line_no, text) of added lines])"""
    a = (old or b"").decode("utf-8", "replace").splitlines()
    b = (new or b"").decode("utf-8", "replace").splitlines()
    if len(a) + len(b) > 40000:
        return 0, 0, []
    add = rem = 0
    added = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            rem += i2 - i1
        if tag in ("replace", "insert"):
            add += j2 - j1
            added.extend((j + 1, b[j]) for j in range(j1, j2))
    return add, rem, added


def _smells(rel, old, new):
    """-> (findings, signal deltas).  Non-blocking hints that an edit may be distorting the project."""
    so = signals(rel, old) if old is not None else Counter()
    sn = signals(rel, new) if new is not None else Counter()
    d = {k: sn[k] - so[k] for k in set(so) | set(sn)}
    out = []
    testish = bool(is_test_path(rel) or so["test"] or sn["test"])
    if testish and (d.get("assert", 0) < 0 or d.get("test", 0) < 0):
        parts = [f"{d[k]} {lab}" for k, lab in (("assert", "assertion(s)"), ("test", "test(s)")) if d.get(k, 0) < 0]
        weak = _finding("Q-TEST", rel, None, "tests weakened: " + ", ".join(parts) + (" (file deleted)" if new is None else ""),
                        fix="restore them, or say in your summary why they are obsolete")
        weak["weak"] = True  # kept only if the TOTAL across all changed files also went down (moved tests are fine)
        out.append(weak)
    for key, code, label, fix in (
            ("skip", "Q-TEST", "skipped/xfail test(s) added", "fix the test or the code instead of skipping"),
            ("only", "Q-TEST", "focused test(s) added (.only)", "remove .only before finishing"),
            ("suppress", "Q-SILENCE", "suppression comment(s) added (noqa/type: ignore/eslint-disable)", "fix the underlying problem, or justify"),
            ("swallow", "Q-SILENCE", "swallowed exception(s) added (empty except/catch)", "handle or log it; do not hide failures"),
            ("debug", "Q-LEFTOVER", "debug leftover(s) added (breakpoint/pdb/console.log/debugger)", "remove before finishing"),
            ("todo", "Q-LEFTOVER", "new TODO/FIXME/XXX/HACK marker(s)", "finish it or mention it in your summary")):
        if d.get(key, 0) > 0:
            out.append(_finding(code, rel, None, f"+{d[key]} {label}", fix=fix))
    return out, d, testish


def _dup_smells(world, rel, facts, delta):
    out = []
    for d in delta:
        if d["ch"] != "added":
            continue
        nd = facts["d"].get(d["q"])
        if not nd or nd["k"] not in ("f", "m") or nd.get("dup") or d["q"].rsplit(".", 1)[-1].startswith("test"):
            continue
        if nd.get("sz", 0) >= 40:
            others = [x for x in world.dup_index().get(nd["fp"], ()) if x != (rel, d["q"])]
            if others:
                out.append(_finding("Q-DUP", rel, nd["l"], f"`{d['q']}` has exactly the same body as `{others[0][1]}` in {others[0][0]}",
                                    fix="reuse the existing one"))
                continue
        name = d["q"].rsplit(".", 1)[-1]
        if nd["k"] == "f" and len(name) >= 8:
            names = world.func_names()
            near = difflib.get_close_matches(name, [n for n in names if n != name], 1, 0.9)
            if near:
                out.append(_finding("Q-DUP", rel, nd["l"], f"new `{name}` is very similar to existing `{near[0]}` ({names[near[0]][0]})",
                                    fix="reuse or extend the existing helper if it does the same job"))
    return out



# ----------------------------------------------------------------------------- review
def _declared(touch, rel, q):
    for t in touch:
        tp, _, tq = t.rpartition("::")
        if (not tp or tp == rel) and (tq == q or q.startswith(tq + ".") or tq == "*"):
            return True
    return False


def review(world, changes, *, touch=(), in_scope=None, budget=40.0):
    """changes: [{path, old: bytes|None, new: bytes|None, opaque?: bool}] -> findings dict."""
    res = {"files": [], "errors": [], "likely": [], "possible": [], "policy": [], "smells": [], "tests": [],
           "untested": [], "notes": [], "partial": world.partial, "net": {"add": 0, "del": 0, "tests": 0, "asserts": 0}}
    errors, likely, cache = [], [], {}
    changed_py, t0, skipped = [], time.monotonic(), 0
    for ch in sorted(changes, key=lambda c: c["path"]):
        rel, old, new = ch["path"], ch.get("old"), ch.get("new")
        entry = {"path": rel, "status": "A" if old is None else ("D" if new is None else "M"),
                 "add": 0, "del": 0, "sym": [], "cosmetic": False}
        if ch.get("opaque"):
            entry["status"], entry["note"] = "?", "private/opaque (not read)"
            res["files"].append(entry)
            continue
        entry["add"], entry["del"], added = _diff(old, new)
        res["files"].append(entry)
        res["net"]["add"] += entry["add"]
        res["net"]["del"] += entry["del"]
        if time.monotonic() - t0 > budget and rel.endswith(CODE_SUFFIXES):
            skipped += 1
            entry["note"] = "not analysed (time budget)"
            continue
        if new is not None:  # secrets: high-confidence patterns on ADDED lines only, any text file
            for ln, text in added[:3000]:
                for rx, label in _SECRETS:
                    if rx.search(text) and "EXAMPLE" not in text.upper():
                        res["policy"].append(_finding("P-SECRET", rel, ln, f"possible {label} in an added line (value not shown)",
                                                      fix="remove it; load secrets from the environment, never commit them"))
                        break
        if rel.endswith(CODE_SUFFIXES):
            found, dsig, testish = _smells(rel, old, new)
            res["smells"] += found
            if testish:
                res["net"]["tests"] += dsig.get("test", 0)
                res["net"]["asserts"] += dsig.get("assert", 0)
            if rel.endswith(".py") and new is not None:
                before = set(unused_imports(old, rel)) if old is not None else set()
                for name, ln in sorted(unused_imports(new, rel).items()):
                    if name not in before:
                        res["smells"].append(_finding("Q-LEFTOVER", rel, ln, f"unused import `{name}` (added by this change)",
                                                      fix="remove it"))
        if rel.endswith(JS) and new is not None:
            errors += world.js_missing(rel, new)
        if not rel.endswith(".py"):
            continue
        O = analyze(old) if old is not None else None
        if O is not None and "d" not in O:
            O = None
        if new is None:
            changed_py.append({"path": rel, "old": O, "new": None})
            continue
        dc = deep_check(new, rel)
        if dc["err"]:
            errors.append(_finding("E-SYNTAX", rel, None, dc["err"]))
            entry["note"] = "does not compile"
            continue
        N = world.files.get(rel)
        if not N or "d" not in N:
            N = analyze(new)
        entry["sym"] = sym_delta(O, N)
        entry["cosmetic"] = not entry["sym"] and old is not None and old != new
        res["smells"] += _dup_smells(world, rel, N, entry["sym"])
        changed_py.append({"path": rel, "old": O, "new": N})
        before = {(f["code"], f["msg"]) for f in (world.check_file(rel, old, O) if O else [])}
        errors += [f for f in world.check_file(rel, new, N) if (f["code"], f["msg"]) not in before]
        if dc["undef"]:
            ob = (deep_check(old, rel)["undef"] or {}) if old is not None else {}
            src_lines = new.decode("utf-8", "replace").splitlines()
            for name, lns in sorted(dc["undef"].items()):
                if name not in ob and not _noqa(src_lines, lns[0]):
                    near = difflib.get_close_matches(name, sorted(set(N["n"]) | BUILTINS), 1, 0.7)
                    likely.append(_finding("L-UNDEF", rel, lns[0], f"undefined name `{name}`",
                                           fix=f"did you mean `{near[0]}`?" if near else None, sym=name))
        if touch and (in_scope is None or in_scope(rel)):
            for d in entry["sym"]:
                if d["ch"] in ("logic", "sig", "removed") and not _declared(touch, rel, d["q"]):
                    res["policy"].append(_finding("P-TOUCH", rel, None,
                                                  f"undeclared {d['ch']} change: {d['q']} (not in --touch)",
                                                  fix="revert it, or re-begin with --touch for it"))
    # incoming: deleted/renamed modules -> everyone who still imports them (resolved in a ghost world)
    deleted = {}
    for ch in changes:
        if ch.get("new") is None and ch.get("old") is not None and not ch.get("opaque"):
            if ch["path"].endswith(".py"):
                O = analyze(ch["old"])
                deleted[ch["path"]] = O if "d" in O else {"v": ANALYZER, "n": [], "o": 0, "d": {}, "i": [], "mf": "", "dy": 0, "al": None, "lc": 0}
            elif ch["path"].endswith(JS):
                deleted[ch["path"]] = {"v": ANALYZER, "js": []}
    if deleted:
        ghost = world.with_ghosts(deleted)
        for gone in sorted(deleted):
            for src, ln, _nm, g in ghost.rev().get(gone, []):
                if not g and src not in deleted:
                    errors.append(_finding("E-GONE", src, ln, f"imports {gone}, which was deleted/renamed"))
    # incoming: who is broken by what changed here
    possible = []
    for c in changed_py:
        path, O, N = c["path"], c["old"], c["new"]
        importers = sorted({s for s, _l, _n, g in world.rev().get(path, []) if not g})[:60]
        if N is None or O is None:
            continue
        delta = sym_delta(O, N)
        ex, op = world.exports(path)
        lost = {n for n in set(O["n"]) - set(N["n"]) if n not in ex}
        removed = lost if not op else set()
        if op and lost:
            for src, ln, nm, g in world.rev().get(path, []):
                if nm in lost and not g:
                    possible.append({"path": src, "line": ln, "name": nm, "total": 1,
                                     "text": f"`{nm}` was removed/renamed in {path} (imported at {src}:{ln}); {path} loads names "
                                             "dynamically, so breakage cannot be proved - check it"})
        sigc = _sigchanged(delta)
        watch = removed | sigc
        if watch:
            for src in importers:
                if src == path:
                    continue
                if src not in cache:
                    sd = read_small(world.root / src)
                    cache[src] = world.check_file(src, sd, world.files.get(src)) if sd is not None else []
                for f in cache[src]:
                    if f.get("tgt") == path and f.get("sym") in watch:
                        if f["code"] == "E-NAME" and f.get("sym") in removed:
                            f = dict(f, msg=f"`{f['sym']}` was removed/renamed in {path} (still imported here)")
                        errors.append(f)
        names = [d["q"] for d in delta if (d["ch"] == "removed" or d["ch"] == "sig") and "." in d["q"]
                 and not d["q"].rsplit(".", 1)[-1].startswith("__")]
        names += [n for n in removed if len(n) > 2]
        for n in sorted(set(x.rsplit(".", 1)[-1] for x in names))[:6]:
            hits, total = world.name_hits(n, exclude={path})
            if hits:
                possible.append({"path": hits[0][0], "line": hits[0][1], "name": n, "total": total, "where": hits[:3],
                                 "why": "removed" if n in removed or any(d["q"].endswith("." + n) and d["ch"] == "removed" for d in delta)
                                 else "signature changed"})
    # changed METHOD signatures: receiver types are unknowable, so check probable call sites by name
    # (only when the method name is unique in the repo) and report the exact mismatch as POSSIBLE
    for c in changed_py:
        if c["new"] is None or c["old"] is None:
            continue
        for d in sym_delta(c["old"], c["new"]):
            name = d["q"].rsplit(".", 1)[-1]
            nd = c["new"]["d"].get(d["q"])
            if (d["ch"] != "sig" or "." not in d["q"] or name.startswith("__") or not nd or nd["k"] != "m"
                    or nd.get("d") or nd.get("dup") or world.method_names().get(name, 0) != 1):
                continue
            files = {c["path"]} | {s for s, _l, _n, g in world.rev().get(c["path"], []) if not g}
            shown = 0
            for src in sorted(files):
                sf = world.files.get(src)
                sd = read_small(world.root / src) if sf and "d" in sf else None
                scan = scan_source(sd) if sd is not None else None
                for kind, ln, chain, extra, _sh in (scan or {"items": []})["items"]:
                    if kind != "call" or len(chain) < 2 or chain[-1] != name:
                        continue
                    probs = call_problems(nd["s"], 1, *extra)
                    if probs and shown < 4:
                        shown += 1
                        possible.append({"path": src, "line": ln, "name": name, "total": 1,
                                         "text": f"`.{name}(...)` at {src}:{ln} looks incompatible with the new "
                                                 f"{d['q']}{nd['s']['t']}: {'; '.join(probs)} (receiver type unknown - verify)"})
    # tests / untested
    prod = [c["path"] for c in changed_py if c["new"] is not None and not is_test_path(c["path"])]
    for rel in {c["path"] for c in changes if c["path"].endswith(JS) and c.get("new") is not None and not is_test_path(c["path"])}:
        prod.append(rel)
    tests = {}
    for rel in prod:
        got = world.tests_for([rel])
        for p, (d, via) in got:
            if p not in tests or d < tests[p][0]:
                tests[p] = (d, via)
        if not got and not world.heuristic_tests(rel) and posixpath.basename(rel) != "__init__.py":
            res["untested"].append(rel)
    res["tests"] = [{"path": p, "depth": d, "via": v} for p, (d, v) in sorted(tests.items(), key=lambda kv: (kv[1][0], kv[0]))][:40]
    seen, uniq = set(), []
    for f in world.drop_ignored(errors):
        if f["code"] == "?-OPEN":
            possible.append({"path": f["path"], "line": f["line"], "name": f["sym"], "total": 1, "text": f["msg"] + f" ({f['path']}:{f['line']})"})
            continue
        k = (f["code"], f["path"], f["line"], f["msg"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    res["errors"], res["likely"], res["possible"] = uniq[:200], likely[:100], possible
    net_t, net_a = res["net"]["tests"], res["net"]["asserts"]
    if net_t >= 0 and net_a >= 0:  # tests merely moved or were reshaped: not a weakening
        res["smells"] = [f for f in res["smells"] if not f.get("weak")]
    else:
        for f in res["smells"]:
            if f.get("weak"):
                f["msg"] += f" [net over all changed files: tests {net_t:+d}, assertions {net_a:+d}]"
    res["smells"] = res["smells"][:60]
    if skipped:
        res["notes"].append(f"{skipped} changed file(s) were NOT analysed (time budget); review them by hand or rerun")
    if world.partial:
        res["notes"].append(f"index partial: {world.partial} source file(s) not analysed yet (time budget); rerun to finish")
    return res


def audit(world, cap=300, budget=25.0):
    """Whole-repo outgoing checks (no baseline): used by `review --all`."""
    found, t0 = [], time.monotonic()
    for rel, f in sorted(world.files.items()):
        if time.monotonic() - t0 > budget:
            world.partial += 1
            continue
        if "d" in f:
            data = read_small(world.root / rel)
            if data is not None:
                found += world.check_file(rel, data, f)
    return world.drop_ignored(found)[:cap]


_TAG = {"E-CALL": "CALL", "E-NAME": "NAME", "E-ATTR": "ATTR", "E-IMPORT": "IMPORT", "E-SYNTAX": "SYNTAX",
        "E-GONE": "GONE", "L-UNDEF": "UNDEF", "P-TOUCH": "TOUCH", "P-SECRET": "SECRET", "Q-TEST": "TEST",
        "Q-SILENCE": "SILENCE", "Q-LEFTOVER": "LEFTOVER", "Q-DUP": "DUP",
        "P-REVERT": "REVERT", "P-UNFIX": "UNFIX", "P-GUARD": "GUARD",
        "W-REGRESSION": "REGRESSION", "W-COUNT": "COUNT", "W-SILENT": "SILENT"}


def finding_line(f, tag):
    loc = f"{f['path']}:{f['line']}" if f.get("line") else f["path"]
    return f"{tag} [{_TAG.get(f['code'], f['code'])}] {loc}  {f['msg']}" + (f"  - {f['fix']}" if f.get("fix") else "")


def render_review(res, task=None, limit=12, runner="agent.py"):
    L = []
    files = res["files"]
    L.append(f"review  {len(files)} file(s) changed" + (f"  (agent changes since begin: {task})" if task else "  (worktree vs HEAD)"))
    for e in files[:30]:
        mark = {"A": "+", "D": "-", "M": "~", "?": "?"}[e["status"]]
        bits = []
        for key, lab in (("sig", "sig"), ("logic", "logic"), ("removed", "-def"), ("added", "+def")):
            qs = [d["q"] for d in e["sym"] if d["ch"] == key]
            if qs:
                bits.append(f"{lab}:" + ",".join(qs[:4]) + (f"(+{len(qs) - 4})" if len(qs) > 4 else ""))
        if e["cosmetic"]:
            bits.append("cosmetic only (comments/format/docstrings)")
        if e.get("note"):
            bits.append(e["note"])
        L.append(f"{mark} {e['path']}  +{e['add']}/-{e['del']}" + ("  " + "  ".join(bits) if bits else ""))
    if len(files) > 30:
        L.append(f"(+{len(files) - 30} more files)")
    net = res.get("net") or {}
    if files:
        L.append(f"NET +{net.get('add', 0)}/-{net.get('del', 0)} lines"
                 + (f" · tests {net['tests']:+d} · assertions {net['asserts']:+d}" if net.get("tests") or net.get("asserts") else ""))
    sections = (("ERRORS", "E", res["errors"]), ("LIKELY", "L", res["likely"]), ("POLICY", "P", res["policy"]))
    for title, pre, items in sections:
        if items:
            L.append(f"{title} ({len(items)}) - " + {"E": "proved from the AST; fix before verify",
                                                      "L": "probably a hallucinated name; confirm",
                                                      "P": "outside declared intent"}[pre])
            for i, f in enumerate(items[:limit], 1):
                L.append("  " + finding_line(f, f"{pre}{i}"))
            if len(items) > limit:
                L.append(f"  (+{len(items) - limit} more)")
    if res.get("smells"):
        L.append(f"SMELLS ({len(res['smells'])}) - not errors; fix them or say why in your summary")
        for i, f in enumerate(res["smells"][:8], 1):
            L.append("  " + finding_line(f, f"Q{i}"))
        if len(res["smells"]) > 8:
            L.append(f"  (+{len(res['smells']) - 8} more)")
    if res.get("history"):
        L.append(f"HISTORY ({len(res['history'])}) - from git history: evidence to check, NOT a verdict "
                 "(measured flag rate on 480 already-merged upstream commits: about 1 in 10, so read the commit "
                 "before believing it)")
        for i, f in enumerate(res["history"][:4], 1):
            L.append("  " + finding_line(f, f"H{i}"))
        if len(res["history"]) > 4:
            L.append(f"  (+{len(res['history']) - 4} more)")
    if res.get("warnings"):
        L.append(f"WARNINGS ({len(res['warnings'])}) - compare with the recorded baseline before trusting a green run")
        for i, f in enumerate(res["warnings"][:4], 1):
            L.append("  " + finding_line(f, f"W{i}"))
    if res["possible"]:
        L.append(f"POSSIBLE ({len(res['possible'])}) - name matches, cannot be proved; check by hand")
        for p in res["possible"][:6]:
            where = p.get("where") or [(p["path"], p["line"])]
            L.append("  ? " + (p["text"] if p.get("text") else
                                f"`{p['name']}` {p['why']}; also used at " + ", ".join(f"{a}:{b}" for a, b in where)
                                + (f" (+{p['total'] - len(where)} more)" if p["total"] > len(where) else "")))
    if res["tests"]:
        L.append("TESTS: " + " · ".join(t["path"] + (f" (via {t['via']})" if t["via"] else "") for t in res["tests"][:8])
                 + (f" (+{len(res['tests']) - 8})" if len(res["tests"]) > 8 else ""))
    if res["untested"]:
        L.append("UNTESTED: " + " · ".join(res["untested"][:6]) + "  (no test imports it - a green run proves nothing about these)")
    for n in res["notes"]:
        L.append("NOTE: " + n)
    bad = len(res["errors"]) + len(res["policy"]) + len(res["likely"])
    L.append(f"RESULT: {'BLOCKED - ' + str(bad) + ' finding(s)' if bad else 'no definite findings'}"
             + (f" -> fix them, then `{runner} verify --task {task}`" if task and bad else "")
             + ("" if bad else " (static only: runtime behaviour, third-party APIs and cross-service contracts are NOT checked)"))
    return "\n".join(L)


def render_short(res, limit=8):
    """Compact finding list for verify's JSON output."""
    out = []
    for pre, items in (("E", res["errors"]), ("L", res["likely"]), ("P", res["policy"])):
        out += [finding_line(f, f"{pre}{i}") for i, f in enumerate(items[:limit], 1)]
    return out[:limit + 4]
