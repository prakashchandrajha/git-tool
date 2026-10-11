import ast, importlib.abc, importlib.machinery, sys


class _Inject(ast.NodeTransformer):
    def __init__(self, mod, targets):
        self.mod, self.targets, self.scope = mod, targets, []

    def _enter(self, node, is_func):
        qual = ".".join(self.scope + [node.name])
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        if is_func and qual in self.targets:
            probe = ast.parse(f"__gt_probe__({self.mod!r}, {qual!r})", mode="eval").body
            node.decorator_list.insert(0, probe)   # outermost
        return node

    def visit_ClassDef(self, n): return self._enter(n, False)
    def visit_FunctionDef(self, n): return self._enter(n, True)
    # async functions: add visit_AsyncFunctionDef and an `async def` wrapper variant in the probe


class _Loader(importlib.machinery.SourceFileLoader):
    def __init__(self, name, path, targets):
        super().__init__(name, path)
        self._t = targets

    def source_to_code(self, data, path, *, _optimize=-1):
        tree = ast.fix_missing_locations(_Inject(self.name, self._t).visit(ast.parse(data, path)))
        return compile(tree, path, "exec", dont_inherit=True, optimize=_optimize)

    def get_code(self, fullname):
        # bypass .pyc entirely: otherwise stale UNinstrumented bytecode is loaded,
        # or instrumented bytecode poisons the cache
        p = self.get_filename(fullname)
        return self.source_to_code(self.get_data(p), p)


class _Finder(importlib.abc.MetaPathFinder):
    def __init__(self, plan):
        self.plan = plan            # {module: {qualnames}}

    def find_spec(self, name, path, target=None):
        if name not in self.plan:
            return None
        spec = importlib.machinery.PathFinder.find_spec(name, path)
        if spec and isinstance(spec.loader, importlib.machinery.SourceFileLoader):
            spec.loader = _Loader(name, spec.origin, self.plan[name])
        return spec


def install(plan):
    """plan: {module_name: set_of_qualnames}. Call BEFORE the target modules are imported."""
    sys.dont_write_bytecode = True
    for m in plan:
        sys.modules.pop(m, None)
    sys.meta_path.insert(0, _Finder(plan))
