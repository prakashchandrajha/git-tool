import dis, sys, types

mon = sys.monitoring


def walk_codes(code):
    yield code
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            yield from walk_codes(c)


def executable_lines(code) -> set[int]:
    """Lines with at least one real instruction. RESUME-only lines (the `def` line) never get LINE events."""
    resume = {i.offset for i in dis.get_instructions(code) if i.opname == "RESUME"}
    out = set()
    for start, end, line in code.co_lines():
        if line is None:
            continue
        if set(range(start, end, 2)) - resume:
            out.add(line)
    return out


def _free_tool_id() -> int:
    for tid in (3, 4):
        try:
            mon.use_tool_id(tid, "gittool-cov")
            return tid
        except ValueError:
            continue
    raise RuntimeError("no free sys.monitoring tool id")


class LineCoverage:
    """with LineCoverage(codes) as cov: run_tests(); cov.hit -> {(code.co_qualname, line)}"""
    def __init__(self, codes):
        self.codes = [c for top in codes for c in walk_codes(top)]
        self.hit: set[tuple[str, int]] = set()

    def __enter__(self):
        self.tid = _free_tool_id()
        def on_line(code, line):
            self.hit.add((code.co_qualname, line))
            return mon.DISABLE                      # fire once per location, then free
        mon.register_callback(self.tid, mon.events.LINE, on_line)
        for c in self.codes:
            mon.set_local_events(self.tid, c, mon.events.LINE)
        return self

    def __exit__(self, *exc):
        for c in self.codes:
            mon.set_local_events(self.tid, c, 0)
        mon.register_callback(self.tid, mon.events.LINE, None)
        mon.free_tool_id(self.tid)

    def missed(self) -> set[tuple[str, int]]:
        want = {(c.co_qualname, l) for c in self.codes for l in executable_lines(c)}
        return want - self.hit
