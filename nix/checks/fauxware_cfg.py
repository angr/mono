from __future__ import annotations

import sys

import angr

proj = angr.Project(sys.argv[1], auto_load_libs=False)
cfg = proj.analyses.CFGFast(normalize=True)
n = len(cfg.kb.functions)
print("functions:", n)
assert n > 0
assert "main" in {f.name for f in cfg.kb.functions.values()}
print("ok")
