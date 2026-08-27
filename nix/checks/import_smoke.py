from __future__ import annotations

import sys

import angr
import archinfo
import claripy
import cle
import pypcode
import pyvex
import z3

print("angr", angr.__version__)
print("cle", cle.__version__, "claripy", claripy.__version__, "pyvex", pyvex.__version__)
print("archinfo", archinfo.__version__, "pypcode", pypcode.__version__)

# The z3 version is the one nix/python-overlay.nix pins (passed by the flake).
# z3.get_version_string() is "4.13.0" for PyPI release "4.13.0.0"; compare the
# numeric tuple (major, minor, build, revision) instead.
pinned_z3 = sys.argv[1]
print("z3", z3.get_version_string(), z3.get_version(), "pinned", pinned_z3)
assert tuple(z3.get_version()) == tuple(int(x) for x in pinned_z3.split(".")), (z3.get_version(), pinned_z3)

irsb = pyvex.lift(b"\x90\xc3", 0x400000, archinfo.ArchAMD64())
assert irsb.jumpkind == "Ijk_Ret", irsb.jumpkind
assert irsb.size == 2, irsb.size

x = claripy.BVS("x", 32)
s = claripy.Solver()
s.add(x * 3 == 42)
assert s.eval(x, 1)[0] == 14

# Floating-point model evaluation goes through Z3_fpa_get_numeral_sign, whose
# ctypes signature changed in later z3 releases (ArgumentError on 4.16).
f = claripy.FPS("f", claripy.FSORT_DOUBLE)
s = claripy.Solver()
s.add(f * claripy.FPV(2.0, claripy.FSORT_DOUBLE) == claripy.FPV(5.0, claripy.FSORT_DOUBLE))
(fv,) = s.eval(f, 1)
assert fv == 2.5, fv
assert s.eval(f * f, 1)[0] == 6.25

ctx = pypcode.Context("x86:LE:64:default")
tx = ctx.translate(b"\x90\xc3")
assert len(tx.ops) > 0

import angr.ailment  # noqa: E402

from angr.rustylib import SegmentList  # noqa: E402,F401

print("ok")

import angr.state_plugins.unicorn_engine as unicorn_engine  # noqa: E402

assert unicorn_engine.unicorn is not None, "python unicorn missing from environment"
assert unicorn_engine._UC_NATIVE is not None, "angr unicornlib did not load"
print("unicorn ok")
