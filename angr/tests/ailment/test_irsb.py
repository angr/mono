# pylint:disable=broad-exception-caught,missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
import pickle
import unittest

import archinfo
import pypcode
import pyvex
from pyvex.enums import irop_enums_to_ints

import angr
from angr import ailment
from angr.ailment.expression import DirtyExpression
from angr.engines.vex.claripy import irop
from angr.rustylib.ailment import RoundingMode, VEXIRSBConverter, _vexop_debug

# pylint: disable=missing-class-docstring
# pylint: disable=line-too-long


class TestIrsb(unittest.TestCase):
    block_bytes = bytes.fromhex(
        "554889E54883EC40897DCC488975C048C745F89508400048C745F0B6064000488B45C04883C008488B00BEA70840004889C7E883FEFFFF"
    )
    block_addr = 0x4006C6
    # A Linux kernel text address: an ordinary address for a 64-bit target that
    # does not fit in a signed 64-bit integer.
    high_block_addr = 0xFFFFFFFF81000330

    def test_convert_from_vex_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, arch, opt_level=0)
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    def test_convert_from_vex_irsb_at_high_address(self):
        arch = archinfo.arch_from_id("AMD64")
        irsb = pyvex.IRSB(self.block_bytes, self.high_block_addr, arch, opt_level=0)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch, self.high_block_addr, self.block_bytes, ailment.Manager(arch=arch), opt_level=0
        )
        assert from_py == from_lift
        for block in (from_py, from_lift):
            assert block.addr == self.high_block_addr
            assert block.statements
            for stmt in block.statements:
                assert self.high_block_addr <= stmt.tags["ins_addr"] < self.high_block_addr + irsb.size
    def test_convert_gymrat_dirty_leaves_memory_effects_unset(self):
        # libVEX cannot decode iretq, so pyvex falls back to its gymrat lifter, which
        # builds the Dirty statement with every memory-effect field unset. Those fields
        # are optional in the AIL model, so the converter has to carry the Nones through
        # instead of demanding a string.
        arch = archinfo.arch_from_id("AMD64")
        irsb = pyvex.lift(b"\x48\xcf", 0x400000, arch)
        dirty = [stmt for stmt in irsb.statements if isinstance(stmt, pyvex.stmt.Dirty)]
        assert len(dirty) == 1
        assert dirty[0].mFx is None
        assert dirty[0].mSize is None

        manager = ailment.Manager(arch=arch)
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock is not None

        converted = [
            expr
            for stmt in ablock.statements
            for expr in (getattr(stmt, "src", None), getattr(stmt, "dst", None))
            if isinstance(expr, DirtyExpression)
        ]
        assert len(converted) == 1
        assert converted[0].callee == "amd64g_dirtyhelper_IRETQ"
        assert converted[0].mfx is None
        assert converted[0].msize is None

    def test_convert_from_pcode_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        p = angr.load_shellcode(
            self.block_bytes, arch, self.block_addr, self.block_addr, engine=angr.engines.UberEnginePcode
        )
        irsb = p.factory.block(self.block_addr).vex
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    def test_convert_from_pcode_irsb_at_high_address(self):
        # The P-code converter assigns Manager.ins_addr from Python, which the
        # VEX converter never does.
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        p = angr.load_shellcode(
            self.block_bytes, arch, self.high_block_addr, self.high_block_addr, engine=angr.engines.UberEnginePcode
        )
        irsb = p.factory.block(self.high_block_addr).vex
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock.addr == self.high_block_addr
        assert manager.block_addr == self.high_block_addr
        ins_addr = manager.ins_addr
        assert ins_addr is not None
        assert self.high_block_addr <= ins_addr < self.high_block_addr + irsb.size

    def test_convert_pcode_uppercase_memory_space(self):
        arch = archinfo.ArchPcode("6502:LE:16:default")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        translation = pypcode.Context(arch.name).translate(bytes.fromhex("ad34128d7856"), base_address=0)
        load_varnode = translation.ops[1].inputs[0]
        store_varnode = translation.ops[5].output
        assert load_varnode is not None
        assert store_varnode is not None
        assert load_varnode.space.name == store_varnode.space.name == "RAM"

        converter = object.__new__(ailment.PCodeIRSBConverter)
        converter._manager = manager
        converter._statement_idx = 0

        load = converter._get_value(load_varnode)
        store = converter._set_value(store_varnode, ailment.Expr.Const(None, 0xAA, 8))

        assert isinstance(load, ailment.Expr.Load)
        assert isinstance(load.addr, ailment.Expr.Const)
        assert load.addr.value == 0x1234
        assert load.size == 1
        assert isinstance(store, ailment.Stmt.Store)
        assert isinstance(store.addr, ailment.Expr.Const)
        assert store.addr.value == 0x5678
        assert store.size == 1
        # The space tag keeps the name the specification chose, case included.
        assert load.tags["pcode_space"] == store.tags["pcode_space"] == "RAM"

    def test_lift_path_matches_python_path(self):
        """The direct libVEX-lift fast path must produce the same AIL block as
        converting a cached pyvex Python IRSB."""
        arch = archinfo.arch_from_id("AMD64")
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, arch, opt_level=0)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch, self.block_addr, self.block_bytes, ailment.Manager(arch=arch), opt_level=0
        )
        assert from_py == from_lift
        assert from_py.statements  # non-empty

    def test_unary_conversion_types(self):
        binary = os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "binaries", "tests", "x86_64", "manyfloatsum"
        )
        project = angr.Project(binary, auto_load_libs=False)
        irsb = project.factory.block(0x4009BE).vex
        blocks = (
            VEXIRSBConverter.convert(irsb, ailment.Manager(arch=project.arch)),
            VEXIRSBConverter.convert_from_lift(
                project.arch,
                irsb.addr,
                bytes(project.loader.memory.load(irsb.addr, irsb.size)),
                ailment.Manager(arch=project.arch),
            ),
        )
        expected = {
            "Iop_F32toF64": (ailment.Expr.Convert.TYPE_FP, ailment.Expr.Convert.TYPE_FP),
            "Iop_I32StoF64": (ailment.Expr.Convert.TYPE_INT, ailment.Expr.Convert.TYPE_FP),
        }

        for block in blocks:
            seen = set()
            for stmt in block.statements:
                src = getattr(stmt, "src", None)
                if not isinstance(src, ailment.Expr.Convert):
                    continue
                vex_stmt_idx = src.tags.get("vex_stmt_idx")
                if vex_stmt_idx is None:
                    continue
                vex_expr = getattr(irsb.statements[vex_stmt_idx], "data", None)
                if not isinstance(vex_expr, pyvex.IRExpr.Unop) or vex_expr.op not in expected:
                    continue
                assert (src.from_type, src.to_type) == expected[vex_expr.op]
                seen.add(vex_expr.op)
            assert seen == expected.keys()


class _LoadCollector(ailment.AILBlockWalker[None, None, list]):
    """Collect every Load expression in a block, at any nesting depth."""

    def __init__(self):
        super().__init__()
        self.loads = []

    def _top(self, expr_idx, expr, stmt_idx, stmt, block):
        del expr_idx, stmt_idx, stmt, block
        if isinstance(expr, ailment.Expr.Load):
            self.loads.append(expr)

    def _stmt_top(self, stmt_idx, stmt, block):
        del stmt_idx, stmt, block

    def _handle_block_end(self, stmt_results, block):
        del stmt_results, block
        return self.loads


class TestPcodeProcessorMemorySpaces(unittest.TestCase):
    """A SLEIGH specification names its own address spaces, and most processors have more than one
    addressable space: RISC-V puts control/status registers in ``csreg``, Z80 port I/O in ``io``, and
    classic BPF packet reads in ``packet``. Every one of them has to convert to a Load or a Store
    that records which space it came from."""

    # (language, block bytes, block address, load spaces in order, store spaces in order)
    CASES = [
        (
            # csrrw t0, mstatus, t1 ; ret
            # The CSR is a csreg varnode operand, so the space reaches the converter on the varnode
            # itself rather than on a p-code LOAD/STORE.
            "RISCV:LE:64:default",
            "f312033067800000",
            0x1000,
            ["csreg"],
            ["csreg"],
        ),
        (
            # in a,(0x10) ; out (0x10),a ; ret
            # Port I/O becomes a p-code LOAD and STORE against the io space. The trailing ret pops
            # from ram, so the ordinary memory space still has to convert alongside it.
            "z80:LE:16:default",
            "db10d310c9",
            0x1000,
            ["io", "ram"],
            ["io"],
        ),
        (
            # ld [0] ; ret
            "BPF:LE:32:default",
            "20000000000000000600000000000000",
            0x0,
            ["packet", "ram"],
            [],
        ),
    ]

    @staticmethod
    def _convert(language, block_bytes, addr):
        arch = archinfo.ArchPcode(language)
        proj = angr.load_shellcode(block_bytes, arch, addr, addr, engine=angr.engines.UberEnginePcode)
        return ailment.IRSBConverter.convert(
            proj.factory.block(addr).vex,
            ailment.Manager(arch=arch),  # pyright: ignore[reportArgumentType]
        )

    def test_processor_spaces_convert_to_tagged_loads_and_stores(self):
        for language, block_hex, addr, load_spaces, store_spaces in self.CASES:
            with self.subTest(language=language):
                block = self._convert(language, bytes.fromhex(block_hex), addr)
                loads = _LoadCollector().walk(block)
                stores = [stmt for stmt in block.statements if isinstance(stmt, ailment.Stmt.Store)]
                assert [load.tags["pcode_space"] for load in loads] == load_spaces
                assert [store.tags["pcode_space"] for store in stores] == store_spaces

    def test_identical_addresses_carry_different_space_tags(self):
        # `in a,(0x10)` and `ld a,(0x10)` both become a one-byte load of address 0x10, from the io
        # space and from ram respectively. Nothing in the two Loads other than the tag says which
        # space each one reads.
        io_loads = _LoadCollector().walk(self._convert("z80:LE:16:default", bytes.fromhex("db10"), 0x1000))
        ram_loads = _LoadCollector().walk(self._convert("z80:LE:16:default", bytes.fromhex("3a1000"), 0x1000))
        assert len(io_loads) == 1
        assert len(ram_loads) == 1
        io_load, ram_load = io_loads[0], ram_loads[0]

        assert io_load.addr == ram_load.addr
        assert io_load.tags["pcode_space"] == "io"
        assert ram_load.tags["pcode_space"] == "ram"
    def test_syscall_has_no_floating_point_return(self):
        arch = archinfo.ArchAMD64()
        block_bytes = bytes.fromhex("0f05")
        from_py = VEXIRSBConverter.convert(
            pyvex.IRSB(block_bytes, 0x1000, arch, opt_level=0),  # pyright: ignore[reportArgumentType]
            ailment.Manager(arch=arch),  # pyright: ignore[reportArgumentType]
        )
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch,  # pyright: ignore[reportArgumentType]
            0x1000,
            block_bytes,
            ailment.Manager(arch=arch),  # pyright: ignore[reportArgumentType]
            opt_level=0,
        )
        assert from_py == from_lift

        for syscall in (from_py.statements[-1], from_lift.statements[-1]):
            assert isinstance(syscall, ailment.Stmt.SideEffectStatement)
            assert isinstance(syscall.expr, ailment.Expr.Call)
            assert isinstance(syscall.expr.target, ailment.Expr.DirtyExpression)
            assert syscall.expr.target.callee == "syscall"
            assert isinstance(syscall.ret_expr, ailment.Expr.Register)
            assert syscall.fp_ret_expr is None


class TestLoadGConversion(unittest.TestCase):
    _CASES = (
        ("ILGop_Ident32", "Ity_I32", 32, 32, False, 0xA5C3E17B),
        ("ILGop_Ident64", "Ity_I64", 64, 64, False, 0x123456789ABCDEF0),
        ("ILGop_IdentV128", "Ity_V128", 128, 128, False, 0),
        ("ILGop_8Uto32", "Ity_I32", 8, 32, False, 0xA5C3E17B),
        ("ILGop_8Sto32", "Ity_I32", 8, 32, True, 0xA5C3E17B),
        ("ILGop_16Uto32", "Ity_I32", 16, 32, False, 0xA5C3E17B),
        ("ILGop_16Sto32", "Ity_I32", 16, 32, True, 0xA5C3E17B),
    )

    @staticmethod
    def _const(value, bits):
        const_cls = pyvex.const.V128 if bits == 128 else getattr(pyvex.const, f"U{bits}")
        return pyvex.IRExpr.Const(const_cls(value))

    @classmethod
    def _loadg_block(cls, cvt, dst_type, output_bits, alt_value, endness):
        arch = archinfo.ArchAMD64()
        tyenv = pyvex.IRTypeEnv(arch)
        dst = tyenv.add(dst_type)
        block_addr = 0x400000
        return pyvex.IRSB.empty_block(
            arch,
            block_addr,
            statements=[
                pyvex.IRStmt.IMark(block_addr, 1, 0),
                pyvex.IRStmt.LoadG(
                    endness,
                    cvt,
                    dst,
                    cls._const(0x401000, 64),
                    cls._const(alt_value, output_bits),
                    cls._const(1, 1),
                ),
            ],
            nxt=cls._const(block_addr + 1, 64),
            tyenv=tyenv,
            jumpkind="Ijk_Boring",
            direct_next=True,
            size=1,
        )

    def test_loadg_conversion_matrix(self):
        for cvt, dst_type, load_bits, output_bits, signed, alt_value in self._CASES:
            for endness in ("Iend_LE", "Iend_BE"):
                with self.subTest(cvt=cvt, endness=endness):
                    irsb = self._loadg_block(cvt, dst_type, output_bits, alt_value, endness)
                    converted = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=irsb.arch))
                    assignment = converted.statements[0]

                    assert isinstance(assignment, ailment.Stmt.Assignment)
                    assert isinstance(assignment.dst, ailment.Expr.Tmp)
                    assert assignment.dst.bits == output_bits
                    assert isinstance(assignment.src, ailment.Expr.ITE)

                    ite = assignment.src
                    assert isinstance(ite.cond, ailment.Expr.Const)
                    assert ite.cond.value == 1 and ite.cond.bits == 1
                    assert isinstance(ite.iffalse, ailment.Expr.Const)
                    assert ite.iffalse.value == alt_value
                    assert ite.iffalse.bits == output_bits

                    true_expr = ite.iftrue
                    if load_bits == output_bits:
                        assert isinstance(true_expr, ailment.Expr.Load)
                        load = true_expr
                    else:
                        assert isinstance(true_expr, ailment.Expr.Convert)
                        assert true_expr.from_bits == load_bits
                        assert true_expr.to_bits == output_bits
                        assert true_expr.is_signed is signed
                        assert isinstance(true_expr.operand, ailment.Expr.Load)
                        load = true_expr.operand

                    assert load.guard is None and load.alt is None
                    assert isinstance(load.addr, ailment.Expr.Const)
                    assert load.addr.value == 0x401000 and load.addr.bits == 64
                    assert load.size == load_bits // 8
                    assert load.bits == load_bits
                    assert load.endness == endness
                    assert ite.bits == output_bits
                    assert ite.depth == max(ite.cond.depth, ite.iffalse.depth, ite.iftrue.depth) + 1

                    # The destination, load, and VEX operands keep the historical allocation order. The canonical
                    # ITE adds one synthesized atom immediately before the Assignment.
                    assert load.idx == assignment.dst.idx + 1
                    assert load.addr.idx == load.idx + 1
                    assert ite.cond.idx == load.addr.idx + 1
                    assert ite.iffalse.idx == ite.cond.idx + 1
                    if isinstance(true_expr, ailment.Expr.Convert):
                        assert true_expr.idx == ite.iffalse.idx + 1
                        assert ite.idx == true_expr.idx + 1
                    else:
                        assert ite.idx == ite.iffalse.idx + 1
                    assert assignment.idx == ite.idx + 1

                    source_tags = {"ins_addr": 0x400000, "vex_block_addr": 0x400000, "vex_stmt_idx": 1}
                    assert dict(assignment.tags) == source_tags
                    assert dict(assignment.dst.tags) == source_tags
                    assert dict(load.addr.tags) == source_tags
                    assert dict(ite.cond.tags) == source_tags
                    assert dict(ite.iffalse.tags) == source_tags
                    assert not dict(load.tags)
                    assert not dict(ite.tags)
                    if isinstance(true_expr, ailment.Expr.Convert):
                        assert not dict(true_expr.tags)

                    assert pickle.loads(pickle.dumps(converted)) == converted

    def test_real_thumb_loadg_matches_direct_lift(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "binaries",
            "tests",
            "armel",
            "decompiler",
            "loadg_ite_thumb.elf",
        )
        project = angr.Project(path, auto_load_libs=False)
        symbol = project.loader.main_object.get_symbol("loadg_ite_mask")
        assert symbol is not None

        block = project.factory.block(symbol.rebased_addr, size=symbol.size, opt_level=1)
        loadgs = [stmt for stmt in block.vex.statements if isinstance(stmt, pyvex.IRStmt.LoadG)]
        assert len(loadgs) == 2
        assert all(stmt.cvt == "ILGop_Ident32" for stmt in loadgs)

        from_python = VEXIRSBConverter.convert(block.vex, ailment.Manager(arch=project.arch))
        from_lift = VEXIRSBConverter.convert_from_lift(
            project.arch,
            symbol.rebased_addr,
            block.bytes,
            ailment.Manager(arch=project.arch),
            opt_level=1,
            bytes_offset=1,
        )
        assert from_python == from_lift

        assignments = {
            stmt.dst.tmp_idx: stmt
            for stmt in from_python.statements
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.dst, ailment.Expr.Tmp)
        }
        for vex_stmt in loadgs:
            src = assignments[vex_stmt.dst].src
            assert isinstance(src, ailment.Expr.ITE)
            assert isinstance(src.cond, ailment.Expr.Tmp) and src.cond.tmp_idx == vex_stmt.guard.tmp
            assert isinstance(src.iffalse, ailment.Expr.Tmp) and src.iffalse.tmp_idx == vex_stmt.alt.tmp
            assert isinstance(src.iftrue, ailment.Expr.Load)
            assert src.iftrue.guard is None and src.iftrue.alt is None

        first_load = assignments[loadgs[0].dst].src.iftrue
        second_load = assignments[loadgs[1].dst].src.iftrue
        assert isinstance(first_load.addr, ailment.Expr.Tmp)
        assert isinstance(second_load.addr, ailment.Expr.Tmp)
        second_addr = assignments[second_load.addr.tmp_idx].src
        assert isinstance(second_addr, ailment.Expr.BinaryOp) and second_addr.op == "Add"
        assert isinstance(second_addr.operands[0], ailment.Expr.Tmp)
        assert second_addr.operands[0].tmp_idx == first_load.addr.tmp_idx
        assert isinstance(second_addr.operands[1], ailment.Expr.Const)
        assert second_addr.operands[1].value == 4
        assert pickle.loads(pickle.dumps(from_python)) == from_python


class TestNonConstRoundingMode(unittest.TestCase):
    """VEX sometimes carries the rounding mode in a tmp (e.g. ARM ``vcvtr``
    reads it from FPSCR); the converter must pass it through as an AIL
    ``Expression`` rather than dropping it, so the decompilation pipeline can
    resolve it to a constant later."""

    # vcvtr.s32.f64 s0, d1 ; bx lr -- F64toI32S(t_rm, t_val) with a computed rm
    block_bytes = bytes.fromhex("410bbdee1eff2fe1")

    @staticmethod
    def _find_convert(expr):
        if isinstance(expr, ailment.Expr.Convert):
            return expr
        for attr in ("operand", "src"):
            inner = getattr(expr, attr, None)
            if inner is not None:
                found = TestNonConstRoundingMode._find_convert(inner)
                if found is not None:
                    return found
        return None

    def test_tmp_rounding_mode_is_expression(self):
        arch = archinfo.arch_from_id("armel")
        irsb = pyvex.IRSB(self.block_bytes, 0x1000, arch, opt_level=1)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch, 0x1000, self.block_bytes, ailment.Manager(arch=arch), opt_level=1
        )
        assert from_py == from_lift

        conv = next(c for c in (self._find_convert(getattr(s, "src", s)) for s in from_py.statements) if c is not None)
        rm = conv.rounding_mode
        assert isinstance(rm, ailment.expression.Expression)
        assert isinstance(rm, ailment.Expr.Tmp)
        # a rebuilt Convert accepts the expression form back
        rebuilt = ailment.Expr.Convert(
            conv.idx,
            conv.from_bits,
            conv.to_bits,
            conv.is_signed,
            conv.operand,
            from_type=conv.from_type,
            to_type=conv.to_type,
            rounding_mode=rm,
            **dict(conv.tags),
        )
        assert rebuilt == conv
        # serde round-trip keeps the expression form
        assert pickle.loads(pickle.dumps(from_py)) == from_py

    def test_const_rounding_mode_still_enum(self):
        arch = archinfo.arch_from_id("i386")
        irsb = pyvex.IRSB(bytes.fromhex("d8c1c3"), 0x1000, arch, opt_level=1)  # fadd st0, st1 ; ret
        blk = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        binop = next(
            s.src
            for s in blk.statements
            if isinstance(getattr(s, "src", None), ailment.Expr.BinaryOp) and s.src.floating_point
        )
        assert isinstance(binop.rounding_mode, RoundingMode)


class TestVectorSignedness(unittest.TestCase):
    @staticmethod
    def _find_haddv(block):
        return next(
            stmt.src
            for stmt in block.statements
            if isinstance(getattr(stmt, "src", None), ailment.Expr.BinaryOp) and stmt.src.op == "HAddV"
        )

    def test_haddv_signedness(self):
        arch = archinfo.arch_from_id("armel")

        for name, block_bytes, expected_signed in (
            ("sadd8", bytes.fromhex("920f11e6"), True),
            ("uadd8", bytes.fromhex("920f51e6"), False),
        ):
            with self.subTest(instruction=name):
                irsb = pyvex.IRSB(block_bytes, 0x1000, arch, opt_level=0)
                from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
                from_lift = VEXIRSBConverter.convert_from_lift(
                    arch, 0x1000, block_bytes, ailment.Manager(arch=arch), opt_level=0
                )

                assert from_py == from_lift
                for block in (from_py, from_lift):
                    haddv = self._find_haddv(block)
                    assert haddv.signed is expected_signed
                    assert haddv.vector_count == 4
                    assert haddv.vector_size == 8


class TestVexConverterAcrossArches(unittest.TestCase):
    """Convert real blocks from test binaries through both the Python-IRSB path
    and the libVEX-lift path, and assert the two agree."""

    BINARIES = [
        ("x86_64", "x86_64/1after909"),
        ("i386", "i386/fauxware"),
        ("armel", "armel/fauxware"),
        ("ppc", "ppc/fauxware"),
        ("mips", "mips/fauxware"),
        ("s390x", "s390x/fauxware"),
    ]

    def _check_binary(self, path):
        if not os.path.exists(path):
            self.skipTest(f"missing binary {path}")
        p = angr.Project(path, auto_load_libs=False)
        arch = p.arch
        cfg = p.analyses.CFGFast(normalize=True)
        checked = 0
        for node in cfg.model.nodes():
            if not node.size:
                continue
            thumb = bool(getattr(node, "thumb", False))
            lift_addr = (node.addr | 1) if thumb else node.addr
            bytes_offset = 1 if thumb else 0
            try:
                # Generous trailing bytes so thumb boundary decode is deterministic.
                data = bytes(p.loader.memory.load(node.addr, node.size + 32))
            except Exception:
                continue
            try:
                irsb = pyvex.IRSB(data, lift_addr, arch, opt_level=1, bytes_offset=bytes_offset)
            except Exception:
                continue
            if irsb.size == 0:
                continue
            try:
                from_py = VEXIRSBConverter.convert(
                    pyvex.IRSB(data, lift_addr, arch, opt_level=1, bytes_offset=bytes_offset),
                    ailment.Manager(arch=arch),
                )
            except Exception:
                continue
            try:
                from_lift = VEXIRSBConverter.convert_from_lift(
                    arch, lift_addr, data, ailment.Manager(arch=arch), opt_level=1, bytes_offset=bytes_offset
                )
            except Exception:
                # The fast path defers blocks with statements/expressions it can't
                # render byte-identically (MBE/LLSC/PutI, GetI/Qop, ...) to the
                # Python-IRSB path; those are exercised by the fallback.
                continue
            assert from_py == from_lift, f"mismatch at {node.addr:#x} in {path}"
            checked += 1
        assert checked > 0, f"no blocks checked in {path}"

    def test_arches(self):
        base = os.path.join(os.path.dirname(__file__), "..", "..", "..", "binaries", "tests")
        for _name, rel in self.BINARIES:
            with self.subTest(binary=rel):
                self._check_binary(os.path.normpath(os.path.join(base, rel)))


class TestLiftWindowOverread(unittest.TestCase):
    """libVEX decoders may read the full length of an instruction that starts
    inside the lift window, i.e. a few bytes past ``max_bytes`` -- and past the
    end of the buffer when the window ends at it. The fast path must pad such
    windows with NULs (mirroring pyvex) instead of lifting adjacent heap
    garbage, which made the block content (jumpkind, temp numbering)
    nondeterministic."""

    # 38 bytes at 0x400b5a in s390x/fauxware: nopr padding + function prologue,
    # ending with the first 4 bytes of a 6-byte `lg` at 0x400b7c. The last two
    # bytes of the `lg` fall outside the window; whether it decodes depends
    # entirely on out-of-window bytes.
    window = bytes.fromhex("070707070707eb6ff0300024b904001fa7fbff60e310f0000024c0c000000a060707e340f110")
    addr = 0x400B5A

    def test_lift_does_not_read_past_window(self):
        arch = archinfo.arch_from_id("s390x")
        from_py = VEXIRSBConverter.convert(
            pyvex.IRSB(self.window, self.addr, arch, opt_level=1), ailment.Manager(arch=arch)
        )
        # 0x04 completes the truncated `lg`: an unguarded overread decodes it
        # and ends the block Ijk_Boring instead of Ijk_NoDecode.
        backing = bytearray(self.window + b"\x04" * 8)
        from_lift_mv = VEXIRSBConverter.convert_from_lift(
            arch, self.addr, memoryview(backing)[: len(self.window)], ailment.Manager(arch=arch), opt_level=1
        )
        from_lift_bytes = VEXIRSBConverter.convert_from_lift(
            arch, self.addr, self.window, ailment.Manager(arch=arch), opt_level=1
        )
        assert from_py == from_lift_mv
        assert from_py == from_lift_bytes


class TestVexOpParity(unittest.TestCase):
    """The Rust vexop classifier must match Python ``vexop_to_simop`` for every
    VEX op (guards against drift in the hand-ported claripy/irop name-sets)."""

    def test_vexop_parity(self):
        mismatches = []
        for name, op_int in irop_enums_to_ints.items():
            if name in ("Iop_INVALID", "Iop_LAST"):
                continue
            rust = _vexop_debug(op_int)
            try:
                simop = irop.vexop_to_simop(name)
            except Exception:
                # Python considers it unsupported; Rust must too.
                if rust is not None:
                    mismatches.append((name, "python-unsupported but rust-supported"))
                continue
            if rust is None:
                mismatches.append((name, "rust-unsupported but python-supported"))
                continue
            checks = {
                "generic_name": simop._generic_name,
                "output_size_bits": simop._output_size_bits,
                "is_signed": simop.is_signed,
                "is_conversion": simop._conversion is not None,
                "float": simop._float,
                "from_size": simop._from_size,
                "to_size": simop._to_size,
                "vector_count": simop._vector_count,
                "vector_size": simop._vector_size,
            }
            for key, expected in checks.items():
                if rust[key] != expected:
                    mismatches.append((name, f"{key}: rust={rust[key]!r} py={expected!r}"))

        assert not mismatches, "vexop parity mismatches:\n" + "\n".join(f"  {n}: {m}" for n, m in mismatches[:50])


if __name__ == "__main__":
    unittest.main()
