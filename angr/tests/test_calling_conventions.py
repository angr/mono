#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests"  # pylint:disable=redefined-builtin

import os
import struct
from unittest import TestCase, main

import archinfo
import claripy

from angr import Project, load_shellcode, types
from angr.calling_conventions import (
    SimCCAArch64,
    SimCCMicrosoftAMD64,
    SimCCMicrosoftCdecl,
    SimCCMicrosoftFastcall,
    SimCCRISCV64,
    SimCCSystemVAMD64,
    SimReferenceArgument,
    SimRegArg,
    SimStackArg,
    SimStructArg,
    SimTypeFixedSizeArray,
    SimTypeFunction,
    SimTypeInt,
    default_cc,
)
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimStructValue,
    SimTypeChar,
    SimTypeDouble,
    SimTypeFloat,
    SimTypeLongLong,
    SimTypePointer,
    SimTypeNum,
    SimTypeRef,
    SimUnion,
    parse_file,
)

from .common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCallingConvention(TestCase):
    def test_SystemVAMD64_flatten_int(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)

        int_type = SimTypeInt().with_arch(arch)
        flattened_int = cc._flatten(int_type)
        self.assertTrue(all(isinstance(key, int) for key in flattened_int))
        self.assertTrue(all(isinstance(value, list) for value in flattened_int.values()))
        for v in flattened_int.values():
            for subtype in v:
                self.assertIsInstance(subtype, SimTypeInt)

    def test_SystemVAMD64_flatten_array(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)

        int_type = SimTypeInt().with_arch(arch)
        array_type = SimTypeFixedSizeArray(int_type, 20).with_arch(arch)
        flattened_array = cc._flatten(array_type)
        self.assertTrue(all(isinstance(key, int) for key in flattened_array))
        self.assertTrue(all(isinstance(value, list) for value in flattened_array.values()))
        for v in flattened_array.values():
            for subtype in v:
                self.assertIsInstance(subtype, SimTypeInt)

    def test_arg_locs_array(self):
        arch = archinfo.arch_from_id("amd64")
        cc = SimCCSystemVAMD64(arch)
        proto = SimTypeFunction([SimTypeFixedSizeArray(SimTypeInt().with_arch(arch), 2).with_arch(arch)], None)

        # It should not raise any exception!
        cc.arg_locs(proto)

    def test_microsoft_fastcall_large_arg(self):
        # Regression test: a >DWORD argument (e.g. __int64/double) landing on a register position
        # must NOT raise "doesn't know how to store large types". Per the __fastcall ABI such
        # arguments are passed on the stack and do not consume an ECX/EDX slot.
        arch = archinfo.arch_from_id("x86")
        cc = SimCCMicrosoftFastcall(arch)

        def footprints(proto):
            return [list(loc.get_footprint()) for loc in cc.arg_locs(proto.with_arch(arch))]

        # __int64 first arg -> stack (two words); the following int still gets ECX.
        assert footprints(SimTypeFunction([SimTypeLongLong(), SimTypeInt()], SimTypeInt())) == [
            [SimStackArg(0x4, 4), SimStackArg(0x8, 4)],
            [SimRegArg("ecx", 4)],
        ]
        # Two small ints fill ECX/EDX, the __int64 spills to the stack.
        assert footprints(SimTypeFunction([SimTypeInt(), SimTypeInt(), SimTypeLongLong()], SimTypeInt())) == [
            [SimRegArg("ecx", 4)],
            [SimRegArg("edx", 4)],
            [SimStackArg(0x4, 4), SimStackArg(0x8, 4)],
        ]
        # An __int64 between two ints: it skips the registers; the trailing int still gets EDX.
        assert footprints(SimTypeFunction([SimTypeInt(), SimTypeLongLong(), SimTypeInt()], SimTypeInt())) == [
            [SimRegArg("ecx", 4)],
            [SimStackArg(0x4, 4), SimStackArg(0x8, 4)],
            [SimRegArg("edx", 4)],
        ]
        # Doubles are passed on the stack too and do not consume a register.
        assert footprints(SimTypeFunction([SimTypeDouble(), SimTypeInt()], SimTypeInt())) == [
            [SimStackArg(0x4, 4), SimStackArg(0x8, 4)],
            [SimRegArg("ecx", 4)],
        ]
        # A sub-DWORD integer still uses a register, refined to its size.
        char_locs = cc.arg_locs(SimTypeFunction([SimTypeChar(), SimTypeInt()], SimTypeInt()).with_arch(arch))
        assert isinstance(char_locs[0], SimRegArg) and char_locs[0].reg_name == "ecx" and char_locs[0].size == 1
        assert char_locs[1] == SimRegArg("edx", 4)

    def test_struct_ffi(self):
        with open(os.path.join(test_location, "../tests_src/test_structs.c"), encoding="utf-8") as fp:
            decls = parse_file(fp.read())

        p = Project(os.path.join(test_location, "x86_64/test_structs.o"), auto_load_libs=False)

        def make_callable(name):
            return p.factory.callable(p.loader.find_symbol(name).rebased_addr, decls[0][name])

        test_small_struct_return = make_callable("test_small_struct_return")
        result = test_small_struct_return()
        self.assertIsInstance(result, SimStructValue)
        self.assertTrue((result.a == 1).is_true())
        self.assertTrue((result.b == 2).is_true())

    def test_array_ffi(self):
        # NOTE: if this test is failing and you think it is wrong, you might be right :)
        p = load_shellcode(b"\xc3", arch="amd64")
        s = p.factory.blank_state()
        s.regs.rdi = 123
        s.regs.rsi = 456
        s.regs.rdx = 789
        execve = parse_file("int execve(const char *pathname, char *const argv[], char *const envp[]);")[0]["execve"]
        cc = p.factory.cc()
        assert all((x == y).is_true() for x, y in zip(cc.get_args(s, execve), (123, 456, 789)))
        # however, this is definitely right
        assert [list(loc.get_footprint()) for loc in cc.arg_locs(execve)] == [
            [SimRegArg("rdi", 8)],
            [SimRegArg("rsi", 8)],
            [SimRegArg("rdx", 8)],
        ]

    def test_microsoft_amd64(self):
        arch = archinfo.ArchAMD64()
        cc = SimCCMicrosoftAMD64(arch)
        ty1 = parse_file("struct foo { int x; int y; };", arch=arch)[1]["struct foo"]
        loc1 = cc.return_val(ty1, perspective_returned=True)
        assert loc1 is not None
        assert loc1.get_footprint() == {SimRegArg("rax", 8)}
        loc2 = cc.return_val(ty1, perspective_returned=False)
        assert loc2 is not None
        assert loc2.get_footprint() == {SimRegArg("rax", 8)}

        ty3 = parse_file("struct foo { short x; int y; short z; };", arch=arch)[1]["struct foo"]
        loc3 = cc.return_val(ty3, perspective_returned=True)
        assert isinstance(loc3, SimReferenceArgument)
        assert loc3.ptr_loc == SimRegArg("rax", 8)
        assert loc3.main_loc.get_footprint() == {SimStackArg(0, 2), SimStackArg(4, 4), SimStackArg(8, 2)}
        loc4 = cc.return_val(ty3, perspective_returned=False)
        assert isinstance(loc4, SimReferenceArgument)
        assert loc4.ptr_loc == SimRegArg("rcx", 8)
        assert loc4.main_loc.get_footprint() == {SimStackArg(0, 2), SimStackArg(4, 4), SimStackArg(8, 2)}

    def test_riscv64_args_actual_values(self):
        bin_path = os.path.join(test_location, "riscv64", "sim_args_riscv64.so")
        src_location = os.path.join(bin_location, "tests_src")

        proj = Project(bin_path, auto_load_libs=False)

        symbol = proj.loader.find_symbol("complex_func")
        func_addr = symbol.rebased_addr
        cc = SimCCRISCV64(proj.arch)

        c_decl = os.path.join(src_location, "arch", "riscv", "sim_args_riscv64.c")
        with open(c_decl, encoding="utf-8") as f:
            raw_content = f.read()
        defns, _ = types.parse_file(raw_content)
        proto = defns["complex_func"].with_arch(proj.arch)

        args = [100, {"f": 1.0, "i": 2}, 3.0, {"x": 10.0, "y": 20.0, "z": 30.0}, 4, 5, 6, 7, 8, 9.0, 10, 11, 12.0]

        state = proj.factory.call_state(func_addr, *args, cc=cc, prototype=proto)

        assert state.solver.eval(state.regs.a0) == 100

        fa0_val = state.solver.eval(state.regs.fa0[31:0].raw_to_fp())
        a1_val = state.solver.eval(state.regs.a1[31:0])
        assert fa0_val == 1.0
        assert a1_val == 2

        fa1_val = state.solver.eval(state.regs.fa1.raw_to_fp())
        assert fa1_val == 3.0

        s2_ptr = state.solver.eval(state.regs.a2)
        s2_x = state.solver.eval(state.memory.load(s2_ptr, 8, endness="Iend_LE").raw_to_fp())
        assert s2_x == 10.0

        sp_val = state.solver.eval(state.regs.sp)
        r9_on_stack = state.solver.eval(state.memory.load(sp_val, 8, endness="Iend_LE"))
        assert r9_on_stack == 10

        fa3_val = state.solver.eval(state.regs.fa3[31:0].raw_to_fp())
        assert fa3_val == 12.0

    def test_riscv64_args_flatten_actual_values(self):
        bin_path = os.path.join(test_location, "riscv64", "sim_args_flatten_riscv64.so")
        src_location = os.path.join(bin_location, "tests_src")

        proj = Project(bin_path, auto_load_libs=False)

        symbol = proj.loader.find_symbol("complex_func")
        func_addr = symbol.rebased_addr

        cc = SimCCRISCV64(proj.arch)

        c_decl = os.path.join(src_location, "arch", "riscv", "sim_args_flatten_riscv64.c")
        with open(c_decl, encoding="utf-8") as f:
            raw_content = f.read()
        defns, _ = types.parse_file(raw_content)
        proto = defns["complex_func"].with_arch(proj.arch)

        args = [{"f": 1.0, "i": 2}, {"x": 10, "y": 20}, {"a": 101.3, "c": 102.3, "d": 60}]
        state = proj.factory.call_state(func_addr, *args, cc=cc, prototype=proto)

        fa0_val = state.solver.eval(state.regs.fa0[31:0].raw_to_fp())
        a0_val = state.solver.eval(state.regs.a0[31:0])
        assert fa0_val == 1.0
        assert a0_val == 2

        a1_val = state.solver.eval(state.regs.a1)
        assert (a1_val & 0xFFFFFFFF) == 10
        assert (a1_val >> 32) == 20

        a2_bits = state.solver.eval(state.regs.a2)
        a3_val = state.solver.eval(state.regs.a3)

        a2_float = struct.unpack("<d", struct.pack("<Q", a2_bits))[0]
        assert abs(a2_float - 101.3) < 0.00001

        c_bits = a3_val & 0xFFFFFFFF
        c_float = struct.unpack("<f", struct.pack("<I", c_bits))[0]
        assert abs(c_float - 102.3) < 0.00001
        assert (a3_val >> 32) == 60

    def test_aarch64_aggregate_args(self):
        arch = archinfo.arch_from_id("aarch64")
        cc = SimCCAArch64(arch)

        def locs(*args):
            return cc.arg_locs(SimTypeFunction(list(args), SimTypeInt()).with_arch(arch))

        integer = SimTypeInt()
        small = SimStruct({"a": SimTypeInt(), "b": SimTypeInt()}, name="Small")
        pair = SimStruct({"x": SimTypeLongLong(), "y": SimTypeLongLong()}, name="Pair")
        big = SimStruct({"a": SimTypeLongLong(), "b": SimTypeLongLong(), "c": SimTypeLongLong()}, name="Big")

        # A composite of one double-word takes one register, one of two takes a consecutive pair.
        assert locs(small)[0].get_footprint() == {SimRegArg("x0", 8)}
        assert locs(pair)[0].get_footprint() == {SimRegArg("x0", 8), SimRegArg("x1", 8)}

        # A composite larger than 16 bytes is passed by reference.
        big_loc = locs(big)[0]
        assert isinstance(big_loc, SimReferenceArgument)
        assert big_loc.ptr_loc == SimRegArg("x0", 8)
        assert big_loc.main_loc.get_footprint() == {SimStackArg(0, 8), SimStackArg(8, 8), SimStackArg(0x10, 8)}

        # Seven integers leave one register free, which a two-register composite cannot use: it goes on
        # the stack, and the register it skipped is not given to the argument after it either.
        spilled = locs(*[integer] * 7, pair, integer)
        assert spilled[6] == SimRegArg("x6", 4)
        assert spilled[7].get_footprint() == {SimStackArg(0, 8), SimStackArg(8, 8)}
        assert spilled[8] == SimStackArg(0x10, 4)

        # A 16-byte integral argument takes a register pair, starting on an even-numbered register.
        assert locs(integer, SimTypeNum(128))[1].get_footprint() == {SimRegArg("x2", 8), SimRegArg("x3", 8)}

    def test_aarch64_aggregate_args_reach_the_callsite(self):
        proj = Project(os.path.join(test_location, "aarch64", "struct_by_value_aarch64.so"), auto_load_libs=False)
        cc = SimCCAArch64(proj.arch)
        pair = SimStruct({"x": SimTypeLongLong(), "y": SimTypeLongLong()}, name="Pair")
        big = SimStruct({"a": SimTypeLongLong(), "b": SimTypeLongLong(), "c": SimTypeLongLong()}, name="Big")
        proto = SimTypeFunction([SimTypeInt(), pair, big, SimTypeInt()], SimTypeInt()).with_arch(proj.arch)
        addr = proj.loader.find_symbol("_Z9call_theml").rebased_addr

        state = proj.factory.call_state(
            addr, 7, {"x": 11, "y": 22}, {"a": 33, "b": 44, "c": 55}, 9, cc=cc, prototype=proto
        )
        evaluate = state.solver.eval
        assert evaluate(state.regs.x0) == 7
        assert evaluate(state.regs.x1) == 11
        assert evaluate(state.regs.x2) == 22
        referenced = evaluate(state.regs.x3)
        assert [evaluate(state.memory.load(referenced + 8 * i, 8, endness="Iend_LE")) for i in range(3)] == [33, 44, 55]
        assert evaluate(state.regs.x4) == 9

    def test_aarch64_class_by_value_argument(self):
        proj = Project(os.path.join(test_location, "aarch64", "struct_by_value_aarch64.so"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)
        func = next(f for f in proj.kb.functions.values() if f.name == "_Z8take_big3Big" and not f.is_plt)
        assert isinstance(func.prototype.args[0], SimCppClass)
        assert len(proj.factory.cc().arg_locs(func.prototype.with_arch(proj.arch))) == 1
        assert proj.analyses.Decompiler(func, cfg=cfg.model).codegen is not None

    def test_aarch64_float_args(self):
        arch = archinfo.arch_from_id("aarch64")
        cc = SimCCAArch64(arch)

        def locs(*args):
            return cc.arg_locs(SimTypeFunction(list(args), SimTypeInt()).with_arch(arch))

        integer = SimTypeInt()
        double = SimTypeDouble()
        pair = SimStruct({"a": SimTypeDouble(), "b": SimTypeDouble()}, name="Pair")
        triple = SimStruct({"x": SimTypeFloat(), "y": SimTypeFloat(), "z": SimTypeFloat()}, name="Triple")
        array = SimStruct({"v": SimTypeFixedSizeArray(SimTypeDouble(), 3)}, name="Array")

        # Floating-point arguments have eight registers of their own and do not consume integer ones.
        assert locs(double, integer, double) == [SimRegArg("v0", 8), SimRegArg("x0", 4), SimRegArg("v1", 8)]
        assert locs(*[double] * 9)[8] == SimStackArg(0, 8)

        # Every member of a homogeneous floating-point aggregate takes a register of its own.
        assert locs(pair)[0].get_footprint() == {SimRegArg("v0", 8), SimRegArg("v1", 8)}
        assert locs(triple)[0].get_footprint() == {SimRegArg("v0", 4), SimRegArg("v1", 4), SimRegArg("v2", 4)}
        assert locs(array)[0].get_footprint() == {SimRegArg("v0", 8), SimRegArg("v1", 8), SimRegArg("v2", 8)}

        # Seven doubles leave one register free, which a two-member aggregate cannot use: it goes on the
        # stack, and the register it skipped is not given to the argument after it either.
        spilled = locs(*[double] * 7, pair, double)
        assert spilled[6] == SimRegArg("v6", 8)
        assert spilled[7].get_footprint() == {SimStackArg(0, 8), SimStackArg(8, 8)}
        assert spilled[8] == SimStackArg(0x10, 8)

        assert cc.return_val(SimTypeDouble().with_arch(arch)) == SimRegArg("v0", 8)
        assert cc.return_val(SimTypeFloat().with_arch(arch)) == SimRegArg("v0", 4)

    def test_aarch64_homogeneous_float_aggregates(self):
        arch = archinfo.arch_from_id("aarch64")
        cc = SimCCAArch64(arch)
        floats = SimStruct({"a": SimTypeFloat(), "b": SimTypeFloat()}, name="TwoFloats")

        # A union is one only if every member is, and the member with the most of them decides the layout.
        homogeneous = SimUnion({"p": floats, "q": SimTypeFloat()}, name="Homogeneous")
        proto = SimTypeFunction([homogeneous], SimTypeInt()).with_arch(arch)
        assert cc.arg_locs(proto)[0].get_footprint() == {SimRegArg("v0", 4), SimRegArg("v1", 4)}

        # None of these is homogeneous, so none of them goes in the SIMD registers: a member of another
        # kind, a member of another floating-point type, or more than four members.
        for name, aggregate in (
            ("mixed union", SimUnion({"f": SimTypeFloat(), "i": SimTypeInt()}, name="MixedUnion")),
            ("widened union", SimUnion({"f": SimTypeFloat(), "d": SimTypeDouble()}, name="WidenedUnion")),
            ("mixed struct", SimStruct({"a": SimTypeDouble(), "n": SimTypeLongLong()}, name="MixedStruct")),
            ("five doubles", SimStruct({k: SimTypeDouble() for k in "abcde"}, name="FiveDoubles")),
            ("long array", SimStruct({"v": SimTypeFixedSizeArray(SimTypeDouble(), 5)}, name="LongArray")),
        ):
            assert cc._hfa_members(aggregate.with_arch(arch)) is None, name  # pylint: disable=protected-access

    def test_aarch64_float_args_reach_the_callee(self):
        proj = Project(os.path.join(test_location, "aarch64", "hfa_args_aarch64.so"), auto_load_libs=False)
        double = SimTypeDouble()
        pair = SimStruct({"a": SimTypeDouble(), "b": SimTypeDouble()}, name="Pair")
        triple = SimStruct({"x": SimTypeFloat(), "y": SimTypeFloat(), "z": SimTypeFloat()}, name="Triple")
        cases = [
            ("take_pair", SimTypeFunction([pair], double), [(1.5, 2.25)], 3.75),
            ("take_triple", SimTypeFunction([triple], SimTypeFloat()), [(1.0, 2.0, 4.0)], 7.0),
            (
                "take_mixed",
                SimTypeFunction([SimTypeLongLong(), triple, double], double),
                [10, (1.0, 2.0, 4.0), 0.5],
                17.5,
            ),
            (
                "spill_pair",
                SimTypeFunction([double] * 7 + [pair, double], double),
                [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, (8.0, 9.0), 10.0],
                55.0,
            ),
        ]
        for name, prototype, args, expected in cases:
            symbol = proj.loader.main_object.get_symbol(name)
            assert symbol is not None
            result = proj.factory.callable(symbol.rebased_addr, prototype=prototype)(*args)
            assert isinstance(result, claripy.ast.FP) and not result.symbolic
            assert result.args[0] == expected

    def test_simcc_arg_locs_returnty_unresolved_simtyperef(self):
        func_proto = SimTypeFunction([], SimTypeRef("std::wstring_t", SimCppClass))

        for arch in [archinfo.ArchAMD64, archinfo.ArchX86, archinfo.ArchARM]:
            proto = func_proto.with_arch(arch())
            cc = default_cc(arch.name)(arch())

            # It should not raise any exception!
            arg_locs = list(cc.arg_locs(proto))
            assert arg_locs is not None

    def test_simcc_arg_locs_returnty_none(self):
        # SimTypeFunction documents returnty=None as void, and SimCC.arg_session accepts it. Rust
        # decompilation produces such prototypes: when arg0 is a return buffer the return type moves
        # into arg0 as a reference and returnty is left None. return_in_implicit_outparam must answer
        # False for it rather than reaching for its size.
        func_proto = SimTypeFunction([SimTypeInt(), SimTypeInt()], None)

        arch = archinfo.ArchAMD64()
        cc = SimCCMicrosoftAMD64(arch)
        assert cc.return_in_implicit_outparam(None) is False

        reg_names = []
        for loc in cc.arg_locs(func_proto.with_arch(arch)):
            assert isinstance(loc, SimRegArg)
            reg_names.append(loc.reg_name)
        assert reg_names == ["rcx", "rdx"]

        for arch_cls in [archinfo.ArchAMD64, archinfo.ArchX86, archinfo.ArchARM]:
            proto = func_proto.with_arch(arch_cls())
            cc_cls = default_cc(arch_cls.name)
            assert cc_cls is not None
            arch_cc = cc_cls(arch_cls())

            # It should not raise any exception!
            arg_locs = list(arch_cc.arg_locs(proto))
            assert len(arg_locs) == 2

    def test_microsoft_fastcall_aggregate_return(self):
        # Regression test: __fastcall changes how arguments are passed, not how values are returned.
        # Without a return_val override the base class refuses every aggregate return type, and a
        # decompiled function returning a small struct comes out empty. This is the return-side
        # counterpart of test_microsoft_fastcall_large_arg above.
        arch = archinfo.arch_from_id("x86")
        fastcall = SimCCMicrosoftFastcall(arch)
        cdecl = SimCCMicrosoftCdecl(arch)

        small = SimStruct({"ptr": SimTypePointer(SimTypeChar()), "len": SimTypeInt()}, name="fatptr").with_arch(arch)
        large = SimStruct({f"f{i}": SimTypeInt() for i in range(8)}, name="big").with_arch(arch)

        # An eight-byte aggregate comes back in EAX:EDX, the same as __cdecl on Windows x86.
        small_ret = fastcall.return_val(small)
        assert isinstance(small_ret, SimStructArg)
        assert list(small_ret.locs.values()) == [SimRegArg("eax", 4), SimRegArg("edx", 4)]
        cdecl_small = cdecl.return_val(small)
        assert isinstance(cdecl_small, SimStructArg)
        assert set(small_ret.get_footprint()) == set(cdecl_small.get_footprint())
        assert fastcall.return_in_implicit_outparam(small) is False

        # A larger one is written through a hidden pointer. That pointer is the call's first
        # argument, so __fastcall passes it in ECX -- not in the stack slot __cdecl uses. This is
        # why the implementation cannot simply be inherited from the cdecl convention.
        large_ret = fastcall.return_val(large)
        assert isinstance(large_ret, SimReferenceArgument)
        assert large_ret.ptr_loc == SimRegArg("ecx", 4)
        cdecl_large = cdecl.return_val(large)
        assert isinstance(cdecl_large, SimReferenceArgument)
        assert cdecl_large.ptr_loc == SimStackArg(0, 4)
        assert fastcall.return_in_implicit_outparam(large) is True

        # The hidden pointer consumes ECX, so the declared arguments shift along.
        proto = SimTypeFunction([SimTypeInt(), SimTypeInt()], large).with_arch(arch)
        assert [list(loc.get_footprint()) for loc in fastcall.arg_locs(proto)] == [
            [SimRegArg("edx", 4)],
            [SimStackArg(0x4, 4)],
        ]


if __name__ == "__main__":
    main()
