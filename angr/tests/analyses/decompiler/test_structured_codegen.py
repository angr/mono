#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import angr
from angr.ailment import Expr, Manager, Stmt
from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpression,
    CGoto,
    CIndexedVariable,
    CStructField,
    CStructuredCodeGenerator,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
    type_to_c_repr_chunks,
)
from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_type import SimStruct, SimTypeBottom, SimTypeChar, SimTypeInt, SimTypeLongLong, SimTypePointer, SimUnion
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _RenderedExpression(CExpression):
    def __init__(self, text, ty=None, *, codegen):
        super().__init__(codegen=codegen)
        self.text = text
        self._type = ty

    @property
    def type(self):
        return self._type

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield self.text, self


def _make_codegen() -> CStructuredCodeGenerator:
    proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen
    assert isinstance(codegen, CStructuredCodeGenerator)
    return codegen


class TestConvertRendering(unittest.TestCase):
    """How CStructuredCodeGenerator renders Convert expressions of assorted widths."""

    codegen: CStructuredCodeGenerator

    @classmethod
    def setUpClass(cls):
        cls.codegen = _make_codegen()
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        cls.codegen = codegen

    def _render(self, from_bits: int, to_bits: int, value: int = 0x1234) -> str:
        conv = Expr.Convert(0, from_bits, to_bits, False, Expr.Const(0, value, from_bits))
        return self.codegen._handle(conv).c_repr()

    def test_truncation_to_unrepresentable_width_is_masked(self):
        # No C type is 5, 3 or 1 bits wide. A cast would round up to the next real type and keep
        # bits the conversion discards, so these have to be spelled as a mask instead.
        assert self._render(32, 5) == "4660 & 31"
        assert self._render(32, 3) == "4660 & 7"
        assert self._render(32, 1) == "4660 & 1"

    def test_truncation_to_representable_width_is_a_cast(self):
        assert self._render(32, 8) == "(char)4660"
        assert self._render(32, 16) == "(unsigned short)4660"

    def test_widening_is_always_a_cast(self):
        # Rounding up only loses information when truncating, so widening keeps casting even to a
        # width no C type has.
        assert self._render(1, 5, value=1) == "(char)1"
        assert self._render(8, 12, value=3) == "(unsigned short)3"
        assert self._render(32, 64, value=3) == "(unsigned long long)3"

    def test_widening_sizeless_child_uses_ail_source_width(self):
        unknown_type = SimTypeBottom().with_arch(self.codegen.project.arch)
        child = CBinaryOp(
            "Shr",
            CConstant(1, unknown_type, codegen=self.codegen),
            CConstant(2, unknown_type, codegen=self.codegen),
            codegen=self.codegen,
        )
        assert child.type.size is None

        conv = Expr.Convert(0, 1, 64, True, Expr.Const(0, 1, 1))
        with patch.object(self.codegen, "_handle", return_value=child):
            rendered = self.codegen._handle_Expr_Convert(conv)

        assert isinstance(rendered, CTypeCast)
        assert isinstance(rendered.expr, CTypeCast)
        assert rendered.expr.dst_type.size == conv.from_bits
        assert getattr(rendered.expr.dst_type, "signed", None) is True
        assert rendered.c_repr() == "(long long)(int1_t)(1 >> 2)"

    def test_widening_known_child_keeps_inferred_width(self):
        known_type = self.codegen.default_simtype_from_bits(16, signed=False)
        child = CConstant(1, known_type, codegen=self.codegen)
        conv = Expr.Convert(0, 32, 64, True, Expr.Const(0, 1, 32))
        with patch.object(self.codegen, "_handle", return_value=child):
            rendered = self.codegen._handle_Expr_Convert(conv)

        assert isinstance(rendered, CTypeCast)
        assert isinstance(rendered.expr, CTypeCast)
        assert rendered.expr.dst_type.size == known_type.size
        assert getattr(rendered.expr.dst_type, "signed", None) is True
        assert rendered.c_repr() == "(long long)(short)1"


class TestGotoRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codegen = SimpleNamespace(
            comment_gotos=False,
            map_addr_to_label={},
            next_ident=lambda name: name,
            next_node_idx=lambda: 0,
        )

    def test_integer_and_pointer_targets_are_cast_to_void_pointer(self):
        target_types = {
            "integer_target": SimTypeInt(signed=False),
            "pointer_target": SimTypePointer(SimTypeInt(signed=False)),
        }

        for name, target_type in target_types.items():
            with self.subTest(target_type=name):
                target = _RenderedExpression(name, target_type, codegen=self.codegen)
                chunks = list(CGoto(target, None, codegen=self.codegen).c_repr_chunks())

                self.assertEqual("".join(text for text, _ in chunks), f"goto *((void *)({name}));\n")
                self.assertIn((name, target), chunks)

    def test_computed_goto_preserves_dereferenced_target(self):
        target = CUnaryOp("Dereference", _RenderedExpression("target", codegen=self.codegen), codegen=self.codegen)
        chunks = CGoto(target, None, codegen=self.codegen).c_repr_chunks()

        self.assertEqual("".join(text for text, _ in chunks), "goto *((void *)(*(target)));\n")

    def test_constant_jump_is_a_direct_goto(self):
        chunks = CGoto(0x400000, None, codegen=self.codegen).c_repr_chunks()

        self.assertEqual("".join(text for text, _ in chunks), "goto LABEL_0x400000;\n")


class TestStoreWidth(unittest.TestCase):
    """A store's emitted C must write as many bytes as the AIL store writes."""

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        cls.codegen = codegen

    def _dst_bits(self, idx: int, value_type, value_bits: int, size: int) -> int:
        # the destination is what _access renders as *(T*)addr, so its type is the width written
        data = Expr.Const(idx, 0, value_bits, type=value_type)
        stmt = Stmt.Store(idx, Expr.Const(idx, 0x400000, 64), data, size, "Iend_LE")
        assignment = self.codegen._handle(stmt, is_expr=False)
        assert isinstance(assignment, CAssignment)
        assert assignment.lhs.type is not None
        return assignment.lhs.type.size

    def test_value_typed_narrower_than_the_store(self):
        assert self._dst_bits(1, SimTypeInt(signed=False), 64, 8) == 64

    def test_value_typed_wider_than_the_store(self):
        assert self._dst_bits(2, SimTypeLongLong(signed=False), 8, 1) == 8

    def test_value_with_no_inferred_type(self):
        assert self._dst_bits(3, SimTypeBottom(), 128, 16) == 128

    def test_value_typed_correctly_is_left_alone(self):
        assert self._dst_bits(4, SimTypeLongLong(signed=False), 64, 8) == 64


class TestStoreRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codegen = _make_codegen()

    def test_mismatched_store_cast_distinguishes_pointer_from_storage(self):
        manager = Manager(arch=self.codegen.project.arch)
        addr = Expr.VirtualVariable(
            manager.next_atom(), 1, self.codegen.project.arch.bits, VirtualVariableCategory.REGISTER
        )
        data = Expr.Const(manager.next_atom(), 0x11223344, 32)
        pointer_store = Stmt.Store(
            manager.next_atom(), addr, data, 4, self.codegen.project.arch.memory_endness, ins_addr=0x401000
        )
        direct_store = Stmt.Store(
            manager.next_atom(), addr, data, 4, self.codegen.project.arch.memory_endness, ins_addr=0x401004
        )
        addr_variable = SimRegisterVariable(0x28, self.codegen.project.arch.bytes, ident="ir_test", name="iter")
        storage_variable = SimStackVariable(-0x10, 4, ident="is_test", name="storage")
        variable_map = VariableMap()
        variable_map.set_variable(addr, addr_variable)
        variable_map.set_variable(direct_store, storage_variable)

        variable_manager = self.codegen.kb.dec_variables[self.codegen._func.addr]
        variable_manager.set_unified_variable(addr_variable, addr_variable)
        variable_manager.set_unified_variable(storage_variable, storage_variable)
        variable_manager.set_variable_type(
            addr_variable, SimTypePointer(SimTypeChar()).with_arch(self.codegen.project.arch)
        )
        variable_manager.set_variable_type(storage_variable, SimTypeChar().with_arch(self.codegen.project.arch))
        old_variable_map = self.codegen._variable_map
        self.codegen._variable_map = variable_map
        try:
            pointer_rendered = self.codegen._handle(pointer_store, is_expr=False).c_repr()
            direct_rendered = self.codegen._handle(direct_store, is_expr=False).c_repr()
        finally:
            self.codegen._variable_map = old_variable_map

        assert direct_rendered == "*((unsigned int *)&storage) = 287454020;\n"
        assert pointer_rendered == "*((unsigned int *)iter) = 287454020;\n"


class TestPostfixExpressionRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        codegen = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg).codegen
        assert isinstance(codegen, CStructuredCodeGenerator)
        cls.codegen = codegen
        struct_type = SimStruct({"field_0": SimTypeInt()}, name="struct_0").with_arch(proj.arch)
        assert isinstance(struct_type, SimStruct)
        cls.struct_type = struct_type
        cls.field = CStructField(cls.struct_type, 0, "field_0", codegen=cls.codegen)

    def _variable(self, name: str, ty):
        return CVariable(
            SimRegisterVariable(0, 8, name=name),
            variable_type=ty,
            codegen=self.codegen,
        )

    def test_member_access_parenthesizes_unary_base(self):
        struct_ptr = SimTypePointer(self.struct_type).with_arch(self.codegen.project.arch)
        struct_ptr_ptr = SimTypePointer(struct_ptr).with_arch(self.codegen.project.arch)
        ptr = self._variable("ptr", struct_ptr)
        ptr_ptr = self._variable("ptr_ptr", struct_ptr_ptr)

        dereferenced_ptr_ptr = CUnaryOp("Dereference", ptr_ptr, codegen=self.codegen)
        assert CVariableField(dereferenced_ptr_ptr, self.field, True, codegen=self.codegen).c_repr() == (
            "(*(ptr_ptr))->field_0"
        )

        dereferenced_ptr = CUnaryOp("Dereference", ptr, codegen=self.codegen)
        assert CVariableField(dereferenced_ptr, self.field, False, codegen=self.codegen).c_repr() == (
            "(*(ptr)).field_0"
        )

        value = self._variable("value", self.struct_type)
        referenced_value = CUnaryOp("Reference", value, codegen=self.codegen)
        assert CVariableField(referenced_value, self.field, True, codegen=self.codegen).c_repr() == (
            "(&value)->field_0"
        )

    def test_member_access_parenthesizes_cast_and_binary_bases(self):
        struct_ptr = SimTypePointer(self.struct_type).with_arch(self.codegen.project.arch)
        ptr = self._variable("ptr", struct_ptr)

        cast_ptr = CTypeCast(struct_ptr, struct_ptr, ptr, codegen=self.codegen)
        assert CVariableField(cast_ptr, self.field, True, codegen=self.codegen).c_repr() == (
            "((struct struct_0 *)ptr)->field_0"
        )

        next_ptr = CBinaryOp("Add", ptr, CConstant(1, SimTypeInt(), codegen=self.codegen), codegen=self.codegen)
        assert CVariableField(next_ptr, self.field, True, codegen=self.codegen).c_repr() == "(ptr + 1)->field_0"

    def test_member_and_index_access_keep_postfix_bases_folded(self):
        struct_ptr = SimTypePointer(self.struct_type).with_arch(self.codegen.project.arch)
        struct_ptr_ptr = SimTypePointer(struct_ptr).with_arch(self.codegen.project.arch)
        ptr_ptr = self._variable("ptr_ptr", struct_ptr_ptr)
        zero = CConstant(0, SimTypeInt(), codegen=self.codegen)

        indexed_ptr = CIndexedVariable(ptr_ptr, zero, codegen=self.codegen)
        assert CVariableField(indexed_ptr, self.field, True, codegen=self.codegen).c_repr() == "ptr_ptr[0]->field_0"

        dereferenced_ptr_ptr = CUnaryOp("Dereference", ptr_ptr, codegen=self.codegen)
        indexed_struct = CIndexedVariable(dereferenced_ptr_ptr, zero, codegen=self.codegen)
        assert indexed_struct.c_repr() == "(*(ptr_ptr))[0]"
        assert CVariableField(indexed_struct, self.field, False, codegen=self.codegen).c_repr() == (
            "(*(ptr_ptr))[0].field_0"
        )


class TestAnonymousAggregateRendering(unittest.TestCase):
    """How type_to_c_repr_chunks renders anonymous aggregates that contain themselves."""

    @staticmethod
    def _render(ty) -> str:
        return "".join(text for text, _ in type_to_c_repr_chunks(ty, full=True))

    def test_nested_anonymous_structs_are_rendered_inline(self):
        inner = SimStruct({"x": SimTypeInt()}, name="<anon>")
        middle = SimStruct({"deep": inner}, name="<anon>")
        outer = SimStruct({"mid": middle, "y": SimTypeInt()}, name="outer")
        assert self._render(outer) == (
            "typedef struct outer {\n"
            "    struct {\n"
            "        struct {\n"
            "            int x;\n"
            "        } deep;\n"
            "    } mid;\n"
            "    int y;\n"
            "} outer;\n\n"
        )

    def test_a_reused_anonymous_struct_is_rendered_in_full_each_time(self):
        # only the enclosing aggregates count as a cycle: the same object used by two sibling
        # fields is rendered twice, in full
        anon = SimStruct({"x": SimTypeInt()}, name="<anon>")
        outer = SimStruct({"a": anon, "b": anon}, name="outer")
        assert self._render(outer) == (
            "typedef struct outer {\n"
            "    struct {\n"
            "        int x;\n"
            "    } a;\n"
            "    struct {\n"
            "        int x;\n"
            "    } b;\n"
            "} outer;\n\n"
        )

    def test_self_referential_anonymous_struct_terminates(self):
        # Type inference can hand codegen an anonymous aggregate that reaches itself. Anonymous
        # aggregates are rendered inline, so there is no name to refer back to and the render
        # descended until the interpreter stopped it.
        anon = SimStruct({}, name="<anon>")
        anon.fields["loop"] = anon
        anon.fields["x"] = SimTypeInt()
        outer = SimStruct({"mid": anon}, name="outer")
        assert self._render(outer) == (
            "typedef struct outer {\n"
            "    struct {\n"
            "        struct { /* recursive */ } loop;\n"
            "        int x;\n"
            "    } mid;\n"
            "} outer;\n\n"
        )

    def test_self_referential_anonymous_union_terminates(self):
        anon = SimUnion({}, name="<anon>")
        anon.members["loop"] = anon
        anon.members["x"] = SimTypeInt()
        outer = SimStruct({"mid": anon}, name="outer")
        assert self._render(outer) == (
            "typedef struct outer {\n"
            "    union {\n"
            "        union { /* recursive */ } loop;\n"
            "        int x;\n"
            "    } mid;\n"
            "} outer;\n\n"
        )


if __name__ == "__main__":
    unittest.main()
