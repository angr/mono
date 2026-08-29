from __future__ import annotations

from pathlib import Path
from typing import Literal

import archinfo
import claripy
import networkx
import pytest

from angr import Project, ailment
from angr.ailment.expression import Const, Extract, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import ConditionalJump, Jump, Return

from angr import ailment
from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Const, Extract, Register, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import ConditionalJump
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.structurer_nodes import IncompleteSwitchCaseHeadStatement, MultiNode
from tests.common import bin_location


def _recover_edge_condition_with_internal_side_exits(
    side_exits: tuple[int | None, ...],
    *,
    false_side_exits: tuple[int | None, ...] | None = None,
    side_exit_target_indices: tuple[int | None, ...] | None = None,
    terminal_target: int | None = 0x5000,
    terminal_target_idx: int | None = None,
    dst_idx: int | None = None,
    internal_jump_target: int | None = None,
    internal_control: Literal["return", "switch"] | None = None,
    wrap_destination: bool = False,
) -> claripy.ast.Bool:
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)
    src_addr = 0x4000
    dst_addr = 0x5000
    false_side_exits = false_side_exits if false_side_exits is not None else (None,) * len(side_exits)
    side_exit_target_indices = side_exit_target_indices or (None,) * len(side_exits)
    assert len(false_side_exits) == len(side_exits)
    assert len(side_exit_target_indices) == len(side_exits)

    statements = []
    for side_exit, false_side_exit, side_exit_target_idx in zip(
        side_exits, false_side_exits, side_exit_target_indices, strict=True
    ):
        condition = VirtualVariable(
            manager.next_atom(),
            1,
            1,
            VirtualVariableCategory.REGISTER,
            oident=arch.registers["rax"][0],
        )
        side_exit_target = (
            Const(manager.next_atom(), side_exit, arch.bits)
            if side_exit is not None
            else VirtualVariable(
                manager.next_atom(),
                arch.bits,
                2,
                VirtualVariableCategory.REGISTER,
                oident=arch.registers["rbx"][0],
            )
        )
        false_side_exit_target = (
            Const(manager.next_atom(), false_side_exit, arch.bits) if false_side_exit is not None else None
        )
        statements.append(
            ConditionalJump(
                manager.next_atom(),
                condition,
                side_exit_target,
                false_side_exit_target,
                true_target_idx=side_exit_target_idx,
                ins_addr=src_addr,
            )
        )

    if internal_jump_target is not None:
        statements.append(
            Jump(
                manager.next_atom(),
                Const(manager.next_atom(), internal_jump_target, arch.bits),
                ins_addr=src_addr + 1,
            )
        )

    if internal_control == "return":
        statements.append(Return(manager.next_atom(), [], ins_addr=src_addr + 1))
    elif internal_control == "switch":
        case_block = ailment.Block(0x6000, 4)
        switch_expr = Const(manager.next_atom(), 0, arch.bits)
        statements.append(
            IncompleteSwitchCaseHeadStatement(
                manager.next_atom(),
                switch_expr,
                [(case_block, 0, case_block.addr, case_block.idx, 0x6004)],
                ins_addr=src_addr + 1,
            )
        )

    direct_target = (
        Const(manager.next_atom(), terminal_target, arch.bits)
        if terminal_target is not None
        else VirtualVariable(
            manager.next_atom(),
            arch.bits,
            3,
            VirtualVariableCategory.REGISTER,
            oident=arch.registers["rcx"][0],
        )
    )
    statements.append(
        Jump(
            manager.next_atom(),
            direct_target,
            target_idx=terminal_target_idx,
            ins_addr=src_addr + 1,
        )
    )
    src = ailment.Block(
        src_addr,
        4,
        statements=statements,
    )
    dst = ailment.Block(dst_addr, 4, idx=dst_idx)
    if wrap_destination:
        dst = MultiNode([dst])
    graph = networkx.DiGraph([(src, dst)])

    return condition_processor.recover_edge_condition(graph, src, dst)


@pytest.mark.parametrize("wrap_destination", [False, True], ids=["block", "multinode"])
def test_internal_side_exit_and_terminal_jump_converge(wrap_destination: bool):
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000, 0x5000),
        side_exit_target_indices=(1, 1),
        terminal_target_idx=1,
        dst_idx=1,
        wrap_destination=wrap_destination,
    )

    assert claripy.is_true(predicate)


def test_internal_side_exit_differs_from_terminal_jump():
    predicate = _recover_edge_condition_with_internal_side_exits((0x6000,))

    assert predicate.symbolic
    assert predicate.op == "Not"


def test_second_internal_side_exit_differs_from_terminal_jump():
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000, 0x6000))

    assert predicate.symbolic


@pytest.mark.parametrize(
    ("side_exits", "terminal_target"),
    [
        pytest.param((None,), 0x5000, id="indirect-side-exit"),
        pytest.param((0x5000,), 0x6000, id="different-terminal-target"),
        pytest.param((0x5000,), None, id="indirect-terminal-target"),
    ],
)
def test_convergence_requires_direct_matching_targets(side_exits, terminal_target):
    predicate = _recover_edge_condition_with_internal_side_exits(side_exits, terminal_target=terminal_target)

    assert predicate.symbolic


def test_convergence_requires_matching_target_indices():
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000,),
        side_exit_target_indices=(2,),
        terminal_target_idx=1,
        dst_idx=1,
    )

    assert predicate.symbolic


def test_convergence_rejects_internal_jump():
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000,), internal_jump_target=0x6000)

    assert predicate.symbolic


@pytest.mark.parametrize("internal_control", ["return", "switch"])
def test_convergence_rejects_internal_control(internal_control):
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000,), internal_control=internal_control)

    assert predicate.symbolic


def test_explicit_false_side_exit_converges():
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000,), false_side_exits=(0x5000,))

    assert claripy.is_true(predicate)


def test_explicit_false_side_exit_differs():
    predicate = _recover_edge_condition_with_internal_side_exits((0x5000,), false_side_exits=(0x6000,))

    assert predicate.symbolic


def test_convergence_requires_matching_terminal_target_idx():
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000,),
        side_exit_target_indices=(1,),
        terminal_target_idx=2,
        dst_idx=1,
    )

    assert predicate.symbolic


def test_convergence_requires_matching_multinode_target_idx():
    predicate = _recover_edge_condition_with_internal_side_exits(
        (0x5000,),
        side_exit_target_indices=(1,),
        terminal_target_idx=1,
        dst_idx=2,
        wrap_destination=True,
    )

    assert predicate.symbolic


def _condition(arch, manager, reg_name):
    reg_offset = arch.registers[reg_name][0]
    return BinaryOp(
        manager.next_atom(),
        "CmpEQ",
        (Register(manager.next_atom(), reg_offset, arch.bits), Const(manager.next_atom(), 0, arch.bits)),
        False,
    )


def _conditional_block(arch, manager, addr, condition, true_addr, false_addr):
    jump = ConditionalJump(
        manager.next_atom(),
        condition,
        Const(manager.next_atom(), true_addr, arch.bits),
        Const(manager.next_atom(), false_addr, arch.bits),
        ins_addr=addr,
    )
    return Block(addr, 1, statements=[jump])


def test_extract_placeholders_include_semantic_properties():
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    base = VirtualVariable(0, 1, 64, VirtualVariableCategory.REGISTER, oident=arch.registers["rax"][0])
    offset = Const(1, 0, 64)
    extract_byte = Extract(2, 8, base, offset, arch.memory_endness)
    extract_word = Extract(3, 16, base, offset, arch.memory_endness)
    extract_byte_be = Extract(4, 8, base, offset, archinfo.Endness.BE)

    byte_ast = condition_processor.claripy_ast_from_ail_condition(extract_byte)
    word_ast = condition_processor.claripy_ast_from_ail_condition(extract_word)
    byte_be_ast = condition_processor.claripy_ast_from_ail_condition(extract_byte_be)

    assert byte_ast.args[0] != word_ast.args[0]
    assert byte_ast.args[0] != byte_be_ast.args[0]
    assert condition_processor.convert_claripy_bool_ast(byte_ast) is extract_byte
    assert condition_processor.convert_claripy_bool_ast(word_ast) is extract_word
    assert condition_processor.convert_claripy_bool_ast(byte_be_ast) is extract_byte_be


# Exact _crt0_entry bodies from the public DecBench ChibiOS binaries. Only PC-relative call offsets differ.
@pytest.mark.parametrize("structurer", ["sailr", "phoenix"])
@pytest.mark.parametrize("optimization", ["O0", "O2", "O2-noinline"])
def test_chibios_crt0_entry_convergent_side_exits(structurer, optimization):
    fixture = Path(bin_location, "tests", "armel", "chibios_crt0_entry", f"{optimization}.bin")
    project = Project(
        fixture,
        main_opts={
            "arch": "ARMCortexM",
            "backend": "blob",
            "base_addr": 0x80001E0,
            "entry_point": 0,
        },
    )
    assert project.filename is not None
    assert Path(project.filename) == fixture
    cfg = project.analyses.CFGFast(
        normalize=True,
        regions=[(0x80001E0, 0x8000266)],
        function_starts=[0x80001E1],
        start_at_entry=False,
        symbols=False,
        force_smart_scan=False,
        show_progressbar=False,
    )
    function = cfg.kb.functions.get_by_addr(0x80001E1)

    decompilation = project.analyses[Decompiler].prep(fail_fast=True)(
        function,
        cfg=cfg.model,
        options=[("structurer_cls", structurer)],
        preset="full",
        use_cache=False,
    )

    assert decompilation.codegen is not None, optimization
    assert not decompilation.errors, optimization
def test_guarding_condition_excludes_all_diverging_paths():
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    first_exit = Block(0x1010, 1)
    second_exit = Block(0x1030, 1)
    first_predecessor = Block(0x1050, 1)
    second_predecessor = Block(0x1060, 1)
    target = Block(0x1070, 1)

    first_condition = _condition(arch, manager, "rax")
    second_condition = _condition(arch, manager, "rbx")
    fork_condition = _condition(arch, manager, "rcx")
    head = _conditional_block(arch, manager, 0x1000, first_condition, first_exit.addr, 0x1020)
    second_branch = _conditional_block(arch, manager, 0x1020, second_condition, second_exit.addr, 0x1040)
    fork = _conditional_block(arch, manager, 0x1040, fork_condition, first_predecessor.addr, second_predecessor.addr)

    graph = networkx.DiGraph(
        [
            (head, first_exit),
            (head, second_branch),
            (second_branch, second_exit),
            (second_branch, fork),
            (fork, first_predecessor),
            (fork, second_predecessor),
            (first_predecessor, target),
            (second_predecessor, target),
        ]
    )

    condition_processor.recover_reaching_conditions(None, graph=graph)
    guarding_condition = condition_processor.guarding_conditions[target]
    first_divergence = condition_processor.recover_edge_condition(graph, head, first_exit)
    second_divergence = condition_processor.recover_edge_condition(graph, second_branch, second_exit)

    solver = claripy.Solver()
    for first_diverges, second_diverges, target_is_guarded in (
        (False, False, True),
        (False, True, False),
        (True, False, False),
        (True, True, False),
    ):
        path_constraints = (
            first_divergence if first_diverges else claripy.Not(first_divergence),
            second_divergence if second_diverges else claripy.Not(second_divergence),
        )
        assert solver.satisfiable(extra_constraints=path_constraints)
        contradicting_guard = claripy.Not(guarding_condition) if target_is_guarded else guarding_condition
        assert not solver.satisfiable(extra_constraints=(*path_constraints, contradicting_guard))


def test_guarding_condition_includes_divergence_path_context():
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    left_exit = Block(0x1030, 1)
    right_exit = Block(0x1060, 1)
    left_predecessor = Block(0x1070, 1)
    right_predecessor = Block(0x1080, 1)
    target = Block(0x1090, 1)

    head = _conditional_block(arch, manager, 0x1000, _condition(arch, manager, "rax"), 0x1010, 0x1040)
    left_branch = _conditional_block(
        arch, manager, 0x1010, _condition(arch, manager, "rbx"), left_exit.addr, left_predecessor.addr
    )
    right_branch = _conditional_block(
        arch, manager, 0x1040, _condition(arch, manager, "rcx"), right_exit.addr, right_predecessor.addr
    )

    graph = networkx.DiGraph(
        [
            (head, left_branch),
            (head, right_branch),
            (left_branch, left_exit),
            (left_branch, left_predecessor),
            (right_branch, right_exit),
            (right_branch, right_predecessor),
            (left_predecessor, target),
            (right_predecessor, target),
        ]
    )

    condition_processor.recover_reaching_conditions(None, graph=graph)
    guarding_condition = condition_processor.guarding_conditions[target]
    take_left = condition_processor.recover_edge_condition(graph, head, left_branch)
    left_divergence = condition_processor.recover_edge_condition(graph, left_branch, left_exit)
    right_divergence = condition_processor.recover_edge_condition(graph, right_branch, right_exit)

    solver = claripy.Solver()
    for takes_left in (False, True):
        for left_diverges in (False, True):
            for right_diverges in (False, True):
                path_constraints = (
                    take_left if takes_left else claripy.Not(take_left),
                    left_divergence if left_diverges else claripy.Not(left_divergence),
                    right_divergence if right_diverges else claripy.Not(right_divergence),
                )
                target_is_guarded = (takes_left and not left_diverges) or (not takes_left and not right_diverges)
                contradicting_guard = claripy.Not(guarding_condition) if target_is_guarded else guarding_condition
                assert solver.satisfiable(extra_constraints=path_constraints)
                assert not solver.satisfiable(extra_constraints=(*path_constraints, contradicting_guard))


def test_guarding_condition_respects_disabled_simplification(monkeypatch):
    arch = archinfo.ArchAMD64()
    manager = ailment.Manager(arch=arch)
    condition_processor = ConditionProcessor(arch, manager)

    exit_node = Block(0x1010, 1)
    first_predecessor = Block(0x1030, 1)
    second_predecessor = Block(0x1040, 1)
    target = Block(0x1050, 1)
    head = _conditional_block(arch, manager, 0x1000, _condition(arch, manager, "rax"), exit_node.addr, 0x1020)
    fork = _conditional_block(
        arch, manager, 0x1020, _condition(arch, manager, "rbx"), first_predecessor.addr, second_predecessor.addr
    )
    graph = networkx.DiGraph(
        [
            (head, exit_node),
            (head, fork),
            (fork, first_predecessor),
            (fork, second_predecessor),
            (first_predecessor, target),
            (second_predecessor, target),
        ]
    )

    def fail_on_simplification(_):
        raise AssertionError("condition simplification must remain disabled")

    monkeypatch.setattr(condition_processor, "simplify_condition", fail_on_simplification)
    condition_processor.recover_reaching_conditions(None, graph=graph, simplify_conditions=False)
    assert target in condition_processor.guarding_conditions
