from __future__ import annotations

import os
import pickle
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from elftools.common.exceptions import DWARFError
from elftools.elf.elffile import ELFFile

import cle
from cle.backends.elf.relocation.ppc64 import R_PPC64_JMP_SLOT
from cle.backends.externs import ExternObject
from cle.backends.symbol import SymbolType

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


class _TestCompilationUnit:
    """Minimal compilation-unit identity used by type-reference tests."""

    def __init__(self, dwarfinfo, cu_offset=0):
        self.dwarfinfo = dwarfinfo
        self.cu_offset = cu_offset


class _TestTypeUnit:
    """Minimal type-unit identity used by type-reference tests."""

    def __init__(self, dwarfinfo, tu_offset=0):
        self.dwarfinfo = dwarfinfo
        self.tu_offset = tu_offset


def _test_die(
    tag,
    offset,
    *,
    byte_size=None,
    referenced=None,
    dwarfinfo=None,
    unit_type: type[_TestCompilationUnit] | type[_TestTypeUnit] = _TestCompilationUnit,
):
    die = Mock()
    die.tag = tag
    die.offset = offset
    die.cu = unit_type(dwarfinfo if dwarfinfo is not None else object())
    die.attributes = {}
    if byte_size is not None:
        die.attributes["DW_AT_byte_size"] = SimpleNamespace(value=byte_size)
    if referenced is not None:
        die.attributes["DW_AT_type"] = SimpleNamespace()
        if isinstance(referenced, Exception):
            die.get_DIE_from_attribute.side_effect = referenced
        else:
            die.get_DIE_from_attribute.return_value = referenced
    return die


def _test_declaration(name, type_die, *, external=False, linkage=False):
    die = _test_die("DW_TAG_variable", 0, referenced=type_die)
    die.attributes["DW_AT_declaration"] = SimpleNamespace(value=True)
    die.attributes["DW_AT_linkage_name" if linkage else "DW_AT_name"] = SimpleNamespace(value=name.encode())
    if external:
        die.attributes["DW_AT_external"] = SimpleNamespace(value=True)
    return die


def test_f_finale_extern_size_hints():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "f_finale.o")
    ld = cle.Loader(path, auto_load_libs=False)
    obj = ld.main_object

    assert obj.is_relocatable  # type: ignore[attr-defined]
    assert hasattr(obj, "extern_size_hints")

    # mobjinfo: max addend is 52
    # min_size = 52 + 8 = 60
    assert obj.extern_size_hints["mobjinfo"] == 60  # type: ignore[attr-defined]

    mobjinfo = None
    for sym in ld.symbols:
        if sym.is_extern and sym.name == "mobjinfo":
            mobjinfo = sym
            break

    assert mobjinfo is not None
    assert mobjinfo.size == 60

    # Find the next symbol after mobjinfo
    next_sym = None
    for sym in ld.symbols:
        if sym.is_extern and sym.rebased_addr > mobjinfo.rebased_addr:
            if next_sym is None or sym.rebased_addr < next_sym.rebased_addr:
                next_sym = sym

    # Verify no overlap: mobjinfo end <= next symbol start
    assert next_sym is not None
    assert mobjinfo.rebased_addr + mobjinfo.size <= next_sym.rebased_addr


def test_ppc64_abiv1_untyped_function_import():
    """An imported function left STT_NOTYPE still needs an ELFv1 function descriptor.

    A jump slot on PowerPC64 ELFv1 holds a whole descriptor rather than an address, so an
    unresolved import needs one however the symbol table typed it. Deciding that from the
    declared type gives an untyped import a pointer-sized slot instead, and the descriptor copy
    then reads past it.
    """
    pristine = os.path.join(TESTS_BASE, "tests", "ppc64", "fauxware")
    untyped = os.path.join(TESTS_BASE, "tests", "ppc64", "fauxware_notype_import")

    def jump_slots(path):
        """The object, and each of its jump slots paired with the symbol it names."""
        obj = cle.Loader(path, auto_load_libs=False).main_object
        slots = []
        for reloc in obj.relocs:
            symbol = reloc.symbol
            if isinstance(reloc, R_PPC64_JMP_SLOT) and symbol is not None:
                slots.append((symbol, reloc))
        return obj, slots

    def descriptors(path):
        obj, slots = jump_slots(path)
        return {
            symbol.name: tuple(obj.memory.unpack_word(reloc.relative_addr + offset) for offset in (0, 8, 16))
            for symbol, reloc in slots
        }

    # the derived fixture has to still carry the shape, or this test proves nothing
    _, slots = jump_slots(untyped)
    assert {s.name for s, _ in slots if s.type is not SymbolType.TYPE_FUNCTION} == {"puts", "exit"}

    expected = descriptors(pristine)
    assert expected, "the pristine fixture has no jump slots to compare"
    assert descriptors(untyped) == expected
def test_dwarf_extern_size_hints():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
    expected_sizes = {
        "Version": 8,
        "argmatch_die": 8,
        "exit_failure": 4,
        "program_name": 8,
    }

    ld = cle.Loader(path, auto_load_libs=False)
    obj = ld.main_object
    extern_sizes = {symbol.name: symbol.size for symbol in ld.symbols if symbol.is_extern}
    for name in expected_sizes:
        assert name not in obj.extern_size_hints  # type: ignore[attr-defined]
        assert extern_sizes[name] == 0

    ld = cle.Loader(path, auto_load_libs=False, load_debug_info=True)
    obj = ld.main_object
    extern_sizes = {symbol.name: symbol.size for symbol in ld.symbols if symbol.is_extern}
    for name, size in expected_sizes.items():
        assert obj.extern_size_hints[name] == size  # type: ignore[attr-defined]
        assert extern_sizes[name] == size

    assert extern_sizes["__assert_fail"] == 0

    allocated_symbols = sorted(ld.extern_object.symbols, key=lambda symbol: symbol.relative_addr)
    for symbol, next_symbol in zip(allocated_symbols, allocated_symbols[1:]):
        allocated_size = (
            8
            if symbol.size == 0
            and symbol.type in (SymbolType.TYPE_NONE, SymbolType.TYPE_OBJECT, SymbolType.TYPE_TLS_OBJECT)
            else max(symbol.size, 1)
        )
        assert symbol.relative_addr + allocated_size <= next_symbol.relative_addr

    final_symbol = allocated_symbols[-1]
    final_size = (
        8
        if final_symbol.size == 0
        and final_symbol.type in (SymbolType.TYPE_NONE, SymbolType.TYPE_OBJECT, SymbolType.TYPE_TLS_OBJECT)
        else max(final_symbol.size, 1)
    )
    assert final_symbol.relative_addr + final_size <= ld.extern_object.map_size


def test_dwarf_extern_size_hints_are_conservative():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
    obj = cle.Loader(path, auto_load_libs=False).main_object
    max_size = ExternObject.default_map_size(obj.arch)

    dwarfinfo = object()
    base_type = _test_die("DW_TAG_base_type", 1, byte_size=8, dwarfinfo=object())
    type_unit_alias = _test_die("DW_TAG_typedef", 1, referenced=base_type, dwarfinfo=dwarfinfo, unit_type=_TestTypeUnit)
    compilation_unit_alias = _test_die("DW_TAG_const_type", 1, referenced=type_unit_alias, dwarfinfo=dwarfinfo)
    assert obj._dwarf_type_size(compilation_unit_alias, max_size) == 8  # type: ignore[attr-defined]

    unsupported_array = _test_die("DW_TAG_array_type", 2, referenced=base_type)
    implicit_pointer = _test_die("DW_TAG_pointer_type", 3, referenced=base_type)
    malformed_qualifier = _test_die("DW_TAG_volatile_type", 5, referenced=DWARFError("bad reference"))
    assert obj._dwarf_type_size(unsupported_array, max_size) is None  # type: ignore[attr-defined]
    assert obj._dwarf_type_size(implicit_pointer, max_size) is None  # type: ignore[attr-defined]
    assert obj._dwarf_type_size(malformed_qualifier, max_size) is None  # type: ignore[attr-defined]

    for offset, size in enumerate((True, False, -1, 0, max_size + 1), start=10):
        invalid_type = _test_die("DW_TAG_base_type", offset, byte_size=size)
        assert obj._dwarf_type_size(invalid_type, max_size) is None  # type: ignore[attr-defined]
    capped_type = _test_die("DW_TAG_base_type", 20, byte_size=max_size)
    assert obj._dwarf_type_size(capped_type, max_size) == max_size  # type: ignore[attr-defined]

    first = _test_die("DW_TAG_const_type", 6, dwarfinfo=dwarfinfo)
    second = _test_die("DW_TAG_typedef", 7, referenced=first, dwarfinfo=dwarfinfo)
    first.attributes["DW_AT_type"] = SimpleNamespace()
    first.get_DIE_from_attribute.return_value = second
    assert obj._dwarf_type_size(first, max_size) is None  # type: ignore[attr-defined]


def test_dwarf_extern_size_hint_declaration_identity():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
    obj = cle.Loader(path, auto_load_libs=False).main_object
    pointer_type = _test_die("DW_TAG_pointer_type", 1, byte_size=obj.arch.bytes)

    obj._load_dwarf_extern_size_hint(_test_declaration("Version", pointer_type))  # type: ignore[attr-defined]
    assert "Version" not in obj.extern_size_hints  # type: ignore[attr-defined]

    obj._load_dwarf_extern_size_hint(  # type: ignore[attr-defined]
        _test_declaration("Version", pointer_type, external=True)
    )
    assert obj.extern_size_hints.pop("Version") == obj.arch.bytes  # type: ignore[attr-defined]

    obj._load_dwarf_extern_size_hint(  # type: ignore[attr-defined]
        _test_declaration("Version", pointer_type, linkage=True)
    )
    assert obj.extern_size_hints["Version"] == obj.arch.bytes  # type: ignore[attr-defined]


def test_dwarf_extern_size_hint_only_scan():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
    obj = cle.Loader(path, auto_load_libs=False).main_object

    with open(path, "rb") as binary:
        obj._load_dwarf_extern_size_hints(ELFFile(binary).get_dwarf_info())  # type: ignore[attr-defined]

    assert obj.extern_size_hints["Version"] == 8  # type: ignore[attr-defined]
    assert obj.extern_size_hints["argmatch_die"] == 8  # type: ignore[attr-defined]
    assert obj.extern_size_hints["exit_failure"] == 4  # type: ignore[attr-defined]
    assert obj.extern_size_hints["program_name"] == 8  # type: ignore[attr-defined]


def test_dwarf_extern_size_hint_scan_contains_known_cu_errors():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
    obj = cle.Loader(path, auto_load_libs=False).main_object
    pointer_type = _test_die("DW_TAG_pointer_type", 1, byte_size=obj.arch.bytes)

    for error in (DWARFError("bad DIE"), KeyError("bad reference"), NotImplementedError("imported unit")):
        obj.extern_size_hints.pop("Version", None)  # type: ignore[attr-defined]
        bad_cu = Mock()
        bad_cu.iter_DIEs.side_effect = error
        good_cu = Mock()
        good_cu.iter_DIEs.return_value = [_test_declaration("Version", pointer_type, external=True)]
        dwarf = Mock()
        dwarf.iter_CUs.return_value = [bad_cu, good_cu]

        obj._load_dwarf_extern_size_hints(dwarf)  # type: ignore[attr-defined]
        assert obj.extern_size_hints["Version"] == obj.arch.bytes  # type: ignore[attr-defined]

    unexpected_cu = Mock()
    unexpected_cu.iter_DIEs.side_effect = RuntimeError("unexpected failure")
    dwarf = Mock()
    dwarf.iter_CUs.return_value = [unexpected_cu]
    with unittest.TestCase().assertRaisesRegex(RuntimeError, "unexpected failure"):
        obj._load_dwarf_extern_size_hints(dwarf)  # type: ignore[attr-defined]


def test_embedded_dwarf_scan_contains_known_cu_errors():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
    obj = cle.Loader(path, auto_load_libs=False).main_object
    pointer_type = _test_die("DW_TAG_pointer_type", 1, byte_size=obj.arch.bytes)

    with open(path, "rb") as binary:
        dwarf = ELFFile(binary).get_dwarf_info()
        structs = next(dwarf.iter_CUs()).structs

    for error in (DWARFError("bad DIE"), KeyError("bad reference"), NotImplementedError("imported unit")):
        obj.extern_size_hints.pop("Version", None)  # type: ignore[attr-defined]
        bad_cu = Mock(structs=structs)
        bad_cu.iter_DIEs.side_effect = error
        good_cu = Mock(structs=structs)
        good_cu.iter_DIEs.return_value = [_test_declaration("Version", pointer_type, external=True)]
        good_cu.get_top_DIE.return_value = SimpleNamespace(tag="DW_TAG_partial_unit")
        dwarf = Mock()
        dwarf.range_lists.return_value = None
        dwarf.iter_CUs.return_value = [bad_cu, good_cu]

        obj._load_dies(dwarf)  # type: ignore[attr-defined]
        assert obj.extern_size_hints["Version"] == obj.arch.bytes  # type: ignore[attr-defined]

    unexpected_cu = Mock(structs=structs)
    unexpected_cu.iter_DIEs.side_effect = RuntimeError("unexpected failure")
    dwarf = Mock()
    dwarf.range_lists.return_value = None
    dwarf.iter_CUs.return_value = [unexpected_cu]
    with unittest.TestCase().assertRaisesRegex(RuntimeError, "unexpected failure"):
        obj._load_dies(dwarf)  # type: ignore[attr-defined]


def test_explicit_debug_symbols_load_extern_size_hints():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
    ld = cle.Loader(path, auto_load_libs=False, main_opts={"debug_symbols": path})

    expected_sizes = {
        "Version": 8,
        "argmatch_die": 8,
        "exit_failure": 4,
        "program_name": 8,
    }
    extern_sizes = {symbol.name: symbol.size for symbol in ld.symbols if symbol.is_extern}
    for name, size in expected_sizes.items():
        assert ld.main_object.extern_size_hints[name] == size  # type: ignore[attr-defined]
        assert extern_sizes[name] == size
class TestSimDataExternTypes(unittest.TestCase):
    """Test that untyped extern requests use definitive SimData types."""

    def test_untyped_imports_adopt_simdata_type(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")

        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            ld = cle.Loader(path, auto_load_libs=False)

        for name in ("stdin", "stdout", "stderr", "optind", "optarg"):
            import_symbol = ld.main_object.get_symbol(name)
            self.assertIsNotNone(import_symbol)
            assert import_symbol is not None
            extern_symbol = import_symbol.resolvedby
            self.assertIsNotNone(extern_symbol)
            assert extern_symbol is not None
            self.assertIs(extern_symbol.type, SymbolType.TYPE_OBJECT)
            self.assertIs(extern_symbol._type, SymbolType.TYPE_OBJECT)

    def test_untyped_tls_simdata_uses_tls_storage(self):
        path = os.path.join(
            TESTS_BASE,
            "tests_src",
            "i2c_master_read-nucleol152re",
            "mbed",
            "TARGET_NUCLEO_L152RE",
            "TOOLCHAIN_GCC_ARM",
            "mbed_retarget.o",
        )
        ld = cle.Loader(path, auto_load_libs=False)

        import_symbol = ld.main_object.get_symbol("errno")
        self.assertIsNotNone(import_symbol)
        assert import_symbol is not None
        self.assertIs(import_symbol.type, SymbolType.TYPE_NONE)

        errno = import_symbol.resolvedby
        self.assertIsNotNone(errno)
        assert errno is not None
        self.assertIsInstance(errno.owner, ExternObject)
        owner = errno.owner
        assert isinstance(owner, ExternObject)

        self.assertIs(errno.type, SymbolType.TYPE_TLS_OBJECT)
        self.assertIs(errno._type, SymbolType.TYPE_TLS_OBJECT)
        self.assertEqual(errno.relative_addr, 0)
        self.assertEqual(owner.tls_next_addr, errno.size)
        self.assertEqual(owner.tls_data_size, errno.size)
        self.assertEqual(owner.tls_block_size, errno.size)
        self.assertTrue(owner.tls_used)
        self.assertIn(owner, ld.tls.modules)
        self.assertIsNotNone(owner.tls_module_id)
        self.assertIsNotNone(getattr(owner, "tls_block_offset", None))

    def test_definite_simdata_type_conflict_still_warns(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "fauxware")
        ld = cle.Loader(path, auto_load_libs=False)
        root = ld.extern_object

        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            progname = root.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)

        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 1)
        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            repeated = root.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)

        self.assertIs(repeated, progname)
        self.assertIs(progname.type, SymbolType.TYPE_OBJECT)
        # SimData.type describes the implementation, while _type retains the caller's definite request.
        self.assertIs(progname._type, SymbolType.TYPE_FUNCTION)
        self.assertIsInstance(progname.owner, ExternObject)
        owner = progname.owner
        assert isinstance(owner, ExternObject)
        self.assertIsNot(owner, root)
        self.assertEqual(owner.tls_next_addr, 0)
        assert owner.tls_data_start is not None
        self.assertGreaterEqual(progname.relative_addr, owner.tls_data_start + owner.tls_data_size)
        self.assertLessEqual(progname.relative_addr + progname.size, owner.next_addr)

    def test_cached_simdata_validates_later_definite_conflict(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "fauxware")
        ld = cle.Loader(path, auto_load_libs=False)

        progname = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_NONE)
        self.assertIsInstance(progname.owner, ExternObject)
        owner = progname.owner
        assert isinstance(owner, ExternObject)
        layout = (
            progname.relative_addr,
            progname.size,
            owner.next_addr,
            owner.tls_next_addr,
            len(owner.symbols),
            len(ld.all_objects),
        )

        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            conflicting = owner.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)
        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 1)
        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            repeated = owner.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)
            repeated_from_root = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)

        self.assertIs(conflicting, progname)
        self.assertIs(repeated, progname)
        self.assertIs(repeated_from_root, progname)
        self.assertIs(progname.type, SymbolType.TYPE_OBJECT)
        self.assertIs(progname._type, SymbolType.TYPE_OBJECT)
        self.assertEqual(
            (
                progname.relative_addr,
                progname.size,
                owner.next_addr,
                owner.tls_next_addr,
                len(owner.symbols),
                len(ld.all_objects),
            ),
            layout,
        )

    def test_dynamic_load_simdata_conflicts_are_per_symbol(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
        ld = cle.Loader(path, auto_load_libs=False)

        old_import = ld.main_object.get_symbol("stdout")
        self.assertIsNotNone(old_import)
        assert old_import is not None
        old_stdout = old_import.resolvedby
        self.assertIsNotNone(old_stdout)
        assert old_stdout is not None
        old_progname = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_NONE)

        with open(path, "rb") as binary:
            loaded = ld.dynamic_load(binary)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        loaded_elf = next(obj for obj in loaded if isinstance(obj, cle.ELF))
        new_import = loaded_elf.get_symbol("stdout")
        self.assertIsNotNone(new_import)
        assert new_import is not None
        new_stdout = new_import.resolvedby
        self.assertIsNotNone(new_stdout)
        assert new_stdout is not None
        self.assertIsNot(new_stdout, old_stdout)
        self.assertIsInstance(old_stdout.owner, ExternObject)
        old_owner = old_stdout.owner
        assert isinstance(old_owner, ExternObject)
        self.assertIsInstance(new_stdout.owner, ExternObject)
        new_owner = new_stdout.owner
        assert isinstance(new_owner, ExternObject)

        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            found_progname = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)
        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 1)
        self.assertIs(found_progname, old_progname)

        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            old_owner.make_extern("stdout", sym_type=SymbolType.TYPE_FUNCTION)
            new_owner.make_extern("stdout", sym_type=SymbolType.TYPE_FUNCTION)
        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 2)
        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            old_owner.make_extern("stdout", sym_type=SymbolType.TYPE_FUNCTION)
            new_owner.make_extern("stdout", sym_type=SymbolType.TYPE_FUNCTION)

    def test_cached_simdata_conflict_survives_legacy_pickle(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "fauxware")
        ld = cle.Loader(path, auto_load_libs=False)
        progname = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_NONE)
        self.assertFalse(hasattr(progname, "_warned_symbol_type_mismatches"))

        restored = pickle.loads(pickle.dumps(ld))
        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            cached = restored.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)
        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 1)
        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            repeated = restored.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)

        self.assertIs(repeated, cached)
        self.assertIs(cached.type, SymbolType.TYPE_OBJECT)
        self.assertIs(cached._type, SymbolType.TYPE_OBJECT)


if __name__ == "__main__":
    unittest.main()
