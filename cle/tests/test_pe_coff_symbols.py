from __future__ import annotations

import os

import cle
from cle.backends.symbol import SymbolType

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def load(*parts):
    return cle.Loader(os.path.join(TEST_BASE, "tests", *parts), auto_load_libs=False).main_object


def symbol(obj, name):
    found = obj.get_symbol(name)
    assert found is not None, f"{name} is not among the symbols cle loaded"
    return found


def exports(obj):
    return {each.name: each for each in obj.symbols if each.is_export}


def test_coff_symbols_carry_the_type_the_table_declares():
    # A MinGW image: 1341 symbol records, the names too long for the eight-byte field in a
    # string table behind them, and auxiliary records in between.
    obj = load("x86_64", "cfg_0_pe")

    assert symbol(obj, "main").type is SymbolType.TYPE_FUNCTION
    assert symbol(obj, "func").type is SymbolType.TYPE_FUNCTION
    assert symbol(obj, "startinfo").type is SymbolType.TYPE_OBJECT
    # A local definition: loaded like the rest, but it cannot describe an export.
    assert symbol(obj, "managedapp").type is SymbolType.TYPE_OBJECT
    # Only the string table can produce this one.
    assert symbol(obj, "__fu0__set_invalid_parameter_handler").type is SymbolType.TYPE_OBJECT


def test_a_symbol_table_outside_the_file_loads_no_symbols():
    # The packed copy keeps the unpacked one's symbol-table pointer and count -- 0x12e00 and
    # 1292 records, as tests/x86/windows/not_packed_pe32.exe has -- in a file 0xbe00 bytes
    # shorter, so the table it describes ends past the end of the file.
    obj = load("x86", "windows", "packed_pe32.exe")

    assert obj.symbols
    assert all(symbol.is_import for symbol in obj.symbols)


def test_exports_take_the_type_of_their_coff_definition():
    obj = load("x86_64", "windows", "coff_export_types.dll")

    assert exports(obj)["exported_counter"].type is SymbolType.TYPE_OBJECT
    assert exports(obj)["exported_function"].type is SymbolType.TYPE_FUNCTION


def test_a_forwarded_export_is_a_function_and_names_its_library():
    obj = load("x86_64", "windows", "coff_export_types.dll")

    forwarded = exports(obj)["forwarded_function"]
    assert forwarded.forwarder == "user32.MessageBoxA"
    assert forwarded.type is SymbolType.TYPE_FUNCTION
    # The import directory names only kernel32 and msvcrt, so the forwarder is the only
    # thing that puts user32 among the dependencies.
    assert "user32.dll" in obj.deps


def test_exports_are_functions_when_no_symbol_table_types_them():
    obj = load("x86_64", "windows", "msvcr120.dll")

class _SymbolList(list):
    """Minimal symbol container used by the fixture-free PE tests."""

    def add(self, symbol) -> None:
        self.append(symbol)


def _make_pe(raw_data: bytes = b"", exports=()) -> Any:
    pe: Any = object.__new__(PE)
    pe._arch = archinfo.ArchAMD64()
    pe._raw_data = raw_data
    pe._pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(PointerToSymbolTable=0, NumberOfSymbols=len(raw_data) // 18),
        sections=[SimpleNamespace(VirtualAddress=0x1000)],
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(symbols=exports),
    )
    pe.symbols = _SymbolList()
    pe._exports = {}
    pe._ordinal_exports = {}
    pe.deps = []
    return pe


def _coff_symbol(name: bytes, value: int, section: int, type_: int, storage_class: int) -> bytes:
    return struct.pack("<8sIhHBB", name, value, section, type_, storage_class, 0)


def test_coff_symbol_type_hints_only_include_external_definitions():
    raw_data = b"".join(
        [
            _coff_symbol(b"function", 0x10, 1, 0x20, IMAGE_SYM_CLASS.EXTERNAL),
            _coff_symbol(b"object", 0x20, 1, 0, IMAGE_SYM_CLASS.EXTERNAL),
            _coff_symbol(b"static", 0x30, 1, 0, IMAGE_SYM_CLASS.STATIC),
            _coff_symbol(b"undefined", 0, 0, 0x20, IMAGE_SYM_CLASS.EXTERNAL),
            _coff_symbol(b"other", 0x40, 1, 0x10, IMAGE_SYM_CLASS.EXTERNAL),
        ]
    )
    pe = _make_pe(raw_data + b"\0\0\0\0")

    symbol_types = pe._load_symbols_from_coff_header()

    assert symbol_types == {
        0x1010: {SymbolType.TYPE_FUNCTION},
        0x1020: {SymbolType.TYPE_OBJECT},
    }
    assert {symbol.name for symbol in pe.symbols} == {"function", "object", "static"}


def test_coff_symbols_are_dropped_when_a_section_number_is_out_of_range():
    raw_data = b"".join(
        [
            _coff_symbol(b"early", 0x10, 1, 0x20, IMAGE_SYM_CLASS.EXTERNAL),
            _coff_symbol(b"stale", 0x20, 2, 0x20, IMAGE_SYM_CLASS.EXTERNAL),
            _coff_symbol(b"late", 0x30, 1, 0x20, IMAGE_SYM_CLASS.EXTERNAL),
        ]
    )
    pe = _make_pe(raw_data + b"\0\0\0\0")

    assert not pe._load_symbols_from_coff_header()
    assert not list(pe.symbols)


def test_exports_inherit_only_unambiguous_coff_symbol_types():
    exports = [
        SimpleNamespace(name=b"data", address=0x1010, forwarder=None, ordinal=1),
        SimpleNamespace(name=b"ambiguous", address=0x1020, forwarder=None, ordinal=2),
        SimpleNamespace(name=b"missing", address=0x1030, forwarder=None, ordinal=3),
        SimpleNamespace(name=b"forwarded", address=0x1040, forwarder=b"other.target", ordinal=4),
    ]
    pe = _make_pe(exports=exports)

    pe._handle_exports(
        {
            0x1010: {SymbolType.TYPE_OBJECT},
            0x1020: {SymbolType.TYPE_FUNCTION, SymbolType.TYPE_OBJECT},
            0x1040: {SymbolType.TYPE_OBJECT},
        }
    )

    assert pe._exports["data"].type is SymbolType.TYPE_OBJECT
    assert pe._exports["ambiguous"].type is SymbolType.TYPE_FUNCTION
    assert pe._exports["missing"].type is SymbolType.TYPE_FUNCTION
    assert pe._exports["forwarded"].type is SymbolType.TYPE_FUNCTION
    assert pe.deps == ["other.dll"]
    assert {symbol.type for symbol in exports(obj).values()} == {SymbolType.TYPE_FUNCTION}
