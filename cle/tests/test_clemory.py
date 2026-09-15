from __future__ import annotations

import os
import sys
import timeit
import unittest

import archinfo
import cffi
import pytest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


@unittest.skipIf(sys.platform == "emscripten", "runtime CFFI compilation is unavailable in Pyodide")
def test_cclemory():  # pylint: disable=no-member
    # This is a test case for C-backed Clemory.

    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, b"\x90" * 1000)
    clemory.add_backer(2000, b"A" * 1000)
    clemory.add_backer(3000, b"ABCDEFGH")

    ffi = cffi.FFI()
    ffi.cdef("""
        int memcmp(const void* s1, const void* s2, size_t n);
    """)
    c = ffi.verify("""
        #include <string.h>
    """)
    bytes_c = [ffi.from_buffer(backer) for _, backer in clemory.backers()]
    assert len(bytes_c) == 3
    out = c.memcmp(ffi.new("unsigned char []", b"\x90" * 10), bytes_c[0], 10)
    assert out == 0

    out = c.memcmp(ffi.new("unsigned char []", b"B" * 1000), bytes_c[1], 1000)
    assert out != 0
    out = c.memcmp(ffi.new("unsigned char []", b"A" * 1000), bytes_c[1], 1000)
    assert out == 0

    out = c.memcmp(ffi.new("unsigned char []", b"ABCDEFGH"), bytes_c[2], 8)
    assert out == 0


def test_clemory():
    # directly write bytes to backers
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, b"A" * 20)
    clemory.add_backer(20, b"A" * 20)
    clemory.add_backer(50, b"A" * 20)
    assert len(clemory._backers) == 3

    clemory.store(10, b"B" * 30)

    assert len(clemory._backers) == 3
    assert clemory.load(0, 40) == b"A" * 10 + b"B" * 30

    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(10, b"A" * 20)
    clemory.add_backer(50, b"A" * 20)
    assert len(clemory._backers) == 2
    try:
        clemory.store(0, b"")
    except KeyError:
        assert True
    else:
        assert False
    assert len(clemory._backers) == 2
    try:
        clemory.load(0, 25)
    except KeyError:
        assert True
    else:
        assert False
    clemory.seek(0)
    assert clemory.read(25) == b""
    assert clemory.load(10, 25) == b"A" * 20


def test_clemory_iter_yields_addresses():
    arch = archinfo.ArchAMD64()

    # add_backer stores a bytes backer as a bytearray, so the first case covers both
    for backer in (bytes((0x00, 0x01, 0x41, 0xFF)), [0x00, 0x01, 0x41, 0xFF]):
        clemory = cle.Clemory(arch, root=True)
        clemory.add_backer(0x100, backer)
        assert list(clemory) == [0x100, 0x101, 0x102, 0x103]

    inner = cle.Clemory(arch)
    inner.add_backer(0x10, bytes((0x00, 0x01, 0x41, 0xFF)))
    outer = cle.Clemory(arch, root=True)
    outer.add_backer(0x1000, inner)
    assert list(outer) == [0x1010, 0x1011, 0x1012, 0x1013]


def test_clemory_iter_loaded_binary():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    expected = set()
    for start, backer in loader.memory.backers():
        expected.update(range(start, start + len(backer)))

    addresses = list(loader.memory)
    assert set(addresses) == expected
    assert len(addresses) == len(expected)


def test_clemory_read_only_view_contains():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    loader.gen_ro_memview()
    view = loader.memory_ro_view
    assert view is not None

    entry = loader.main_object.entry
    assert entry in view
    assert entry - 0x10000 not in view

    # The view answers the same as the clemory it was flattened from, including in the gaps
    # between backers.
    for start, backer in loader.memory.backers():
        for addr in (start - 1, start, start + len(backer) - 1, start + len(backer)):
            assert (addr in view) == (addr in loader.memory)


def test_clemory_view_backers_are_clamped_to_the_window():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    memory = loader.memory

    # A window clamped at its high end only.
    view = cle.ClemoryView(memory, 0x400000, 0x400100)
    assert [(start, len(backer)) for start, backer in view.backers()] == [(0, 0x100)]
    assert b"".join(bytes(backer) for _, backer in view.backers()) == memory.load(0x400000, 0x100)

    # A window clamped at both ends, given an offset of its own, so both clamps and the
    # translation back into the view's address space are exercised together.
    view = cle.ClemoryView(memory, 0x400010, 0x400100, offset=0x1000)
    assert [(start, len(backer)) for start, backer in view.backers()] == [(0x1000, 0xF0)]
    assert b"".join(bytes(backer) for _, backer in view.backers()) == memory.load(0x400010, 0xF0)


def test_clemory_find_bounds():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    memory = loader.memory

    # A match that ends on the last byte of the searched range is still a match. The default
    # search_max is max_addr, so this is the last eight bytes of the loaded image.
    end = memory.max_addr
    tail = memory.load(end - 8, 8)
    assert (end - 8) in set(memory.find(tail))

    needle = b"SOSNEAKY"
    (addr,) = memory.find(needle)

    # search_max is exclusive: a range ending where the match ends still reports it.
    assert list(memory.find(needle, search_max=addr + len(needle))) == [addr]
    assert list(memory.find(needle, search_max=addr + len(needle) - 1)) == []

    # search_min bounds where a match may start. A backer is out of range once search_min is
    # past the end of the backer, not past its start plus the length of the needle.
    assert list(memory.find(needle, search_min=addr)) == [addr]
    assert list(memory.find(needle, search_min=addr + 1)) == []


def test_clemory_find_stays_inside_its_backers():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    memory = loader.memory

    # The empty bytestring is the only needle a buffer reports at the offset one past its own
    # end, and that offset is not an address in memory. fauxware leaves a gap after each of its
    # first two backers, so master reports two addresses here that it does not contain.
    assert [addr for addr in memory.find(b"") if addr not in memory] == []


def test_clemory_find_stays_inside_the_range_it_was_given():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    memory = loader.memory
    entry = loader.main_object.entry

    # A zero-length match has no bytes to run past search_max, so only a bound on where a match
    # may start keeps the empty bytestring out of the searched range's own end.
    assert list(memory.find(b"", search_min=entry, search_max=entry + 4)) == [
        entry,
        entry + 1,
        entry + 2,
        entry + 3,
    ]


def performance_clemory_contains():
    # With the consecutive optimization:
    #   5.72 sec
    # Without the consecutive optimization:
    #   13.11 sec
    t = timeit.timeit(
        "0x400002 in clemory",
        setup="import cle; clemory = cle.Clemory(None, root=True); clemory.add_backer(0x400000, 'A' * 200000)",
        number=20000000,
    )
    print(t)


def test_split_backer_refuses_to_split_through_a_nested_clemory():
    child = cle.Clemory(None)  # type: ignore[arg-type]
    child.add_backer(0, b"A" * 0x200)
    child.add_backer(0x200, b"B" * 0x200)

    clemory = cle.Clemory(None, root=True)  # type: ignore[arg-type]
    clemory.add_backer(0, b"C" * 0x400)
    clemory.add_backer(0x400, child)

    before = [(start, bytes(backer)) for start, backer in clemory.backers()]

    with pytest.raises(ValueError, match="itself a clemory"):
        clemory.split_backer(0x401)

    assert [(start, bytes(backer)) for start, backer in clemory.backers()] == before
    assert clemory.load(0x600, 0x10) == b"B" * 0x10


def test_split_backer_refuses_to_split_through_a_loaded_object():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests/x86_64/fauxware")
    ld = cle.Loader(filename, auto_load_libs=False)
    assert any(isinstance(backer, cle.Clemory) for _, backer in ld.memory._backers)

    addr = ld.main_object.entry
    before = [(start, bytes(backer)) for start, backer in ld.memory.backers()]

    with pytest.raises(ValueError, match="itself a clemory"):
        ld.memory.split_backer(addr + 1)

    assert [(start, bytes(backer)) for start, backer in ld.memory.backers()] == before


def test_clemory_contains():
    clemory = cle.Clemory(None, root=True)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 0
    assert clemory.consecutive is True

    # Add one backer
    clemory.add_backer(0, b"A" * 10)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 10
    assert clemory.consecutive is True

    # Add another backer
    clemory.add_backer(10, b"B" * 20)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 30
    assert clemory.consecutive is True

    # Add one more
    clemory.add_backer(40, b"A" * 30)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 70
    assert clemory.consecutive is False

    # Add another one to make it consecutive
    clemory.add_backer(30, b"C" * 10)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 70
    assert clemory.consecutive is True


def test_remove_backer():
    clemory = cle.Clemory(archinfo.ArchAMD64(), root=True)
    clemory.add_backer(0, b"A")
    clemory.add_backer(10, b"BB")
    clemory.add_backer(20, b"CCC")

    # The search used to bisect right, landing one past the backer being removed, so no removal ever found its target.
    clemory.remove_backer(0)
    assert [start for start, _ in clemory.backers()] == [10, 20]
    clemory.remove_backer(20)
    assert list(clemory.backers()) == [(10, bytearray(b"BB"))]
    assert clemory.min_addr == 10
    assert clemory.max_addr == 12

    # Only the address a backer starts at identifies it.
    with pytest.raises(ValueError):
        clemory.remove_backer(11)

    # Emptying a clemory leaves it in the state a freshly constructed one is in.
    clemory.remove_backer(10)
    assert not list(clemory.backers())
    assert clemory.min_addr == 0
    assert clemory.max_addr == 0
    assert clemory.consecutive is True
    assert 10 not in clemory


def test_split_backer():
    clemory = cle.Clemory(archinfo.ArchAMD64(), root=True)
    clemory.add_backer(0, b"ABCDEFGH")

    # Splitting removes the backer and re-adds the two halves, so it only works once removal does.
    clemory.split_backer(4)

    assert list(clemory.backers()) == [(0, bytearray(b"ABCD")), (4, bytearray(b"EFGH"))]
    assert clemory.load(0, 8) == b"ABCDEFGH"


def test_add_backer_overwrite():
    clemory = cle.Clemory(archinfo.ArchAMD64(), root=True)
    clemory.add_backer(0, b"ABCDEFGH")

    # Overwriting splits the backer around the new data and drops what the new data replaces, both of which need
    # removal to work.
    clemory.add_backer(2, b"xy", overwrite=True)

    assert clemory.load(0, 8) == b"ABxyEFGH"


def test_clemory_view_setitem():
    clemory = cle.Clemory(None, root=True)  # type: ignore[arg-type]
    clemory.add_backer(0x1000, b"AAAABBBB")
    view = cle.ClemoryView(clemory, 0x1000, 0x1008)

    view[0] = 0x5A
    assert view[0] == 0x5A
    assert clemory[0x1000] == 0x5A
    assert clemory.load(0x1000, 8) == b"ZAAABBBB"

    with pytest.raises(KeyError):
        view[8] = 0x5A


def test_clemory_view_contains():
    clemory = cle.Clemory(None, root=True)  # type: ignore[arg-type]
    clemory.add_backer(0x1000, b"AAAABBBBCCCCDDDD")
    view = cle.ClemoryView(clemory, 0x1000, 0x1010)

    assert 0 in view
    assert 0xF in view
    assert 0x10 not in view
    assert -1 not in view

    offset_view = cle.ClemoryView(clemory, 0x1000, 0x1010, offset=0x20)
    assert 0x20 in offset_view
    assert 0x2F in offset_view
    assert 0x30 not in offset_view
    assert 0x1F not in offset_view


def test_clemory_view_find():
    clemory = cle.Clemory(None, root=True)  # type: ignore[arg-type]
    clemory.add_backer(0x1000, b"AAAABBBBCCCCDDDD")

    view = cle.ClemoryView(clemory, 0x1000, 0x1010)
    assert list(clemory.find(b"CCCC")) == [0x1008]
    assert list(view.find(b"CCCC")) == [0x8]
    assert view[0x8] == ord("C")
    assert list(view.find(b"CCCC", search_max=0x4)) == []

    offset_view = cle.ClemoryView(clemory, 0x1000, 0x1010, offset=0x20)
    assert list(offset_view.find(b"CCCC")) == [0x28]
    assert offset_view[0x28] == ord("C")

    windowed = cle.Clemory(None, root=True)  # type: ignore[arg-type]
    windowed.add_backer(0x1000, b"CCCCAAAACCCCAAAA")
    inner = cle.ClemoryView(windowed, 0x1004, 0x1010)
    assert list(windowed.find(b"CCCC")) == [0x1000, 0x1008]
    assert list(inner.find(b"CCCC")) == [0x4]


def test_clemory_read_only_view_backers_match_the_clemory():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    loader.gen_ro_memview()
    view = loader.memory_ro_view
    assert view is not None

    def listing(backers):
        return [(start, bytes(backer)) for start, backer in backers]

    expected = listing(loader.memory.backers())
    assert len(expected) > 1
    assert listing(view.backers()) == expected

    for start, backer in expected:
        for addr in (start - 1, start, start + 1, start + len(backer) - 1, start + len(backer)):
            assert listing(view.backers(addr)) == listing(loader.memory.backers(addr))


def test_clemory_read_only_view_refuses_writes():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    loader.gen_ro_memview()
    view = loader.memory_ro_view
    assert view is not None

    entry = loader.main_object.entry
    before = loader.memory.load(entry, 16)
    nops = b"\x90" * 8

    for write in (
        lambda: view.store(entry, nops),
        lambda: view.pack(entry, "8s", nops),
        lambda: view.pack_word(entry, int.from_bytes(nops, "little")),
    ):
        refused = False
        try:
            write()
        except NotImplementedError:
            refused = True
        assert refused
        assert loader.memory.load(entry, 16) == before


def main():
    g = globals()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()


if __name__ == "__main__":
    main()
