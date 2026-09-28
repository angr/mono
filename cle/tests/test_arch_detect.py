# pylint:disable=no-self-use
from __future__ import annotations

import os
import unittest

import archinfo

try:
    import pypcode
except ImportError:
    pypcode = None

import cle
from cle.backends.elf.elf import ELF

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))


@unittest.skipIf(pypcode is None, "pypcode not installed")
class TestArchPcodeDetect(unittest.TestCase):
    """
    Test architecture detection.
    """

    def test_elf_x32(self):
        # The x32 ABI puts x86-64 code in an ELFCLASS32 container: the class gives the pointer width
        # and the machine gives the instruction set. Resolving by the class alone picks 32-bit X86,
        # and none of the instruction stream decodes.
        path = os.path.join(test_location, "x86_64", "x32_relocatable.o")
        ld = cle.Loader(path, main_opts={"backend": "elf"}, auto_load_libs=False)

        assert isinstance(ld.main_object.arch, archinfo.ArchAMD64)

    def test_elf_m68k(self):
        binpath = os.path.join(test_location, "m68k/mul_add_sub_xor_m68k_be")
        ld = cle.Loader(binpath, auto_load_libs=True)
        arch = ld.main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "68000:BE:32:default"

    def test_elf_nds32(self):
        binpath = os.path.join(test_location, "nds32/crt0_nds32le.o")
        ld = cle.Loader(binpath, auto_load_libs=False)
        arch = ld.main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "NDS32:LE:32:default"

    def test_elf_hppa(self):
        # The only ELF opinion for EM_PARISC applies to e_flags 528, which this file has.
        binpath = os.path.join(test_location, "hppa/test-instr_hppa")
        ld = cle.Loader(binpath, auto_load_libs=False)
        arch = ld.main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "pa-risc:BE:32:default"

    def test_opinion_secondary_forms(self):
        # The three forms the shipped opinions write e_flags in: decimal for PA-RISC,
        # hexadecimal for MSP430X, and a bit pattern with free bits for LoongArch lp64d.
        matches = ELF._pcode_secondary_matches
        assert matches("528", 0x210)
        assert not matches("528", 0x214)
        assert matches("0x2d", 0x2D)
        assert not matches("0x2d", 0)
        assert matches("0b .... .... .... .... .... .... .... .011", 0x43)
        assert not matches("0b .... .... .... .... .... .... .... .011", 0x42)
        assert not matches("golang", 0)


if __name__ == "__main__":
    unittest.main()
