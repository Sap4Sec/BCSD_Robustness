from capstone import *
from capstone.x86 import *

import sys

sys.path.append("../")

from transformations.SlicerArchIndep import Slicer as SlicerArchIndep


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
slicer = SlicerArchIndep(debug=False)


def lift_radare_block(disasm, asm, offset):

    return slicer.liftRadareBlock(disasm, asm, offset)


def radare_2_capstone(address, block):

    cap_instrs = []
    for i in md.disasm(bytes.fromhex(block), address):
        cap_instrs.append(i)

    return cap_instrs


def _radare_2_capstone(address, block):

    cap_instrs = []
    for i in md.disasm(block, address):
        cap_instrs.append(i)

    return cap_instrs


def is_valid_block(node):
    try:
        tmp = node.instructions
        tmp = node.bytes
    except Exception:
        tmp = None
    return tmp is not None
