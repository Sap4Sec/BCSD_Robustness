import json

import os
import uuid

import copy

from transformations.add_strand import add_strand_at_addr
from transformations.semnops import get_semnop_from_size, get_radare_instr


def apply_strand_for_importance(source_cfg, block_id, instr_addr):
    # create a strand with only nops
    nop_strand = []
    nop_bytes = get_semnop_from_size(1)[0]['asm_bytes']
    nop_instr = get_radare_instr(nop_bytes, 0x0, name=f"disp_{uuid.uuid4()}")
    nop_strand = [copy.deepcopy(nop_instr), copy.deepcopy(nop_instr), copy.deepcopy(nop_instr)]

    block = source_cfg.nodes[block_id]

    source_cfg, _ = add_strand_at_addr(source_cfg, (block_id, block), instr_addr, nop_strand)

    return source_cfg


def apply_strandadd_for_optimizer(source_cfg, block_id, filtered_strand, shellcode, radare_st, instr_addr):
    # strand_list_filtered = filtered_strand.split(" NEXT_I ")
    # shellcode = ast.literal_eval(shellcode)

    radare_strand = json.loads(radare_st)

    block = source_cfg.nodes[block_id]

    instr_index = block['disasm'].index(next(d for d in block['disasm'] if d.get('addr') == instr_addr))

    if instr_index == 0:
        return source_cfg, 0

    source_cfg, to_increase = add_strand_at_addr(source_cfg, (block_id, block), instr_addr, radare_strand)

    return source_cfg, to_increase
