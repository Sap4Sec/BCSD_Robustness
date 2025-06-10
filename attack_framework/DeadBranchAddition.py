import json

import uuid
import copy

from transformations.dead_branch import add_dead_branch
from transformations.semnops import get_semnop_from_size, get_radare_instr


x86_equal_jump = ['jz', 'je', 'jb', 'jc', 'jo', 'js', 'jg', 'jl', 'ja', 'jp', 'jpe', 'jnle', 'jnbe', 'jnge', 'jnae']
x86_no_equal_jump = ['jnz', 'jne', 'jnb', 'jae', 'jnc', 'jno', 'jns', 'jng', 'jle', 'jnl', 'jge', 'jna', 'jbe', 'jnp', 'jpo']
x86_branch = x86_equal_jump + x86_no_equal_jump


def parallel_dba(parameters):
    source_cfg = parameters[0]
    node = parameters[1]
    instr_addr = parameters[2]
    starting_addr_for_dba = parameters[3]
    instrs_to_insert = parameters[4]
    last_dba_addr = starting_addr_for_dba

    instr_idx = node[1]['disasm'].index(next(d for d in node[1]['disasm'] if d.get('addr') == instr_addr))

    target_instr = node[1]['disasm'][instr_idx]

    if target_instr['mnemonic'] == 'ret' or target_instr['mnemonic'] == 'jmp' or target_instr['mnemonic'] in x86_branch or target_instr['mnemonic'] == 'cmp' or target_instr['mnemonic'] == 'call':
        print(target_instr['mnemonic'])

    if instr_idx == len(node[1]['disasm']) - 1 or instr_idx == 0:
        return source_cfg, last_dba_addr

    if instr_idx:
        source_cfg, last_dba_addr = add_dead_branch(source_cfg, node, instr_idx,
                                                    instrs_to_insert,
                                                    starting_addr_for_dba)

    return source_cfg, last_dba_addr


def apply_dba_for_importance(source_cfg, chosen_node, instr_addr, starting_addr_for_dba):

    # create a strand with only nops
    nop_strand = []
    nop_bytes = get_semnop_from_size(1)[0]['asm_bytes']
    nop_instr = get_radare_instr(nop_bytes, 0x0, name=f"disp_{uuid.uuid4()}")
    nop_strand = [copy.deepcopy(nop_instr), copy.deepcopy(nop_instr), copy.deepcopy(nop_instr)]

    cfg_with_db, _ = parallel_dba(
        [source_cfg, (chosen_node, source_cfg.nodes[chosen_node]), instr_addr,
         starting_addr_for_dba, nop_strand]
    )

    return cfg_with_db


def apply_dba_for_optimizer(source_cfg, chosen_node, instr_addr, starting_addr_for_dba, instrs_to_insert):
    radare_strand = json.loads(instrs_to_insert)

    cfg_with_db, new_db_addr = parallel_dba(
        [source_cfg, (chosen_node, source_cfg.nodes[chosen_node]), instr_addr,
         starting_addr_for_dba, radare_strand]
    )

    return cfg_with_db, new_db_addr