import time
import uuid
import binascii
import os

from copy import deepcopy

import networkx as nx

from keystone import Ks, KS_ARCH_X86, KS_MODE_64

from transformations.RadareAnalyzer import RadareAnalyzer

assembler = Ks(KS_ARCH_X86, KS_MODE_64)


def filter_strand(strand):
    ret_dict = {
        'opcode': 'ret',
        'disasm': 'ret',
        'pseudo': 're',
        'description': 'return from subroutine. pop 4 bytes from esp and jump there.',
        'mnemonic': 'ret',
        'mask': 'ff',
        'esil': 'rsp,[8],rip,=,8,rsp,+=',
        'sign': False,
        'id': 633,
        'opex': {'operands': [...]},
        'addr': -1,
        'bytes': 'c3',
        'size': 1,
        'type': 'ret',
        'esilcost': 8,
        'cycles': 3,
        'failcycles': 0,
        'delay': 0,
        'stack': 'inc',
        'stackptr': -1,
        'family': 'cpu',
        'operands': []
    }

    strand.append(ret_dict)

    new_strand = []

    for instr in strand:
        if 'push' not in instr['opcode'] and 'pop' not in instr['opcode']:
            new_strand.append(instr)

    return strand if not new_strand else new_strand


def get_radare_instructions(block_bytes):
    name = uuid.uuid4()
    with open(f'radare_{name}.bin', 'wb') as file:
        file.write(block_bytes)

    r2_analyzer = RadareAnalyzer(f'radare_{name}.bin')

    block_instrs = r2_analyzer.analyze_instruction(size=len(block_bytes), is_disp=True)

    r2_analyzer.r2.quit()

    os.remove(f'radare_{name}.bin')

    return block_instrs


def get_cmp_je_pair(base_address, address, name=None):
    # create cmp-jne pair
    # cmp rax, 0xdeadbeef
    # je dead_branch_address

    # cmp rax, 0xdeadbeef
    # .byte 0x74
    # .byte {address} - (base_address + 11)
    jump_pattern = f"cmp eax, 0xdeadbeef\n .byte 0x0f\n .byte 0x84\n .long {address - base_address - 11}"

    # jmp_bytes = bytes(assembler.asm(
    #     f'cmp eax, 0xdeadbeef \n je {address}', base_address)[0])

    jmp_bytes = bytes(assembler.asm(jump_pattern)[0])

    # create tmp file for Radare2
    with open(f'{name}.bin', 'wb') as file:
        file.write(jmp_bytes)

    r2_analyzer = RadareAnalyzer(f'{name}.bin')

    cmp_jmp_pair = r2_analyzer.analyze_instruction(is_dba=True, size=2)

    r2_analyzer.r2.quit()

    cumulative_size = 0
    for instr in cmp_jmp_pair:
        cumulative_size += instr['size']

    address += cumulative_size

    fake_addr = cmp_jmp_pair[1]['opcode'].split(" ")[1]
    for key, value in cmp_jmp_pair[1].items():
        if key != 'bytes' and isinstance(cmp_jmp_pair[1][key], str) and fake_addr in cmp_jmp_pair[1][key]:
            cmp_jmp_pair[1][key] = cmp_jmp_pair[1][key].replace(fake_addr, hex(address))
    cmp_jmp_pair[1]['jump'] = address
    cmp_jmp_pair[1]['opex']['operands'][0]['value'] = address
    cmp_jmp_pair[1]['operands'][0]['value'] = address

    os.remove(f'{name}.bin')

    return cmp_jmp_pair


def add_dead_branch(cfg, node, instr_idx, instrs_to_insert, starting_addr_for_dba):
    entry_point = int(starting_addr_for_dba)

    dead_branch = [entry_point, {}]

    # block containing original code to be executed
    left_instrs = [0, {}]
    left_disasm = []

    # size of cmp-je pair to add to original instructions address
    cumulative_size = 0

    # get successors of splitted node (original node)
    node_succs = [s for s in cfg.successors(node[0])]

    first_node = list(cfg.nodes(data=True))[0]
    function_ep = first_node[1]['func_addr']

    # split original node and populate dead branch
    start = time.perf_counter()
    for i, instr in enumerate(node[1]['disasm']):

        if i >= instr_idx:
            if i == instr_idx:
                # cmp_je_to_DB = get_cmp_je_pair(instr['addr'], entry_point, name=f"dba_{uuid.uuid4()}")
                cmp_je_to_DB = get_cmp_je_pair(function_ep, entry_point, name=f"dba_{uuid.uuid4()}")

                for idx in range(len(cmp_je_to_DB)):
                    cmp_je_to_DB[idx]['addr'] += node[1]['disasm'][i]['addr']
                    cmp_je_to_DB[idx]['trans_type'] = 'dba'
                    cumulative_size += cmp_je_to_DB[idx]['size']

                # update 'fail' attribute of je instruction
                cmp_je_to_DB[1]['fail'] = node[1]['disasm'][i]['addr'] + cumulative_size

                dead_branch[0] += cumulative_size
                dead_branch[1]['entry_point'] = hex(dead_branch[0])
                dead_branch[1]['func_addr'] = function_ep
                dead_branch[1]['original_ep'] = dead_branch[0]
                dead_branch[1]['text_addr'] = node[1]['text_addr']
                dead_branch[1]['calls'] = node[1]['calls']
                dead_branch[1]['can_disp'] = True
                dead_branch[1]['is_db'] = True

                # original code
                left_instrs_ep = cmp_je_to_DB[0]['addr']  # + cumulative_size
                left_instrs[0] = left_instrs_ep
                left_instrs[1]['func_addr'] = function_ep
                left_instrs[1]['entry_point'] = hex(left_instrs_ep)
                left_instrs[1]['original_ep'] = left_instrs_ep
                left_instrs[1]['text_addr'] = node[1]['text_addr']
                left_instrs[1]['calls'] = node[1]['calls']
                left_instrs[1]['can_disp'] = True
                left_instrs[1]['is_db'] = False

            # remove from original node and insert in new one
            node[1]['disasm'][i] = None
            instr['dba'] = True
            left_disasm.append(instr)
            node[1]['disasm'][i] = None

    # add jump to the dead branch and update starting node
    node[1]['disasm'][instr_idx:instr_idx] = cmp_je_to_DB
    node[1]['disasm'] = [i for i in node[1]['disasm'] if i is not None]
    node_bytes = ''
    for instr in node[1]['disasm']:
        node_bytes += instr['bytes']
    node[1]['asm'] = bytes.fromhex(node_bytes)

    block_bb_heads = []
    block_bb_disasm = []
    block_bb_mnems = []
    for n_ins in node[1]['disasm']:
        block_bb_disasm.append(n_ins['disasm'])
        block_bb_heads.append(n_ins['addr'])
        block_bb_mnems.append(n_ins['mnemonic'])

    node[1]['bb_disasm'] = block_bb_disasm
    node[1]['bb_heads'] = block_bb_heads
    node[1]['bb_mnems'] = block_bb_mnems

    # filter strand from push-pop pairs
    instrs_to_insert = filter_strand(instrs_to_insert)

    # INITIALIZE DEAD BRANCH WITH A RANDOM STRAND
    # add instr_to_insert into the dead branch and update dead branch
    strand_cumulative_addr, to_increase, strand_opcodes = dead_branch[0], 0, []
    for idx in range(len(instrs_to_insert)):
        instrs_to_insert[idx]['trans_type'] = 'dba'
    dead_branch[1]['disasm'] = instrs_to_insert

    for i, instr in enumerate(dead_branch[1]['disasm']):
        instr['addr'] = strand_cumulative_addr
        strand_cumulative_addr += instr['size']
        if 'strand' in instr and instr['strand']:
            to_increase += instr['size']
            instr['strand'] = False
            strand_opcodes.append((instr['addr'], instr['opcode']))

    db_bytes = ''
    for instr in dead_branch[1]['disasm']:
        db_bytes += instr['bytes']
    dead_branch[1]['asm'] = bytes.fromhex(db_bytes)

    block_bb_heads = []
    block_bb_disasm = []
    block_bb_mnems = []
    for n_ins in dead_branch[1]['disasm']:
        block_bb_disasm.append(n_ins['disasm'])
        block_bb_heads.append(n_ins['addr'])
        block_bb_mnems.append(n_ins['mnemonic'])

    dead_branch[1]['bb_disasm'] = block_bb_disasm
    dead_branch[1]['bb_heads'] = block_bb_heads
    dead_branch[1]['bb_mnems'] = block_bb_mnems

    # update the CFG by adding the dead branch and new edges
    cfg.add_node(dead_branch[0],
                 func_addr=dead_branch[1]['func_addr'],
                 entry_point=dead_branch[1]['entry_point'],
                 asm=dead_branch[1]['asm'],
                 disasm=dead_branch[1]['disasm'],
                 original_ep=dead_branch[1]['original_ep'],
                 text_addr=dead_branch[1]['text_addr'],
                 calls=dead_branch[1]['calls'],
                 can_disp=dead_branch[1]['can_disp'],
                 is_db=dead_branch[1]['is_db'],
                 bb_disasm=dead_branch[1]['bb_disasm'],
                 bb_heads=dead_branch[1]['bb_heads'],
                 bb_mnems=dead_branch[1]['bb_mnems'])

    cfg.add_edge(node[0], dead_branch[0])

    # update node with original instructions
    left_instrs[1]['disasm'] = left_disasm
    left_bytes = ''
    for idx in range(len(left_instrs[1]['disasm'])):
        left_bytes += left_instrs[1]['disasm'][idx]['bytes']
        # left_instrs[1]['disasm'][idx]['addr'] += cumulative_size
    left_instrs[1]['asm'] = bytes.fromhex(left_bytes)

    left_bb_heads = []
    left_bb_disasm = []
    left_bb_mnems = []
    for l_ins in left_instrs[1]['disasm']:
        left_bb_disasm.append(l_ins['disasm'])
        left_bb_heads.append(l_ins['addr'])
        left_bb_mnems.append(l_ins['mnemonic'])

    left_instrs[1]['bb_disasm'] = left_bb_disasm
    left_instrs[1]['bb_heads'] = left_bb_heads
    left_instrs[1]['bb_mnems'] = left_bb_mnems

    # update the cfg by adding a new node containing the instructions after the instr_idx one
    # add an edge from the original node to this node
    cfg.add_node(left_instrs[0],
                 func_addr=left_instrs[1]['func_addr'],
                 entry_point=left_instrs[1]['entry_point'],
                 asm=left_instrs[1]['asm'],
                 disasm=left_instrs[1]['disasm'],
                 original_ep=left_instrs[1]['original_ep'],
                 text_addr=left_instrs[1]['text_addr'],
                 calls=left_instrs[1]['calls'],
                 can_disp=left_instrs[1]['can_disp'],
                 is_db=left_instrs[1]['is_db'],
                 bb_disasm=left_instrs[1]['bb_disasm'],
                 bb_heads=left_instrs[1]['bb_heads'],
                 left_bb_mnems=left_instrs[1]['bb_mnems'])
    cfg.add_edge(node[0], left_instrs[0])

    # remove original outgoing edges from node
    for succ in node_succs:
        if succ != dead_branch[1]['entry_point'] and succ != left_instrs[1]['entry_point']:
            cfg.remove_edge(node[0], succ)
            cfg.add_edge(left_instrs[0], succ)

    # update address of instructions > left_instrs[0]
    nodes_mapping = {}
    for n in cfg.nodes(data=True):
        if n[0] == node[0] or n[0] == dead_branch[0]:
            continue
        else:
            new_disasm = deepcopy(n[1]['disasm'])
            new_bytes = b''

            original_ep = n[1]['original_ep']
            original_can_disp = n[1]['can_disp']
            original_is_db = n[1]['is_db']

            new_ep = n[0]
            if n[0] >= cmp_je_to_DB[0]['addr']:
                new_ep = n[0] + cumulative_size

            for n_ins in new_disasm:
                # if "fxch" in n_ins['disasm']:
                #     print(f"DBA (OLD BLOCKS): {n_ins['addr']} \t {n_ins['disasm']}")
                # check address
                if n_ins['addr'] >= cmp_je_to_DB[0]['addr']:
                    n_ins['addr'] += cumulative_size
                # check target of jump (CHECK ADDRESS WITH OFFSET W.R.T. TEXT SECTION)
                # if 'description' in n_ins and n_ins['mnemonic'] != 'ret' and 'jump' in n_ins['description']:
                if 'type' in n_ins and (n_ins['type'] == 'cjmp' or n_ins['type'] == 'jmp'):
                    if n_ins['jump'] >= cmp_je_to_DB[0]['addr']:
                        n_ins['opcode'] = n_ins['opcode'].replace(hex(n_ins['jump']),
                                                                  hex(n_ins['jump'] + cumulative_size))
                        n_ins['disasm'] = n_ins['disasm'].replace(hex(n_ins['jump']),
                                                                  hex(n_ins['jump'] + cumulative_size))
                        n_ins['pseudo'] = n_ins['pseudo'].replace(hex(n_ins['jump']),
                                                                  hex(n_ins['jump'] + cumulative_size))
                        n_ins['esil'] = n_ins['esil'].replace(hex(n_ins['jump']),
                                                              hex(n_ins['jump'] + cumulative_size))

                        try:
                            asm_bytes = b'' + bytes(assembler.asm(n_ins['opcode'])[0])
                            n_ins['bytes'] = binascii.hexlify(asm_bytes).decode('utf-8')
                        except Exception as e:
                            print(f"Error in assembling instruction: {n_ins['addr']} \t {n_ins['opcode']}")
                            n_ins['bytes'] = n_ins['bytes']
                        n_ins['size'] = len(n_ins['bytes'])
                        n_ins['opex']['operands'][0]['value'] = n_ins['jump'] + cumulative_size

                        n_ins['jump'] = n_ins['jump'] + cumulative_size

                    if 'fail' in n_ins and n_ins['fail'] >= cmp_je_to_DB[0]['addr']:
                        n_ins['fail'] = n_ins['fail'] + cumulative_size
                if 'type' in n_ins and n_ins['type'] == 'call':
                    call_target = n_ins['opex']['operands'][0]['value']
                    temp_opcode = n_ins['opcode'].replace(hex(call_target),
                                                          hex(call_target - n_ins['addr']))
                    try:
                        call_bytes = b'' + bytes(assembler.asm(temp_opcode)[0])
                        n_ins['bytes'] = binascii.hexlify(call_bytes).decode('utf-8')
                    except Exception as e:
                        n_ins['bytes'] = n_ins['bytes']

                new_bytes += bytes.fromhex(n_ins['bytes'])

            new_bb_heads = []
            new_bb_disasm = []
            new_bb_mnems = []
            for n_ins in new_disasm:
                new_bb_disasm.append(n_ins['disasm'])
                new_bb_heads.append(n_ins['addr'])
                new_bb_mnems.append(n_ins['mnemonic'])

            new_attrs = {n[0]: {'disasm': new_disasm,
                                'asm': new_bytes,
                                'entry_point': hex(new_ep),
                                'original_ep': original_ep,
                                'can_disp': original_can_disp,
                                'is_db': original_is_db,
                                'bb_disasm': new_bb_disasm,
                                'bb_heads': new_bb_heads,
                                'bb_mnems': new_bb_mnems
                                }}

            nx.set_node_attributes(cfg, new_attrs)
            nodes_mapping[n[0]] = new_ep

    # update labels
    cfg = nx.relabel_nodes(cfg, nodes_mapping)

    last_instr = dead_branch[1]['disasm'][-1]
    next_ep = last_instr['addr'] + last_instr['size']

    return cfg, next_ep