import time

import networkx as nx
import pyvex
import archinfo
import random
import os
import binascii

from copy import deepcopy

from keystone import Ks, KS_ARCH_X86, KS_MODE_64

from transformations.SlicerArchIndep import Slicer
from transformations.RadareAnalyzer import RadareAnalyzer

not_REX_regs = {'ah': 16, 'ch': 24, 'dh': 32, 'bh': 40}
REX_regs = {'sih': 64, 'dih': 72, 'r8b': 80, 'r9b': 88, 'r10b': 96, 'r11b': 104, 'r12b': 112, 'r13b': 120,
            'r14b': 128, 'r15b': 136}

GEN_PURPOSE_regs = {'rax': 16, 'rcx': 24, 'rdx': 32, 'rbx': 40, 'rsp': 48, 'rbp': 56, 'rsi': 64, 'rdi': 72, 'r8': 80,
                    'r9': 88, 'r10': 96, 'r11': 104, 'r12': 112, 'r13': 120, 'r14': 128, 'r15': 136}

CC_regs = ['cc_op', 'ccp_dep1', 'cc_dep2', 'cc_ndep', 'acflag', 'idflag']


def x86_to_vex_reg(reg):
    # fake vex block to access x86 registers
    vex_block = pyvex.IRSB(b'\x00', 0, archinfo.arch_from_id('x86_64'), opt_level=0)
    return vex_block.arch.registers.get(reg, None)[0]


def get_live_at_address(block_instrs, block_bytes, block_addr, instr_addr):
    slicer = Slicer(debug=False)

    try:
        _, asm2vex = slicer.lift_bytes(block_instrs, block_bytes, block_addr)
    except Exception as e:
        print(f"Entry point: {block_addr}")
        for instr in block_instrs:
            print(f"{instr['addr']} \t {instr['disasm']}")
        return None

    live_vars = []

    for instr in asm2vex:
        if instr <= instr_addr:
            live_vars.extend(asm2vex[instr]['idef'])
            live_vars.extend(asm2vex[instr]['iref'])

    live_vars = set(live_vars)

    live_regs = []

    for el in live_vars:
        if el[0] == "R" and int(el[1:]) in slicer.x86_mapping.keys():  # check only registers
            live_regs.append((int(el[1:]), slicer.x86_mapping[int(el[1:])]))

    return set(live_regs)


# simple sem-preserving strand
def create_strand(reg):
    strand = f"""push {reg}
mov {reg}, {reg}
add {reg}, 5
sub {reg}, 5
pop {reg}"""

    strand = strand.split("\n")
    return strand


"""
List of math strands: 
    - op_strand can be used to substitute the operation op with a strand or to insert a sem-preserving strand among
    (xor, and, or):
        - xor reg1, reg2 followed by xor reg1, reg2
        - and reg, reg
        - or reg, reg
    - op_with_imm_strand can be used to insert a sem-preserving strand among (add, sub):
        - add reg, 0
        - sub reg, 0
"""

# X ^ Y  ->  (X | Y) - (X & Y)  ->  x xor y = (x or y) - (x and y)  ->  xor op1, op2
xor_strand = lambda op1, op2, full_r1, r1: (f"""push {full_r1}
mov {r1}, {op1}
or {op1}, {op2}
and {op2}, {r1}
sub {op1}, {op2}
pop {full_r1}""")

# xor op1, imm
xor_with_imm_strand = lambda op1, op2, full_r1, r1, full_r2, r2: (f"""push {full_r1}
push {full_r2}
mov {r2}, {op2}
mov {r1}, {op1}
or {op1}, {r2}
and {r2}, {r1}
sub {op1}, {r2}
pop {full_r2}
pop {full_r1}""")

# X + Y  ->	 (X & Y) + (X | Y)  ->  x + y = (x and y) + (x or y)  ->  add op1, op2
add_strand = lambda op1, op2, full_r1, r1: (f"""push {full_r1}
mov {r1}, {op1}
and {op1}, {op2}
or {op2}, {r1}
add {op1}, {op2}
pop {full_r1}""")

# add op1, imm
add_with_imm_strand = lambda op1, op2, full_r1, r1, full_r2, r2: (f"""push {full_r1}
push {full_r2}
mov {r2}, {op2}
mov {r1}, {op1}
and {op1}, {r2}
or {r2}, {r1}
add {op1}, {r2}
pop {full_r2}
pop {full_r1}""")

# X - Y  ->  (X ^ -Y) + 2*(X & -Y)  ->  x - y = (x xor -y) + 2*(x and -y)  ->  sub op1, op2
sub_strand = lambda op1, op2, full_r1, r1: (f"""push {r1}
mov {r1}, {op1}
neg {op2}
xor {op1}, {op2}
and {op2}, {r1}
imul {op2}, 2
add {op1}, {op2}
pop {full_r1}""")

# sub op1, imm
sub_with_imm_strand = lambda op1, op2, full_r1, r1, full_r2, r2: (f"""push {full_r1}
push {full_r2}
mov {r2}, {op2}
mov {r1}, {op1}
neg {r2}
xor {op1}, {r2}
and {r2}, {r1}
imul {r2}, 2
add {op1}, {r2}
pop {full_r2}
pop {full_r1}""")

# X & Y  ->  (X + Y) - (X | Y)  ->  x and y = (x + y) - (x or y)  ->  and op1, op2
and_strand = lambda op1, op2, full_r1, r1: (f"""push {full_r1}
mov {r1}, {op1}
add {op1}, {op2}
or {op2}, {r1}
sub {op1}, {op2}
pop {full_r1}
""")

# and op1, imm
and_with_imm_strand = lambda op1, op2, full_r1, r1, full_r2, r2: (f"""push {full_r1}
push {full_r2}
mov {r2}, {op2}
mov {r1}, {op1}
add {op1}, {r2}
or {r2}, {r1}
sub {op1}, {r2}
pop {full_r2}
pop {full_r1}""")

# X | Y  ->  X + Y + 1 + (~X | ~Y)  ->  x or y = x + y + 1 + (not x or not y)  ->  or op1, op2
or_strand = lambda op1, op2, full_r1, r1: (f"""push {full_r1}
mov {r1}, {op1}
inc {r1}
add {r1}, {op2}
not {op2}
not {op1}
or {op1}, {op2}
add {op1}, {r1}
pop {full_r1}
""")

# or op1, imm
or_with_imm_strand = lambda op1, op2, full_r1, r1, full_r2, r2: (f"""push {full_r1}
push {full_r2}
mov {r2}, {op2}
mov {r1}, {op1}
inc {r1}
add {r1}, {r2}
not {r2}
not {op1}
or {op1}, {r2}
add {op1}, {r1}
pop {full_r2}
pop {full_r1}""")


def get_substitute(mnem, op1, op2, full_r1, r1, op2_type, full_r2=None, r2=None):
    strand = ""
    if mnem == "xor":
        if op2_type == "reg":
            strand = xor_strand(op1, op2, full_r1, r1)
        elif op2_type == "imm":
            strand = xor_with_imm_strand(op1, op2, full_r1, r1, full_r2, r2)
    elif mnem == "add":
        if op2_type == "reg":
            strand = add_strand(op1, op2, full_r1, r1)
        elif op2_type == "imm":
            strand = add_with_imm_strand(op1, op2, full_r1, r1, full_r2, r2)
    elif mnem == "sub":
        if op2_type == "reg":
            strand = sub_strand(op1, op2, full_r1, r1)
        elif op2_type == "imm":
            strand = sub_with_imm_strand(op1, op2, full_r1, r1, full_r2, r2)
    elif mnem == "and":
        if op2_type == "reg":
            strand = and_strand(op1, op2, full_r1, r1)
        elif op2_type == "imm":
            strand = and_with_imm_strand(op1, op2, full_r1, r1, full_r2, r2)
    elif mnem == "or":
        if op2_type == "reg":
            strand = or_strand(op1, op2, full_r1, r1)
        elif op2_type == "imm":
            strand = or_with_imm_strand(op1, op2, full_r1, r1, full_r2, r2)

    strand = strand.split("\n")
    return strand


def strand_for_sub(slicer, instr, available_regs):
    strand = None
    operands = []
    for op in instr['operands']:
        operands.append((op['size'], op['value'], op['type']))

    reg_for_strand = random.choice(available_regs)
    reg_with_size = list(filter(lambda x: (x[1] == operands[0][0]), slicer.subreg_mapping[reg_for_strand[0]]))[0]

    # substitute instr with a strand (instr is a xor in the example)
    can_substitute = ['xor', 'add', 'sub', 'and', 'or']
    if instr['mnemonic'] in can_substitute:
        reg_for_imm, reg_for_imm_with_size = None, None
        if operands[1][2] == "imm":
            reg_for_imm = random.choice(list(set(available_regs) - set(reg_for_strand)))
            reg_for_imm_with_size = list(filter(lambda x: (x[1] == operands[1][0]),
                                                slicer.subreg_mapping[reg_for_imm[0]]))[0]

        strand = get_substitute(instr['mnemonic'], operands[0][1], operands[1][1], reg_for_strand[1], reg_with_size[0],
                                operands[1][2], full_r2=reg_for_imm[1], r2=reg_for_imm_with_size[0])

    return strand


def strand_sem_pres(slicer, instr, available_regs):
    strand = None
    operands = []
    for op in instr['operands']:
        # if op['type'] == 'mem':
        #    value = f"{op['base']}{op['disp']}"
        if op['type'] == 'reg' or op['type'] == 'imm':
            operands.append((op['size'], op['value'], op['type']))

    if operands[0][1] in not_REX_regs:
        for el in REX_regs:
            removed = slicer.subreg_mapping.pop(REX_regs[el])
            to_remove = (REX_regs[el], removed[0][0])
            if to_remove in available_regs:
                available_regs.remove((REX_regs[el], removed[0][0]))

    if operands[0][1] in REX_regs:
        for el in not_REX_regs:
            removed = slicer.subreg_mapping.pop(not_REX_regs[el])
            to_remove = (not_REX_regs[el], removed[0][0])
            if to_remove in available_regs:
                available_regs.remove((not_REX_regs[el], removed[0][0]))

    reg_for_strand = None
    reg_with_size = None
    for el in available_regs:
        to_check = list(filter(lambda x: (x[1] == operands[0][0]), slicer.subreg_mapping[el[0]]))
        if to_check:
            reg_for_strand = el
            reg_with_size = to_check[0]
            break

    if reg_with_size is None:
        return None

    available_for_imm = list(set(available_regs) - {reg_for_strand})

    reg_for_imm = None
    reg_for_imm_with_size = None
    for el in available_for_imm:
        to_check = list(filter(lambda x: (x[1] == operands[0][0]), slicer.subreg_mapping[el[0]]))
        if to_check:
            reg_for_imm = el
            reg_for_imm_with_size = to_check[0]
            break

    if reg_for_imm is None:
        return None

    strand_type = random.choice(['add', 'sub', 'and', 'or'])

    if reg_for_imm_with_size:
        if strand_type == "add" or strand_type == "sub":
            imm_value = 0
            if strand_type == "add":
                strand = add_with_imm_strand(operands[0][1], imm_value, reg_for_strand[1], reg_with_size[0],
                                             reg_for_imm[1], reg_for_imm_with_size[0])
            else:
                strand = sub_with_imm_strand(operands[0][1], imm_value, reg_for_strand[1], reg_with_size[0],
                                             reg_for_imm[1], reg_for_imm_with_size[0])
        elif strand_type == "and":
            strand = and_with_imm_strand(operands[0][1], operands[0][1], reg_for_strand[1], reg_with_size[0],
                                         reg_for_imm[1], reg_for_imm_with_size[0])
        elif strand_type == "or":
            strand = or_with_imm_strand(operands[0][1], operands[0][1], reg_for_strand[1], reg_with_size[0],
                                        reg_for_imm[1], reg_for_imm_with_size[0])

    strand = strand.split("\n")
    return strand


def get_radare_strand(asm_bytes, strand, name):
    with open(f'strand_{name}.bin', 'wb') as file:
        file.write(asm_bytes)

    # print(f"File: strand_{name}.bin\t Len: {len(asm_bytes)}\t {str_asm_bytes}")

    r2_analyzer = RadareAnalyzer(f'strand_{name}.bin')

    radare_instrs = r2_analyzer.analyze_instruction(size=len(strand))

    for el in radare_instrs:
        el['strand'] = True

    r2_analyzer.r2.quit()

    os.remove(f'strand_{name}.bin')

    return radare_instrs


def get_strand_size(asm_bytes, strand, name):
    radare_strand = get_radare_strand(asm_bytes, strand, name)

    size = 0
    for instr in radare_strand:
        size += instr['size']

    return size


def get_push_pop(live_registers):
    pushes = []
    pops = []

    for el in live_registers:
        if el[1] in list(GEN_PURPOSE_regs.keys()):
            pushes.append(f"push {el[1]}")
            pops.append(f"pop {el[1]}")
        elif el[1] in CC_regs and 'pushfq' not in pushes and 'popfq' not in pops:
            pushes.append('pushfq')
            pops.append('popfq')

    pops.reverse()

    assembler = Ks(KS_ARCH_X86, KS_MODE_64)
    push_bytes, pop_bytes = b'', b''

    for asm_str in pushes:
        try:
            push_bytes += bytes(assembler.asm(asm_str)[0])
        except Exception as e:
            print(e)
            return None, None

    for asm_str in pops:
        try:
            pop_bytes += bytes(assembler.asm(asm_str)[0])
        except Exception as e:
            print(e)
            return None, None

    # radare_pushes = get_radare_strand(push_bytes, pushes, f"push_{random.randint(0, 1000000)}")
    # radare_pops = get_radare_strand(pop_bytes, pops, f"pop_{random.randint(0, 1000000)}")

    return (pushes, push_bytes), (pops, pop_bytes)


def get_strands_from_regs(instr, live_regs, type="sem-pres"):
    slicer = Slicer(debug=False)

    all_regs = [(k, v) for k, v in slicer.x86_mapping.items()][:16]  # only general-purpose registers
    all_regs = all_regs[:4] + all_regs[6:]  # exclude rsp and rbp

    available_regs = list(set(all_regs) - set(live_regs))

    if len(available_regs) >= 2:
        if type == "substitute":
            strand = strand_for_sub(slicer, instr, available_regs)
        else:
            strand = strand_sem_pres(slicer, instr, available_regs)

        if strand is None:
            return None

        return strand


def strand_with_no_live(strand, name=None, type="sem-pres"):
    if strand:
        assembler = Ks(KS_ARCH_X86, KS_MODE_64)
        asm_bytes = b''
        for asm_str in strand:
            try:
                asm_bytes += bytes(assembler.asm(asm_str)[0])
            except Exception as e:
                return None

        # str_asm_bytes = ''.join([f'\\x{byte:02x}' for byte in asm_bytes])

        radare_instrs = get_radare_strand(asm_bytes, strand, name)

        return radare_instrs

    return None


assembler = Ks(KS_ARCH_X86, KS_MODE_64)


def filter_strand(strand):
    new_strand = []

    for instr in strand:
        if 'push' not in instr['opcode'] and 'pop' not in instr['opcode']:
            new_strand.append(instr)

    return strand if not new_strand else new_strand


def add_strand_at_addr(source_cfg, block_pair, instr_addr, strand):
    block_ep = block_pair[0]
    block = block_pair[1]

    try:
        instr_idx = block['disasm'].index(list(filter(lambda x: x['addr'] == instr_addr, block['disasm']))[0])
    except Exception as e:
        print("IN EXC")

    # check if in dead branch -> filter out push/pop pairs
    strand = filter_strand(strand) if block['is_db'] is True else strand

    # strand_opcodes = [el['opcode'] for el in strand]
    strand_opcodes = []

    cumulative_addr, to_increase = block['disasm'][instr_idx]['addr'], 0
    first_strand_addr = cumulative_addr
    for idx in range(len(strand)):
        strand[idx]['trans_type'] = 'strandadd'
    block['disasm'][instr_idx:instr_idx] = strand

    for i, instr in enumerate(block['disasm']):
        if i < instr_idx:
            continue
        instr['addr'] = cumulative_addr
        cumulative_addr += instr['size']
        if 'strand' in instr and instr['strand']:
            to_increase += instr['size']
            instr['strand'] = False
            strand_opcodes.append((instr['addr'], instr['opcode']))

    # fix jump targets in block with added strand and update 'asm' field
    new_bytes = b''
    for i, instr in enumerate(block['disasm']):
        if 'type' in instr and (instr['type'] == 'cjmp' or instr['type'] == 'jmp'):
            if instr['jump'] > first_strand_addr:
                instr['opcode'] = instr['opcode'].replace(hex(instr['jump']),
                                                          hex(instr['jump'] + to_increase))
                instr['disasm'] = instr['disasm'].replace(hex(instr['jump']),
                                                          hex(instr['jump'] + to_increase))
                instr['pseudo'] = instr['pseudo'].replace(hex(instr['jump']),
                                                          hex(instr['jump'] + to_increase))
                instr['esil'] = instr['esil'].replace(hex(instr['jump']),
                                                      hex(instr['jump'] + to_increase))
                try:
                    asm_bytes = b'' + bytes(assembler.asm(instr['opcode'])[0])
                    instr['bytes'] = binascii.hexlify(asm_bytes).decode('utf-8')
                except Exception as e:
                    print(f"Error in assembling instruction: {instr['addr']} \t {instr['opcode']}")
                    instr['bytes'] = instr['bytes']
                instr['opex']['operands'][0]['value'] = instr['jump'] + to_increase

                instr['jump'] = instr['jump'] + to_increase

            if 'fail' in instr and instr['fail'] >= first_strand_addr:
                instr['fail'] = instr['fail'] + to_increase
        if 'type' in instr and instr['type'] == 'call':
            call_target = instr['opex']['operands'][0]['value']
            temp_opcode = instr['opcode'].replace(hex(call_target),
                                                  hex(call_target - instr['addr']))
            try:
                call_bytes = b'' + bytes(assembler.asm(temp_opcode)[0])
                instr['bytes'] = binascii.hexlify(call_bytes).decode('utf-8')
            except Exception as e:
                instr['bytes'] = instr['bytes']

        new_bytes += bytes.fromhex(instr['bytes'])
    block['asm'] = new_bytes
    # block['capstone'] = _radare_2_capstone(block_ep, new_bytes)

    # last_strand_addr = block['disasm'][instr_idx+len(strand)]['addr']

    nodes_mapping = {}
    for n in source_cfg.nodes(data=True):
        if n[0] == block_ep:
            continue
        else:
            # create new attributes and update node
            new_disasm = deepcopy(n[1]['disasm'])
            new_bytes = b''

            original_ep = n[1]['original_ep']
            original_can_disp = n[1]['can_disp']
            original_is_db = n[1]['is_db']
            original_text_addr = n[1]['text_addr']
            original_calls = n[1]['calls']

            new_ep = n[0]
            if n[0] >= first_strand_addr:
                new_ep = n[0] + to_increase

            for n_ins in new_disasm:
                # check address
                if n_ins['addr'] >= first_strand_addr and (n_ins['addr'], n_ins['opcode']) not in strand_opcodes:
                    n_ins['addr'] += to_increase
                # check target of jump (CHECK ADDRESS WITH OFFSET W.R.T. TEXT SECTION)
                # if 'description' in n_ins and n_ins['mnemonic'] != 'ret' and 'jump' in n_ins['description']:
                if 'type' in n_ins and (n_ins['type'] == 'cjmp' or n_ins['type'] == 'jmp'):
                    if n_ins['jump'] > first_strand_addr:
                        n_ins['opcode'] = n_ins['opcode'].replace(hex(n_ins['jump']),
                                                                  hex(n_ins['jump'] + to_increase))
                        n_ins['disasm'] = n_ins['disasm'].replace(hex(n_ins['jump']),
                                                                  hex(n_ins['jump'] + to_increase))
                        n_ins['pseudo'] = n_ins['pseudo'].replace(hex(n_ins['jump']),
                                                                  hex(n_ins['jump'] + to_increase))
                        n_ins['esil'] = n_ins['esil'].replace(hex(n_ins['jump']),
                                                              hex(n_ins['jump'] + to_increase))

                        try:
                            asm_bytes = b'' + bytes(assembler.asm(n_ins['opcode'])[0])
                            n_ins['bytes'] = binascii.hexlify(asm_bytes).decode('utf-8')
                        except Exception as e:
                            print(f"Error in assembling instruction: {n_ins['addr']} \t {n_ins['opcode']}")
                            n_ins['bytes'] = n_ins['bytes']
                        n_ins['opex']['operands'][0]['value'] = n_ins['jump'] + to_increase

                        n_ins['jump'] = n_ins['jump'] + to_increase

                    if 'fail' in n_ins and n_ins['fail'] >= first_strand_addr:
                        n_ins['fail'] = n_ins['fail'] + to_increase

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

            new_attrs = {n[0]: {'disasm': new_disasm,
                                'asm': new_bytes,
                                'entry_point': hex(new_ep),
                                'original_ep': original_ep,
                                'text_addr': original_text_addr,
                                'calls': original_calls,
                                'can_disp': original_can_disp,
                                'is_db': original_is_db}
                         }

            nx.set_node_attributes(source_cfg, new_attrs)
            nodes_mapping[n[0]] = new_ep

    # update nodes labels
    source_cfg = nx.relabel_nodes(source_cfg, nodes_mapping)

    return source_cfg, to_increase


if __name__ == "__main__":
    reg = "rax"
    vex_offset = x86_to_vex_reg(reg)

    print("OK")
