import sys
sys.path.append("../")

from transformations.RadareAnalyzer import RadareAnalyzer

import random
random.seed(1000)  # original seed = 10

import os
import binascii

from keystone import Ks, KS_ARCH_X86, KS_MODE_64

REGISTERS_64 = ["rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
                "r15"]

REGISTERS_32 = ["eax", "ecx", "edx", "ebx", "esi", "edi", "esp", "ebp", "r8d", "r9d", "r10d", "r11d",
                "r12d", "r13d", "r14d", "r15d"]

REGISTERS_16 = ["ax", "cx", "dx", "bx", "si", "di", "sp", "bp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]

REGISTERS_8 = ["al", "ah", "cl", "ch", "dl", "dh", "bl", "bh", "sil", "dil", "spl", "bpl", "r8b", "r9b", "r10b",
                  "r11b", "r12b", "r13b", "r14b", "r15b"]

TO_PRESERV = ["rbx", "ebx", "bx", "bl", "bh", "rsp", "esp", "sp", "spl", "rbp", "ebp", "bp", "bpl",
              "r12", "r12d", "r12w", "r12b", "r13", "r13d", "r13w", "r13b", "r14", "r14d", "r14w", "r14b",
              "r15", "r15d", "r15w", "r15b"]


def get_atomic_nops():

    global REGISTERS_64, REGISTERS_32, REGISTERS_16, REGISTERS_8, TO_PRESERV

    atomic_nops = [{'asm_bytes': [b'\x90'], 'asm_str': ['nop'], 'size': 1}]

    assembler = Ks(KS_ARCH_X86, KS_MODE_64)

    for reg_64 in REGISTERS_64:
        if reg_64 not in TO_PRESERV:
            asm_str = f"mov {reg_64}, {reg_64}"
            asm_bytes = b'' + bytes(assembler.asm(asm_str)[0])
            at_nop = {'asm_bytes': [asm_bytes], 'asm_str': [asm_str], 'size': len(asm_bytes)}
            atomic_nops.append(at_nop)

    for reg_32 in REGISTERS_32:
        if reg_32 not in TO_PRESERV:
            asm_str = f"mov {reg_32}, {reg_32}"
            asm_bytes = b'' + bytes(assembler.asm(asm_str)[0])
            at_nop = {'asm_bytes': [asm_bytes], 'asm_str': [asm_str], 'size': len(asm_bytes)}
            atomic_nops.append(at_nop)

    for reg_16 in REGISTERS_16:
        if reg_16 not in TO_PRESERV:
            asm_str = f"mov {reg_16}, {reg_16}"
            asm_bytes = b'' + bytes(assembler.asm(asm_str)[0])
            at_nop = {'asm_bytes': [asm_bytes], 'asm_str': [asm_str], 'size': len(asm_bytes)}
            atomic_nops.append(at_nop)

    for reg_8 in REGISTERS_8:
        if reg_8 not in TO_PRESERV:
            asm_str = f"mov {reg_8}, {reg_8}"
            asm_bytes = b'' + bytes(assembler.asm(asm_str)[0])
            at_nop = {'asm_bytes': [asm_bytes], 'asm_str': [asm_str], 'size': len(asm_bytes)}
            atomic_nops.append(at_nop)

    return atomic_nops


def get_combo_nops():

    global REGISTERS_64, REGISTERS_32, TO_PRESERV

    combo_nops = []

    assembler = Ks(KS_ARCH_X86, KS_MODE_64)

    # bswap instruction
    for reg_64 in REGISTERS_64:
        if reg_64 not in TO_PRESERV:
            asm_str = f"bswap {reg_64}"
            asm_bytes = b'' + bytes(assembler.asm(asm_str)[0])
            at_nop = {'asm_bytes': [asm_bytes, asm_bytes], 'asm_str': [asm_str, asm_str], 'size': 2 * len(asm_bytes)}
            combo_nops.append(at_nop)

    # bswap instruction
    for reg_32 in REGISTERS_32:
        if reg_32 in TO_PRESERV:
            asm_str = f"bswap {reg_32}"
            asm_bytes = b'' + bytes(assembler.asm(asm_str)[0])
            at_nop = {'asm_bytes': [asm_bytes, asm_bytes], 'asm_str': [asm_str, asm_str], 'size': 2 * len(asm_bytes)}
            combo_nops.append(at_nop)

    # xchg instruction
    for reg_64_1 in REGISTERS_64:
        if reg_64_1 not in TO_PRESERV:
            for reg_64_2 in REGISTERS_64:
                if reg_64_2 not in TO_PRESERV:
                    asm_str = f"xchg {reg_64_1}, {reg_64_2}"
                    asm_bytes = b'' + bytes(assembler.asm(asm_str)[0])
                    at_nop = {'asm_bytes': [asm_bytes, asm_bytes], 'asm_str': [asm_str, asm_str],
                              'size': 2 * len(asm_bytes)}
                    combo_nops.append(at_nop)

    # xchg instruction
    for reg_32_1 in REGISTERS_32:
        if reg_32_1 not in TO_PRESERV:
            for reg_32_2 in REGISTERS_32:
                if reg_32_2 not in TO_PRESERV:
                    asm_str = f"xchg {reg_32_1}, {reg_32_2}"
                    asm_bytes = b'' + bytes(assembler.asm(asm_str)[0])
                    at_nop = {'asm_bytes': [asm_bytes, asm_bytes], 'asm_str': [asm_str, asm_str],
                              'size': 2 * len(asm_bytes)}
                    combo_nops.append(at_nop)

    return combo_nops


def get_semnop_from_size(size):

    at_nops = get_atomic_nops()
    combo_nops = get_combo_nops()

    insert_nops = []

    to_process = size

    while to_process > 0:

        filt_nops = list(filter(lambda d: d['size'] <= to_process, at_nops))
        filt_nops.extend(list(filter(lambda d: d['size'] <= to_process, combo_nops)))

        random_nop = random.choice(filt_nops)
        insert_nops.append(random_nop)

        to_process = to_process - random_nop['size']

    return insert_nops


def get_radare_instr(instr_bytes, address, name=None):

    # create tmp file for Radare2
    with open(f'sequence{name}.bin', 'wb') as file:
        file.write(instr_bytes)

    r2_analyzer = RadareAnalyzer(f'sequence{name}.bin')

    radare_instr = r2_analyzer.analyze_instruction()[0]
    radare_instr['addr'] = address

    r2_analyzer.r2.quit()

    os.remove(f'sequence{name}.bin')

    return radare_instr


def get_random_nops():

    sem_nops = get_atomic_nops()
    sem_nops.extend(get_combo_nops())

    random_nops = random.choice(sem_nops)

    radare_nops = []
    for s_bytes in random_nops['asm_bytes']:
        radare_nops.append(get_radare_instr(s_bytes, 0x0))

    return radare_nops


def add_nops_to_node(parameters):

    source_cfg = parameters[0]
    node = parameters[1]
    sem_nops = parameters[2]

    assembler = Ks(KS_ARCH_X86, KS_MODE_64)

    to_increase = 0

    sem_opcodes = [el['opcode'] for el in sem_nops]

    # nop_addr contains the address of the last inserted sem-nop
    first_nop_addr, nop_addr, last_idx = 0, 0, 0
    for ins in sem_nops:
        if to_increase == 0:
            last_idx = len(node[1]['disasm']) // 2
            nop_addr = node[1]['disasm'][last_idx]['addr'] + node[1]['disasm'][last_idx]['size']
            first_nop_addr = nop_addr
            last_idx += 1
        else:
            nop_addr += to_increase
            last_idx += 1
        ins['addr'] = nop_addr
        node[1]['disasm'].insert(last_idx, ins)
        to_increase += ins['size']

    for n in source_cfg.nodes(data=True):
        new_bytes = b''
        for n_ins in n[1]['disasm']:
            # check address
            if n_ins['addr'] >= first_nop_addr and n_ins['opcode'] not in sem_opcodes:
                n_ins['addr'] += to_increase
            # check target of jump (CHECK ADDRESS WITH OFFSET W.R.T. TEXT SECTION)
            if 'description' in n_ins and n_ins['description'] == 'jump':
                if n_ins['jump'] > nop_addr:
                    n_ins['opcode'] = n_ins['opcode'].replace(hex(n_ins['jump']), hex(n_ins['jump']+to_increase))
                    n_ins['disasm'] = n_ins['disasm'].replace(hex(n_ins['jump']), hex(n_ins['jump']+to_increase))
                    n_ins['pseudo'] = n_ins['pseudo'].replace(hex(n_ins['jump']), hex(n_ins['jump']+to_increase))
                    n_ins['esil'] = n_ins['esil'].replace(hex(n_ins['jump']), hex(n_ins['jump'] + to_increase))

                    asm_bytes = b'' + bytes(assembler.asm(n_ins['opcode'])[0])
                    n_ins['bytes'] = binascii.hexlify(asm_bytes).decode('utf-8')
                    n_ins['opex']['operands'][0]['value'] = n_ins['jump']+to_increase
                    # n_ins['operands'][0]['value'] = n_ins['jump']+to_increase

                    n_ins['jump'] = n_ins['jump'] + to_increase

                if 'fail' in n_ins and n_ins['fail'] > nop_addr:
                    n_ins['fail'] = n_ins['fail']+to_increase

            new_bytes += bytes.fromhex(n_ins['bytes'])
        n[1]['asm'] = new_bytes

    return source_cfg, len(sem_opcodes)


if __name__ == "__main__":

    #sem_nop_with_size = get_semnop_from_size(8)
    sem_nop = get_random_nops()

    print("OK")