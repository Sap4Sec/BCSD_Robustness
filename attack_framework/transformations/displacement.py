import time
import uuid

from keystone import Ks, KS_ARCH_X86, KS_MODE_64

import os
from copy import deepcopy

from transformations.RadareAnalyzer import RadareAnalyzer
from transformations.semnops import get_semnop_from_size, get_radare_instr


def get_radare_instructions(block_bytes):
    name = uuid.uuid4()
    with open(f'radare_{name}.bin', 'wb') as file:
        file.write(block_bytes)

    r2_analyzer = RadareAnalyzer(f'radare_{name}.bin')

    block_instrs = r2_analyzer.analyze_instruction(size=len(block_bytes), is_disp=True)

    r2_analyzer.r2.quit()

    os.remove(f'radare_{name}.bin')

    return block_instrs


def get_jump(base_address, address, name=None, is_disp=False):
    assembler = Ks(KS_ARCH_X86, KS_MODE_64)
    # if address > base_address:
    #     jmp_bytes = bytes(assembler.asm(f'jmp {base_address+address}', base_address)[0])
    # else:

    # .byte 0xe9
    # .long {address} - (base_address + 5)

    jump_pattern = f".byte 0xe9\n .long {address} - ({base_address + 5})"

    # jmp_bytes = bytes(assembler.asm(f'jmp {address}', base_address)[0])
    jmp_bytes = bytes(assembler.asm(jump_pattern)[0])

    # create tmp file for Radare2
    with open(f'{name}.bin', 'wb') as file:
        file.write(jmp_bytes)

    r2_analyzer = RadareAnalyzer(f'{name}.bin')

    new_jump = r2_analyzer.analyze_instruction(is_disp=is_disp)[0]

    r2_analyzer.r2.quit()

    # if address <= base_address:
    fake_addr = new_jump['opcode'].split(" ")[1]
    for key, value in new_jump.items():
        if key != 'bytes' and isinstance(new_jump[key], str) and fake_addr in new_jump[key]:
            new_jump[key] = new_jump[key].replace(fake_addr, hex(address))
    new_jump['jump'] = address
    new_jump['opex']['operands'][0]['value'] = address
    new_jump['operands'][0]['value'] = address

    os.remove(f'{name}.bin')

    return new_jump


def displace_node(cfg, node, bytes_to_displace, starting_index, disp_addr):
    # first_disp_addr is the entry point of the first new displaced node
    # last_instr_addr is the address of the last instruction of the last displaced node

    # entry_point = int(0xdeadbeef + last_instr_addr)  # set with a real address
    entry_point = int(disp_addr)
    disp_node = [entry_point, {}]
    disp_bytes = 0
    disp_disasm = []

    left_instrs = [0, {}]  # left_instrs[0] is the entry_point, left_instrs[1] contains the attributes of the node
    left_disasm = []

    radare_sem_nops = []

    # get successor of node to displace
    node_succs = [s for s in cfg.successors(node[0])]

    # node_labels = list(cfg.nodes())

    # if disp_node[0] in node_labels:
    #     print("DISP IS ALREADY DEFINED")
    first_node = list(cfg.nodes(data=True))[0]
    function_ep = first_node[1]['func_addr']

    # add instructions to the new block
    start = time.perf_counter()
    for i, instr in enumerate(node[1]['disasm']):
        if i >= starting_index and disp_bytes + instr['size'] <= bytes_to_displace:
            if disp_bytes == 0:

                jump_to_disp = get_jump(function_ep, entry_point, name=f"disp_{uuid.uuid4()}", is_disp=True)
                # jump_to_disp = get_jump(instr['addr'], entry_point, name=f"disp_{uuid.uuid4()}", is_disp=True)
                jump_to_disp['addr'] = node[1]['disasm'][i]['addr']
                jump_to_disp['trans_type'] = 'displacement'

                # get address of the next instruction to create the jump back from the fake block
                # (check the number of bytes occupied by the jump instruction and then
                # calculate this address)
                jump_back_address = node[1]['disasm'][i]['addr'] + jump_to_disp['size']

                # node[1]['disasm'][i] = jump_to_disp

                # first instruction of the new node that contains semantics-nops and the original instructions
                # set only the entry-point of the new block that will contain the sem-nops and the left instructions
                left_instrs[0] = jump_back_address
                left_instrs[1]['entry_point'] = hex(jump_back_address)
                left_instrs[1]['func_addr'] = function_ep
                left_instrs[1]['original_ep'] = jump_back_address
                left_instrs[1]['text_addr'] = node[1]['text_addr']
                left_instrs[1]['calls'] = node[1]['calls']
                left_instrs[1]['can_disp'] = False
                left_instrs[1]['is_db'] = False

                disp_node[1]['text_addr'] = node[1]['text_addr']
                disp_node[1]['calls'] = node[1]['calls']

                # if left_instrs[0] in node_labels:
                #     print("LEFT IS ALREADY DEFINED")

                if jump_to_disp['size'] > bytes_to_displace:
                    return cfg, disp_addr

                # get semantics-nops to fill the space between the jump and the first instruction after the displacement
                # the address of the first nop will be the entry point of the block
                sem_nops = get_semnop_from_size(bytes_to_displace - jump_to_disp['size'])
                for s_nops in sem_nops:
                    for s_bytes in s_nops['asm_bytes']:
                        radare_sem_nops.append(get_radare_instr(s_bytes, 0x0, name=f"disp_{uuid.uuid4()}"))

            instr['addr'] = entry_point + disp_bytes
            instr['displacement'] = True
            disp_bytes += instr['size']
            disp_disasm.append(instr)
            node[1]['disasm'][i] = None

        elif i >= starting_index and disp_bytes + instr['size'] > bytes_to_displace:
            # insert original instructions into the new block (third one)
            left_disasm.append(instr)
            node[1]['disasm'][i] = None

    # add jump from the splitted node to the displaced block
    node[1]['disasm'][starting_index] = jump_to_disp
    node[1]['disasm'] = [i for i in node[1]['disasm'] if i is not None]
    node_bytes = ''
    block_bb_heads = []
    block_bb_disasm = []
    block_bb_mnems = []
    for instr in node[1]['disasm']:
        node_bytes += instr['bytes']
        block_bb_disasm.append(instr['disasm'])
        block_bb_heads.append(instr['addr'])
        block_bb_mnems.append(instr['mnemonic'])
    node[1]['asm'] = bytes.fromhex(node_bytes)

    node[1]['bb_disasm'] = block_bb_disasm
    node[1]['bb_heads'] = block_bb_heads
    node[1]['bb_mnems'] = block_bb_mnems

    # block_instr = get_radare_instructions(node[1]['asm'])

    # node[1]['can_disp'] = False

    # add to displaced node a jump back to the original block
    jump_back = get_jump(entry_point + disp_bytes, jump_back_address, name=f"disp_{uuid.uuid4()}")
    jump_back['addr'] = entry_point + disp_bytes

    disp_disasm.append(jump_back)
    for idx in range(len(disp_disasm)):
        disp_disasm[idx]['trans_type'] = 'displacement'

    new_bytes = ''
    block_bb_heads = []
    block_bb_disasm = []
    block_bb_mnems = []
    for instr in disp_disasm:
        new_bytes += instr['bytes']
        block_bb_disasm.append(instr['disasm'])
        block_bb_heads.append(instr['addr'])
        block_bb_mnems.append(instr['mnemonic'])

    # update displaced node attributes
    disp_node[1]['func_addr'] = function_ep
    disp_node[1]['disasm'] = disp_disasm
    disp_node[1]['asm'] = bytes.fromhex(new_bytes)
    disp_node[1]['entry_point'] = hex(entry_point)
    disp_node[1]['original_ep'] = entry_point
    disp_node[1]['can_disp'] = False
    disp_node[1]['is_db'] = False
    disp_node[1]['bb_disasm'] = block_bb_disasm
    disp_node[1]['bb_heads'] = block_bb_heads
    disp_node[1]['bb_mnems'] = block_bb_mnems

    # block_instr = get_radare_instructions(disp_node[1]['asm'])

    added_sem_nops = 0
    for s_nop in radare_sem_nops:
        s_nop['addr'] = jump_back_address + added_sem_nops
        added_sem_nops += s_nop['size']

    left_disasm = radare_sem_nops + left_disasm

    for idx in range(len(left_disasm)):
        left_disasm[idx]['trans_type'] = 'displacement'

    left_bytes = ''
    block_bb_heads = []
    block_bb_disasm = []
    block_bb_mnems = []
    for instr in left_disasm:
        left_bytes += instr['bytes']
        block_bb_disasm.append(instr['disasm'])
        block_bb_heads.append(instr['addr'])
        block_bb_mnems.append(instr['mnemonic'])

    # update left instrs node attributes
    left_instrs[1]['disasm'] = left_disasm
    left_instrs[1]['asm'] = bytes.fromhex(left_bytes)
    left_instrs[1]['bb_disasm'] = block_bb_disasm
    left_instrs[1]['bb_heads'] = block_bb_heads
    left_instrs[1]['bb_mnems'] = block_bb_mnems

    # update the cfg by adding the new node and edges
    cfg.add_node(disp_node[0],
                 func_addr=disp_node[1]['func_addr'],
                 entry_point=disp_node[1]['entry_point'],
                 asm=disp_node[1]['asm'],
                 disasm=disp_node[1]['disasm'],
                 original_ep=disp_node[1]['original_ep'],
                 calls=disp_node[1]['calls'],
                 text_addr=disp_node[1]['text_addr'],
                 can_disp=disp_node[1]['can_disp'],
                 is_db=disp_node[1]['is_db'],
                 bb_disasm=disp_node[1]['bb_disasm'],
                 bb_heads=disp_node[1]['bb_heads'],
                 bb_mnems=disp_node[1]['bb_mnems'])
    cfg.add_edge(node[0], disp_node[0])

    # update the cfg adding a new node containing the instructions after the displaced ones
    # add an edge from the displaced code and the new node
    # if len(disasm) == 0 then only last instr of previous block has been displaced so is not
    # necessary to insert the left_instrs node
    if len(left_instrs[1]['disasm']) > 0:
        cfg.add_node(left_instrs[0],
                     func_addr=left_instrs[1]['func_addr'],
                     entry_point=left_instrs[1]['entry_point'],
                     asm=left_instrs[1]['asm'],
                     disasm=left_instrs[1]['disasm'],
                     original_ep=left_instrs[1]['original_ep'],
                     calls=left_instrs[1]['calls'],
                     text_addr=disp_node[1]['text_addr'],
                     can_disp=left_instrs[1]['can_disp'],
                     is_db=left_instrs[1]['is_db'],
                     bb_disasm=left_instrs[1]['bb_disasm'],
                     bb_heads=left_instrs[1]['bb_heads'],
                     bb_mnems=left_instrs[1]['bb_mnems'])
    # else:
    #     print("CASE 0")
    cfg.add_edge(disp_node[0], left_instrs[0])

    # remove outgoing edges from the original node and add new edges from the node containing
    # the original instructions to the successors of the original node
    for succ in node_succs:
        if succ != entry_point:
            cfg.remove_edge(node[0], succ)
            cfg.add_edge(left_instrs[0], succ)

    end = time.perf_counter()
    # print(f"Time to displace: {end - start}")

    next_ep = jump_back['addr'] + jump_back['size']

    return cfg, next_ep
