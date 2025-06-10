import pyvex
import archinfo

import pickle

from copy import deepcopy

from transformations.SlicerArchIndep import Slicer

slicer = Slicer(debug=False)


def get_swappable(block_instrs, block_bytes, block_addr):
    try:
        asm_instructions, asm2vex = slicer.lift_bytes(block_instrs, block_bytes, block_addr)
        strands = slicer.retrieve_ir_strands_from_ref_def(asm_instructions, asm2vex)
    except Exception as e:
        print(e)

        """
        print(f"Entry point: {block_addr}")
        for instr in block_instrs:
            print(f"{instr['addr']} \t {instr['disasm']}")
        """
        return None

    is_swappable = []
    for i, instr in enumerate(asm_instructions[:-2]):

        for strand in strands:
            if asm2vex[asm_instructions[i]]['disasm'] in strand and asm2vex[asm_instructions[i + 1]][
                'disasm'] in strand:
                are_dependent = True
                break
        # if 'call' in asm2vex[asm_instructions[i]]['disasm'] or 'call' in asm2vex[asm_instructions[i+1]]['disasm']:
        # cannot swap a call instruction with its successor or predecessor
        #    are_dependent = True
        else:
            checkWAR = slicer.check_dependence(asm2vex[asm_instructions[i]]['iref'],
                                               asm2vex[asm_instructions[i + 1]]['idef'])
            checkWAW = slicer.check_dependence(asm2vex[asm_instructions[i]]['idef'],
                                               asm2vex[asm_instructions[i + 1]]['idef'])
            checkRAW = slicer.check_dependence(asm2vex[asm_instructions[i]]['idef'],
                                               asm2vex[asm_instructions[i + 1]]['iref'])
            are_dependent = checkWAR or checkWAW or checkRAW
        is_swappable.append(not are_dependent)

    return is_swappable


def block_pp(block):
    for instr in block:
        print(f"{hex(instr['addr'])}\t {instr['disasm']}")


def swap_single_instr(block, address, instr_addr, detailed_logger=None):
    is_swappable = get_swappable(block['disasm'], block['asm'], address)

    if is_swappable:
        not_swapped = list(range(0, len(block['disasm'][:-2])))

        new_block = deepcopy(block['disasm'])
        for i, instr in enumerate(block['disasm'][:-2]):

            if instr['addr'] == instr_addr and i in not_swapped and is_swappable[
                i]:  # can swap instruction i with the next one
                new_block[i], new_block[i + 1] = deepcopy(block['disasm'][i + 1]), deepcopy(block['disasm'][i])
                # Adjust addresses
                new_block[i]['addr'] = new_block[i + 1]['addr']
                new_block[i + 1]['addr'] = new_block[i]['addr'] + new_block[i]['size']
                not_swapped.remove(i)
                if i + 1 in not_swapped:  # avoid error on last instruction
                    not_swapped.remove(i + 1)
                if detailed_logger:
                    detailed_logger.info(
                        f"[Swapper] Swapped {block['disasm'][i]['disasm']} <---> {block['disasm'][i + 1]['disasm']}")

                break
        # block_pp(new_block)

        new_block_bytes = b''
        for ins in new_block:
            new_block_bytes += bytes.fromhex(ins['bytes'])

        return new_block, new_block_bytes

    return None


if __name__ == "__main__":
    slicer = Slicer(debug=False)

    function_cfg = "/app/vol/CFGExtractor/extracted_cfgs_variants_angr_zeek_6000/x64-clang-O0_aacps_common.o_read_ipdopd_data.pkl"

    with open(function_cfg, 'rb') as file:
        loaded_graph = pickle.load(file)

    cfg = loaded_graph['cfg']

    node = list(cfg.nodes(data=True))[0]
    block = node[1]

    is_swappable = get_swappable(block['disasm'], block['asm'], node[0])

    print("OK")

