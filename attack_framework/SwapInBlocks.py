import networkx as nx
from copy import deepcopy
from multiprocessing import Pool
import random

from Attack import Attack

from transformations.instr_swap import swap_single_instr


def parallel_instr_swap(parameters):
    source_cfg = parameters[0]
    node = parameters[1]
    instr_addr = parameters[2]

    new_blocks = {}

    block = node[1]
    for instr in block['disasm']:
        if instr['addr'] == instr_addr:
            swap_result = swap_single_instr(block, block['disasm'][0]['addr'], instr_addr,
                                            detailed_logger=None)
            if swap_result:
                new_blocks[node[0]] = swap_result

                new_bb_heads = []
                new_bb_disasm = []
                new_bb_mnems = []
                for n_ins in new_blocks[node[0]][0]:
                    new_bb_disasm.append(n_ins['disasm'])
                    new_bb_heads.append(n_ins['addr'])
                    new_bb_mnems.append(n_ins['mnemonic'])

                new_attrs = {node[0]: {'disasm': new_blocks[node[0]][0], 'asm': new_blocks[node[0]][1],
                                       # added by Tong
                                       'bb_disasm': new_bb_disasm,
                                       'bb_heads': new_bb_heads,
                                       'bb_mnems': new_bb_mnems

                                       }}
                nx.set_node_attributes(source_cfg, new_attrs)
            return source_cfg

    return None


def apply_swap_for_optimizer(source_cfg, node_addr, instr_addr):
    new_cfg = parallel_instr_swap([source_cfg, (node_addr, source_cfg.nodes[node_addr]), instr_addr])

    return new_cfg
