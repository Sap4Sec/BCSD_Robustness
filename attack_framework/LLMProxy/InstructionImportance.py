from tqdm import tqdm
import pandas as pd
import time
import random
import networkx as nx
import sys

random.seed(10)

sys.path.append('../')

from copy import deepcopy

x86_equal_jump = ['jz', 'je', 'jb', 'jc', 'jo', 'js', 'jg', 'jl', 'ja', 'jp', 'jpe', 'jnle', 'jnbe', 'jnge', 'jnae']
x86_no_equal_jump = ['jnz', 'jne', 'jnb', 'jae', 'jnc', 'jno', 'jns', 'jng', 'jle', 'jnl', 'jge', 'jna', 'jbe', 'jnp',
                     'jpo']
x86_branch = x86_equal_jump + x86_no_equal_jump


def get_positions(model, source_cfg, initial_similarity, top_k, pool, use_importance=True, variant_idx=None,
                  logger=None):
    parameters = []
    for n in source_cfg.nodes(data=True):
        block_id = n[0]
        block = n[1]
        for instr in block['disasm']:
            if instr['mnemonic'] == 'ret' or instr['mnemonic'] == 'jmp' or instr['mnemonic'] in x86_branch or instr[
                'mnemonic'] == 'cmp' or instr['mnemonic'] == 'call':
                continue
            parameters.append([source_cfg, block_id, instr['addr']])

    if logger is not None:
        start = time.perf_counter()
    new_cfgs = pool.map(parallel_instr_remove, parameters)
    if logger is not None:
        end = time.perf_counter()
        logger.info(f"[Importance] Remove instructions for importance: {end - start}")

    if use_importance:
        if logger is not None:
            start = time.perf_counter()
        similarities = model.evaluate_batch(new_cfgs, pool,
                                            variant_idx) if variant_idx is not None else model.evaluate_batch(new_cfgs,
                                                                                                              pool)
        if logger is not None:
            end = time.perf_counter()
            logger.info(f"[Importance] Run model in batch for Importance: {end - start}")

        absolute_diffs = [abs(sim - initial_similarity) for sim in similarities]

        top = top_k if len(absolute_diffs) > top_k else len(absolute_diffs)

        best_indices = sorted(range(len(absolute_diffs)), key=lambda i: absolute_diffs[i], reverse=True)[
                       :top]

        best_instrs = [[parameters[i][1], parameters[i][2]] for i in best_indices]

        return best_instrs

    indices = random.sample(range(len(new_cfgs)), top_k if len(new_cfgs) > top_k else len(new_cfgs))
    best_instrs = [[parameters[i][1], parameters[i][2]] for i in indices]
    del new_cfgs
    gc.collect()

    return best_instrs


def delete_from_func(block_id, instr_addr, source_cfg):
    for instr in source_cfg.nodes[block_id]['disasm']:
        if instr['addr'] == instr_addr:
            source_cfg.nodes[block_id]['disasm'].remove(instr)
            break

    return source_cfg


def copy_node(node_attrs):
    new_node = {
        'func_addr': node_attrs['func_addr'],
        'entry_point': node_attrs['entry_point'],
        'original_ep': node_attrs['original_ep'],
        'asm': node_attrs['asm'],
        'disasm': deepcopy(node_attrs['disasm']),
        'calls': node_attrs['calls'],
        'text_addr': node_attrs['text_addr'],
        'can_disp': node_attrs['can_disp'],
        'is_db': node_attrs['is_db'],
        'bb_disasm': node_attrs['bb_disasm'],
        'bb_heads': node_attrs['bb_heads'],
        'bb_mnems': node_attrs['bb_mnems']
    }

    return new_node


def parallel_instr_remove(parameters):
    source_cfg = parameters[0]
    block_id = parameters[1]
    instr_addr = parameters[2]

    new_cfg = nx.DiGraph()
    new_data = copy_node(source_cfg.nodes[block_id])

    for node, data in source_cfg.nodes(data=True):
        if node == block_id:
            new_cfg.add_node(block_id, **new_data)
        else:
            new_cfg.add_node(node, **data)

    new_cfg.add_edges_from(source_cfg.edges(data=True))

    new_cfg.graph.update(source_cfg.graph)

    return delete_from_func(block_id, instr_addr, new_cfg)
