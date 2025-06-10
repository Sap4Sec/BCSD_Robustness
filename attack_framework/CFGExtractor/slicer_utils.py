import pyvex.stmt as vex_stm

import random
from datetime import datetime

import itertools

import networkx as nx

# rdi, rsi, rdx, rcx, r8, r9
cc_reg_offsets = [72, 64, 32, 24, 80, 88]


# Given a strand, returns its shellcode
def get_shellcode_by_strand(strand):
    shellcode = bytearray()
    for i in range(len(strand)):
        try:
            shellcode += strand[i][1].insn.bytes
        except Exception:
            continue
    return shellcode


# Given a strand, returns its string representation
def get_string_by_strand(strand, called_name):
    string_representation = ""
    for _, instruction in strand:
        if "call" in instruction.mnemonic and called_name:
            string_representation += str(instruction).replace(instruction.op_str, called_name) + "\n"
        else:
            string_representation += str(instruction) + "\n"
    return string_representation


def remove_subsets(machine_strands):
    x = {}
    for i in machine_strands:
        x[tuple(i)] = 0
    y = x.copy()
    for a in x:
        for b in x:
            if id(a) != id(b):
                if set(a) <= set(b):
                    if a in y:
                        y.pop(a)
    z = []
    for k in y:
        s = []
        for i in k:
            s.append(i)
        z.append(s)
    return z


def order_set(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


def needed_vex(definitions, references):
    return set(references).intersection(definitions)


def vex_to_machine(statement, block_vex, block_asm):
    last_imark = None

    for i, x in enumerate(block_vex):
        if isinstance(x, vex_stm.IMark):
            last_imark = x
        if statement == i:
            break

    if last_imark is not None:
        last_address = last_imark.addr
        for ins_idx, ins in enumerate(block_asm):
            if last_address == ins.address:
                return ins_idx, ins

    return None


def random_walk(g, max_paths=20, max_depth=50):
    paths = []
    random.seed(datetime.now())

    for n in range(0, max_paths):
        current_node = [node for node in g if node == -1][0]
        path = []
        while len(path) < max_depth:
            successors = list(g.successors(current_node))
            if len(successors):
                current_node = random.choice(successors)
                path.append(current_node)
            else:
                break
        if path not in paths:
            paths.append(path)

    # remove duplicated paths
    paths.sort()
    paths_no_dup = list(k for k, _ in itertools.groupby(paths))
    return paths_no_dup


def build_nx_graph(function_nodes, function_edges):

    nx_graph = nx.DiGraph()
    nx_graph.add_node(-1)

    if len(function_nodes) == 0:
        return nx_graph

    nx_graph.add_nodes_from(function_nodes)
    nx_graph.add_edges_from(function_edges)

    for node in nx_graph.nodes:
        if not nx_graph.in_degree(node) and node != -1:
            nx_graph.add_edge(-1, node)

    if nx_graph.out_degree(-1) == 0:
        nx_graph.add_edge(-1, min(map(lambda x: x, function_nodes)))

    return nx_graph
