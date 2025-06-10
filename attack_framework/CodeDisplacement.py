from transformations.displacement import displace_node

BYTES_TO_DISPLACE = 8


x86_equal_jump = ['jz', 'je', 'jb', 'jc', 'jo', 'js', 'jg', 'jl', 'ja', 'jp', 'jpe', 'jnle', 'jnbe', 'jnge', 'jnae']
x86_no_equal_jump = ['jnz', 'jne', 'jnb', 'jae', 'jnc', 'jno', 'jns', 'jng', 'jle', 'jnl', 'jge', 'jna', 'jbe', 'jnp', 'jpo']
x86_branch = x86_equal_jump + x86_no_equal_jump


def select_starting_index(node, instr_addr=None):

    if len(node[1]['disasm']) < 2:
        return 0, -1

    instr_index = node[1]['disasm'].index(next(d for d in node[1]['disasm'] if d.get('addr') == instr_addr))

    # if the targeted block contains only one instruction then it is not a valid block where to insert
    # the perturbation
    if instr_index == len(node[1]['disasm']) - 1 or instr_index == 0:
        return 0, -1

    sum_bytes = 0
    for instr in (node[1]['disasm'][instr_index:-1]):
        if instr['mnemonic'] == 'ret' or instr['mnemonic'] == 'jmp' or instr['mnemonic'] in x86_branch or instr['mnemonic'] == 'cmp' or instr['mnemonic'] == 'call':
            break
        else:
            sum_bytes += instr['size']

    bytes_to_displace = min(sum_bytes, BYTES_TO_DISPLACE)

    # round number of bytes to displace
    if bytes_to_displace != 0:
        r_bytes_to_displace = node[1]['disasm'][instr_index]['size']
        i = 1
        while r_bytes_to_displace < bytes_to_displace:
            r_bytes_to_displace += node[1]['disasm'][instr_index + i]['size']
            i += 1
        return r_bytes_to_displace, instr_index
    return 0, instr_index


def parallel_code_displacement(parameters):
    source_cfg = parameters[0]
    node = parameters[1]
    instr = parameters[2]
    source_addr_for_disp = parameters[3]
    last_disp_addr = source_addr_for_disp

    if node[1]['can_disp']:
        r_bytes_to_displace, starting_index = select_starting_index(node, instr_addr=instr)

        if r_bytes_to_displace == 0 and starting_index == -1:
            return source_cfg, last_disp_addr

        if r_bytes_to_displace != 0 and starting_index:
            source_cfg, last_disp_addr = displace_node(source_cfg, node, r_bytes_to_displace, starting_index,
                                                       source_addr_for_disp)

        node[1]['can_disp'] = False

    return source_cfg, last_disp_addr


def apply_disp_for_optimizer(source_cfg, chosen_node, instr_addr, source_addr_for_disp):
    displaced_cfg, new_disp_addr = parallel_code_displacement(
        [source_cfg, (chosen_node, source_cfg.nodes[chosen_node]), instr_addr,
         source_addr_for_disp])

    return displaced_cfg, new_disp_addr
