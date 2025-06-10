def filter_reg(op):
    return op["value"]


def filter_imm(op):
    imm = int(op["value"])
    if -int(5000) <= imm <= int(5000):
        ret = str(hex(op["value"]))
    else:
        ret = str('HIMM')
    return ret


def filter_mem(op):
    if "base" not in op:
        op["base"] = 0
    if op["base"] == 0:
        r = "[" + "MEM" + "]"
    else:
        reg_base = str(op["base"])
        disp = str(op["disp"])
        scale = str(op["scale"])
        r = '[' + reg_base + "*" + scale + "+" + disp + ']'
    return r


def filter_memory_references(i):
    inst = "" + i["mnemonic"]
    for op in i["operands"]:
        if op["type"] == 'reg':
            inst += " " + filter_reg(op)
        elif op["type"] == 'imm':
            inst += " " + filter_imm(op)
        elif op["type"] == 'mem':
            inst += " " + filter_mem(op)
        if len(i["operands"]) > 1:
            inst = inst + ","
    if "," in inst:
        inst = inst[:-1]
    inst = inst.replace(" ", "_")
    return str(inst)


def function_to_inst(instruction, arch='x86'):
    stringized = filter_memory_references(instruction)
    if arch == 'x86':
        filtered_instruction = "X_" + stringized
    elif arch == 'arm':
        filtered_instruction = "A_" + stringized
    else:
        filtered_instruction = "UNK_" + stringized
    return filtered_instruction


def filter_instructions(cfg):

    sorted_nodes = sorted(cfg.nodes(data=True), key=lambda x: x[0])

    cfg_inst = []
    for n in sorted_nodes:
        n_inst = n[1]['disasm']

        cfg_inst.append(n_inst)

    instructions = []
    for block in cfg_inst:
        for inst in block:
            instructions.append(function_to_inst(inst))
    return instructions


def parallel_filter_instructions(cfg):

    return filter_instructions(cfg)
