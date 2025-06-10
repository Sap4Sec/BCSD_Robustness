#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pickle

import angr
import pyvex.stmt as vex_stm
import pyvex.expr as vex_expr

import pyvex
import archinfo

import copy

# rdi, rsi, rdx, rcx, r8, r9
cc_reg_offsets = [72, 64, 32, 24, 80, 88]

rip_offset = 184


def vex_to_x86_mapping():
    reg_list = archinfo.arch_from_id('x86_64').register_list

    x86_map = {}

    """
    for reg in reg_list:
        if reg.vex_offset not in x86_map:
            x86_map[reg.vex_offset] = [(reg.name, reg.size)]
            for subreg in reg.subregisters:
                x86_map[reg.vex_offset].append((subreg[0], subreg[2]))
    """
    for reg in reg_list:
        if reg.vex_offset not in x86_map:
            x86_map[reg.vex_offset] = reg.name

    return x86_map


def x86_subregisters():
    reg_list = archinfo.arch_from_id('x86_64').register_list

    x86_map = {}

    for reg in reg_list:
        if reg.vex_offset not in x86_map:
            x86_map[reg.vex_offset] = [(reg.name, reg.size)]
            for subreg in reg.subregisters:
                x86_map[reg.vex_offset].append((subreg[0], subreg[2]))

    return x86_map


class Slicer:
    inst_set = None

    def __init__(self, debug=False):
        self.debug = debug
        self.x86_mapping = vex_to_x86_mapping()
        self.subreg_mapping = x86_subregisters()
        nop = 0

    def map_reg_from_size(self, offset, size):
        reg_list = self.x86_mapping[offset]
        to_ret = []
        for el in reg_list:
            if el[1] == size:
                to_ret.append(el[0])
        return to_ret

    def get_shellcode(self, strand):
        shellcode = bytearray()
        for i in range(0, len(strand)):
            shellcode += strand[i].insn.bytes
        return shellcode

    def get_string(self, strand, called_name):
        stringInst = ""
        for inst in strand:
            if "call" in inst.mnemonic and called_name:
                stringInst += str(inst).replace(inst.op_str, called_name) + "\n"
            else:
                stringInst += str(inst) + "\n"
        return stringInst

    # prende una espressione Vex e mi ritorna le variabili usate
    # Parsa l'espressione a seconda della semantica
    # For instance for the expression  Sub64(t15,0x0000000000000008) it returns T15
    def parse_expression(self, exp):
        vars = []

        if isinstance(exp, vex_expr.Get):
            """
            Read a guest register, at a fixed offset in the guest state.
            """
            vars.append("R" + str(exp.offset))  # registro
            # vars.append(self.x86_mapping[exp.offset])

        elif isinstance(exp, vex_expr.GetI):  # check ty_int
            """
            Read a guest register at a non-fixed offset in the guest state.
            """
            if hasattr(exp, "offset"):
                vars.append("R" + str(exp.offset))  # registro
                # vars.append(self.x86_mapping[exp.offset])

        elif isinstance(exp, vex_expr.Load):  # this expr load the value stored at a memory address
            """
            A load from memory.
            """
            addr = exp.addr  # the address specified by another IR Expression (Recursion Needed).
            vars = vars + self.parse_expression(addr)

        elif isinstance(exp, vex_expr.RdTmp):
            """
            Read the value held by a temporary.
            """
            vars.append("T" + str(exp.tmp))

        elif isinstance(exp, vex_expr.Const):
            """
            A constant expression.
            """
            # costante non fare nulla
            nop = 0

        elif isinstance(exp, vex_expr.CCall):
            """
            A call to a pure (no side-effects) helper C function.
            """

            for x in exp.args:
                vars = vars + self.parse_expression(x)

        elif isinstance(exp, vex_expr.Binop) or isinstance(exp, vex_expr.Unop) \
                or isinstance(exp, vex_expr.Triop) or isinstance(exp, vex_expr.Qop):
            """
            Binop: A binary operation (2 arguments)
            Unop: A unary operation (1 argument)
            Triop: A ternary operation (3 arguments)
            Qop: A quaternary operation (4 arguments)
            """
            for x in exp.args:
                vars = vars + self.parse_expression(x)

        elif isinstance(exp, vex_expr.ITE):
            """
            An if-then-else expression.
            """
            vars = vars + self.parse_expression(exp.cond)
            vars = vars + self.parse_expression(exp.iffalse)
            vars = vars + self.parse_expression(exp.iftrue)

        return vars

    # Returns definitions and references of a vex statement
    # For example for the statement t0 = GET:I64(offset=56) it returns (['T0'], ['R56'])
    def _ref_def_vex(self, vex_instr, num_args, call_ins_address):
        if self.debug:
            print(vex_instr)

        Def = []
        Ref = []

        if isinstance(vex_instr, vex_stm.WrTmp):
            """
            Assign a value to a temporary.  Note that SSA rules require each tmp is only assigned to once. 
            IR sanity checking will reject any block containing a temporary which is not assigned to exactly once.
            """
            data = vex_instr.data
            Ref = Ref + self.parse_expression(data)
            Def = Def + ["T" + str(vex_instr.tmp)]

        elif isinstance(vex_instr, vex_stm.NoOp) or isinstance(vex_instr, vex_stm.Exit):
            nop = 0

        elif isinstance(vex_instr, vex_stm.Put):
            """
            Write to a guest register, at a fixed offset in the guest state.
            """
            data = vex_instr.data
            if vex_instr.offset != rip_offset:  # check for rip write
                Ref = Ref + self.parse_expression(data)
                # Def = Def + [self.x86_mapping[vex_instr.offset]]  # offset = ID registro (per mapping)
                Def = Def + ['R' + str(vex_instr.offset)]

        elif isinstance(vex_instr, vex_stm.PutI):
            """
            Write to a guest register, at a non-fixed offset in the guest state.
            """
            # TODO **to implement??
            nop = 0

        elif isinstance(vex_instr, vex_stm.Store):
            """
            Write a value to memory..
            """
            data = vex_instr.data
            Ref = Ref + self.parse_expression(data)
            Def = Def + self.parse_expression(vex_instr.addr)  # Modificato da Ref a Def

        elif isinstance(vex_instr, vex_stm.CAS):
            """
            an atomic compare-and-swap operation.
            """
            # TODO
            nop = 0

        elif isinstance(vex_instr, vex_stm.LLSC):
            """
            Either Load-Linked or Store-Conditional, depending on STOREDATA. If STOREDATA is NULL then this 
            is a Load-Linked, else it is a Store-Conditional.
            """
            Ref = Ref + self.parse_expression(vex_instr.addr)
            Def = Def + ["T" + str(vex_instr.result)]

        elif isinstance(vex_instr, vex_stm.Dirty):
            nop = 0

        elif isinstance(vex_instr, vex_stm.MBE):
            # Done checked the instruction does nothing
            nop = 0

        elif isinstance(vex_instr, vex_stm.LoadG):
            """
            A guarded load.
            """
            # TODO to check
            Ref = Ref + self.parse_expression(vex_instr.addr)
            Def = Def + ["T" + str(vex_instr.dst)]

        elif isinstance(vex_instr, vex_stm.StoreG):
            """
            A guarded store.
            """
            # TODO to check
            data = vex_instr.data
            Ref = Ref + self.parse_expression(data)
            Ref = Ref + self.parse_expression(vex_instr.addr)

        elif isinstance(vex_instr, vex_stm.IMark):
            if vex_instr.addr == call_ins_address:
                for i in range(0, min(num_args, len(cc_reg_offsets))):
                    if str(cc_reg_offsets[i]) == '184':
                        print("found")
                    Ref.append("R" + str(cc_reg_offsets[i]))
                Def.append("R16")

        return Def, Ref

    def needed_vex(self, Def, Ref):  # variabili scritte da i confrontate con quelle lette da i+1
        needed = []
        for refVar in Ref:
            for defVar in Def:
                if refVar == defVar:
                    needed.append(refVar)
        return needed

    # For each referenced variable, it looks at its expression in global dictionary
    # and performs a substitution
    def iterate_expression(self, global_expressions, expressions):
        solved_expression = {}
        for e in expressions:
            # if it is reading from a tmp var
            if isinstance(e, vex_expr.RdTmp):
                # if the tmp var was already defined
                if e.tmp in global_expressions:
                    solved_expression[e.tmp] = global_expressions[e.tmp]
                # keep its tmp name
                else:
                    solved_expression[e.tmp] = 't' + str(e.tmp)
            # in any case, let's analyze smaller expression
            solved_expression.update(self.iterate_expression(global_expressions, e.child_expressions))
        return solved_expression

    # Questa funzione dato un statement vex mi ritorna l'espressione dello statement con
    # le variabili espanse'
    def get_instr_string(self, dictionary, instruction):
        instString = ''
        # if(not isinstance(instruction,vex_stm.IMark)):
        if hasattr(instruction, 'data'):
            innerDict = self.iterate_expression(dictionary, instruction.expressions)

            if isinstance(instruction.data, vex_expr.Unop):
                if isinstance(instruction.data.args[0], vex_expr.RdTmp):
                    instString = str(instruction.data.args[0].tmp)

            elif isinstance(instruction, vex_stm.Store):
                instString = str(instruction.addr)

            else:
                instString = str(instruction.data)

            for item in innerDict.keys():
                variable = 't' + str(item)
                instString = instString.replace(variable, innerDict[item])

        return instString

    def check_dependence(self, vars1, vars2):

        # needed = []

        for v1 in vars1:
            if v1 in vars2:  # se v1 acceduto da i1 viene acceduto anche da i2 allora i1 e i2 sono dipendenti
                return True \
                    # needed.append(v1)

        # return needed
        return False  # qua ci stanno i registri acceduti da entrambe le istruzioni

    def return_dependences(self, vars1, vars2):

        needed = []

        for v1 in vars1:
            if v1 in vars2:  # se v1 acceduto da i1 viene acceduto anche da i2 allora i1 e i2 sono dipendenti
                needed.append(v1)

        return needed

    def needed_vex(self, definitions, references):
        return set(references).intersection(definitions)

    def extract_independent_instructions(self, instructions, asm2vex, hazard="WAR"):
        available_indices = list(range(0, len(instructions) - 1))

        dependency_list = []

        instr_number = len(instructions) - 1

        while (len(available_indices)) > 0:
            minUsed = min(available_indices)
            available_indices.remove(minUsed)

            dependentInstrs = [instructions[minUsed]]

            varsRef = asm2vex[instructions[minUsed]]['iref']
            varsDef = asm2vex[instructions[minUsed]]['idef']

            for i in range(minUsed + 1, instr_number):
                to_test = instructions[i]

                if hazard == "WAR":
                    needed = self.return_dependences(varsRef, asm2vex[to_test]['idef'])  # WAR dependency
                elif hazard == "WAW":
                    needed = self.return_dependences(varsDef, asm2vex[to_test]['idef'])  # WAW dependency
                else:
                    needed = self.return_dependences(varsDef, asm2vex[to_test]['iref'])  # RAW dependency

                if len(needed) > 0:
                    dependentInstrs.append(instructions[i])

                    for item in needed:
                        if hazard == "WAR":
                            varsRef.remove(item)
                        elif hazard == "WAW":
                            varsDef.remove(item)
                        else:
                            varsDef.remove(item)

                    varsDef.extend(asm2vex[to_test]['idef'])
                    varsRef.extend(asm2vex[to_test]['iref'])
                    if i in available_indices:
                        available_indices.remove(i)
                """
                if not depends:
                    if i-minUsed == 1:  # consecutive instructions
                        break  # can swap
                    continue
                else:
                    dependentInstrs.append(instructions[i])
                """

            dependency_list.append(dependentInstrs)

        return dependency_list

    def extract_ref_def(self, instructions, num_args=0, call_ins_address=None):

        references = []
        definitions = []
        strands = []

        # This dictionary is used to save vars expressions
        vars_expressions = {}

        # This dictionary stores complete expression of variables that contain address of a load or store op
        stores_loads_dict = {}

        if instructions is None:
            return strands

        for inst in instructions:
            if inst:
                instr_string = self.get_instr_string(vars_expressions, inst)
                # print "instString"+str(instString)

                i_stores_loads_dict = {}

                idef, iref = self._ref_def_vex(inst, num_args, call_ins_address)

                if isinstance(inst, vex_stm.WrTmp):
                    vars_expressions[inst.tmp] = instr_string

                    # if load instruction, save its address in tmpDict
                    if isinstance(list(inst.expressions)[0], vex_expr.Load):
                        # TODO TO CHECK
                        try:
                            var = list(inst.expressions)[1].tmp
                            if var in vars_expressions.keys():
                                i_stores_loads_dict['ld_' + str(var)] = vars_expressions[var]
                                iref.append(vars_expressions[var])
                        except AttributeError:
                            pass

                # Se ho uno statement store salvo l'indirizzo nel dizionario storeLoad
                if isinstance(inst, vex_stm.Store):
                    # TODO to check
                    try:
                        var = list(inst.expressions)[0].tmp
                        if var in vars_expressions.keys():
                            i_stores_loads_dict['st_' + str(var)] = vars_expressions[var]
                            idef.append(instr_string)
                            # queryStr = instDictionary[inst.expressions[0].tmp]
                    except AttributeError:
                        pass

                stores_loads_dict.update(i_stores_loads_dict)
            else:
                idef = []
                iref = []

            definitions.append(idef)
            references.append(iref)

        assert (len(definitions) == len(references))

        return definitions, references

    def _extract_strand_IR(self, instructions, asm2vex, n_args=0, call_ins_address=None):
        strands = []
        if instructions is None:
            return strands
        # references, definitions = self.get_def_use(instructions, n_args, call_ins_address)
        strands = self.retrieve_ir_strands_from_ref_def(instructions, asm2vex)
        return strands

    def retrieve_ir_strands_from_ref_def(self, instructions, asm2vex):

        strands = []

        unused_instructions = list(range(0, len(instructions)))

        while len(unused_instructions) > 0:

            # max_id = max(unused_instructions)
            # unused_instructions.remove(max_id)

            max_id = unused_instructions[-1]
            unused_instructions = unused_instructions[:-1]

            new_strand = [asm2vex[instructions[max_id]]['disasm']]
            i_references = asm2vex[instructions[max_id]]['iref']
            i_definitions = asm2vex[instructions[max_id]]['idef']

            for i in reversed(range(0, max_id)):

                current_instruction = instructions[i]
                need = self.needed_vex(asm2vex[instructions[i]]['idef'], i_references)

                if len(need) > 0:
                    new_strand.insert(0, copy.copy(asm2vex[instructions[i]]['disasm']))

                    for item in need:
                        i_references.remove(item)

                    i_references.extend(asm2vex[instructions[i]]['iref'])
                    i_definitions.extend(asm2vex[instructions[i]]['idef'])

                    if i in unused_instructions:
                        unused_instructions.remove(i)

            # new_strand.reverse()
            strands.append(new_strand)
        return strands

    def vex_to_machine(self, block, statement):
        last_imark = None
        irsb = block.vex
        last_address = 0
        for x in irsb.statements:
            if isinstance(x, vex_stm.IMark):
                last_imark = x
            if str(statement) == str(x):
                break
        if not (last_imark is None):
            last_address = last_imark.addr
            for ins in block.capstone.insns:
                if last_address == ins.address:
                    return ins
        return None

    def machine_to_vex(self, irsb, instr):
        first_imark = None
        # irsb = block.vex
        vex_instrs = []
        for x in irsb.statements:
            if isinstance(x, vex_stm.IMark):
                if x.addr == instr['addr']:
                    first_imark = x
                else:
                    first_imark = None
            if first_imark:
                vex_instrs.append(x)
        return vex_instrs

    def convert_vex_strands_to_machine_strands(self, vex_strands, block):
        machine_strands = []
        pointer = 0
        for x in vex_strands:
            if self.debug:
                print("Strand Vex" + str(pointer))
                for it in x:
                    print(it)
                pointer = pointer + 1
            asm = []
            if self.debug:
                print("Strand Machine Language" + str(pointer))
            for it in x:
                asm = asm + [self.vex_to_machine(block, it)]
            asm = self.order_set(asm)
            if self.debug:
                print(asm)
            machine_strands.append(asm)
        return self.remove_subsets(machine_strands)

    def remove_subsets(self, machine_strands):
        x = {}
        for i in machine_strands:
            x[tuple(i)] = 0
        y = x.copy()
        for a in x:
            for b in x:
                if (id(a) != id(b)):
                    if set(a) <= set(b):
                        if (a in y.keys()):
                            y.pop(a)
        l = []
        for k in y.keys():
            s = []
            for i in k:
                s.append(i)
            l.append(s)
        return l

    def order_set(self, seq):
        seen = set()
        seen_add = seen.add
        return [x for x in seq if not (x in seen or seen_add(x))]

    def get_block_vex_inst(self, block):
        # statements = []
        # if block.capstone.insns:
        #     address = block.capstone.insns[-1].address
        #     for item in block.vex.statements + [block.vex.next]:
        #         if(isinstance(item,vex_stm.IMark)):
        #             if(item.addr == address):
        #                 break;
        #             else:
        #                 statements.append(item)
        #         else:
        #                 statements.append(item)
        statements = block.vex.statements  # + [block.vex.next]
        return statements

    def lift_bytes(self, block_instrs, block_bytes, block_addr):

        lifted_block = pyvex.IRSB(block_bytes, block_addr, archinfo.arch_from_id('x86_64'), opt_level=0)

        asm_instructions = []
        asm2vex = {}
        for instr in block_instrs:
            if instr['addr'] in lifted_block.instruction_addresses:
                instr_addr = instr['addr']
                instr_disasm = instr['disasm']
                asm_instructions.append(instr_addr)
                asm2vex[instr_addr] = {'vex': self.machine_to_vex(lifted_block, instr)}
                idef, iref = self.extract_ref_def(asm2vex[instr_addr]['vex'])
                asm2vex[instr_addr]['idef'] = [var1 for defs in idef for var1 in defs]
                asm2vex[instr_addr]['iref'] = [var2 for refs in iref for var2 in refs]
                asm2vex[instr_addr]['disasm'] = instr_disasm
            else:
                # lift remaining portion of the block
                new_block_bytes = b''
                for ins in block_instrs[len(lifted_block.instruction_addresses):]:
                    new_block_bytes += bytes.fromhex(ins['bytes'])
                lifted_block = pyvex.IRSB(new_block_bytes, instr['addr'], archinfo.arch_from_id('x86_64'), opt_level=0)
                instr_addr = instr['addr']
                instr_disasm = instr['disasm']
                asm_instructions.append(instr_addr)
                asm2vex[instr_addr] = {'vex': self.machine_to_vex(lifted_block, instr)}
                idef, iref = self.extract_ref_def(asm2vex[instr_addr]['vex'])
                asm2vex[instr_addr]['idef'] = [var1 for defs in idef for var1 in defs]
                asm2vex[instr_addr]['iref'] = [var2 for refs in iref for var2 in refs]
                asm2vex[instr_addr]['disasm'] = instr_disasm

        return asm_instructions, asm2vex

    def lift_radare_block(self, block_instrs, block_bytes, block_addr):

        lifted_block, processed_blocks = [], []

        _lifted_block = pyvex.IRSB(block_bytes, block_addr,
                                   archinfo.arch_from_id('x86_64'), opt_level=0)

        for i, instr in enumerate(block_instrs):
            if instr['addr'] not in _lifted_block.instruction_addresses:
                # lifted_block.extend(self.machine_to_vex(_lifted_block, instr))
                new_block_bytes = b''
                for ins in block_instrs[len(_lifted_block.instruction_addresses):]:
                    new_block_bytes += bytes.fromhex(ins['bytes'])
                _lifted_block = pyvex.IRSB(new_block_bytes, instr['addr'],
                                           archinfo.arch_from_id('x86_64'), opt_level=0)
            if _lifted_block not in processed_blocks:
                lifted_block.append([i, _lifted_block])
                processed_blocks.append(_lifted_block)

            # lifted_block.extend(self.machine_to_vex(_lifted_block, instr))

        return lifted_block

    def printStrands(self, strands):
        for i, strand in enumerate(strands):
            print(f"----- Strand number: {i} -----")
            for ins in strand:
                print(str(ins))


if __name__ == '__main__':
    # proj = angr.project.load_shellcode(b'\x8B\x45\xF8\x8B\x45\xF8\x83\xC0\x01', 'X86_64', 0)
    # bytes = b'\xF3\x0F\x1E\xFA\x55\x48\x89\xE5\x89\x7D\xFC\x89\x75\xF8\x8B\x45\xFC\x0F\xAF\x45\xF8\x5D\xC3'
    # bytes = b'\x83E\xec\x01\x8bE\xe89E\xec|\xcb'
    # bytes = b'H\x89\xdeH\x89\xc7\xe8\xeb\xff\x0f\x00'
    # bytes = b'\xf3\x0f\x1e\xfaUH\x89\xe5H\x83\xec\x10\xbe\x02\x00\x00\x00\xbf\x01\x00\x00\x00\xe8\xb3\xff\xff\xff'
    # proj = angr.project.load_shellcode(bytes, 'X86_64', 0)
    # state = proj.factory.entry_state()

    # block = state.block(opt_level=0)
    # target_node.block.capstone.pp()
    slicer = Slicer(debug=False)

    function_cfg = "/app/vol/CFGExtractor/extracted_cfgs_variants_angr_zeek_6000/x64-clang-O0_aacps_common.o_read_ipdopd_data.pkl"

    with open(function_cfg, 'rb') as file:
        loaded_graph = pickle.load(file)

    cfg = loaded_graph['cfg']

    node = list(cfg.nodes(data=True))[0]
    block = node[1]

    asm_instructions, asm2vex = slicer.lift_bytes(block['disasm'], block['asm'], node[0])

    strands = slicer.retrieve_ir_strands_from_ref_def(asm_instructions, asm2vex)

    print("OK")

    """
    # irsb = block.vex
    print(irsb)
    block.disassembly.pp()
    # for x in irsb.statements:
    #    slicer._ref_def_vex(x)
    statements = slicer.get_block_vex_inst(block)
    strands = slicer.ExtractStrandIR(statements)  # , 2, 22) #+ [irsb.next])
    # strands = slicer.ExtractStrandIR(irsb.statements)  # + [irsb.next])
    print("\nIRSB STRAND")
    for x in strands:
        for i in x:
            print(str(i))
        print("----")
    strands = slicer.convert_vex_strands_to_machine_strands(strands, block)
    print("\nMACHINE STRAND")
    for x in strands:
        for i in x:
            print(str(i))
        print("----")
    # print(slicer.getShellcode(strands[0]))
    """
