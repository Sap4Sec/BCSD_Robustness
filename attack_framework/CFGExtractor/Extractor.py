import string

import angr
import json
import claripy
import binascii

import time

import networkx as nx

import sys

sys.path.append("../")

from keystone import Ks, KS_ARCH_X86, KS_MODE_64

from CFGExtractor.FunctionAnalyzerRadare import RadareFunctionAnalyzer
from CFGExtractor.extractor_utils import radare_2_capstone, lift_radare_block

from CFGExtractor.slicer_utils import build_nx_graph

from transformations.SlicerArchIndep import Slicer as SlicerArchIndep


def is_valid_block(node: angr.Block):
    try:
        tmp = node.instructions
        tmp = node.bytes
    except Exception:
        tmp = None
    return tmp is not None


assembler = Ks(KS_ARCH_X86, KS_MODE_64)


class Extractor:

    def __init__(self, filename, function_name, libc_signatures, use_angr=False):

        if use_angr:
            angr.logging.disable(level=angr.logging.WARNING)
            angr.logging.disable(level=angr.logging.ERROR)

        self.filename = filename
        self.function_name = function_name

        with open(libc_signatures, "r") as f:
            self.libc_signatures = json.load(f)

        self.radare_analyzer = RadareFunctionAnalyzer(filename, function_name, use_symbol=True)

        if use_angr:
            self.proj = angr.Project(self.filename, auto_load_libs=False)
            self.angr_cfg = self.proj.analyses.CFGFast()
            self.angr_ep = self.proj.entry

        self.radare_cfg = self.radare_analyzer.get_cfg()

        self.arch = None
        self.offset_radare = self.radare_analyzer.get_text_address()

        if use_angr:
            self.funcs_in_bin = self.radare_analyzer.get_all_functions()

            self.funcs_dict = self.get_funcs_in_bin()

        # Close r2pipe connection
        self.radare_analyzer.r2.quit()

    def get_funcs_in_bin(self):

        funcs_dict = dict()

        for func in self.funcs_in_bin:

            function_angr_symbol = self.proj.loader.find_symbol(func['name'])
            function_angr_address = func['address'] - self.offset_radare

            if function_angr_symbol is not None:
                if function_angr_address != function_angr_symbol.rebased_addr:
                    function_angr_address = function_angr_symbol.rebased_addr

            try:
                function_angr = self.angr_cfg.functions[function_angr_address]
            except KeyError:
                print(f"[Angr] Function {self.function_name} at address {hex(func['address'])} was not found in angr")
                continue

            funcs_dict[function_angr.addr] = func

        return funcs_dict

    def get_radare_cfg(self):

        return self.radare_cfg

    def get_radare_functions(self):
        return self.funcs_in_bin

    def extract_func_cfg(self, use_angr=False):

        func_cfg = {
            'filename': self.filename,
            'name': self.radare_cfg["function_name"],
            'entry_point': self.radare_cfg["entry_point"],
            'radare_offset': self.offset_radare,
            'cfg': self.radare_cfg["cfg"],
            'string_addresses': self.radare_cfg["string_addresses"],
            'addr_for_disp': self.radare_cfg["addr_for_disp"]
        }

        if use_angr:

            func_cfg['angr_offset'] = self.angr_ep

            function_angr_symbol = self.proj.loader.find_symbol(self.radare_cfg['function_name'])
            function_angr_address = self.radare_cfg['entry_point'] - self.offset_radare

            if function_angr_symbol is not None:
                if function_angr_address != function_angr_symbol.rebased_addr:
                    function_angr_address = function_angr_symbol.rebased_addr

            # extract angr function CFG
            try:
                function_angr = self.angr_cfg.functions[function_angr_address]
            except KeyError:
                print(
                    f"[Angr] Function {self.function_name} at address {hex(self.radare_cfg['entry_point'])} was not found in angr")
                return None

            func_cfg['angr_cfg'] = function_angr

            angr_instrs = {}
            angr_nodes = [node for node in list(func_cfg['angr_cfg'].blocks) if is_valid_block(node)]
            for node in angr_nodes:
                instrs = node.capstone.insns
                for i in instrs:
                    angr_instrs[i.address + self.offset_radare - self.angr_ep] = i

            func_cfg['angr_instrs'] = angr_instrs  # add comment when extracting pool

            # fix calls in radare blocks
            for bb in func_cfg['cfg'].nodes(data=True):
                new_bytes = b''
                for instr in bb[1]['disasm']:
                    if instr['type'] == "call" and instr['addr'] in angr_instrs:
                        # check whether angr resolves this call
                        angr_instr = angr_instrs[instr['addr']]
                        new_call_target = angr_instr.operands[0].imm + self.offset_radare - self.angr_ep
                        instr['opcode'] = instr['opcode'].replace(hex(instr['jump']),
                                                                  hex(new_call_target))
                        instr['disasm'] = instr['disasm'].replace(hex(instr['jump']),
                                                                  hex(new_call_target))
                        instr['pseudo'] = instr['pseudo'].replace(hex(instr['jump']),
                                                                  hex(new_call_target))
                        instr['esil'] = instr['esil'].replace(str(instr['jump']),
                                                              str(new_call_target))
                        try:
                            temp_opcode = instr['opcode'].replace(hex(new_call_target),
                                                                  hex(new_call_target - instr['addr']))
                            asm_bytes = b'' + bytes(assembler.asm(temp_opcode)[0])
                            instr['bytes'] = binascii.hexlify(asm_bytes).decode('utf-8')
                        except Exception as e:
                            instr['bytes'] = instr['bytes']

                        instr['opex']['operands'][0]['value'] = new_call_target
                    new_bytes += bytes.fromhex(instr['bytes'])

                bb[1]['asm'] = new_bytes

            angr_nodes = [node for node in list(func_cfg['angr_cfg'].blocks) if is_valid_block(node)]

            # check addresses correspondence between angr and radare2
            code_constants = [const.value
                              for block in angr_nodes
                              for const in block.vex.constants
                              ]
            strings = patched_string_references(func_cfg['angr_cfg'], angr_nodes,
                                                code_constants, vex_only=True)
            string_map = {addr + self.offset_radare - self.angr_ep: value for addr, value in strings}
            func_cfg["strings"] = string_map

            call_map = {func.addr + self.offset_radare - self.angr_ep: func.name for func in
                        func_cfg['angr_cfg'].functions_called()}
            func_cfg["call_map"] = call_map

        return func_cfg

    # Checks whether the node contains call and extract the called function with function prototype
    # original signature: def _check_jump_kind(self, block)
    def _check_jump_kind(self, cap_block, vex_block, angr_instrs):

        is_call_jump, call_name, call_ins_address, n_args_call = False, None, None, 0

        # if block.vex.jumpkind == "Ijk_Call":
        if vex_block.jumpkind == "Ijk_Call":
            is_call_jump = True
            call_ins = angr_instrs[cap_block[-1].address]  # block.capstone.insns[-1]
            call_ins_address = call_ins.address  # address where the call instruction is located
            called_address = call_ins.operands[0].imm  # + self.angr_ep

            # retrieving symbol associated to the called_address
            if called_address is not None:

                # if called_address is in cfg_func means that it is an internal call and we have args
                if called_address in self.funcs_dict:
                    n_args_call = self.funcs_dict[called_address]['args']
                # it is library call probably -> find symbol and then args by name
                else:
                    symbol = self.proj.loader.find_symbol(called_address)
                    try:
                        # if symbol -> access name else try in reverse_plt. otherwise is none, then is a register
                        call_name = symbol.name if symbol is not None and symbol.name \
                            else self.proj.loader.main_object.reverse_plt[called_address]
                    except KeyError:
                        call_name = None
                        pass

                    if call_name in self.libc_signatures:
                        n_args_call = self.libc_signatures[call_name]['args']

        # call instr address patched to radare2 format
        patched_call_ins_address = call_ins_address + self.offset_radare - self.angr_ep if call_ins_address else None

        return is_call_jump, call_name, patched_call_ins_address, n_args_call


# string_references of Angr with nodes patch
def patched_string_references(function, blocks, constants, minimum_length=2, vex_only=False):
    strings = []
    memory = function._project.loader.memory

    # get known instruction addresses and call targets
    # these addresses cannot be string references, but show up frequently in the runtime values
    known_executable_addresses = set()
    for block in blocks:
        known_executable_addresses.update(block.instruction_addrs)
    for function in function._function_manager.values():
        known_executable_addresses.update(set(x.addr for x in function.graph.nodes()))

    # loop over all local runtime values and check if the value points to a printable string
    for addr in function.local_runtime_values if not vex_only else constants:
        if not isinstance(addr, claripy.fp.FPV) and not isinstance(addr, float) and addr in memory:
            # check that the address isn't a pointing to known executable code
            # and that it isn't an indirect pointer to known executable code
            try:
                possible_pointer = memory.unpack_word(addr)
                if addr not in known_executable_addresses and possible_pointer not in known_executable_addresses:
                    # build string
                    stn = ""
                    offset = 0
                    current_char = chr(memory[addr + offset])
                    while current_char in string.printable:
                        stn += current_char
                        offset += 1
                        current_char = chr(memory[addr + offset])

                    # check that the string was a null terminated string with minimum length
                    if current_char == "\x00" and len(stn) >= minimum_length:
                        strings.append((addr, stn))
            except KeyError:
                pass
    return strings
