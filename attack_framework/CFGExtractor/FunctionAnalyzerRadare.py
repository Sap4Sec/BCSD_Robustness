# SAFE TEAM
#
#
# distributed under license: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) #
#
import json
from json import JSONDecodeError

import r2pipe
import networkx as nx
import warnings
import re

warnings.filterwarnings("ignore")

import sys

sys.path.append("../")

# from transformations.SlicerArchIndep import Slicer
from transformations.SlicerArchIndep import Slicer as SlicerArchIndep
from CFGExtractor.extractor_utils import *

import binascii


class Dict2Obj(object):
    """
    Turns a dictionary into a class
    """

    # ----------------------------------------------------------------------
    def __init__(self, dictionary):
        """Constructor"""
        for key in dictionary:
            setattr(self, key, dictionary[key])


class RadareFunctionAnalyzer:

    def __init__(self, filename, function, use_symbol):
        self.r2 = r2pipe.open(filename, flags=['-2'])

        # SET INTEL SYNTAX
        self.r2.cmd("e asm.syntax=intel")

        self.filename = filename
        self.arch, _ = self.get_arch()
        self.use_symbol = use_symbol
        self.function_name = function

    def __enter__(self):
        return self

    @staticmethod
    def get_callref(my_function, depth):
        calls = {}
        if 'callrefs' in my_function and depth > 0:
            for cc in my_function['callrefs']:
                if cc["type"] == "C":
                    calls[cc['at']] = cc['addr']
        return calls

    def _fix_r2pipe(self):
        output = b""
        # p1, p2 = None, b""
        while True:
            try:
                # starting from pending or pipe itself
                if len(self.r2.pending) > 0:
                    pending = self.r2.pending
                    # p1 = pending
                    self.r2.pending = b""
                else:
                    read = self.r2.process.stdout.read(4096)
                    # p2 += read if read is not None else p2
                    pending = read

                if pending is not None:
                    output += pending
                    zero = output.count(b"\x00")
                    if zero == 1 and output[-1] == 0:
                        # the result is now complete
                        break
                    elif zero == 1 and output[-1] != 0:
                        print(f"[Radare2] There is a null byte in the middle")
                        # print(pending)
                        output = b'[]\n'
                        break
                    elif zero > 1:
                        print(f"[Radare2] There is more than one null byte")
                        # print(pending)
                        output = b'[]\n'
                        break

            except Exception as ex:
                print(f"[Radare2] Exception in _fix_r2pipe: {ex}")
                pass

        decoded = output.decode("UTF-8")
        # return p1, p2, output, decoded.strip('\x00')
        return decoded.strip('\x00')

    def get_block_offset(self, block):
        return block['offset']

    def get_block_bytes(self, block):
        block_bytes = b""
        for op in block['ops']:
            if 'disasm' in op:
                block_bytes += bytes(op['bytes'], 'utf-8')

        return block_bytes

    def get_linearized_function(self, function_ep):

        self.r2.cmd(f"s " + str(function_ep))

        try:
            instructions = json.loads(self.r2.cmd("pdfj"))
        except JSONDecodeError:
            payload = self._fix_r2pipe()
            instructions = json.loads(payload)
        except Exception as e:
            print(f"[Radare2] Exception in get_linearized_function: {e}")

        return instructions

    def process_block(self, block, text_addr):
        block_bytes = ""  # b""
        disasm = []

        bb_heads = []
        bb_mnems = []
        bb_disasm = []

        self.r2.cmd("s " + str(block['offset']))
        try:
            instructions = json.loads(self.r2.cmd("aoj " + str(len(block['ops']))))
        except JSONDecodeError:
            payload = self._fix_r2pipe()
            instructions = json.loads(payload)
        except Exception as e:
            print(f"[Radare2] Exception in process_block: {e}")

        for instr in instructions:
            operands = []
            if 'opex' in instr:
                for op in instr['opex']['operands']:
                    operands.append(op)
            instr['operands'] = operands
            instr['orig_addr'] = hex(instr['addr'] - text_addr)

            disasm.append(instr)
            block_bytes += instr['bytes']

            bb_mnems.append(instr['mnemonic'])
            bb_heads.append(instr['addr'])
            bb_disasm.append(instr['opcode'])

        asm = bytes.fromhex(block_bytes)

        return disasm, asm, bb_mnems, bb_heads, bb_disasm

    def get_text_address(self):

        # GET .text address
        try:
            var_iSj = self.r2.cmd('iSj')
            sections = json.loads(var_iSj)
        except JSONDecodeError:
            payload = self._fix_r2pipe()
            sections = json.loads(payload)
        except Exception as e:
            print(f"[Radare2] Exception in get_BB_entry_points: {e}")
            return []

        text_addr = [el['vaddr'] for el in sections if el['name'] == '.text'][0]

        return text_addr

    # Returns entry point of binary, if exists (olivetree code)
    def get_entry_point(self):
        res = []
        try:
            res = json.loads(self.r2.cmd('iej'))
        except JSONDecodeError:
            # this could happen due to a null byte at the beginning of the buffer
            payload = self._fix_r2pipe()
            res = json.loads(payload)
        except Exception as ex:
            print(f"[Radare2] Exception {ex} in get_entry_point")

        if len(res) > 0:
            return res[0]['vaddr']
        else:
            return None

    def get_offset(self, entry_point_angr):

        return self.get_text_address()

    def get_addr_for_disp(self, nx_cfg):

        sorted_nodes = sorted(nx_cfg.nodes(data=True), key=lambda x: x[0])
        linearized_cfg = []
        for n in sorted_nodes:
            n_instrs = n[1]['disasm']
            linearized_cfg.extend(n_instrs)

        highest_orig_addr = linearized_cfg[0]['addr']
        highest_size = linearized_cfg[0]['size']

        for instr in linearized_cfg:
            if 'addr' in instr and instr['addr'] >= highest_orig_addr:
                highest_orig_addr = instr['addr']
                highest_size = instr['size']

        return highest_orig_addr + highest_size

    def get_BB_entry_points(self, func):
        if self.use_symbol:
            s = 'vaddr'
        else:
            s = 'offset'

        self.r2.cmd('s ' + str(func[s]))
        try:
            var_agfj = self.r2.cmd('agfj ' + str(func[s]))
            cfg = json.loads(var_agfj)
        except JSONDecodeError:
            # this could happen due to a null byte at the beginning of the buffer
            payload = self._fix_r2pipe()
            cfg = json.loads(payload)
        except Exception as e:
            print(f"[Radare2] Exception in get_BB_entry_points: {e}")
            cfg = []

        if len(cfg) == 0:
            return []
        else:
            cfg = cfg[0]

        entry_points = []
        function_bytes = b""
        for block in cfg['blocks']:
            function_bytes += self.get_block_bytes(block)
            bb_entry_point = self.get_block_offset(block)
            entry_points.append(hex(bb_entry_point))

        function_bytes = binascii.unhexlify(function_bytes)

        return entry_points, function_bytes

    def get_calls(self):
        '''
        Creating dictionaries for callers and callees
        '''

        temp = self.r2.cmd("afx")
        calls = {"callers": [],
                 "callees": []}
        # callees = []
        lines = temp.split("\n")
        for l in lines[:len(lines) - 1]:
            line = l.strip().split()
            if (line[0] == "C"):
                # print(line)
                callee_dict = {
                    "call": line[5],
                    "instr_address": line[1]
                }
                calls["callees"].append(callee_dict)

        temp = self.r2.cmd("axt")

        lines = temp.split("\n")
        for l in lines[:len(lines) - 1]:
            line = l.strip().split()
            caller_dict = {
                "call": line[0],
                "instr_address": line[1]
            }
            calls["callers"].append(caller_dict)

        return calls

    def function_to_cfg(self, func):
        if self.use_symbol:
            s = 'vaddr'
        else:
            s = 'offset'

        self.r2.cmd('s ' + str(func[s]))

        calls = self.get_calls()

        try:
            var_agfj = self.r2.cmd('agfj ' + str(func[s]))
            cfg = json.loads(var_agfj)
        except JSONDecodeError:
            # this could happen due to a null byte at the beginning of the buffer
            payload = self._fix_r2pipe()
            cfg = json.loads(payload)
        except Exception as e:
            print(f"[Radare2] Exception in function_to_cfg: {e}")
            cfg = []

        my_cfg, string_addresses = nx.DiGraph(), []

        edge_list, node_list, basic_blocks = [], [], dict()

        if len(cfg) == 0:
            return my_cfg
        else:
            cfg = cfg[0]

        function_addr = cfg['offset']
        attrs_cfg = {'function_addr': function_addr}
        my_cfg.graph.update(attrs_cfg)

        text_addr = self.get_text_address()

        for block in cfg['blocks']:
            disasm, block_bytes, bb_mnems, bb_heads, bb_disasm = self.process_block(block, text_addr)
            my_cfg.add_node(block['offset'],
                            func_addr=function_addr,
                            entry_point=hex(block['offset']),
                            asm=block_bytes,
                            disasm=disasm,
                            calls=calls,
                            original_ep=block['offset'],
                            text_addr=text_addr,
                            can_disp=True,
                            is_db=False,
                            bb_disasm=bb_disasm,
                            bb_heads=bb_heads,
                            bb_mnems=bb_mnems
                            )
            node_list.append(block['offset'])
            basic_blocks[str(block['offset'])] = {
                'bb_bytes': block_bytes,
                'bb_disasm': bb_disasm,
                'bb_heads': bb_heads,
                'bb_len': len(block_bytes),
                'bb_mnems': bb_mnems
            }

        for block in cfg['blocks']:
            if 'jump' in block:
                if block['jump'] in my_cfg.nodes:
                    my_cfg.add_edge(block['offset'], block['jump'])
                    edge_list.append([block['offset'], block['jump']])
            if 'fail' in block:
                if block['fail'] in my_cfg.nodes:
                    my_cfg.add_edge(block['offset'], block['fail'])
                    edge_list.append([block['offset'], block['fail']])

        try:
            var_izzj = json.loads(self.r2.cmd('izzj'))
            string_addresses = [s['vaddr'] for s in var_izzj]
        except JSONDecodeError:
            payload = self._fix_r2pipe()
            string_addresses = json.loads(payload)
        except Exception as e:
            print(f"[Radare2] Exception in function_to_cfg (string_addresses): {e}")

        addr_for_disp = self.get_addr_for_disp(my_cfg)

        return my_cfg, string_addresses, addr_for_disp, edge_list, node_list, basic_blocks, function_addr

    def get_arch(self):
        try:
            try:
                info = json.loads(self.r2.cmd('ij'))
            except JSONDecodeError:
                # this could happen due to a null byte at the beginning of the buffer
                payload = self._fix_r2pipe()
                info = json.loads(payload)
            except Exception as e:
                print(f"[Radare2] Exception in get_arch: {e}")
                info = []
            if 'bin' in info:
                arch = info['bin']['arch']
                bits = info['bin']['bits']

        except Exception as e:
            print(e)
            arch = None
            bits = None
        return arch, bits

    def find_functions(self):
        self.r2.cmd('aaa')
        try:
            function_list = json.loads(self.r2.cmd('aflj'))
        except JSONDecodeError:
            # this could happen due to a null byte at the beginning of the buffer
            payload = self._fix_r2pipe()
            function_list = json.loads(payload)
        except Exception as e:
            print(f"[Radare2] Exception in find_functions: {e}")
            function_list = []
        return function_list

    def find_functions_by_symbols(self):
        self.r2.cmd('aaa')
        try:
            var_isj = self.r2.cmd('isj')
            symbols = json.loads(var_isj)
            fcn_symb = [s for s in symbols if s['type'] == 'FUNC']
        except JSONDecodeError:
            # this could happen due to a null byte at the beginning of the buffer
            payload = self._fix_r2pipe()
            symbols = json.loads(payload)
            fcn_symb = [s for s in symbols if s['type'] == 'FUNC']
        except Exception as e:
            print(f"[Radare2]: Exception in find_functions_by_symbols {e}")
            fcn_symb = []
        return fcn_symb

    def get_all_functions(self):

        functions_names = self.find_functions_by_symbols()
        functions_infos = self.find_functions()

        functions = []

        for f_name in functions_names:
            try:
                f_info = list(filter(lambda x: x['name'] == f_name['flagname'] or
                                               x['name'] == f_name['name'], functions_infos))
            except Exception as e:
                print(f"[Radare2]: Exception in get_all_functions {e}")
                continue

            if len(f_info) > 0:
                f_info = f_info[0]

                functions.append({
                    "address": f_name['vaddr'],
                    "name": f_name['name'],
                    "flagname": f_name['flagname'],
                    "signature": f_info['signature'],
                    "size": f_info['realsz'],
                    "args": f_info['nargs']
                })
            else:
                continue

        return functions

    def analyze(self):
        if self.use_symbol:
            function_list = self.find_functions_by_symbols()
            s = 'vaddr'
        else:
            function_list = self.find_functions()
            s = 'offset'

        result = {}

        # Filtering function names
        filtered_list = []
        for my_function in function_list:
            x = re.search(r"(?:^|\W)" + self.function_name + r"(?:$|\W)", my_function['name'])
            if bool(x):
                filtered_list.append(my_function)

        for my_function in filtered_list:
            try:
                cfg, string_addresses, addr_for_disp, edge_list, node_list, basic_blocks, function_addr = self.function_to_cfg(
                    my_function)

                entry_point = my_function[s]

                cfg.graph.update(
                    {'binary_name': self.filename,
                     'function_name': my_function['name'],
                     'function_addr': function_addr}
                )

                result[my_function['name']] = {
                    'cfg': cfg,
                    'string_addresses': string_addresses,
                    'addr_for_disp': addr_for_disp,
                    'entry_point': entry_point,
                    'function_name': my_function['name'],
                    'edge_list': edge_list,
                    'node_list': node_list,
                    'basic_blocks': basic_blocks,
                    'file_name': self.filename
                }
            except Exception as e:
                print(f"[Radare2] Error in functions: {my_function['name']} from {self.filename}")
                print(e)
                return {}

        # self.r2.quit()

        return result

    def get_cfg(self):

        functions = self.analyze()
        for function in functions:
            if self.function_name in function:
                # self.r2.quit()
                return functions[function]

        # self.r2.quit()
        return None

    def close(self):
        self.r2.quit()

    def __exit__(self, exc_type, exc_value, traceback):
        self.r2.quit()


def cfg_pp(result):
    for n in result.nodes(data=True):
        print(f"-------- NODE {n[0]} --------")
        for i in n[1]['disasm']:
            print(i['opcode'])
