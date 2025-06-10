import r2pipe

import json


class RadareAnalyzer:

    def __init__(self, filename):

        self.r2 = r2pipe.open(filename, flags=['-2'])

        # SET INTEL SYNTAX
        self.r2.cmd("e asm.syntax=intel")

        self.filename = filename

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
                        print(f"[Radare2-InstrAnalyzer] There is a null byte in the middle")
                        # print(pending)
                        output = b'[]\n'
                        break
                    elif zero > 1:
                        print(f"[Radare2-InstrAnalyzer] There is more than one null byte")
                        # print(pending)
                        output = b'[]\n'
                        break

            except Exception as ex:
                print(f"[Radare2-InstrAnalyzer] Exception in _fix_r2pipe: {ex}")
                pass

        decoded = output.decode("UTF-8")
        # return p1, p2, output, decoded.strip('\x00')
        return decoded.strip('\x00')

    def analyze_instruction(self, size=None, is_disp=False, is_dba=False):

        try:
            if size:
                instruction = json.loads(self.r2.cmd(f"aoj {size}"))
            else:
                instruction = json.loads(self.r2.cmd("aoj"))
        except json.JSONDecodeError:
            payload = self._fix_r2pipe()
            instruction = json.loads(payload)
        except Exception as e:
            print(f"[Radare2-InstrAnalyzer] Exception in processing instruction bytes: {e}")

        disasm = []
        for instr in instruction:
            operands = []
            if 'opex' in instr:
                for op in instr['opex']['operands']:
                    operands.append(op)
            instr['operands'] = operands
            if is_disp:
                instr['displacement'] = is_disp
            if is_dba:
                instr['dba'] = is_dba
            disasm.append(instr)

        self.r2.quit()

        return disasm

    def close(self):
        self.r2.quit()

    def __exit__(self, exc_type, exc_value, traceback):
        self.r2.quit()
