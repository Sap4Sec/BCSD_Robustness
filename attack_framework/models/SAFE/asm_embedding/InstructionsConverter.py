# SAFE TEAM
# distributed under license: GPL 3 License http://www.gnu.org/licenses/
import json


class InstructionsConverter:

    def __init__(self, json_i2id):
        f = open(json_i2id, 'r')
        self.i2id = json.load(f)
        f.close()

    def convert_to_ids(self, instructions_list):
        ret_array = []
        # For each instruction we add +1 to its ID because the first
        # element of the embedding matrix is zero
        for function in instructions_list:
            f_ret_array = []
            for x in function:
                if x in self.i2id:
                    f_ret_array.append(self.i2id[x] + 1)
                elif 'X_' in x:
                    # print(str(x) + " is not a known x86 instruction")
                    f_ret_array.append(self.i2id['X_UNK'] + 1)
                elif 'A_' in x:
                    # print(str(x) + " is not a known arm instruction")
                    f_ret_array.append(self.i2id['A_UNK'] + 1)
                else:
                    # print("There is a problem " + str(x) + " does not appear to be an asm or arm instruction")
                    f_ret_array.append(self.i2id['X_UNK'] + 1)
            ret_array.append(f_ret_array)
        return ret_array


