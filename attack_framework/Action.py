from abc import ABC


class Action(ABC):

    def __init__(self, action_type, action_node, action_strand, action_shellcode, action_strand_id, action_radare_strand,
                 action_instr, action_source_addr_for_disp):
        self.type = action_type
        self.node = action_node
        self.strand = action_strand
        self.shellcode = action_shellcode
        self.strand_id = action_strand_id
        self.radare_strand = action_radare_strand
        self.instr = action_instr
        self.source_addr_for_disp = action_source_addr_for_disp

    def __str__(self):
        return str((self.type, self.node, self.strand, self.shellcode, self.strand_id, self.radare_strand, self.instr,
                    self.source_addr_for_disp))

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
            self.type == other.type and \
            self.node == other.node and \
            self.strand == other.strand and \
            self.shellcode == other.shellcode and \
            self.strand_id == other.strand_id and \
            self.radare_strand == other.radare_strand and \
            self.instr == other.instr and \
            self.source_addr_for_disp == other.source_addr_for_disp

    def __hash__(self):
        return hash((self.type, self.node, self.strand, self.shellcode, self.strand_id, self.radare_strand, self.instr,
                     self.source_addr_for_disp))
