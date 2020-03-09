class AsmInstruction:
    ta = int()
    pa = ""
    name = ""
    hexstr = ""
    operand = []

    def set(self, ta, pa, name, operand, hexstr):
        self.ta = ta
        self.pa = pa
        self.name = name
        self.operand = operand
        self.hexstr = hexstr

    def get_ta(self):
        return self.ta

    def get_pa(self):
        return self.pa

    def get_name(self):
        return self.name

    def get_operand(self):
        return self.operand

    def get_hex(self):
        return self.hexstr

    def from_string(self, ta, pa, string, hexstr):
        str = string.strip()
        src = str.split(', ')
        tmp = src.pop(0).split(' ')
        opcode = tmp.pop(0)
        dst = " ".join(tmp)
        src.insert(0, dst)
        self.set(int(ta), pa, opcode, src, hexstr)