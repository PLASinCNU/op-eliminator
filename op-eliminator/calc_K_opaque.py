from __future__ import print_function
import sys
import z3
from miasm.arch.x86.arch import *
from miasm.arch.x86.regs import regs_init
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import TranslatorZ3
from miasm.expression.expression import *


ARITHMETIC_OPERATORS = ["ADD", "SUB", "MUL", "DIV",
                        "ADC", "SBC", "IMUL", "IDIV",
                        "INC", "DEC"]
LOGICAL_OPERATORS = ["AND", "OR", "XOR", "NOT", "NEG"]
BINARY_OPERATORS = ["SHR", "SAR", "SHL", "SAL",
                    "ROR", "ROL", "RCR", "RCL"]
COMPARE_OPERATORS = ["CMP", "TEST"]
DATA_MOVEMENT = ["MOV", "LEA"]  #"PUSH", "POP",

OPERATORS = ARITHMETIC_OPERATORS + LOGICAL_OPERATORS + BINARY_OPERATORS

OF_JUMPS = ["JO", "JNO", "JL", "JG", "JGE", "JLE", "JPE", "JNP"]  # Arith combined with PF
SF_JUMPS = ["JL", "JG", "JGE", "JS", "JNS", "JLE"]  # Arith(except *,/), Logic
ZF_JUMPS = ["JZ", "JE", "JNZ", "JNE", "JBE", "JA", "JG", "JLE"]  # Arith, cmp, test
CF_JUMPS = ["JB", "JAE", "JBE", "JA"]  # Arith, Binary
#PF_JUMPS = ["JPE", "JNP"]  # Arith
CX_JUMPS = ["JCXZ", "JECXZ", "JRCXZ"]  # ECX


class AsmInstruction:
    ta = int()
    pa = ""
    name = ""
    binstr = ""
    operand = []

    def set(self, ta, pa, name, operand, binstr):
        self.ta = ta
        self.pa = pa
        self.name = name
        self.operand = operand
        self.binstr = binstr

    def get_ta(self):
        return self.ta

    def get_pa(self):
        return self.pa

    def get_name(self):
        return self.name

    def get_operand(self):
        return self.operand

    def get_binstr(self):
        return self.binstr

    # def splitOperand(self):
    #     op = self.get_operand()
    #     print (op)
    #     dstsrc =op.split(", ")
    #     return dstsrc

    def from_string(self, ta, pa, string, binstr):
        str = string.strip()
        src = str.split(', ')
        tmp = src.pop(0).split(' ')
        opcode = tmp.pop(0)
        dst = " ".join(tmp)
        src.insert(0, dst)
        self.set(int(ta), pa, opcode, src, binstr)

# def group_cmp_jz(cmp_jz_ta_group, trace_list):
#     ta_map = dict()
#     for i in range(0, len(cmp_jz_ta_group)):
#         pa = trace_list[cmp_jz_ta_group[i]].get_pa()
#         if pa in ta_map:
#             if isinstance(ta_map[pa], list):
#                 li = ta_map[pa]
#                 li.append(cmp_jz_ta_group[i])
#                 ta_map[pa] = li
#             else:
#                 li = []
#                 li.append(ta_map[pa])
#                 li.append(cmp_jz_ta_group[i])
#                 ta_map[pa] = li
#         else:
#             ta_map[pa] = cmp_jz_ta_group[i]
#     return ta_map

def TraceFromFile(filename):
    f = open(filename, "rw")
    lines = f.readlines()
    trace_list = []

    for line in lines:
        asm_instr = AsmInstruction()
        li = line.split(";")
        li2 = li[2].split('\\x')
        byte_stream = ""
        for b in li2:
            byte_stream += b.strip()
        asm_instr.from_string(li[0].strip(), li[1].strip(), li[3].strip(), byte_stream)
        trace_list.append(asm_instr)
    f.close()

    return trace_list


def FindCJmp(trace_list):
    cjmp_ta_list = []
    cjmp_index_list = []

    for i in range(0, len(trace_list)):
        name = trace_list[i].get_name().upper()
        if name in conditional_branch:
            cjmp_ta_list.append(trace_list[i].get_ta())
            cjmp_index_list.append(i)
    return cjmp_ta_list, cjmp_index_list


def BinToStr(trace_list, k, cjmp_ta):
    binstr = ""

    for trace in trace_list[k:cjmp_ta]:
        binstr += trace.get_binstr()

    return bytearray.fromhex(binstr)


def OF_Factor(trace_list, cjmp_ta):
    factors = []
    ta = cjmp_ta-1
    while True:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(reg.upper())
            break
        ta -= 1
    return factors, ta


def SF_Factor(trace_list, cjmp_ta):
    factors = []
    ta = cjmp_ta - 1
    while True:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + LOGICAL_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(reg.upper())
            break
        ta -= 1
    return factors, ta


def CF_Factor(trace_list, cjmp_ta):
    factors = []
    ta = cjmp_ta - 1
    while True:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + BINARY_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(reg.upper())
            break
        ta -= 1
    return factors, ta


def ZF_Factor(trace_list, cjmp_ta):
    factors = []
    ta = cjmp_ta - 1
    while True:
        #print(trace_list[ta].get_name().upper())
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + LOGICAL_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(reg.upper())
            break
        ta -= 1
    factors = list(set(factors))
    return factors, ta
#
# def PF_Factor(trace_list, cjmp_ta):
#     factors = []
#     ta = cjmp_ta - 1
#     while True:
#         if trace_list[ta].get_operand() in ARITHMETIC_OPERATORS:
#             for reg in trace_list[ta].splitOperand():
#                 if not reg.startswith("0x"):
#                     factors.append(reg)
#             break
#         ta -= 1
#     return factors

#
# def CX_Factor(trace_list, cjmp_ta):
#     factors = []
#     ta = cjmp_ta - 1
#     while True:
#         if trace_list[ta].get_operand() in ARITHMETIC_OPERATORS:
#             for reg in trace_list[ta].splitOperand():
#                 if not reg.startswith("0x"):
#                     factors.append(reg)
#             break
#         ta -= 1
#     return ta


def BackPropagation(trace_list, ta, max_ta, factor):
    bp_factors = []
    bp_ta = ta - 1
    not_found_flag = True

    while bp_ta > max_ta or bp_ta >= 0:
        regs = []
        if trace_list[bp_ta].get_name().upper() in OPERATORS:
            regs = trace_list[bp_ta].get_operand()
                #print("regs : ",regs)
                # regs[0] == dst
            if regs[0].upper() == factor:
                not_found_flag = False
                for reg in regs:
                    if not reg.startswith("0x"):
                            #print("bp_ta : ", bp_ta)
                        bp_factors.append(reg.upper())
                        #print("bp_fac : ", bp_factors)
                break
        elif trace_list[bp_ta].get_name().upper() in DATA_MOVEMENT:
            regs = trace_list[bp_ta].get_operand()
            if regs[0].upper() == factor:
                not_found_flag = False
                if regs[1].startswith("0x"):
                    bp_factors = []
                else:
                    bp_factors.append(regs[1].upper())
                break
        bp_ta -= 1

    if not_found_flag:
        bp_ta = ta
    bp_factors = list(set(bp_factors))
    return bp_factors, bp_ta


def FigureK(trace_list, cjmp_ta):
    cnt = 3
    factors = []
    factor_ta_dict = dict()
    cjmp = trace_list[cjmp_ta].get_name().upper()
    ta = cjmp_ta
    if cjmp in OF_JUMPS :
        factors, ta = OF_Factor(trace_list, cjmp_ta)
    elif cjmp in SF_JUMPS:
        factors, ta = SF_Factor(trace_list, cjmp_ta)
    elif cjmp in CF_JUMPS:
        factors, ta = CF_Factor(trace_list, cjmp_ta)
    elif cjmp in ZF_JUMPS:
        factors, ta = ZF_Factor(trace_list, cjmp_ta)
    elif cjmp in CX_JUMPS:
        factors = ["ECX"]
        ################### implemnet here

    for factor in factors:
        factor_ta_dict[factor] = ta

    print("factors : ", factors)

    while cnt:
        new_factors = []
        for factor in factors:

            bp_factors, bp_ta = BackPropagation(trace_list, factor_ta_dict[factor], cjmp_ta-30, factor)
            for bp_factor in bp_factors:
                factor_ta_dict[bp_factor] = bp_ta
            new_factors.extend(bp_factors)

        factors = list(set(new_factors))
        print("update factors : ", 4-cnt, " // ", factors)
        cnt -= 1

    if factor_ta_dict is None:
        ta_min = min(factor_ta_dict.values())
    else:
        ta_min = cjmp_ta - 10
    #print("cjump :", cjmp_ta, "ta_min : ", ta_min)

    return ta_min


def ConstructAsmblock(binstr):
    ####### need to check
    machine = Machine('x86_32')
    c = Container.from_string(binstr)
    mdis = machine.dis_engine(c.bin_stream)

    asmblocks = []
    offset = 0

    while offset < len(binstr):
        block = mdis.dis_block(offset)
        start, end = block.get_range()
        asmblocks.append(block)
        offset = end

    return asmblocks, mdis.loc_db


def GetSymbVal(asmblocks, loc_db):
    machine = Machine('x86_32')
    sym_state = None
    sym_pc = None

    for asmblock in asmblocks:

        offset, end = asmblock.get_range()

        ira = machine.ira(loc_db)
        ircfg = ira.new_ircfg()
        ira.add_asmblock_to_ircfg(asmblock, ircfg)

        symb = SymbolicExecutionEngine(ira, regs_init)
        sym_pc = symb.run_at(ircfg, offset)

        if sym_state is None:
            sym_state = symb.get_state()
        else:
            sym_state.merge(symb.get_state())
    return sym_state, sym_pc


# def GetKBlocks(trace_index, trace_list, asmblocks, k):
#     asmblock_index = trace_list[trace_index].asmblock_index
#     #set index
#     index = asmblock_index
#     start = 0
#     end = index + 1
#     if index < k:
#         start = 0
#     else:
#         start = end - k
#     kblocks = asmblocks[start: end]
#
#     return kblocks

def IsUnsatTa(asmblocks, trace_index, trace_list, loc_db):
    try:
        sym_state, sym_pc = GetSymbVal(asmblocks, loc_db)
        translator = TranslatorZ3(endianness="<", loc_db=loc_db)

        solver = z3.Solver()
        solver_ = z3.Solver()
        expr_eip = ExprId('EIP', 32)

        if isinstance(sym_state.symbols[expr_eip], ExprCond):
            z3_expr_id = translator.from_expr(sym_state.symbols[expr_eip])
            src1 = translator.from_expr(sym_state.symbols[expr_eip].src1)
            src2 = translator.from_expr(sym_state.symbols[expr_eip].src2)

            simple_expr = z3.simplify(z3_expr_id)
            ebp_8 = ExprMem(ExprOp('+', ExprId('EBP_init', 32), ExprInt(0x8, 32)), 32)
            z3_ebp8 = translator.from_expr(ebp_8)

            # solver.insert(z3_ebp8 < 1000)
            # solver_.insert(z3_ebp8 < 1000)
            # solver.insert(z3_ebp8 > -1000)
            # solver_.insert(z3_ebp8 > -1000)
            solver.add(simple_expr == src1)
            solver_.add(simple_expr == src2)

            s_check = solver.check()
            s_check2 = solver_.check()
            if s_check != s_check2:
                print('======', trace_list[trace_index].get_ta(), '=====')
                print("It's opaque predicate, sat and unsat")
                print(trace_list[trace_index].get_pa())
            elif trace_list[trace_index].get_ta() == 2122:
                print(solver_)
                print(solver_.model)
        else:
            print('==========', trace_list[trace_index].get_ta(), '==========')
            print('EIP is not cond, Its opaque predicate')
    except Exception as e:
        pass


trace_list = TraceFromFile(sys.argv[1])
print("Trace len : ", len(trace_list))
cjmp_ta_list, cjmp_index_list = FindCJmp(trace_list)

print(cjmp_index_list)

for trace_index in cjmp_index_list:
    k = FigureK(trace_list, trace_index)
    bin_str = BinToStr(trace_list, k, trace_index)

    # print(bin_str, " @ ", k," @ ", trace_index)
    asm_blocks, loc_db = ConstructAsmblock(bin_str)
    IsUnsatTa(asm_blocks, trace_index, trace_list, loc_db)
