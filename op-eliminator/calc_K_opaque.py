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

# REGISTER_CONVERT_DICT = dict()
ACCUMULATOR_REGISTERS = ["RAX", "EAX", "AX", "AL", "AH"]
BASE_REGISTERS = ["RBX", "EBX", "BX", "BL", "BH"]
COUNTER_REGISTERS = ["RCX", "ECX", "CX", "CL", "CH"]
DATA_REGISTERS = ["RDX", "EDX", "DX", "DL", "DH"]
STACK_POINTER_REGISTERS = ["RSP", "ESP", "SP"]
STACK_BASE_POINTER_REGISTERS = ["RBP", "EBP", "BP"]
SOURCE_REGISTERS = ["RSI", "ESI", "SI"]
DESTINATION_REGISTERS = ["RDI", "EDI", "DI"]
# for reg in ACCUMULATOR_REGISTERS:
#     REGISTER_CONVERT_DICT[reg] = "EAX"
# for reg in BASE_REGISTERS:
#     REGISTER_CONVERT_DICT[reg] = "EBX"
# for reg in COUNTER_REGISTERS:
#     REGISTER_CONVERT_DICT[reg] = "ECX"
# for reg in DATA_REGISTERS:
#     REGISTER_CONVERT_DICT[reg] = "EDX"
# for reg in STACK_POINTER_REGISTERS:
#     REGISTER_CONVERT_DICT[reg] = "ESP"
# for reg in STACK_BASE_POINTER_REGISTERS:
#     REGISTER_CONVERT_DICT[reg] = "EBP"
# for reg in SOURCE_REGISTERS:
#     REGISTER_CONVERT_DICT[reg] = "ESI"
# for reg in DESTINATION_REGISTERS:
#     REGISTER_CONVERT_DICT[reg] = "EDI"


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


def RegisterTranslator(reg):
    if reg in ACCUMULATOR_REGISTERS:
        unified_reg = "EAX"
    elif reg in BASE_REGISTERS:
        unified_reg = "EBX"
    elif reg in COUNTER_REGISTERS:
        unified_reg = "ECX"
    elif reg in DATA_REGISTERS:
        unified_reg = "EDX"
    elif reg in STACK_POINTER_REGISTERS:
        unified_reg = "ESP"
    elif reg in STACK_BASE_POINTER_REGISTERS:
        unified_reg = "EBP"
    elif reg in SOURCE_REGISTERS:
        unified_reg = "ESI"
    elif reg in DESTINATION_REGISTERS:
        unified_reg = "EDX"
    else:
        unified_reg = reg

    return unified_reg


def OF_Factor(trace_list, cjmp_ta):
    factors = []
    ta = cjmp_ta-1
    while ta >= cjmp_ta-10 and ta > 0:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(RegisterTranslator(reg.upper()))
            break
        ta -= 1
    return factors, ta


def SF_Factor(trace_list, cjmp_ta):
    factors = []
    ta = cjmp_ta - 1
    while ta >= cjmp_ta-10 and ta > 0:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + LOGICAL_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(RegisterTranslator(reg.upper()))
            break
        ta -= 1
    return factors, ta


def CF_Factor(trace_list, cjmp_ta):
    factors = []
    ta = cjmp_ta - 1
    while ta >= cjmp_ta-10 and ta > 0:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + BINARY_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(RegisterTranslator(reg.upper()))
            break
        ta -= 1
    return factors, ta


def ZF_Factor(trace_list, cjmp_ta):
    factors = []
    ta = cjmp_ta - 1
    while ta >= cjmp_ta-10 and ta > 0:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + LOGICAL_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(RegisterTranslator(reg.upper()))
            break
        ta -= 1
    factors = list(set(factors))
    return factors, ta


def CX_Factor(trace_list, cjmp_ta):
    factors = ["ECX"]
    ta = cjmp_ta - 1
    while ta >= cjmp_ta-10 and ta > 0:
        operand = trace_list[ta].get_operand()

        if RegisterTranslator(operand[0]) in COUNTER_REGISTERS:
            if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS:
                if not operand[1].startswith("0x"):
                    factors.append(RegisterTranslator(operand[1]))
                break
            elif trace_list[ta].get_name().upper() in DATA_MOVEMENT:
                break
        ta -= 1

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


# new
def BackPropagation(trace_list, size, ta, max_ta, factors):
    bp_factors = factors
    bp_ta = ta - 1
    influencing_ta_set = set()
    influencing_ta_set.add(ta)

    while bp_ta >= max_ta and bp_ta >= 0:
        regs = trace_list[bp_ta].get_operand()
        if trace_list[bp_ta].get_name().upper() in OPERATORS:
            if RegisterTranslator(regs[0].upper()) in bp_factors:
                influencing_ta_set.add(bp_ta)
                for reg in regs:
                    if not reg.startswith("0x"):
                        bp_factors.append(RegisterTranslator(reg.upper()))
        elif trace_list[bp_ta].get_name().upper() in DATA_MOVEMENT:
            if RegisterTranslator(regs[0].upper()) in bp_factors:
                influencing_ta_set.add(bp_ta)
                bp_factors.remove(RegisterTranslator(regs[0].upper()))
                if not regs[1].startswith("0x"):
                    bp_factors.append(RegisterTranslator(regs[1].upper()))

        if len(bp_factors) == 0:
            break
        if len(influencing_ta_set) == size:
            break
        bp_ta -= 1

        return influencing_ta_set


# new
def Recursive_BP(trace_list, factor_ta, max_ta, factors):
    influencing_ta_set = BackPropagation(trace_list, 10, factor_ta, max_ta, factors)

    return influencing_ta_set

#  original
# def BackPropagation(trace_list, cnt, ta, max_ta, factor, ta_min):
#     bp_factors = []
#     bp_ta = ta - 1
#     ta_min_list = []
#
#     if cnt:
#         while bp_ta >= max_ta and bp_ta >= 0:
#             if trace_list[bp_ta].get_name().upper() in OPERATORS:
#                 regs = trace_list[bp_ta].get_operand()
#                 if RegisterTranslator(regs[0].upper()) == factor:
#                     for reg in regs:
#                         if not reg.startswith("0x"):
#                             bp_factors.append(RegisterTranslator(reg.upper()))
#                     break
#             elif trace_list[bp_ta].get_name().upper() in DATA_MOVEMENT:
#                 regs = trace_list[bp_ta].get_operand()
#                 if RegisterTranslator(regs[0].upper()) == factor:
#                     if regs[1].startswith("0x"):
#                         bp_factors = []
#                     else:
#                         bp_factors.append(RegisterTranslator(regs[1].upper()))
#                     break
#             bp_ta -= 1
#         if len(bp_factors) == 0:
#             return ta_min
#         elif len(bp_factors) == 1:
#             return BackPropagation(trace_list, cnt-1, bp_ta, max_ta, bp_factors[0], bp_ta)
#         else:
#             for bp_factor in bp_factors:
#                 ta_min_list.append(BackPropagation(trace_list, cnt-1, bp_ta, max_ta, bp_factor, ta_min))
#             return min(ta_min_list)
#     else:
#         return ta_min
#
#
# def Recursive_BP(trace_list, factor_ta, max_ta, factors):
#     ta_min = factor_ta
#     for factor in factors:
#         ta_min = min(ta_min, BackPropagation(trace_list, 3, factor_ta, max_ta, factor, ta_min))
#
#     return ta_min

def FigureK(trace_list, cjmp_ta):
    factors = []
    cjmp = trace_list[cjmp_ta].get_name().upper()
    factor_ta = cjmp_ta
    if cjmp in OF_JUMPS :
        factors, factor_ta = OF_Factor(trace_list, cjmp_ta)
    elif cjmp in SF_JUMPS:
        factors, factor_ta = SF_Factor(trace_list, cjmp_ta)
    elif cjmp in CF_JUMPS:
        factors, factor_ta = CF_Factor(trace_list, cjmp_ta)
    elif cjmp in ZF_JUMPS:
        factors, factor_ta = ZF_Factor(trace_list, cjmp_ta)
    elif cjmp in CX_JUMPS:
        factors, factor_ta = CX_Factor(trace_list, cjmp_ta)

    influencing_instruction_ta_list = Recursive_BP(trace_list, factor_ta, cjmp_ta-30,  factors)
    if not influencing_instruction_ta_list is None:
        ta_min = min(influencing_instruction_ta_list)
    else:
        ta_min = cjmp_ta-10
    print(influencing_instruction_ta_list)
    print("ta_min : ", trace_list[ta_min].get_ta(), " cjmp_ta : ", trace_list[cjmp_ta].get_ta())

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


