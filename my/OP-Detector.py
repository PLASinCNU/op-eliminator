from __future__ import print_function
import sys
import z3
from miasm.arch.x86.arch import *
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import TranslatorZ3
from miasm.expression.expression import *
from criteria_opd import *
from arch_opd import *

def TraceFromFile_PLAS(filename):
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


def TraceFromFile_NSR(filename):
    f_input = open(filename, "rw")
    lines = f_input.readlines()
    hex_str = ""  # binary code
    trace_list = []
    ta = 0;
    for line in lines:
        li = line.split(" ")
        try:
            if li[0].strip() == '':
                continue
            elif li[0].strip() == '#arch:x86_32':
                continue
            elif li[0] == 'Basic' or li[1] == 'Basic':
                continue
            else:
                i = 3
                asm_instr = AsmInstruction()
                operand = []
                src= ""
                if li[i-1] != '#':
                    operand.append(li[i-1].strip(','))
                    while li[i] != '#':
                        src += li[i] + ' '
                        i += 1
                    if src != "":
                        operand.append(src.strip())
                asm_instr.set(ta, li[0], li[1], operand, li[i+1].strip())
                trace_list.append(asm_instr)
                ta += 1
        except Exception as e:
            print(li)
    f_input.close()

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


def BinToStr(trace_list, min_ta, cjmp_ta):
    binstr = ""

    for trace in trace_list[min_ta:cjmp_ta+1]:
        binstr += trace.get_hex()
    return str(bytearray.fromhex(binstr))


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


# new
def BackPropagation(trace_list, size, ta, max_ta, factors):
    bp_factors = factors
    bp_ta = ta - 1
    influencing_ta_set = set()
    influencing_ta_set.add(ta)
    cmov_ta = int()
    cmov_factors = []

    while bp_ta >= max_ta and bp_ta >= 0:
        if len(cmov_factors) != 0:
            if cmov_ta == bp_ta:
                influencing_ta_set.add(cmov_ta)
                bp_factors.extend(cmov_factors)
                bp_factors = list(set(bp_factors))
                cmov_factors = []
                bp_ta -= 1
                continue
        regs = trace_list[bp_ta].get_operand()
        bp_opc = trace_list[bp_ta].get_name().upper()
        if bp_opc in OPERATORS:
            if RegisterTranslator(regs[0].upper()) in bp_factors:
                influencing_ta_set.add(bp_ta)
                for reg in regs:
                    if not reg.startswith("0x"):
                        bp_factors.append(RegisterTranslator(reg.upper()))
        elif bp_opc in DATA_MOVEMENT:
            if RegisterTranslator(regs[0].upper()) in bp_factors:
                influencing_ta_set.add(bp_ta)
                bp_factors.remove(RegisterTranslator(regs[0].upper()))
                if not regs[1].startswith("0x"):
                    bp_factors.append(RegisterTranslator(regs[1].upper()))
        elif bp_opc.startswith("CMOV"):
            if RegisterTranslator(regs[0].upper()) in bp_factors:
                if bp_opc in OF_CMOVS:
                    cmov_factors, cmov_ta = OF_Factor(trace_list, bp_ta)
                elif bp_opc in SF_CMOVS:
                    cmov_factors, cmov_ta = SF_Factor(trace_list, bp_ta)
                elif bp_opc in CF_CMOVS:
                    cmov_factors, cmov_ta = CF_Factor(trace_list, bp_ta)
                elif bp_opc in ZF_CMOVS:
                    cmov_factors, cmov_ta = ZF_Factor(trace_list, bp_ta)
                elif bp_opc in CX_CMOVS:
                    cmov_factors, cmov_ta = CX_Factor(trace_list, bp_ta)
                influencing_ta_set.add(bp_ta)
                if not regs[1].startswith("0x"):
                    bp_factors.append(RegisterTranslator(regs[1].upper()))

        # print("[ bp_ta ] : ", trace_list[bp_ta].get_ta(), "[ factors ] : ", bp_factors)
        if len(bp_factors) == 0:
            break
        if len(influencing_ta_set) == size:
            break
        bp_ta -= 1

    return influencing_ta_set


# new
def Recursive_BP(trace_list, factor_ta, max_ta, factors):
    influencing_ta_set = BackPropagation(trace_list, 9, factor_ta, max_ta, factors)

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

    influencing_instruction_ta_list = Recursive_BP(trace_list, factor_ta, cjmp_ta-100,  factors)
    if not influencing_instruction_ta_list is None:
        ta_min = min(influencing_instruction_ta_list)
    else:
        ta_min = cjmp_ta-10
    print(influencing_instruction_ta_list)

    return ta_min


def GetSymbVal(binstr):
    machine = Machine('x86_64')
    c = Container.from_string(binstr)
    mdis = machine.dis_engine(c.bin_stream)
    loc_db = mdis.loc_db

    ira = machine.ira(loc_db)
    ircfg = ira.new_ircfg()
    symb = SymbolicExecutionEngine(ira)

    block_start = 0

    while block_start < len(binstr):
        block = mdis.dis_block(block_start)
        block_start, block_end = block.get_range()
        ira.add_asmblock_to_ircfg(block, ircfg)
        symbolic_pc = symb.run_at(ircfg, block_start)
        block_start = block_end
    sym_state = symb.get_state()

    return sym_state, symbolic_pc, loc_db


def GetSymbVal2(binstr):
    machine = Machine('x86_64')
    c = Container.from_string(binstr)
    mdis = machine.dis_engine(c.bin_stream)
    loc_db = mdis.loc_db

    ira = machine.ira(loc_db)
    ircfg = ira.new_ircfg()
    symb = SymbolicExecutionEngine(ira)

    block_start = 0

    while block_start < len(binstr):
        block = mdis.dis_block(block_start)
        block_start, block_end = block.get_range()
        ira.add_asmblock_to_ircfg(block, ircfg)
        symbolic_pc = symb.run_at(ircfg, block_start)
        block_start = block_end
    sym_state = symb.get_state()

    # for symbol in sym_state.symbols:
    #     print(symbol, "  >>>>> ", sym_state.symbols[symbol])

    return sym_state, symbolic_pc, loc_db


def IsUnsatTa(binstr, trace_index, trace_list):
    if trace_list[trace_index].get_ta() == 137: #137
        sym_state, sym_pc, loc_db = GetSymbVal2(binstr)
    else:
        sym_state, sym_pc, loc_db = GetSymbVal(binstr)
    translator = TranslatorZ3(endianness="<", loc_db=loc_db)
    solver = z3.Solver()
    solver_ = z3.Solver()
    print("[sym_pc] : ", sym_pc)
    if isinstance(sym_pc, ExprCond):
        # z3_expr_id = translator.from_expr(sym_state.symbols[expr_eip])
        # src1 = translator.from_expr(sym_state.symbols[expr_eip].src1)
        # src2 = translator.from_expr(sym_state.symbols[expr_eip].src2)
        # ebp_8 = ExprMem(ExprOp('+', ExprId('EBP_init', 32), ExprInt(0x8, 32)), 32)
        # z3_ebp8 = translator.from_expr(ebp_8)
        # solver.insert(z3_ebp8 < 1000)
        # solver_.insert(z3_ebp8 < 1000)
        # solver.insert(z3_ebp8 > -1000)
        # solver_.insert(z3_ebp8 > -1000)

        z3_expr_id = translator.from_expr(sym_pc)
        src1 = translator.from_expr(sym_pc.src1)
        src2 = translator.from_expr(sym_pc.src2)
        simple_expr = z3.simplify(z3_expr_id)

        solver.add(simple_expr == src1)
        solver_.add(simple_expr == src2)

        s_check = solver.check()
        s_check2 = solver_.check()

        if s_check != s_check2:
            print('======', trace_list[trace_index].get_ta(), '=====')
            print("It's opaque predicate, sat and unsat")
            print(trace_list[trace_index].get_pa())
    else:
        print('==========', trace_list[trace_index].get_ta(), '==========')
        print('PC is not cond, Its opaque predicate')


trace_list = TraceFromFile_NSR(sys.argv[1])
# trace_list = TraceFromFile_PLAS(sys.argv[1])
print("Trace len : ", len(trace_list))
cjmp_ta_list, cjmp_index_list = FindCJmp(trace_list)

print(cjmp_index_list)

for trace_index in cjmp_index_list:
    k = FigureK(trace_list, trace_index)
    print(" min ta : ", k, " max ta : ", trace_index)
    bin_str = BinToStr(trace_list, k, trace_index)
    IsUnsatTa(bin_str, trace_index, trace_list)
