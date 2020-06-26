from __future__ import print_function
# import sys
import os
import csv
import z3
import numpy as np
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
        try:
            li2 = li[2].split('\\x')
            byte_stream = ""
            for b in li2:
                byte_stream += b.strip()
            asm_instr.from_string(li[0].strip(), li[1].strip(), li[3].strip(), byte_stream)
        except Exception as e:
            print(li, e)
        trace_list.append(asm_instr)
    f.close()

    return trace_list


def TraceFromFile_NSR(filename):
    f_input = open(filename, "r")
    lines = f_input.readlines()
    trace_list = []
    ta = 0
    for line in lines:
        li = line.split(" ")
        try:
            if li[0].startswith('00'):
                asm_instr = AsmInstruction()
                sharp_index = li.index('#')
                oprd = " ".join(li[2:sharp_index])
                operand = oprd.split(",")
                operand = list(map(lambda v: v.strip(), operand))
                asm_instr.set(ta, li[0], li[1], operand, li[sharp_index + 1].strip())
                trace_list.append(asm_instr)
                ta += 1
            else:
                continue
        except Exception as e:
            print(e, " TraceFromFile")
    f_input.close()

    return trace_list


def is_next_pa_neq(trace_list, index_list):
    next_pa = trace_list[index_list[0]+1].get_pa()
    for index in index_list:
        if next_pa != trace_list(index+1).get_pa():
            return True
    return False


def findPredicates(trace_list):
    predicate_ta_list = []
    predicate_index_list = []
    index_dict = dict()

    for i in range(0, len(trace_list)):
        name = trace_list[i].get_name().upper()
        if name in CJMPS:
            pa = trace_list[i].get_pa()
            if pa in index_dict:
                if isinstance(index_dict[pa], list):
                    index_dict[pa].append(i)
                else:
                    new_list = [index_dict[pa], i]
                    index_dict[pa] = new_list
            else:
                index_dict[pa] = i

    for key in filter(lambda k: isinstance(index_dict[k], list), index_dict.keys()):
        if is_next_pa_neq(trace_list, index_dict[key]):
            del(index_dict[key])

    for v in (np.array(index_dict.values())).sort():
        predicate_ta_list.append(trace_list[v].get_ta())
        predicate_index_list.append(v)

    return predicate_ta_list, predicate_index_list


def BinToStr(trace_list, sliced_trace, predicate_ta):
    binary_string = ""
    # min_ta = min(sliced_trace)
    # max_ta = max(sliced_trace)
    # while min_ta <= max_ta:
    #     binary_string += trace_list[min_ta].get_hex();
    #     min_ta += 1
    for trace in sliced_trace:
        binary_string += trace_list[trace].get_hex()
    binary_string += trace_list[predicate_ta].get_hex()
    # print (binary_string)

    return str(bytearray.fromhex(binary_string))


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


def OF_Factor(trace_list, predicate_ta):
    factors = []
    ta = predicate_ta - 1
    while ta >= predicate_ta-10 and ta > 0:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(RegisterTranslator(reg.upper()))
            break
        ta -= 1
    return factors, ta


def SF_Factor(trace_list, predicate_ta):
    factors = []
    ta = predicate_ta - 1
    while ta >= predicate_ta-10 and ta > 0:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + LOGICAL_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(RegisterTranslator(reg.upper()))
            break
        ta -= 1
    return factors, ta


def CF_Factor(trace_list, predicate_ta):
    factors = []
    ta = predicate_ta - 1
    while ta >= predicate_ta-10 and ta > 0:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + BINARY_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(RegisterTranslator(reg.upper()))
            break
        ta -= 1
    return factors, ta


def ZF_Factor(trace_list, predicate_ta):
    factors = []
    ta = predicate_ta - 1
    while ta >= predicate_ta-10 and ta > 0:
        if trace_list[ta].get_name().upper() in ARITHMETIC_OPERATORS + LOGICAL_OPERATORS + COMPARE_OPERATORS:
            for reg in trace_list[ta].get_operand():
                if not reg.startswith("0x"):
                    factors.append(RegisterTranslator(reg.upper()))
            break
        ta -= 1
    factors = list(set(factors))
    return factors, ta


def CX_Factor(trace_list, predicate_ta):
    factors = ["ECX"]
    ta = predicate_ta - 1
    while ta >= predicate_ta-10 and ta > 0:
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
            # print('regs', regs, 'bp_opc : ', bp_opc, trace_list[bp_ta].get_hex())
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
        if len(bp_factors) == 0:
            break
        if len(influencing_ta_set) >= size:
            break
        bp_ta -= 1

    return influencing_ta_set


# new
def Recursive_BP(trace_list, factor_ta, max_ta, factors, k):
    influencing_ta_set = BackPropagation(trace_list, k, factor_ta, max_ta, factors)

    return influencing_ta_set


def FigureK(trace_list, predicate_ta, k):
    factors = []
    condition_jump_instruction = trace_list[predicate_ta].get_name().upper()
    factor_ta = predicate_ta
    if condition_jump_instruction in OF_JUMPS:
        factors, factor_ta = OF_Factor(trace_list, predicate_ta)
    elif condition_jump_instruction in SF_JUMPS:
        factors, factor_ta = SF_Factor(trace_list, predicate_ta)
    elif condition_jump_instruction in CF_JUMPS:
        factors, factor_ta = CF_Factor(trace_list, predicate_ta)
    elif condition_jump_instruction in ZF_JUMPS:
        factors, factor_ta = ZF_Factor(trace_list, predicate_ta)
    elif condition_jump_instruction in CX_JUMPS:
        factors, factor_ta = CX_Factor(trace_list, predicate_ta)

    if predicate_ta-300 < 0:
        min_ta = 0
    else:
        min_ta = predicate_ta - 300

    influencing_instruction_ta_list = Recursive_BP(trace_list, factor_ta, min_ta, factors, k)
    # if influencing_instruction_ta_list is not None:
    #     ta_min = min(influencing_instruction_ta_list)
    # else:
    #     ta_min = cjmp_ta

    return influencing_instruction_ta_list


def GetSymbVal(binary_string):
    machine = Machine('x86_32')
    c = Container.from_string(binary_string)
    mdis = machine.dis_engine(c.bin_stream)
    loc_db = mdis.loc_db

    ira = machine.ira(loc_db)
    ircfg = ira.new_ircfg()
    symb = SymbolicExecutionEngine(ira)

    block_start = 0

    while block_start < len(binary_string):
        block = mdis.dis_block(block_start)
        block_start, block_end = block.get_range()
        try:
            ira.add_asmblock_to_ircfg(block, ircfg)
        except Exception as e:
            print("GetSymbVal exception : ", e)
            continue
        symbolic_pc = symb.run_at(ircfg, block_start)
        block_start = block_end
    sym_state = symb.get_state()

    return sym_state, symbolic_pc, loc_db


def isOpaquePredicate(binary_string, trace_index, trace_list, pa_dict):
    op_cnt = 0
    # suns_ta = None
    # sun = None
    try:
        sym_state, sym_pc, loc_db = GetSymbVal(binary_string)
    except Exception as e:
        print(trace_index, e)

    translator = TranslatorZ3(endianness="<", loc_db=loc_db)
    solver = z3.Solver()
    solver_ = z3.Solver()
    if isinstance(sym_pc, ExprCond):
        try:
            z3_expr_id = translator.from_expr(sym_pc)
            src1 = translator.from_expr(sym_pc.src1)
            src2 = translator.from_expr(sym_pc.src2)
            simple_expr = z3.simplify(z3_expr_id)
            solver.add(simple_expr == src1)
            solver_.add(simple_expr == src2)
            s_check = solver.check()
            s_check2 = solver_.check()
            if s_check != s_check2:
                print('==========', trace_list[trace_index].get_pa(), '==========')
                print("It's opaque predicate, sat and unsat")
                print(trace_list[trace_index].get_ta())
                op_cnt += 1
                pa_dict[trace_list[trace_index].get_pa()] = 1
                # suns_ta = trace_list[trace_index].get_ta()
        except Exception as e:
            print(e, " fffff")
    else:
        print('==========', trace_list[trace_index].get_pa(), '==========')
        print('PC is not cond, Its opaque predicate')
        # sun = trace_list[trace_index].get_ta()
        op_cnt += 1
        pa_dict[trace_list[trace_index].get_pa()] = 1

    return op_cnt, pa_dict


def main():
    path_dir = '/home/ubuntu/synthesizer/miasm/choi/analysis'
    # out_path = '/home/ubuntu/sliced.csv'
    out_path = '/home/ubuntu/original.csv'
    # out_path2 = '/home/ubuntu/2019_obfus/trace/K_time3.csv'
    f_output = open(out_path, "w")
    # f_output2 = open(out_path2, 'w')
    wr = csv.writer(f_output)
    # wr2 = csv.writer(f_output2)

    pa_dict = dict()
    file_list = os.listdir(path_dir)
    file_list.sort()

    for target in file_list:
        print("###################Testing ...  : ", target)
        trace_list = TraceFromFile_NSR(path_dir + "/" + target)
        predicate_ta_list, predicate_index_list = findPredicates(trace_list)

        k_list = [15]
        for k in k_list:
            ta_op_cnt = 0
            for predicate_ta in predicate_index_list:
                sliced_trace = list(FigureK(trace_list, predicate_ta, k))
                sliced_trace.sort()
                binary_string = BinToStr(trace_list, sliced_trace, predicate_ta)
                op, pa_dict = isOpaquePredicate(binary_string, predicate_ta, trace_list, pa_dict)
                ta_op_cnt += op
            wr.writerow([target, ta_op_cnt, pa_dict])
            pa_dict.clear()
    f_output.close()


main()
