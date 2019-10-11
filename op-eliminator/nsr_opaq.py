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

class Asm_instruction:
    ta = int()
    pa = ""
    name = ""
    operand = ""
    asmblock_index = None

    def __init__(self):
        self.len = None
        self.offset = None

    def set(self, ta, pa, name, operand):
        self.ta = ta
        self.pa = pa
        self.name = name
        self.operand = operand

    def get_ta(self):
        return self.ta

    def get_pa(self):
        return self.pa

    def get_name(self):
        return self.name

    def get_operand(self):
        return self.operand

    def set_asmblock(self, asmblock, index):
        self.asmblock = asmblock
        self.asmblock_index = index

    def set_offset(self, offset, len):
        self.len = len
        self.offset = offset

    def __repr__(self):
        pass

    def __str__(self):
        return "TA: " + str(self.ta) + ", PA: " + str(self.pa) + ", instruction: " + self.name + " " + self.operand


def trace_from_file(filename):
    f = open(filename, "rw")
    lines = f.readlines()
    hex_str = ""  # binary code
    trace_list = []
    ta = 0;

    for line in lines:
        li = line.split(" ")
        if li[0] == '\n':
            continue
        elif li[0] == '#arch:x86_32\n' or li[0] == '#arch:x86_64\n':
            continue
        elif li[0] == 'Basic' or li[1] == 'Basic':
            continue
        else:
            i = 3
            operand = li[2]
            asm_instr = Asm_instruction()
            while li[i] != '#':
                operand += ' ' + li[i]
                i += 1
            asm_instr.set(ta, li[0], li[1], operand)
            trace_list.append(asm_instr)
            byte_stream = li[i + 1].strip()
            hex_str += byte_stream
            ta += 1
    hex_code = bytearray.fromhex(hex_str)
    f.close()

    return str(hex_code), trace_list


def group_cmp_jz(cmp_jz_ta_group, trace_list):
    ta_map = dict()
    for i in range(0, len(cmp_jz_ta_group)):
        pa = trace_list[cmp_jz_ta_group[i]].get_pa()
        if pa in ta_map:
            if isinstance(ta_map[pa], list):
                li = ta_map[pa]
                li.append(cmp_jz_ta_group[i])
                ta_map[pa] = li
            else:
                li = []
                li.append(ta_map[pa])
                li.append(cmp_jz_ta_group[i])
                ta_map[pa] = li
        else:
            ta_map[pa] = cmp_jz_ta_group[i]
    return ta_map

def cmp_jz(trace_list):
    cmp_jz_ta = []

    for i in range(0, len(trace_list)):
        name = trace_list[i].get_name().upper()
        if name in conditional_branch:
            cmp_jz_ta.append(i)

    return cmp_jz_ta


def construct_asmblock(binstr, trace_list):
    asmblocks = []
    c = Container.from_string(binstr)
    ####### need to check
    machine = Machine('x86_32')
    machine_dis = machine.dis_engine(c.bin_stream)
    offset = 0
    index = 0
    block_index = 0

    while offset < len(binstr):
        asmblock = machine_dis.dis_block(offset)
        start, end = asmblock.get_range()
        asmblocks.append(asmblock)
        for trace in trace_list[index: index+len(asmblock.lines)]:
            trace.set_asmblock(asmblock, block_index)
        offset = end
        index += len(asmblock.lines)
        block_index += 1

    return asmblocks, machine_dis.loc_db


def makeConstraint_str(asmblocks, loc_db):
    machine = Machine('x86_32')
    sym_state = None
    sym_pc = None

    for asmblock in asmblocks:

        offset, end =asmblock.get_range()

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

def get_k_blocks(trace_index, trace_list, asmblocks, k):
    asmblock_index = trace_list[trace_index].asmblock_index
    #set index
    index = asmblock_index
    start = 0
    end = index + 1
    if( index < k):
        start = 0
    else :
        start = end - k
    kblocks = asmblocks[start: end]

    return kblocks

def is_unsat_ta(asmblocks, trace_index, trace_list, loc_db, k = 10):
    try:
        asmblock = trace_list[trace_index].asmblock
        asmblocks.append(asmblock)
        constraint_asmblock = get_k_blocks(trace_index, trace_list, asmblocks, k)

        sym_state, sym_pc = makeConstraint_str(constraint_asmblock, loc_db)

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

            solver.insert(z3_ebp8 < 1000)
            solver_.insert(z3_ebp8 < 1000)
            solver.insert(z3_ebp8 > -1000)
            solver_.insert(z3_ebp8 > -1000)
            solver.add( simple_expr== src1)
            solver_.add( simple_expr== src2)

            s_check = solver.check()
            s_check2 = solver_.check()
            if s_check != s_check2:
                print('======', trace_list[trace_index].get_pa(), '=====')
                print("It's opaque predicate, sat and unsat")
                print(trace_list[trace_index].get_pa())
        else :
            print('==========', trace_list[trace_index].get_pa(), '==========')
            print('EIP is not cond, Its opaque predicate')
    except Exception as e:
        pass


k = 0
if sys.argv[2] is not None:
    k = sys.argv[2]
hex_str, trace_list = trace_from_file(sys.argv[1])
print(len(trace_list))
cmp_jz_list = cmp_jz(trace_list)

ta_map = group_cmp_jz(cmp_jz_list, trace_list)
cmp_jz_ta_list = []
for i in range(0, len(cmp_jz_list)):
    real_ta = trace_list[cmp_jz_list[i]].get_ta()
    cmp_jz_ta_list.append(real_ta)
asmblocks, loc_db = construct_asmblock(hex_str, trace_list)

for trace_index in cmp_jz_list:
    is_unsat_ta(asmblocks, trace_index, trace_list, loc_db, int(k))

print(cmp_jz_ta_list)
