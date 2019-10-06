from __future__ import print_function
import sys
import z3

from miasm.arch.x86.arch import *
from miasm.arch.x86.regs import regs_init
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import Z3Mem, TranslatorZ3
from miasm.expression.expression import *

class Asm_instruction:
    ta = int()
    pa = ""
    name = ""
    operand = []


    def set(self, ta, pa, name, operand):
        self.ta = ta
        self.pa = pa
        self.name = name
        self.operand = operand
        self.asmblock_index = None
        self.asmblock = None

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
        self.offset = offset
        self.len = len

    def from_string(self, ta, pa, string):
        li = string.split(' ')
        for i in range(len(li)):
            li[i].strip()
        opc = li[0]
        del li[0]
        self.set(int(ta), pa, opc, li)\

    def __repr__(self):
        pass
    def __str__(self):
        str = "TA: "+ str(self.ta)+ ", PA: "+str(self.pa)+", instruction: "+self.name+", asmblock:"+str(self.asmblock.loc_key)
        return str


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


def trace_from_file(filename):
    f = open(filename, "rw")
    lines = f.readlines()
    binstr = ""  # binary code
    trace_list = []
    offset = 0
    for line in lines:
        asm_instr = Asm_instruction()
        li = line.split(";")
        asm_instr.from_string(li[0].strip(), li[1].strip(), li[3].strip())
        trace_list.append(asm_instr)
        li2 = li[2].split('\\x')
        byte_stream = ""

        for b in li2:
            byte_stream += b.strip()
        binstr += byte_stream
        byte_stream = bytearray.fromhex(byte_stream)
        asm_instr.set_offset(offset, len(byte_stream))

    binstr = bytearray.fromhex(binstr)

    f.close()

    return str(binstr), trace_list

def construct_asmblock(binstr, trace_list):
    asmblocks = []

    c = Container.from_string(binstr)

    ####### need to check
    machine = Machine('x86_32')

    mdis = machine.dis_engine(c.bin_stream)

    offset = 0
    index = 0
    block_index = 0
    
    f = open('./byte_to_asm.txt', 'w')
    while offset < len(binstr):
        asmblock = mdis.dis_block(offset)
        f.write(asmblock.to_string())
        start, end = asmblock.get_range()
        asmblocks.append(asmblock)
        for trace in trace_list[index: index+len(asmblock.lines)]:
            trace.set_asmblock(asmblock, block_index)
        offset = end
        index += len(asmblock.lines)
        block_index += 1
    f.close()
   
    return asmblocks, mdis.loc_db


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

def makeConstraint_str2(asmblocks, loc_db):
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
    asmblock = trace_list[trace_index].asmblock
    asmblocks.append(asmblock)
    constraint_asmblock = get_k_blocks(trace_index, trace_list, asmblocks, k)

    if (trace_list[trace_index].get_ta() == 2116):
        sym_state, sym_pc = makeConstraint_str2(constraint_asmblock, loc_db)
    else:
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

        solver.insert(z3_ebp8 < 10000)
        solver_.insert(z3_ebp8 < 10000)
        solver.insert(z3_ebp8 > -10000)
        solver_.insert(z3_ebp8 > -10000)
        solver.add( simple_expr== src1)
        solver_.add( simple_expr== src2)

        s_check = solver.check()
        s_check2 = solver_.check()
        if s_check != s_check2:
            print('======', trace_list[trace_index].get_ta(), '=====')
            print("It's opaque predicate, sat and unsat")
            print(trace_list[trace_index].get_pa())
    else :
        print('==========', trace_list[trace_index].get_ta(), '==========')
        print('EIP is not cond, Its opaque predicate')

k = 0
if sys.argv[2] is not None:
    k = sys.argv[2]
binstr, trace_list = trace_from_file(sys.argv[1])

print(len(trace_list))

cmp_jz_list = cmp_jz(trace_list)
ta_map = group_cmp_jz(cmp_jz_list, trace_list)

cmp_jz_ta_list = []
for i in range(0, len(cmp_jz_list)):
    real_ta = trace_list[cmp_jz_list[i]].get_ta()
    cmp_jz_ta_list.append(real_ta)

asmblocks, loc_db = construct_asmblock(binstr, trace_list)
for trace_index in cmp_jz_list:
    is_unsat_ta(asmblocks, trace_index, trace_list, loc_db, int(k))

print(cmp_jz_ta_list)
