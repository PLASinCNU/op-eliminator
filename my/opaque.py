from __future__ import print_function
import sys
import z3


from miasm.arch.x86.arch import *
# from miasm.arch.x86.regs import EDX
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import *
from miasm.ir.translators.z3_ir import Z3Mem, TranslatorZ3
from miasm.expression.expression import *
from pdb import pm
from miasm.core import parse_asm
from future.utils import viewitems

#zf = z3.BitVec('zf', 1)
#of = z3.BitVec('of', 1)
#cf = z3.BitVec('cf', 1)
#sf = z3.BitVec('sf', 1)
#pf = z3.BitVec('pf', 1)
#CX = z3.BitVec('CX', 16)
#ECX = z3.BitVec('ECX', 32)
#RCX = z3.BitVec('RCX', 64)

#def build_constraints( *args ):
#    solver = z3.Solver()
#    solver.add(*args)
#    return solver

#conditional_branch_constriaint = {  "JO":build_constraints(of == 1), "JNO":build_constraints(of == 1), "JB":build_constraints(cf ==1), "JAE":build_constraints(cf ==1),
#                                    "JZ":build_constraints(zf == 0), "JNZ":build_constraints(zf == 0),
#                                    "JBE":build_constraints(z3.Or(zf==1, cf==1)), "JA":build_constraints(z3.And(cf==0, zf==0)),
#                                    "JS":build_constraints(sf == 0), "JNS":build_constraints(sf == 0), "JPE":build_constraints(pf==1), "JNP":build_constraints(pf==1),
#                                    "JL":build_constraints(sf != of), "JGE":build_constraints(sf == of), "JLE":build_constraints(z3.Or(zf == 1, sf !=of)),
#                                   "JG":build_constraints(z3.And(zf==0, sf == of)),
#                                    "JCXZ":build_constraints(CX == 0), "JECXZ":build_constraints(ECX == 0), "JRCXZ":build_constraints(RCX == 0)}

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


def is_zf_zero(ta, trace_list, binstr):
    zf = ExprId('zf', 1)
    zf_val = ExprInt(1, 1)

    loc_db = LocationDB()
    c = Container.from_string(binstr)
    machine = Machine('x86_64')
    mdis = machine.dis_engine(c.bin_stream)
    asmcfg = mdis.dis_multiblock(0)
    ira = machine.ira(loc_db)
    ircfg = ira.new_ircfg_from_asmcfg(asmcfg)
    sb = SymbolicExecutionEngine(ira)
    sb.symbols[machine.mn.regs.ECX] = ExprInt(253, 32)
    symbolic_pc = sb.run_at(ircfg, loc_db._offset_to_loc_key.keys()[0])

    info = sb.info_ids[ta]
    flags = info[1]

    if flags[zf] == zf_val:
        return True
    else:
        return False


def additional_constraint_str(ta, trace_list):
    if is_zf_zero(ta, trace_list):
        print('zf == 1')
    else:
        print('zf == 0')


def is_next_varying(ta_list, trace_list):
    if isinstance(ta_list, list):
        cmp_pa = trace_list[ta_list[0]]
        for ta in ta_list:
            pa = trace_list[ta]
            if cmp_pa != pa:
                raise ValueError
            return True
        else:
            return True


def non_varying_predicate_pa(ta_map, trace_list):
    keys = list(ta_map.keys())
    pa_list = []
    for key in keys:
        ta_list = ta_map[key]
        if is_next_varying(ta_list, trace_list):
            pa_list.append(key)

    return pa_list


def cmp_jz_next_ta(ta, trace_list):
    name = trace_list[ta].get_name().upper()
    if name in conditional_branch:
        return ta
    else:
        raise ValueError


def cmp_jz_next_pa(ta, trace_list):
    ta2 = cmp_jz_next_ta(ta, trace_list)
    return trace_list[ta2].get_pa()


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
    machine = Machine('x86_64')

    mdis = machine.dis_engine(c.bin_stream)

    offset = 0
    index = 0
    block_index = 0
    while offset < len(binstr):
        asmblock = mdis.dis_block(offset)
        start, end = asmblock.get_range()
        asmblocks.append(asmblock)
        for trace in trace_list[index: index+len(asmblock.lines)]:
            trace.set_asmblock(asmblock, block_index)
        offset = end
        index += len(asmblock.lines)
        block_index += 1

    return asmblocks, mdis.loc_db


def makeConstraint_str(asmblocks, loc_db):
    machine = Machine('x86_64')
    sym_state = None
    for asmblock in asmblocks:
        offset, end =asmblock.get_range()

        ira = machine.ira(loc_db)
        ircfg = ira.new_ircfg()
        ira.add_asmblock_to_ircfg(asmblock, ircfg)

        symb = SymbolicExecutionEngine(ira)
        symb.run_at(ircfg, offset)


        if sym_state is None:
            sym_state = symb.get_state()
        else:
            sym_state.merge(symb.get_state())


    return sym_state

def add_state_constraint(ar, z3):
    pass

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

def is_unsat_ta(asmblocks, trace_index, trace_list, loc_db, k = 0):
    asmblock = trace_list[trace_index].asmblock
    jmp_inst = trace_list[trace_index].get_name().upper()
#    constraints = conditional_branch_constriaint[jmp_inst]

    offset = trace_list[trace_index].offset
    asmblocks.append(asmblock)
    constraint_asmblock = get_k_blocks(trace_index, trace_list, asmblocks, k)
    sym_state = makeConstraint_str(constraint_asmblock, loc_db)

#    print(sym_state.symbols[ExprId("IRDst", 64)])
    IRDst_state = sym_state.symbols[ExprId("IRDst", 64)]
    if(isinstance(IRDst_state, ExprCond)):
#        print("It's not opaque predicate")
        pass
    else:
        print("It's opaque predicate")
        print(trace_list[trace_index].get_pa())
    pass

k = 0
if sys.argv[2] is not None:
    k = sys.argv[2]
binstr, trace_list = trace_from_file(sys.argv[1])

print(len(trace_list))
cmp_jz_list = cmp_jz(trace_list)
group_cmp_jz(cmp_jz_list, trace_list)
asmblocks, loc_db = construct_asmblock(binstr, trace_list)
for trace_index in cmp_jz_list:
    is_unsat_ta(asmblocks, trace_index, trace_list, loc_db, int(k))

print(cmp_jz_list)

