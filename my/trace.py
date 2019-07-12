from __future__ import print_function
from miasm.arch.x86.arch import mn_x86
#from miasm.arch.x86.regs import EDX
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import *

from pdb import pm
from miasm.core import parse_asm    
from future.utils import viewitems


class Asm_instruction:
    ta = int()
    pa = ""
    name = ""
    operand = []
	
    def set(self,ta,pa,name, operand):
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

    def from_string(self,ta,pa,string):
        li = string.split(' ')
        for i in range(len(li)):
            li[i].strip()
        opc = li[0]
        del li[0]
        self.set(int(ta),pa,opc,li)
def is_zf_zero(ta, trace_list, binstr):

    zf = ExprId('zf',1)
    zf_val = ExprInt(1,1)

    loc_db = LocationDB()
    c = Container.from_string(binstr)
    machine = Machine('x86_64')
    mdis = machine.dis_engine(c.bin_stream)
    asmcfg = mdis.dis_multiblock(0)
    ira = machine.ira(loc_db)
    ircfg = ira.new_ircfg_from_asmcfg(asmcfg)
    sb = SymbolicExecutionEngine(ira)
    sb.symbols[machine.mn.regs.ECX] = ExprInt(253,32)
    symbolic_pc = sb.run_at(ircfg,loc_db._offset_to_loc_key.keys()[0])

    info = sb.info_ids[ta]
    flags = info[1]

    if flag[zf] == zf_val:
        return True
    else:
        return False

def additional_constraint_str(ta,trace_list):
    if is_zf_zero(ta,trace_list):
        print('zf == 1')
    else:
        print('zf == 0')

def is_next_varying(ta_list, trace_list):
    if isinstance(ta_list,list):
        cmp_pa = trace_list[ta_list[0]]
	for ta in ta_list:
	    pa = trace_list[ta]
            if cmp_pa != pa:
		raise ValueError
	    return True
	else:
            return True

def non_varying_predicate_pa(ta_map,trace_list):
    keys = list(ta_map.keys())
    pa_list = []
    for key in keys:
    	ta_list = ta_map[key]
    	if is_next_varying(ta_list,trace_list):
            pa_list.append(key)
	
    return pa_list
		

def cmp_jz_next_ta(ta, trace_list):
    if(trace_list[ta].get_name() == 'cmp') and (trace_list[ta+1].get_name() == 'jz'):
        return ta+1
    else:
    	raise ValueError
		
def cmp_jz_next_pa(ta, trace_list):
    ta2 = cmp_jz_next_ta(ta,trace_list)
    return trace_list[ta2].get_pa()

def group_cmp_jz(cmp_jz_ta_group,trace_list):
    ta_map = dict()
    for i in range(0,cmp_jz_ta_group):
	pa = trace_list[cmp_jz_ta_group[i]].get_pa()
	if pa in ta_map:
            if isinstance(ta_map[pa],list):
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
    for i in range(0,len(trace_list)):
        if (trace_list[i].get_name() == 'cmp') :
            if(trace_list[i+1].get_name() == 'jz'):
		cmp_jz_ta.append(i)
    return cmp_jz_ta_group

def trace_from_file(filename):
    f= open(filename, "rw")
    lines = f.readlines()
    binstr = "" # binary code
    trace_list = []
    for line in lines:
	asm_instr = Asm_instruction()
        li = line.split(";")
	asm_instr.from_string(li[0].strip(),li[1].strip(),li[3].strip())
	trace_list.append(asm_instr)
        li2 = li[2].split('\\x')
        for b in li2:
            binstr += b.strip()
    binstr = bytearray.fromhex(binstr)
    f.close()

    return str(binstr), trace_list

def main():
    binstr,trace_list = trace_from_file('calltrace.log')
    loc_db = LocationDB()
    ira = machine.ira(loc_db)
    c = Container.from_string(binstr)
    machine = Machine('x86_64')
    mdis = machine.dis_engine(c.bin_stream)

    ############################################
#    asmcfg = mdis.dis_multiblock(0)
    
#    for block in asmcfg.blocks:
#        #block.lines[0].args[0] = EDX
#        #print(block.lines[0])
#        #print(block.lines[0].name)
#        print(block.to_string(asmcfg.loc_db))
#    #print (asmcfg.loc_db._offset_to_loc_key)
    
    #############################################    

    #++++++++++++++++++++++++++++++++++++++++++++#
#    offset = 0
#    sym_state = None
#    i = 0
#    while offset < len(binstr):
#        if i>10:
#            break
#        asmblock = mdis.dis_block(offset)
#        start, end = asmblock.get_range()
        
#        ira = machine.ira(mdis.loc_db)
#        ircfg = ira.new_ircfg()
#        ira.add_asmblock_to_ircfg(asmblock, ircfg)

#        symb = SymbolicExecutionEngine(ira)
#        cur_addr = symb.run_at(ircfg,offset)

#        for state in symb.get_state():
#            print(state)
#        if sym_state is None:
#            sym_state = symb.get_state()
#        else:
#           syb_state.merge(symb.get_state())
#       print(offset)
#       offet = end
#        i += 1
#    for state in sym_state:
#        print(state)

    #++++++++++++++++++++++++++++++++++++++++++++#
#    ircfg = ira.new_ircfg_from_asmcfg(asmcfg)
    
#    for lbl, irblock in viewitems(ircfg.blocks):
#        print(irblock)
    #################################################
#    asmcfg = parse_asm.parse_txt(mn_x86, 64,binstr)
#    loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)

main()
