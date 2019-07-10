from __future__ import print_function
import sys

from miasm.core.asmblock import AsmBlockBad
from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.arch.x86.arch import mn_x86
from miasm.ir.translators.z3_ir import Z3Mem, TranslatorZ3

trace_address=list()

def trace_from_file(filename):
    f= open(filename, "rw")
    lines = f.readlines()
    binstr = "" # binary code
    ta = [] # trace number
    pa = [] # intruction address
    asm_list = [] # asm code list
    for line in lines:
        li = line.split(";")
        ta.append(li[0].strip())
        pa.append(li[1].strip())
        asm_list.append(li[3].strip())
        li2 = li[2].split('\\x')
        for b in li2:
            binstr += b.strip()
    binstr = bytearray.fromhex(binstr)
    f.close()

    return str(binstr), ta, pa, asm_list



def remove_cmp(bin_str):
    print("remove_cmp")
    loc_db=LocationDB()
    f=open("new_trace.txt", 'w')
    t=open("instr_trace.txt", 'w')
    cur_addr = 0

    try:
        binstr = bin_str
        c = Container.from_string(binstr)
        machine = Machine('x86_64')
        mdis = machine.dis_engine(c.bin_stream)
        print(str(len(binstr)))

        # block disam

        ira = machine.ira(loc_db)
        offset = 0

        sym_state = None
        i = 0
        while offset < len(binstr):
            if i > 10:
                break
            asmblock = mdis.dis_block_trace(offset)
            start, end = asmblock.get_range()

            # Translate ASM -> IR
            ira = machine.ira(mdis.loc_db)
            ircfg = ira.new_ircfg()
            ira.add_asmblock_to_ircfg(asmblock, ircfg)

            # Instantiate a Symbolic Execution engine with default value for registers
            symb = SymbolicExecutionEngine(ira)            # symb = SymbolicExecutionEngine(ira)

            cur_addr = symb.run_at(ircfg, offset)

            for state in symb.get_state():
                print(state)
            if sym_state is None:
                sym_state = symb.get_state()
            else :
                sym_state.merge(symb.get_state())
            # for step, info in enumerate(symb.info_ids):
            #     print('###### step', step + 1)
            #     print('\t', info[0])
            #     print('\t### info_ids')
            #     print('\t\t', info[1])
            #     print('\t### info_mems')
            #     print('\t\t', symb.info_mems[step][1])
            print(offset)
            offset = end
            i += 1

        for state in sym_state:
            print(state)

        translator = TranslatorZ3(endianness="<", loc_db=loc_db)

        # print(l)
        # print(l.name)x
        # if l.name == "CMP":
        #     continue
        # f.write(bcode + "\n")

    except Exception as e:
        print(e)

def makeConstraint_str(expr):
    pass

def add_state_constraint(ar, z3):
    pass

def is_unsat_ta(ta, z3):
    pass


count_bcode = trace_from_file(sys.argv[1])
remove_cmp(count_bcode[0])
