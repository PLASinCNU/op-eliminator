from __future__ import print_function
import z3

from miasm.arch.x86.arch import mn_x86
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.ir.symbexec import SymbolicExecutionEngine

from miasm.expression.expression import *
from miasm.ir.translators.z3_ir import Z3Mem, TranslatorZ3

loc_db = LocationDB()
s = '\x8dI\x04\x8d[\x01\x80\xf9\x01t\x05\x8d[\xff\xeb\x03\x8d[\x01\x89\xd8\xc3'
c = Container.from_string(s)
machine = Machine('x86_32')
mdis = machine.dis_engine(c.bin_stream)
asmcfg = mdis.dis_multiblock(0)
# for block in asmcfg.blocks:
#     print(block.to_string(asmcfg.loc_db))
ira = machine.ira(loc_db)
ircfg = ira.new_ircfg_from_asmcfg(asmcfg)
# ircfg = ira.new_ircfg(asmcfg)
# print(loc_db._offset_to_loc_key.keys()[0])
sb = SymbolicExecutionEngine(ira)
# symbolic_pc = sb.run_at(ircfg, loc_db._offset_to_loc_key.keys()[0])
# for index, info in enumerate(sb.info_ids):
#     print('###### step', index+1)
#     print('\t', info[0])
#     for reg in info[1]:
#         print('\t\t', reg, ':', info[1][reg])

sb.symbols[machine.mn.regs.ECX] = ExprInt(253, 32)
symbolic_pc = sb.run_at(ircfg, loc_db._offset_to_loc_key.keys()[0])
print('###### modified state step by step')
for step, info in enumerate(sb.info_ids):
    print('###### step', step + 1)
    print('\t', info[0])
    print('\t### info_ids')
    print('\t\t', info[1])
    # for reg in info[1]:
    #     print('\t\t', reg, ':', info[1][reg])
    print('\t### info_mems')
    print('\t\t', sb.info_mems[step][1])
print()

translator = TranslatorZ3(endianness="<", loc_db=loc_db)
z3_expr_dict = dict()
print('###### z3_expr about variable step by step')
for step, info in enumerate(sb.info_ids):
    z3_expr_dict[step + 1] = dict()
    for variable in info[1]:
        z3_expr_dict[step + 1][variable] = translator.from_expr(info[1][variable])
for step in z3_expr_dict.keys():
    print('###### step', step, sb.info_ids[step-1][0])
    for variable in z3_expr_dict[step]:
        print('\t', variable, ':', z3_expr_dict[step][variable])
print()
#
# z3_expr_dst = translator.from_expr(ExprId('zf', 1))
# z3_expr_value = translator.from_expr(sb.info_ids[3][1][ExprId('zf', 1)])
# print('###z3_expr', z3_expr_value)
#
# solver = z3.Solver()
# solver.add(z3_expr_dst == 1)
# solver.add(z3_expr_dst == z3_expr_value)
# solver.check()
# print(solver.model())
