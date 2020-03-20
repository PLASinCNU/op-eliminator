from idaapi import *

# CopyRight JHY MAR, 2020


def get_BB_end(ea):
	f = idaapi.get_func(ea)
	if not f:
		print "No function at 0x%x" % (ea)
		return ea
	fc = FlowChart(f)
	for block in fc:
		if block.startEA <= ea:
			if block.endEA > ea:
				return block.endEA
	return ea

def get_op_BB(jmp_dst_ea,adjacent_ea):
	if get_item_color(jmp_dst_ea) == 16054993:
		return adjacent_ea
	else:
		return jmp_dst_ea


def get_Jump_Dst(ea):
	instr = GetDisasm(ea).split()
	if instr[1] == "short":
		return str2ea(instr[2])
	
	return str2ea(instr[1])


def op2nop(op_ea_set):
	for op_ea in op_ea_set:
		jmp_dst_ea = get_Jump_Dst(op_ea)
		adjacent_ea = NextHead(ea)
		next_ea = get_op_BB(jmp_dst_ea,adjacent_ea)
		#while get_item_color(next_ea) == 4294967295:
		#	patch_byte(next_ea,0x90)
		#	next_ea += 1
		patch_byte(next_ea,0x90)
		end_ea = get_BB_end(next_ea)
		while next_ea <= end_ea:
			patch_byte(next_ea,0x90)
			next_ea += 1


def taint_op(lines):
	op_ea_set = set()
	op_lines = lines[-1].split(',')
	for op_line in op_lines:
		print(op_line)
		try:
			ea = str2ea(op_line)
			op_ea_set.add(ea)
			SetColor(ea,CIC_ITEM,0x003458)
		except Exception as e:
			pass
			# print e + str(op_line)
	return op_ea_set


def taint_traced(lines):
	for line in lines:
		try:
			ea = str2ea(line)
			SetColor(ea,CIC_ITEM,0xf4fad1)
		except Exception as e:
			pass
			#print e + str(line)
	

def read_file():
	filepath = "C:\Users\user\Desktop\ida_address.tpa"
	f = open(filepath,'r')
	lines = f.readlines()
	
	return lines


def main() :
	lines = read_file()
	taint_traced(lines)
	op_ea_set = taint_op(lines)
	op2nop(op_ea_set)
	
	
main()