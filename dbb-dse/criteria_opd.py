ARITHMETIC_OPERATORS = ["ADD", "SUB", "MUL", "DIV",
                        "ADC", "SBC", "IMUL", "IDIV",
                        "INC", "DEC"]
LOGICAL_OPERATORS = ["AND", "OR", "XOR", "NOT", "NEG"]
BINARY_OPERATORS = ["SHR", "SAR", "SHL", "SAL",
                    "ROR", "ROL", "RCR", "RCL"]
COMPARE_OPERATORS = ["CMP", "TEST"]
DATA_MOVEMENT = ["MOV", "LEA", "MOVZX", "MOVSX"]  #"PUSH", "POP",

OPERATORS = ARITHMETIC_OPERATORS + LOGICAL_OPERATORS + BINARY_OPERATORS

OF_JUMPS = ["JO", "JNO", "JL", "JG", "JGE", "JLE", "JPE", "JNP"]  # Arith combined with PF
SF_JUMPS = ["JL", "JG", "JGE", "JS", "JNS", "JLE"]  # Arith(except *,/), Logic
ZF_JUMPS = ["JZ", "JE", "JNZ", "JNE", "JBE", "JA", "JG", "JLE"]  # Arith, cmp, test
CF_JUMPS = ["JB", "JAE", "JBE", "JA", "JNB", "JNBE"]  # Arith, Binary
#PF_JUMPS = ["JPE", "JNP"]  # Arith
CX_JUMPS = ["JCXZ", "JECXZ", "JRCXZ"]  # ECX
CJMPS = OF_JUMPS + SF_JUMPS + ZF_JUMPS + CF_JUMPS + CX_JUMPS

OF_CMOVS = ["CMOVO", "CMOVNO", "CMOVL", "CMOVG", "CMOVGE", "CMOVLE", "CMOVPE", "CMOVNP"]  # Arith combined with PF
SF_CMOVS = ["CMOVL", "CMOVG", "CMOVGE", "CMOVS", "CMOVNS", "CMOVLE"]  # Arith(except *,/), Logic
ZF_CMOVS = ["CMOVZ", "CMOVE", "CMOVNZ", "CMOVNE", "CMOVBE", "CMOVA", "CMOVG", "CMOVLE"]  # Arith, cmp, test
CF_CMOVS = ["CMOVB", "CMOVAE", "CMOVBE", "CMOVA"]  # Arith, Binary
#PF_CMOVS = ["JPE", "JNP"]  # Arith
CX_CMOVS = ["CMOVCXZ", "CMOVECXZ", "CMOVRCXZ"]  # ECX

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