from typing import Tuple, List

# Size of the RAM in bytes
MEMORY_SIZE = 255

# RAM
MEMORY = [0 for _ in range(MEMORY_SIZE)]
REGISTERS = [0 for _ in range(16)]

# Instruction set
INSTRUCTIONS = {
	"EXIT": 255,               # Exit the program
	"PUT": 1,                  # Put a value into a memory address, args: value, addr (size = 3)
	"LOAD": 2,                 # Load from memory into register, args: src_addr, dst_register (size = 3)
	"STORE": 3,                # Store from register into memory, args: src_register, dst_addr (size = 3)
	"ARITHMETIC_PLUS": 4,      # Add from two registers, args: in_reg_0, in_reg_1, out_reg (size = 4)
	"ARITHMETIC_MULTIPLY": 5,  # Multiply from two registers, args: in_reg_0, in_reg_1, out_reg (size = 4)
	"ARITHMETIC_NEGATE": 6,    # Negate from register, args: in_reg, out_reg (size = 3)
	"LOGICAL_AND": 7,          # Logical AND from two registers, args: in_reg_0, in_reg_1, out_reg (size = 4)
	"LOGICAL_OR": 8,           # Logical OR from two registers, args: in_reg_0, in_reg_1, out_reg (size = 4)
	"LOGICAL_NOT": 9,          # Logical NOT from register, args: in_reg, out_reg (size = 3)
	"JUMP": 10,                # Jump to address, args: addr (size = 2)
	"JUMP_IF_ZERO": 11,        # Jump to address if register is zero, args: reg, addr (size = 3)
	"JUMP_IF_NOT_ZERO": 12,    # Jump to address if register is not zero, args: reg, addr (size = 3)

	"COUNT": 13,               # Upper limit of the instruction set
}

# Number of arguments for each instruction
NUM_ARGS = {
	"EXIT": 0,
	"PUT": 2,
	"LOAD": 2,
	"STORE": 2,
	"ARITHMETIC_PLUS": 3,
	"ARITHMETIC_MULTIPLY": 3,
	"ARITHMETIC_NEGATE": 2,
	"LOGICAL_AND": 3,
	"LOGICAL_OR": 3,
	"LOGICAL_NOT": 2,
	"JUMP": 1,
	"JUMP_IF_ZERO": 2,
	"JUMP_IF_NOT_ZERO": 2
}

# Position of the currently executing instruction
prog_ctr = 0

# Instruction layout:
# -------------------
# op_code, args...
# instruction size: 1 + num_args

def to_instruction_key(value: int | str) -> str:
	# Special case for EXIT instruction
	if value == 255 or value == "255" or value == "EXIT":
		return "EXIT"

	if isinstance(value, int) and value < INSTRUCTIONS["COUNT"]:
		return next(k for k, v in INSTRUCTIONS.items() if v == value)

	if isinstance(value, str):
		converted = value.to_upper()

		if converted in ["EXIT", "PUT", "LOAD", "STORE"]:
			# No name changes are necessary
			return converted
		elif converted == "ADD":
			return "ARITHMETIC_PLUS"
		elif converted == "MUL":
			return "ARITHMETIC_MULTIPLY"
		elif converted == "NEG":
			return "ARITHMETIC_NEGATE"
		elif converted == "AND":
			return "LOGICAL_AND"
		elif converted == "OR":
			return "LOGICAL_OR"
		elif converted == "NOT":
			return "LOGICAL_NOT"
		elif converted == "JMP":
			return "JUMP"
		elif converted == "JZ":
			return "JUMP_IF_ZERO"
		elif converted == "JNZ":
			return "JUMP_IF_NOT_ZERO"

	raise ValueError(f"Invalid instruction value: {value}")


def decode_instruction() -> Tuple[int, List[int]]:
	"""
	Decodes an instruction from the current position in memory.
	"""
	global prog_ctr

	op_code = MEMORY[prog_ctr]
	prog_ctr += 1

	num_args = NUM_ARGS[op_code]
	args = []

	for _ in range(num_args):
		args.append(MEMORY[prog_ctr])
		prog_ctr += 1

	return op_code, args


def execute_instruction(op_code: int, arguments: List[int]):
	"""
	Executes the given instruction with its arguments.
	"""
	global prog_ctr

	if op_code == INSTRUCTIONS["PUT"]:
		value, addr = arguments
		MEMORY[addr] = value
	elif op_code == INSTRUCTIONS["LOAD"]:
		src_addr, dst_reg = arguments
		REGISTERS[dst_reg] = MEMORY[src_addr]
	elif op_code == INSTRUCTIONS["STORE"]:
		src_reg, dst_addr = arguments
		MEMORY[dst_addr] = REGISTERS[src_reg]
	elif op_code == INSTRUCTIONS["ARITHMETIC_PLUS"]:
		in_reg_0, in_reg_1, out_reg = arguments
		REGISTERS[out_reg] = REGISTERS[in_reg_0] + REGISTERS[in_reg_1]
	elif op_code == INSTRUCTIONS["ARITHMETIC_MULTIPLY"]:
		in_reg_0, in_reg_1, out_reg = arguments
		REGISTERS[out_reg] = REGISTERS[in_reg_0] * REGISTERS[in_reg_1]
	elif op_code == INSTRUCTIONS["ARITHMETIC_NEGATE"]:
		in_reg, out_reg = arguments
		REGISTERS[out_reg] = -REGISTERS[in_reg]
	elif op_code == INSTRUCTIONS["LOGICAL_AND"]:
		in_reg_0, in_reg_1, out_reg = arguments
		REGISTERS[out_reg] = REGISTERS[in_reg_0] & REGISTERS[in_reg_1]
	elif op_code == INSTRUCTIONS["LOGICAL_OR"]:
		in_reg_0, in_reg_1, out_reg = arguments
		REGISTERS[out_reg] = REGISTERS[in_reg_0] | REGISTERS[in_reg_1]
	elif op_code == INSTRUCTIONS["LOGICAL_NOT"]:
		in_reg, out_reg = arguments
		REGISTERS[out_reg] = ~REGISTERS[in_reg]
	elif op_code == INSTRUCTIONS["JUMP"]:
		addr = arguments[0]
		prog_ctr = REGISTERS[addr]
	elif op_code == INSTRUCTIONS["JUMP_IF_ZERO"]:
		reg, addr = arguments
		if REGISTERS[reg] == 0:
			prog_ctr = REGISTERS[addr]
	elif op_code == INSTRUCTIONS["JUMP_IF_NOT_ZERO"]:
		reg, addr = arguments
		if REGISTERS[reg] != 0:
			prog_ctr = REGISTERS[addr]
	else:
		raise ValueError(f"Invalid instruction: {op_code}")


def cpu_cycle():
	"""
	Performs a CPU cycle that decodes and executes a single instruction from
	the current position in memory.
	"""
	op_code, args = decode_instruction()
	execute_instruction(op_code, args)


def run_computer():
	"""
	Runs the computer.
	"""
	global prog_ctr

	# Keep running until we have an exit instruction
	while True:
		cpu_cycle()

		if MEMORY[prog_ctr] == INSTRUCTIONS["EXIT"]:
			break


if __name__ == "__main__":
	"""
	Main entry point.
	"""

	run_computer()
