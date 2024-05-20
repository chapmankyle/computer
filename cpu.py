import sys

from typing import Tuple, List

# True to print out debug information, False otherwise
DEBUG = False

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
	"TITLE": 13,               # Title of the program, args: prog_name (size = 2)

	"COUNT": 14,               # Upper limit of the instruction set
}

# Number of arguments for each instruction, in form INSTRUCTION_CODE: NUM_ARGS
NUM_ARGS = {
	255: 1,   # EXIT
	1: 2,     # PUT
	2: 2,     # LOAD
	3: 2,     # STORE
	4: 3,     # ARITHMETIC_PLUS
	5: 3,     # ARITHMETIC_MULTIPLY
	6: 2,     # ARITHMETIC_NEGATE
	7: 3,     # LOGICAL_AND
	8: 3,     # LOGICAL_OR
	9: 2,     # LOGICAL_NOT
	10: 1,    # JUMP
	11: 2,    # JUMP_IF_ZERO
	12: 2,    # JUMP_IF_NOT_ZERO
	13: 1     # TITLE
}

# List of programs that we have loaded into memory
PROGRAMS = []

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
		converted = value.upper()

		if converted in ["EXIT", "PUT", "LOAD", "STORE", "TITLE"]:
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


def read_program_from_file(file, start_addr = 0):
	"""
	Reads a program from a file and loads it into memory.
	"""
	global MEMORY

	prog_title = ""
	last_instr_end_addr = start_addr

	with open(file, "r") as f:
		lines = f.readlines()

		for i, line in enumerate(lines):
			if line.startswith("TITLE"):
				prog_title = line[6:].strip()
				continue

			# Remove comments and whitespace
			line = line.split("#")[0].strip()

			# Remove any commas
			line = line.replace(",", "")

			# Skip empty lines
			if not line:
				continue

			# Split the line into tokens
			tokens = line.split(" ")

			# Get the instruction key
			instruction_key = to_instruction_key(tokens[0])

			# Get the instruction value
			instruction_value = INSTRUCTIONS[instruction_key]

			# Get the arguments
			args = [int(arg) for arg in tokens[1:]]

			# Truncate the arguments
			if len(args) > NUM_ARGS[instruction_value]:
				args = args[:NUM_ARGS[instruction_value]]

			# Append zeros to the arguments
			if len(args) < NUM_ARGS[instruction_value]:
				args += [0] * (NUM_ARGS[instruction_value] - len(args))

			if i == 0:
				curr_idx = start_addr
			else:
				curr_idx = last_instr_end_addr

			# Update the end address
			last_instr_end_addr = curr_idx + 1 + len(args)

			# Check if we have enough memory to write the instruction
			if last_instr_end_addr >= MEMORY_SIZE:
				raise ValueError("Out of memory!")

			if DEBUG:
				print(f"Writing instruction: {instruction_key} {args} at address {curr_idx}")

			# Write instruction to memory
			MEMORY[curr_idx] = instruction_value
			MEMORY[curr_idx + 1:last_instr_end_addr] = args

	# Return the address that this program ends at (and title if available)
	return last_instr_end_addr, prog_title


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
	global prog_ctr, MEMORY

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


def run_program(program):
	"""
	Runs the given program, starting at its position in memory.
	"""
	global prog_ctr
	prog_ctr = program["start_addr"]
	ret_value = None

	while True:
		# No more memory to read from
		if prog_ctr >= MEMORY_SIZE:
			break

		# Do not perform cycle when there is no instruction
		if MEMORY[prog_ctr] == 0:
			prog_ctr += 1
			continue

		cpu_cycle()

		if DEBUG:
			print(f"\nAT INDEX ({prog_ctr})\n------------")
			print(MEMORY)

		# Keep running until we have an exit instruction
		if MEMORY[prog_ctr] == INSTRUCTIONS["EXIT"]:
			final_addr = MEMORY[prog_ctr + 1]
			ret_value = None if MEMORY[final_addr] <= 0 else MEMORY[final_addr]
			break

	if ret_value is not None:
		print(("\n" if DEBUG else "") + "Output: " + str(ret_value))


def load_program(path: str, start_addr: int = 0) -> int:
	"""
	Loads a program from the given path and adds it to the list of programs.

	@returns End address of the program + 1, so the next program can start at
	the returned address.
	"""
	global PROGRAMS

	end_addr, name = read_program_from_file(path, start_addr)

	if not name:
		name = "Unnamed Program"

	PROGRAMS.append({
		"name": name,
		"start_addr": start_addr,
		"end_addr": end_addr
	})

	if DEBUG:
		print(f"\nProgram loaded into memory from address {start_addr} to {end_addr - 1}.")

	return end_addr


if __name__ == "__main__":
	"""
	Main entry point.
	"""
	if len(sys.argv) > 1:
		DEBUG = True if sys.argv[1] == "1" else False

	start_addr = 0
	load_program("programs/add-two-numbers.txt", start_addr)

	if DEBUG:
		print("\nINITIAL\n------------")
		print(MEMORY)

	run_program(PROGRAMS[0])
