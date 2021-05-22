#!/usr/bin/python3.8

'''
The redacted version of the YDB architecture compiler.

Contains methods to compile binary "bytecode" from a textual representation
of the interpreted languange in question.

Also handles the 64-bit version of the architecture as well, all methods
are interchangable and will work correctly as long as the argument orders
and other randomized identifiers have been retrieved correctly from
the given binary.
'''

import sys
import os

from pwn import *

# Change instruction arg order in the Instruction class

REG_OFFSET = 0x3fc
STACK_OFFSET = 0x2fd

# Register offsets look to be consistent between runs
register_offsets = {
	0x3fc: 'a',
	0x3fd: 'b',
	0x3fe: 'c',
	0x3ff: 'd',
	0x400: 's',
	0x401: 'i',
	0x402: 'f'
} 

# The starting values in the registers
registers = {
	'a': 0,
	'b': 0,
	'c': 0,
	'd': 0,
	's': 0,
	'i': 0,
	'f': 0 
}

# The value of the switch case in write_register()
# Match up the value with the register_offsets above
reg_ids = {
	0x00: 'NONE',
	0x20: 'a',
	0x10: 'b',
	0x02: 'c',
	0x04: 'd',
	0x01: 's',
	0x08: 'i',
	0x40: 'f'
}


# The values from the main loop of interpret_instruction
# < '\0' means 0x80
opcodes = {
	0x08: 'imm',
	0x10: 'add',
	0x40: 'stk',
	0x02: 'stm',
	0x04: 'ldm',
	0x80: 'cmp',
	0x01: 'jmp',
	0x20: 'sys'
}

# Value of the "and" in the switch cases in interpret_sys
# read_code()'s offset will just be reg['a']'s value (base + 0x3fd)
# read_memory will be that number plus the stack offset (0x2fd)
syscall_nums = {
	'open': 0x01,
	'read_code': 0x10,
	'read_memory': 0x02,
	'write': 0x08,
	'sleep': 0x20,
	'exit': 0x04
}



# The value of the OR in interpret_cmp()
flag_meanings = {
	0x08: 'arg1 < arg2',
	0x01: 'arg1 > arg2',
	0x10: 'arg1 == arg2',
	0x02: 'arg1 != arg2',
	0x04: 'arg1 == arg2 == 0'
}

# Used just for ~REDACTED~ syntax, copy paste and rename the symbols to  L, G, E, N, Z
flag_symbols = {
	0x08: 'L',
	0x01: 'G',
	0x10: 'E',
	0x02: 'N',
	0x04: 'Z'
}

file_descriptors = {
	0: 'STDIN',
	1: 'STDOUT',
	2: 'STDERR'
}

# REDACTED_64 instructions
# static
reg_offsets_64 = {
	'a': 0xba,
	'b': 0xbb,
	'c': 0xbc,
	'd': 0xbd,
	's': 0xbe,
	'f': 0xbf,
	'i': 0xb9
}

# Get these from helper_mov_imm. Match the reg offset with the switch case value
reg_ids_64 = {
	'a': p64(0x20),
	'b': p64(0x10),
	'c': p64(0x08),
	'd': p64(0x01),
	's': p64(0x02),
	'f': p64(0x04),
	'i': p64(0x40)
}

# Get these from emit_instruction switch case
opcodes_64 = {
	'imm': p64(0x20),
	'add': p64(0x10),
	'stk': p64(0x40),
	'stm': p64(0x80),
	'ldm': p64(0x04),
	'cmp': p64(0x01),
	'jmp': p64(0x08),
	'sys': p64(0x02)
}


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

class Instruction():

	opcode_index = 2
	arg1_index = 1
	arg2_index = 0

	def __init__(self, instruction_bytes):
		# arg2, arg1, opcode order
		# self.opcode = int(instruction_bytes[4:6], 16)
		# self.arg1 = int(instruction_bytes[2:4], 16)
		# self.arg2 = int(instruction_bytes[0:2], 16)

		# Opcode position can be determined by the AND's in interpret_instruction.
		# 2 sets of trailing 00's indicate that the opcode comes last in ghidra output (MSB)

		# Can find in interpret imm. arg1 will be the 2nd param to write_register, arg2 will be the 3rd
		# (char) instruction or instruction & 0xff means
		# that item is listed first in the ghidra output for an instruction (LSB technically)


		self.opcode = int(instruction_bytes[Instruction.opcode_index*2:(Instruction.opcode_index*2)+2], 16)
		self.arg1 = int(instruction_bytes[Instruction.arg1_index*2:(Instruction.arg1_index*2)+2], 16)
		self.arg2 = int(instruction_bytes[Instruction.arg2_index*2:(Instruction.arg2_index*2)+2], 16)
		self.raw_instruction = instruction_bytes

	def __str__(self):
		if opcodes[self.opcode] == 'imm':
			to_return = 'mov {}, {}'.format(reg_ids[self.arg1], hex(self.arg2))

		elif opcodes[self.opcode] == 'add':
			to_return = 'add {arg1}, {arg2} ({arg1} += {arg2})'.format(arg1=reg_ids[self.arg1], arg2=reg_ids[self.arg2])

		elif opcodes[self.opcode] == 'stm':
			to_return = 'stm Stack[{arg1}], {arg2} (*{arg1} = {arg2})'.format(arg1=reg_ids[self.arg1], arg2=reg_ids[self.arg2])

		elif opcodes[self.opcode] == 'stk':
			if self.arg2 != 0:
				to_return = 'push {}'.format(reg_ids[self.arg2])
				if self.arg1 != 0:
					to_return += '\npop {}'.format(reg_ids[self.arg1])
			elif self.arg1 != 0:
				to_return = 'pop {}'.format(reg_ids[self.arg1])

		elif opcodes[self.opcode] == 'ldm':
			to_return = 'ldm {arg1}, Stack[{arg2}] ({arg1} = *{arg2})'.format(arg1=reg_ids[self.arg1], arg2=reg_ids[self.arg2])

		elif opcodes[self.opcode] == 'cmp':
			to_return = 'cmp {}, {}'.format(reg_ids[self.arg1], reg_ids[self.arg2])

		elif opcodes[self.opcode] == 'jmp':
			if self.arg1 == 0:
				to_return = 'jmp {}'.format(hex(registers[reg_ids[self.arg2]]))
			else:
				to_return = 'jmp {} if {}\n'.format(hex(registers[reg_ids[self.arg2]]), show_flags(self.arg1))
				if self.arg1 & registers['f'] != 0:
					to_return += '  ..Taken'
				else:
					to_return += '  ..Not Taken'

		elif opcodes[self.opcode] == 'sys':
			if self.arg1 == syscall_nums['open']:
				to_return = 'syscall: open(filename: stack[reg_a], flags: reg_b, mode: rec_c) => {}'.format(reg_ids[self.arg2])
			elif self.arg1 == syscall_nums['read_code']:
				to_return = 'syscall: read_code(fd: reg_a, buf: reg_b, count: reg_c) => {}'.format(reg_ids[self.arg2])
			elif self.arg1 == syscall_nums['read_memory']:
				to_return = 'syscall: read_memory(fd: reg_a, buf: stack[reg_b], count: reg_c) => {}'.format(reg_ids[self.arg2])
			elif self.arg1 == syscall_nums['write']:
				to_return = 'syscall: write(fd: reg_a, buf: stack[reg_b], count: reg_c) => {}'.format(reg_ids[self.arg2])
			elif self.arg1 == syscall_nums['sleep']:
				to_return = 'syscall: sleep(reg_a) => {}'.format(reg_ids[self.arg2])
			elif self.arg1 == syscall_nums['exit']:
				to_return = 'syscall: exit(reg_a)'

		else:
			to_return = 'Error, invalid opcode: {}'.hex(self.opcode)

		return to_return

	# Used solely for TEACHER syntax output
	def __repr__(self):
		to_return = '[I] op:{} arg1:{} arg2:{}\n'.format(hex(self.opcode), hex(self.arg1), hex(self.arg2))
		
		if opcodes[self.opcode] == 'imm':
			to_return += '[s] IMM {} = {}'.format(reg_ids[self.arg1], hex(self.arg2))

		elif opcodes[self.opcode] == 'add':
			to_return += '[s] ADD {} {}'.format(reg_ids[self.arg1], reg_ids[self.arg2])

		elif opcodes[self.opcode] == 'stm':
			to_return += '[s] STM *{} = {}'.format(reg_ids[self.arg1], reg_ids[self.arg2])

		elif opcodes[self.opcode] == 'stk':
			to_return += '[s] STK {} {}'.format(reg_ids[self.arg1], reg_ids[self.arg2])
			if self.arg2 != 0:
				to_return += '[s] ... pushing {}'.format(reg_ids[self.arg2])
				if self.arg1 != 0:
					to_return += '\n[s] ... popping {}'.format(reg_ids[self.arg1])
			elif self.arg1 != 0:
				to_return += '[s] ... popping {}'.format(reg_ids[self.arg1])

		elif opcodes[self.opcode] == 'ldm':
			to_return += '[s] LDM {} - *{}'.format(reg_ids[self.arg1], [self.arg2])

		elif opcodes[self.opcode] == 'cmp' or self.opcode & 0x80 != 0:
			to_return += '[s] CMP {} {}'.format(reg_ids[self.arg1], reg_ids[self.arg2])

		elif opcodes[self.opcode] == 'jmp':
			to_return += '[j] JMP {} {}\n'.format(show_flags(self.arg1, teacher_syntax=True), hex(registers[reg_ids[self.arg2]]))
			if self.arg1 & registers['f'] != 0:
				to_return += '[j] ... TAKEN'
			else:
				to_return += '[j] ... NOT TAKEN'

		elif opcodes[self.opcode] == 'sys':
			to_return += '[s] SYS {} {}\n'.format(hex(self.arg1), reg_ids[self.arg2])
			if self.arg1 == syscall_nums['open']:
				to_return += '[s] ... open'
			elif self.arg1 == syscall_nums['read_code']:
				to_return += '[s] ... read_code'
			elif self.arg1 == syscall_nums['read_memory']:
				to_return += '[s] ... read_memory'
			elif self.arg1 == syscall_nums['write']:
				to_return += '[s] ... write'
			elif self.arg1 == syscall_nums['sleep']:
				to_return += '[s] ... sleep'
			elif self.arg1 == syscall_nums['exit']:
				to_return += '[s] ... exit'

		else:
			to_return = 'Error, invalid opcode: {}'.hex(self.opcode)
		return to_return


	@staticmethod
	def compile(instruction_str, line_no=1, verbose=False):
		"""
		Create the instruction bytes from a text version of REDACTED
		ie - add a, b
		would compile to something like 
			b'\x10\x20\x10'
		if add = 0x10, a_id = 0x20, b_id = 0x10, and the arg order was op, arg1, arg2.
		"""
		if instruction_str.lstrip().startswith('#'):
			return bytearray()

		if verbose:
			print('{}: {}'.format(line_no, instruction_str))
		parsed = list(filter(None, instruction_str.lstrip().rstrip().replace(',', ' ').split(' ')))
		assert len(parsed) == 3, 'Error on instruction #{} "{}", not enough arguments'.format(line_no, instruction_str.encode())

		opcode, arg1, arg2 = parsed[0], parsed[1], parsed[2]
		opcode = opcode.strip()
		arg1 = arg1.strip()
		arg2 = arg2.strip()

		# The integer value to "compile" to
		opcode_val = None
		for imm, name in opcodes.items():
			if opcode == name:
				opcode_val = imm

		assert opcode_val is not None, 'Invalid opcode "{}"'.format(opcode)

		def parse_reg_id(reg_id):
			to_return = None
			for imm, name in reg_ids.items():
				if reg_id == name:
					to_return = imm
					break

			return to_return

		def parse_imm(val):
			int_base = 10
			if val.startswith('0x'):
				int_base = 16
			elif val.startswith('0b'):
				int_base = 2
			try:
				to_return = int(val, int_base)
				if to_return > 0xff:
					to_return = None
			except:
				to_return = None

			finally:
				return to_return

		def parse_flags(val):
			val_int = parse_imm(val)
			if val_int is None or val_int >= max(flag_symbols << 1):
				raise ValueError('{} is not a valid flag value'.format(val))

			# Check that the flags are valid
			flag_vals = ''

			bit = max(flag_symbols)
			while bit > 0:
				if val_int & bit:
					flag_vals.append(flag_symbols[bit])
				bit = bit >> 1

			assert len(flag_vals) > 3



			return val_int

		def parse_syscall_name(val):
			if val is None or val not in syscall_nums:
				raise ValueError('{} is not a valid syscall value'.format(val))

			return syscall_nums[val]

		opcode_byte = opcode_val
		arg1_byte = None
		arg2_byte = None

		to_return = bytearray(b'\x00' * 3)

		if opcode == 'imm':
			arg1_byte = parse_reg_id(arg1)
			arg2_byte = parse_imm(arg2)

			assert arg1_byte is not None
			assert arg2_byte is not None

		elif opcode == 'add':
			arg1_byte = parse_reg_id(arg1)
			arg2_byte = parse_reg_id(arg2)

			assert arg1_byte is not None
			assert arg2_byte is not None

		elif opcode == 'stm':
			arg1_byte = parse_reg_id(arg1)
			arg2_byte = parse_reg_id(arg2)

			assert arg1_byte is not None
			assert arg2_byte is not None

		elif opcode == 'stk':
			arg1_byte = parse_reg_id(arg1)
			arg2_byte = parse_reg_id(arg2)

			assert arg1_byte is not None or arg2_byte is not None

			if arg1_byte is None:
				arg1_byte = parse_imm(arg1)
				assert arg1_byte == 0

			if arg2_byte is None:
				arg2_byte = parse_imm(arg2)
				assert arg2_byte == 0

		elif opcode == 'ldm':
			arg1_byte = parse_reg_id(arg1)
			arg2_byte = parse_reg_id(arg2)

			assert arg1_byte is not None
			assert arg2_byte is not None

		elif opcode == 'cmp':
			arg1_byte = parse_reg_id(arg1)
			arg2_byte = parse_reg_id(arg2)

			assert arg1_byte is not None
			assert arg2_byte is not None

		elif opcode == 'jmp':
			arg1_byte = parse_flags(arg1)
			arg2_byte = parse_reg_id(arg2)

			assert arg1_byte is not None
			assert arg2_byte is not None

		elif opcode == 'sys':
			arg1_byte = parse_syscall_name(arg1)
			arg2_byte = parse_reg_id(arg2)

			assert arg1_byte is not None
			assert arg2_byte is not None

		else:
			assert False, 'Error, invalid opcode: {}'.hex(self.opcode)


		to_return[Instruction.opcode_index] = opcode_val
		to_return[Instruction.arg1_index] = arg1_byte
		to_return[Instruction.arg2_index] = arg2_byte

		return to_return

	@staticmethod
	def compile_64(instruction_str, line_no=1, verbose=False):
		"""
		Create the instruction bytes from a text version of REDACTED_64
		REDACTED_64 instructions are 24 bytes, 3 8byte operands
		ie - add a, b
		would compile to something like 
			b'\x10\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00'
		if add = 0x10, a_id = 0x20, b_id = 0x10, and the arg order was op, arg1, arg2.
		"""
		if instruction_str.lstrip().startswith('#'):
			return bytearray()

		if instruction_str.lstrip().startswith('nop'):
			return bytearray(b'\x00' * 24)

		if verbose:
			print('{}: {}'.format(line_no, instruction_str))
		
		parsed = list(filter(None, instruction_str.lstrip().rstrip().replace(',', ' ').split(' ')))
		
		assert len(parsed) == 3, 'Error on instruction #{} "{}", not enough arguments'.format(line_no, instruction_str.encode())

		opcode, arg1, arg2 = parsed[0], parsed[1], parsed[2]
		opcode = opcode.strip()
		arg1 = arg1.strip()
		arg2 = arg2.strip()

		# The integer value to "compile" to
		opcode_val = None
		for name, imm in opcodes_64.items():
			if opcode == name:
				opcode_val = imm

		assert opcode_val is not None, 'Invalid opcode "{}"'.format(opcode)

		def parse_reg_id(reg_id):
			to_return = None
			for name, imm in reg_ids_64.items():
				if reg_id == name:
					to_return = imm
					break

			return to_return

		def parse_imm(val):
			int_base = 10
			if val.startswith('0x'):
				int_base = 16
			elif val.startswith('0b'):
				int_base = 2
			try:
				to_return = int(val, int_base)
			except:
				to_return = None

			finally:
				return p64(to_return)

		def parse_flags(val):
			'''
			Update this for 64 if needs be, comparison jumps were explicitly disallowed in
			toddler1_level8

			val_int = parse_imm(val)
			if val_int is None or val_int >= max(flag_symbols << 1):
				raise ValueError('{} is not a valid flag value'.format(val))

			# Check that the flags are valid
			flag_vals = ''

			bit = max(flag_symbols)
			while bit > 0:
				if val_int & bit:
					flag_vals.append(flag_symbols[bit])
				bit = bit >> 1

			assert len(flag_vals) > 3



			return val_int
			'''
			return p64(0)

		def parse_syscall_name(val):
			'''
			Same case as the flags function above 

			if val is None or val not in syscall_nums:
				raise ValueError('{} is not a valid syscall value'.format(val))

			return syscall_nums[val]
			'''
			pass

		arg1_val = None
		arg2_val = None

		if opcode == 'imm':
			arg1_val = parse_reg_id(arg1)
			arg2_val = parse_imm(arg2)

			assert arg1_val is not None
			assert arg2_val is not None

		elif opcode == 'add':
			arg1_val = parse_reg_id(arg1)
			arg2_val = parse_reg_id(arg2)

			assert arg1_val is not None
			assert arg2_val is not None

		elif opcode == 'stm':
			arg1_val = parse_reg_id(arg1)
			arg2_val = parse_reg_id(arg2)

			assert arg1_val is not None
			assert arg2_val is not None

		elif opcode == 'stk':
			arg1_val = parse_reg_id(arg1)
			arg2_val = parse_reg_id(arg2)

			assert arg1_val is not None or arg2_val is not None

			if arg1_val is None:
				arg1_val = parse_imm(arg1)
				assert arg1_val == b'\x00' * 8

			if arg2_val is None:
				arg2_val = parse_imm(arg2)
				assert arg2_val == b'\x00' * 8

		elif opcode == 'ldm':
			arg1_val = parse_reg_id(arg1)
			arg2_val = parse_reg_id(arg2)

			assert arg1_val is not None
			assert arg2_val is not None

		elif opcode == 'cmp':
			arg1_val = parse_reg_id(arg1)
			arg2_val = parse_reg_id(arg2)

			assert arg1_val is not None
			assert arg2_val is not None

		elif opcode == 'jmp':
			arg1_val = parse_flags(arg1)
			arg2_val = parse_reg_id(arg2)

			assert arg1_val is not None
			assert arg2_val is not None

		elif opcode == 'sys':
			arg1_val = parse_syscall_name(arg1)
			arg2_val = parse_reg_id(arg2)

			assert arg1_val is not None
			assert arg2_val is not None

		else:
			assert False, 'Error, invalid opcode: {}'.hex(self.opcode)

		to_return = bytearray()

		for index in range(3):
			if index == Instruction.opcode_index:
				to_return += opcode_val
			elif index == Instruction.arg1_index:
				to_return += arg1_val
			elif index == Instruction.arg2_index:
				to_return += arg2_val


		return to_return

	
def compile(lines, verbose=False):
	to_return = bytearray()
	line_no = 1
	for line in filter(None, lines.rstrip().lstrip().replace('\t', '').split('\n')):
		to_return += Instruction.compile(line, line_no, verbose=verbose)
		line_no += 1
	return to_return

def compile_64(lines, verbose=True):
	to_return = bytearray()
	line_no = 1
	for line in filter(None, lines.rstrip().lstrip().replace('\t', '').split('\n')):
		to_return += Instruction.compile_64(line, line_no, verbose=verbose)
		line_no += 1
	return to_return

def compile_script(filename):
	# One instruction per line
	to_return = bytearray()

	line_no = 1
	with open(filename, 'r') as file:
		for line in file:
			if not line.startswith('#') and line != '\n':
				to_return += Instruction.compile(line, line_no)
			line_no += 1

	filename, file_extension = os.path.splitext(filename)

	with open(filename + '.yb', 'wb') as file:
		file.write(to_return)





if __name__ == '__main__':
	compile_script(sys.argv[1])

		

