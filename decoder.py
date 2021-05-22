#!/usr/bin/python3 -u


'''
The redacted version of the decoder / disassembler / debugger for this project

This file has been prepared to run with level 14
'''

import os
import time
import sys

INSTRUCTION_FILE = 'inst'
MEMORY_FILE = 'mem_init.txt'



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

Memory = [0] * max(register_offsets.keys())

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def parse_num(number):
	'''
	Utility function that parses a positive or negative user-supplied number that may either be
	decimal or hex, and returns the parsed number as an int or throws an error
	'''

	if number.startswith('s[') or number.startswith('m['):
		number = number[2:]

	if number.endswith(']'):
		number = number[:-1]

	# 0-base means make Python infer 10 or 16 base
	return int(number, 0)


def show_flags(flags, teacher_syntax=False):
	to_return = ''
	if not teacher_syntax:
		for flag, meaning in flag_meanings.items():
			if flag & flags != 0:
				to_return += meaning
	else:
		for flag, meaning in flag_symbols.items():
			if flag & flags != 0:
				to_return += meaning
	return to_return

def show_regs(teacher_syntax=False):
	if not teacher_syntax:
		return (
			'\ta:{}, b:{}, c:{}, d:{}\n'
			'\ts:{}, i:{}, f:{}'.format(
				hex(registers['a']),
				hex(registers['b']),
				hex(registers['c']),
				hex(registers['d']),
				hex(registers['s']),
				hex(registers['i']),
				hex(registers['f']) ))
	else:
		return ('[V] a:{} b:{} c:{} d:{} s:{} i:{} f:{}'.format(
				hex(registers['a']),
				hex(registers['b']),
				hex(registers['c']),
				hex(registers['d']),
				hex(registers['s']),
				hex(registers['i']),
				hex(registers['f']) ))


class Instruction():
	def __init__(self, instruction_bytes):
		# arg2, arg1, opcode order
		# self.opcode = int(instruction_bytes[4:6], 16)
		# self.arg1 = int(instruction_bytes[2:4], 16)
		# self.arg2 = int(instruction_bytes[0:2], 16)

		# Opcode position can be determined by the AND's in interpret_instruction.
		# 2 sets of trailing 00's indicate that the opcode comes last in ghidra output (MSB), and will be 4:6

		# Can find in interpret imm. arg1 will be the 2nd param to write_register, arg2 will be the 3rd
		# (char) instruction or instruction & 0xff means
		# that item is listed first in the ghidra output for an instruction (LSB technically)

		self.opcode = int(instruction_bytes[4:6], 16)
		self.arg1 = int(instruction_bytes[2:4], 16)
		self.arg2 = int(instruction_bytes[0:2], 16)
		self.raw_instruction = '0x' + str(instruction_bytes).zfill(6)

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
				to_return = 'syscall: open(filename: stack[reg_a], flags: reg_b, mode: reg_c) => {}'.format(reg_ids[self.arg2])
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

	# Used solely for teacher syntax output
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

def load_instructions(filename, Memory):
	with open(filename, 'r') as file:
		contents = file.read()

	# Iterate over the instuctions one instruction chunk at a time.
	# For an input formatted "71 04 08 91"(string, not binary), iterate over each byte
	for offset, byte in enumerate(chunks(contents.replace(' ', ''), 2)):
		Memory[offset] = int(byte, 16)

	'''
	inst_num = 0
	for inst_chunk in chunks(contents, 3):
		# arg2, arg1, opcode order
		Memory[(3 * inst_num) + 0] = int(inst_chunk[0].replace('\n', ''), 16)
		Memory[(3 * inst_num) + 1] = int(inst_chunk[1].replace('\n', ''), 16)
		Memory[(3 * inst_num) + 2] = int(inst_chunk[2].replace('\n', ''), 16)
		inst_num += 1
	'''


# Contents of vm_mem symbol in the binary
# Highlight vm_mem, from bytes view, right click program highlight entire selection, copy, paste into sublime
# file contents should be an entire line
def load_memory(filename):
	with open(filename, 'r') as file:
		contents = file.read()

	for num, byte in enumerate(contents.split(' ')):
		if num >= REG_OFFSET:
			print('This file contains initial register values')
			exit()
		Memory[STACK_OFFSET + num] = int(byte, 16) 

# Change teacher_syntax to true to output in a format identical to the babyrev
def instruction_dump(teacher_syntax=False):
	inst_num = 0

	while inst_num < 0x100:
		instruction_bytes = (
			'{:02X}'.format((Memory[(3 * inst_num) + 0]))
			+ '{:02X}'.format(Memory[(3 * inst_num) + 1])
			+ '{:02X}'.format((Memory[(3 * inst_num) + 2]))
			)
		inst = Instruction(instruction_bytes)

		if not teacher_syntax:
			try:
				print('[{}] \t{}'.format(hex(inst_num), str(inst).replace('\n', '\n\t\t')))
			except:
			 	print('[{}] \tGarbage instruction {}'.format(hex(inst_num), instruction_bytes))
		else:
			try:
				print(repr(inst))
			except:
				print('Garbage instruction')
		inst_num += 1


load_instructions(INSTRUCTION_FILE, Memory)
# load_memory(MEMORY_FILE)

# Uncomment these 2 lines to get a ~REDACTED~code disassembly dump
#instruction_dump()
#exit()



running = True

# Set this to True to enter continue mode and continually run instructions
cont = False
toggle_regs = False
breakpoints = []
# Set to True to automatically break on every syscall
break_sys = False

# Set to True to automatically break on every jump instruction
break_jmp = False

# Set to True to automatically break on every cmp instruction
break_cmp = False

''' Not yet implemented 
register_breaks = {
	'a': False,
	'b': False,
	'c': False,
	'd': False,
	's': False,
	'i': False,
	'f': False
}
'''

watching = {
	'a': False,
	'b': False,
	'c': False,
	'd': False,
	's': False,
	'i': False,
	'f': False
}

# A dictionary of lists for each register
watched_values = {
	'a': [],
	'b': [],
	'c': [],
	'd': [],
	's': [],
	'i': [],
	'f': []
}

# A list of memory breakpoints. Whenever a memory location (offset from the stack) is
# accessed on this list, the program will drop into step instruction mode
memory_breakpoints = []

def process_debugger_commands(inst):
	global registers
	global break_sys
	global break_jmp
	global break_cmp
	global toggle_regs
	global cont

	cont = False
	command = None
	while command != '':
		command = input('YDB> ')

		if command.startswith('m['):
			if ':' in command:
				start, end = command.split(':')
				start = parse_num(start)
				end = parse_num(end)

				# Translate negative indeces back to their proper positive meanings so
				# that the loop works and displays properly
				if start < 0:
					start = len(Memory) + index
				if end < 0:
					end = len(Memory) + index

				for index in range(start, end):
					var = Memory[index]
					if var < 127:
						print('\t[{}] -> {}\t({})'.format(hex(index), hex(var), repr(chr(var))))
					else:
						# Empty to not confuse with space
						print('\t[{}] -> {}\t()'.format(hex(index), hex(var)))
			else:
				index = parse_num(command[2:-1])
				if index < 0:
					index = len(Memory) + index
				var = Memory[index]
				if var < 127:
					print('\t[{}] -> {}\t({})'.format(hex(index), hex(var), repr(chr(var))))
				else:
					# Empty to not confuse with space
					print('\t[{}] -> {}\t()'.format(hex(index), hex(var)))

		elif command == 's':
			print('Current stack dump')
			if registers['s'] == 0:
				print('Empty Stack')
			for x in range(registers['s'] + 1):
				var = Memory[STACK_OFFSET + x]

				if var < 127:
					print('\t[{}] -> {}\t({})'.format(hex(x), hex(var), repr(chr(var))))
				else:
					# Empty to not confuse with space
					print('\t[{}] -> {}\t()'.format(hex(x), hex(var)))

		elif command.startswith('s['):
			if ':' in command:
				start, end = command.split(':')
				if start == 's[':
					start = 0
				else:
					start = parse_num(start)
				if end == ']':
					end = -1
				else:
					end = parse_num(end)

				# Translate negative indeces back to their proper positive meanings so
				# that the loop works and displays properly
				if start < 0:
					start = registers['s'] + 1 + start
				if end < 0:
					end = registers['s'] + 1 + end

				if end - start == 0:
					print('Empty Stack')
				for index in range(start, end):
					var = Memory[STACK_OFFSET + index]
					if var < 127:
						print('\t[{}] -> {}\t({})'.format(hex(index), hex(var), repr(chr(var))))
					else:
						# Empty to not confuse with space
						print('\t[{}] -> {}\t()'.format(hex(index), hex(var)))
			else:
				index = parse_num(command[2:-1])

				if index >= 0:
					var = Memory[STACK_OFFSET + index]
				else:
					var = Memory[STACK_OFFSET + (registers['s'] + 1 + index)]
					# Need to change it to have proper index show up in below print report
					index = registers['s'] + 1 + index
				if var < 127:
					print('\t[{}] -> {}\t({})'.format(hex(index), hex(var), repr(chr(var))))
				else:
					print('\t[{}] -> {}\t()'.format(hex(index), hex(var)))

		elif command == 'reg':
			print(show_regs())

		elif command.startswith('inst'):
			if command == 'inst':
				print('\tinstruction: {}\n\topcode:{}, arg1:{}, arg2:{}\n\tRaw Bytes: {}'
					.format(
						inst,
						hex(inst.opcode),
						hex(inst.arg1),
						hex(inst.arg2),
						inst.raw_instruction))
			else:
				com = command.split(' ')
				num = parse_num(com[1])
				for x in range(min(0, num), max(0, num)):
					next_instruction_bytes = (
						'{:02X}'.format((Memory[(3 * (registers['i'] + x)) + 0]))
						+ '{:02X}'.format((Memory[(3 * (registers['i'] + x)) + 1]))
						+ '{:02X}'.format((Memory[(3 * (registers['i'] + x)) + 2]))
						)
					next_inst = Instruction(next_instruction_bytes)
					try:
						print('\tcurrent + {}: {}'
							.format(
								x,
								next_inst))
					except:
						print('\tcurrent + {}: Garbage Instruction => {}'
							.format(
								x,
								next_inst.raw_instruction))

		elif command.startswith('break'):

			args = command.split(' ')

			if len(args) == 1:
				print('Breakpoints:')
				print(list(map(hex, breakpoints)))
				print('')
				print('Memory breakpoints:')
				print(list(map(hex, memory_breakpoints)))
				print('')
				print('Break on syscalls?', break_sys)
				print('Break on jumps?', break_jmp)
				print('Break on compare?', break_cmp)

			elif len(args) > 1:
				break_inst = args[1]

				if break_inst == 'sys':
					break_sys = not break_sys
				elif break_inst == 'jmp':
					break_jmp = not break_jmp
				elif break_inst == 'cmp':
					break_cmp = not break_cmp

				elif break_inst == 'mem':
					if args[2].startswith('0x'):
						val = int(args[2][2:], 16)
					else:
						val = int(args[2])
					memory_breakpoints.append(val)
				else:
					break_inst = int(break_inst, 16)
					if break_inst not in breakpoints:
						breakpoints.append(break_inst)

				if break_inst == 'mem':
					confirmation_prompt = "Added breakpoint to memory address {}".format(hex(val))
				else:
					confirmation_prompt = 'Added breakpoint to instruction {}'.format(break_inst)
				print(confirmation_prompt)

		elif command.startswith('del'):
			args = command.split(' ')

			# Regular breakpoint removal
			if len(args) == 2:
				# If specified in hex, will remove breakpoint at the address if exists
				if args[1].startswith('0x'):
					val = int(args[1][2:], 16)
					if val in breakpoints:
						print('Removing address breakpoint {}'.format(hex(val)))
						del breakpoints[breakpoints.index(val)]

				# Remove breakpoint from breakpoint index # !! 0-indexed !!
				else:
					val = int(args[1])
					if len(breakpoints) > val:
						print('Removing address breakpoint {}'.format(hex(breakpoints[val])))
						breakpoints.remove(val)

			elif len(args) == 3:
				# Delete a memory breakpoint
				if args[1] == 'mem':
					if args[2].startswith('0x'):
						val = int(args[2][2:], 16)
						if val in memory_breakpoints:
							print('Removing address breakpoint {}'.format(hex(val)))
							del memory_breakpoints[memory_breakpoints.index(val)]

					# Remove breakpoint from breakpoint index # !! 0-indexed !!
					else:
						val = int(args[2])
						if len(breakpoints) > val:
							print('Removing address breakpoint {}'.format(hex(memory_breakpoints[val])))
							memory_breakpoints.remove(val)
							
		elif command == 'c':
			cont = True
			break

		elif 'tr' == command:
			toggle_regs = not toggle_regs
			if toggle_regs:
				print('Showing regs on each step')
			else:
				print('Not showing regs on each step')

		elif 'fd' == command:
			print('File Descriptors')
			for key, value in file_descriptors.items():
				print('\t', key, ' -> ', value)

		elif command.startswith('set'):
			com, operand, value = command.split(' ')

			value = parse_num(value)

			if operand.startswith('m['):
				address = parse_num(operand[2:-1])
				Memory[address] = value

			elif operand.startswith('s['):
				address = parse_num(operand[2:-1])

				Memory[address + STACK_OFFSET] = value

			elif operand in registers:
				registers[operand] = value

				if operand == 'i':
					instruction_bytes = (
						'{:2X}'.format((Memory[(3 * registers['i']) + 0]))
						+ '{:02X}'.format(Memory[(3 * registers['i']) + 1])
						+ '{:02X}'.format((Memory[(3 * registers['i']) + 2]))
						)

					inst = Instruction(instruction_bytes)

				# If we set a watched register, add our new value to the watchlist
				if watching[operand]:
					watched_values[operand].append(value)

		elif command.startswith('watch'):
			args = command.split(' ')
			if len(args) == 1:
				print('Watching registers:')
				for key, value in watching.items():
					print(key, ': ', value)

				for reg, is_watched in watching.items():
					if is_watched:
						print('{} recorded values: {}'.format(reg, list(map(hex, watched_values[reg]))))

			elif len(args) == 2:
				reg_name = args[1]
				watching[reg_name] = not watching[reg_name]
				if watching[reg_name]:
					print('Watching reg {}'.format(reg_name))
					watched_values[reg_name].append(registers[reg_name])
				else:
					print('No longer watching reg {}'.format(reg_name))
					watched_values[reg_name] = []


		elif '' == command:
			pass
		else:
			print('Unknown command "{}"'.format(command))

# Main loop
while running:

	instruction_bytes = (
		'{:02X}'.format((Memory[(3 * registers['i']) + 0]))
		+ '{:02X}'.format(Memory[(3 * registers['i']) + 1])
		+ '{:02X}'.format((Memory[(3 * registers['i']) + 2]))
		)

	inst = Instruction(instruction_bytes)
	print('[{}] '.format(hex(registers['i'])), end='')
	registers['i'] += 1

	if toggle_regs:
		print(show_regs()) # .replace('\n', '\n\t'))
	print('\t' + str(inst).replace('\n', '\n\t'))


	# Process debugger commands
	if (not cont) or registers['i'] in breakpoints\
			or ((opcodes[inst.opcode] == 'sys') and break_sys)\
			or ((opcodes[inst.opcode] == 'jmp') and break_jmp)\
			or ((opcodes[inst.opcode] == 'cmp') and break_cmp):
		process_debugger_commands(inst)

	# Process Instruction
	if opcodes[inst.opcode] == 'imm':
		registers[reg_ids[inst.arg1]] = inst.arg2
		if watching[reg_ids[inst.arg1]]:
			watched_values[reg_ids[inst.arg1]].append(inst.arg2)

	elif opcodes[inst.opcode] == 'add':
		registers[reg_ids[inst.arg1]] = (registers[reg_ids[inst.arg1]] + registers[reg_ids[inst.arg2]]) % 256
		if watching[reg_ids[inst.arg1]]:
			watched_values[reg_ids[inst.arg1]].append(registers[reg_ids[inst.arg1]])

	elif opcodes[inst.opcode] == 'stm':
		if (registers[reg_ids[inst.arg1]]) in memory_breakpoints:
			print('Memory breakpoint at location {}'.format(hex(registers[reg_ids[inst.arg1]])))
			process_debugger_commands(inst)
		Memory[STACK_OFFSET + registers[reg_ids[inst.arg1]]] = registers[reg_ids[inst.arg2]]

	elif opcodes[inst.opcode] == 'stk':
		if inst.arg2 != 0:
			# Push
			registers['s'] += 1
			if registers['s'] in memory_breakpoints:
				print('Memory breakpoint at location {}'.format(hex(registers['s'])))
				process_debugger_commands(inst)
			Memory[STACK_OFFSET + registers['s']] = registers[reg_ids[inst.arg2]]
		if inst.arg1 != 0:
			# Pop
			if registers['s'] in memory_breakpoints:
				print('Memory breakpoint at location {}'.format(hex(registers['s'])))
				process_debugger_commands(inst)
			registers[reg_ids[inst.arg1]] = Memory[STACK_OFFSET + registers['s']]
			if watching[reg_ids[inst.arg1]]:
				watched_values[reg_ids[inst.arg1]].append(registers[reg_ids[inst.arg1]])
			registers['s'] -= 1
		
	elif opcodes[inst.opcode] == 'ldm':
		if registers[reg_ids[inst.arg2]] in memory_breakpoints:
				print('Memory breakpoint at location {}'.format(hex(registers[reg_ids[inst.arg2]])))
				process_debugger_commands(inst)
		registers[reg_ids[inst.arg1]] = Memory[STACK_OFFSET + registers[reg_ids[inst.arg2]]]
		if watching[reg_ids[inst.arg1]]:
			watched_values[reg_ids[inst.arg1]].append(registers[reg_ids[inst.arg1]])

	elif opcodes[inst.opcode] == 'cmp':
		registers['f'] = 0
		arg1 = registers[reg_ids[inst.arg1]]
		arg2 = registers[reg_ids[inst.arg2]]

		for flag, meaning in flag_meanings.items():
			if '<' in meaning and (arg1 < arg2):
				registers['f'] |= flag
			if '>' in meaning and (arg1 > arg2):
				registers['f'] |= flag
			if  meaning == 'arg1 == arg2' and (arg1 == arg2):
				registers['f'] |= flag
			if '!' in meaning and (arg1 != arg2):
				registers['f'] |= flag
			if '0' in meaning and (arg1 == 0) and (arg2 == 0):
				registers['f'] |= flag
		if watching['f']:
			watched_values['f'].append(registers['f'])

	elif opcodes[inst.opcode] == 'jmp':
		if inst.arg1 == 0:
			registers['i'] = registers[reg_ids[inst.arg2]]
		else:
			if inst.arg1 & registers['f'] != 0:
				registers['i'] = registers[reg_ids[inst.arg2]]
		if watching['i']:
			watched_values['i'].append(registers['i'])

		if registers['i'] in breakpoints:
			cont = False

	elif opcodes[inst.opcode] == 'sys':
		if inst.arg1 == syscall_nums['open']:
			filename = ''
			offset = 0
			while Memory[STACK_OFFSET + registers['a'] + offset] != 0:
				filename += chr(Memory[STACK_OFFSET + registers['a'] + offset])
				offset += 1

			print('File "{}" opened to fd {} with flags {} and mode {}'
				.format(filename, len(file_descriptors), registers['b'], registers['c']))

			registers[reg_ids[inst.arg2]] = len(file_descriptors)
			if watching[reg_ids[inst.arg2]]:
				watched_values[reg_ids[inst.arg2]].append(registers[reg_ids[inst.arg2]])

			file_descriptors[len(file_descriptors)] = filename
			os.open(filename, registers['b'], registers['c'])



		elif inst.arg1 == syscall_nums['read_code']:
			if registers['a'] == 0:
				print('Enter input for read syscall:')
			result = os.read(registers['a'], registers['c'])
			if registers['a'] == 0:
				print('')
				os.read(0, 500) # Clear the stdin buffer

			for byte in range(registers['c']):
				if (registers['b'] + byte) in memory_breakpoints:
					print('Memory breakpoint at location {}'.format(hex(registers['b'] + byte)))
					process_debugger_commands(inst)

				# Must be result backwards bc ~REDACTED~ reads things in little endian
				Memory[registers['b'] + byte] = ((int.from_bytes(result[::-1], byteorder='big') >> (8 * byte)) & 0xff)

			registers[reg_ids[inst.arg2]] = len(result)
			if watching[reg_ids[inst.arg2]]:
				watched_values[reg_ids[inst.arg2]].append(registers[reg_ids[inst.arg2]])

		elif inst.arg1 == syscall_nums['read_memory']:
			if registers['a'] == 0:
				print('Enter input for read syscall:')
			result = os.read(registers['a'], registers['c'])
			if registers['a'] == 0:
				print('')
				os.read(0, 500) # Clear the stdin buffer

			for byte in range(registers['c']):
				if (registers['b'] + byte) in memory_breakpoints:
					print('Memory breakpoint at location {}'.format(hex(registers['b'] + byte)))
					process_debugger_commands(inst)

				# Must be result backwards bc ~REDACTED~ reads things in little endian
				Memory[registers['b'] + STACK_OFFSET + byte] = ((int.from_bytes(result[::-1], byteorder='big') >> (8 * byte)) & 0xff)
			registers[reg_ids[inst.arg2]] = len(result)
			if watching[reg_ids[inst.arg2]]:
				watched_values[reg_ids[inst.arg2]].append(registers[reg_ids[inst.arg2]])

		elif inst.arg1 == syscall_nums['write']:
			write_str = b''
			for x in range(registers['c']):
				if (registers['b'] + x) in memory_breakpoints:
					print('Memory breakpoint at location {}'.format(hex(registers['b'] + x)))
					process_debugger_commands(inst) 
				write_str += chr(Memory[STACK_OFFSET + registers['b'] + x]).encode()
			result = os.write(registers['a'], write_str)
			registers[reg_ids[inst.arg2]] = result
			if watching[reg_ids[inst.arg2]]:
				watched_values[reg_ids[inst.arg2]].append(registers[reg_ids[inst.arg2]])

		elif inst.arg1 == syscall_nums['sleep']:
			time.sleep(registers['a'])
			registers[reg_ids[inst.arg2]] = registers['a']
			if watching[reg_ids[inst.arg1]]:
				watched_values[reg_ids[inst.arg2]].append(registers[reg_ids[inst.arg2]])
		elif inst.arg1 == syscall_nums['exit']:
			running = False
			sys.exit(registers['a'])







