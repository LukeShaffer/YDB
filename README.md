# Welcome to YDB, the World's first <REDACTED> Custom Architecture Assembler, Disassembler and Debugger!

This project contains a set of scripts I wrote to help complete a series of
binary reverse engineering challenges (and more) that I faced during a
cybersecurity course I took. This custom architecture also recently featured
prominently in a recent DEF CON CTF Qualifier, and you can find a good writeup
about it here: <REDACTED>.

The challenges were presented as such:

1) You are given a compiled linux binary that implements this custom
architecture in an interpreter written in C.  The trick with each level is that
all of the values of everything in the interpreter (register ID's,
syscall opcodes, instruction opcodes) are randomized between each level, so
these will need to be frequently changed out and replaced between levels.

2) You craft an input in the form of binary assembled <REDACTED> that implements
features of the architecture, such as opening and reading and writing files to
and from memory, and feed that to the original executable to have it be
interpreted and executed.

3) You identify a security vulnerability in each challenge's implementation
of the <REDACTED> architecture (in either the architecture itself or the C
interpreter) and exploit that with your input to pass the challenge and get the
flag.

As everyone knows, hand-crafting and decoding an assembled program is EXTREMELY
tedious work, no good programmer could imagine doing that much manual repetitive
labor.

So I wrote a set of scripts to do the work for me.

And here I present this project that will assemble, disassemble, and even let
you debug programs written in assembled <REDACTED>.

=====================================================================
Before we begin, it would be helpful for the user to obtain 
1) The challenge binary that will be running the <REDACTED> interpreter.

2) ghidra to be able to copy and paste the pre-loaded <REDACTED> instructions
into a text-form that this assembler/debugger is capable of reading.
=====================================================================

## Assembling from Instructions
This project allows you to translate "high-level" instructions in the form

imm i, 25
add a, b
stk c, 0
ldm a, s
... etc

into the binary that the C interpreter will run as valid <REDACTED>.


To utilize this project's assembly capabilities, direct your attention to the
<REDACTED>\_assembler.py file.  There are routines in place for both the
regular and extended 64-bit version of the architecture present in this file.
You can use the assemble(), assemble\_64(), or assemble\_script() functions to
either create <REDACTED> bytecode dynamically in Python (perhaps to solve a
blind reversing challenge) or statically assemble your instructions from an
outside file into another file containing the bytecode for you to feed to the
<REDACTED> interpreter later.

As each challenge of the reverse engineering section was "randomized", the
system I developed is extremely modular so that all someone needs to do between
levels is to plug in their new identifiers into the nicely labeled dictionaries
at the top, and the same sequence of high level <REDACTED> instructions will be
assembled to a new binary sequence.

# Decompiling <REDACTED>
This repo comes pre-loaded with the <REDACTED> instructions taken from an
example interpreter challenge so that you can try it out right away.

To get a static list of the decoded instructions, just import the decoder.py
file, load the instructions (and optional preloaded memory if that level
contains it) via the load_instructions() and load_memory() functions, and then
invoke the instruction_dump() function. You will get a list of all instructions
contained in the program in a format like this:

[0x1] 	mov c, 0x91
[0x2] 	stm Stack[c], d (*c = d)
[0x3] 	mov d, 0x4f
[0x4] 	mov c, 0x96
[0x5] 	stm Stack[c], d (*c = d)


If you toggle register display before getting the list, it will look like this:
[0x1] 	a:0x0, b:0x0, c:0x0, d:0x71
	s:0x0, i:0x2, f:0x0
	mov c, 0x91
[0x2] 	a:0x0, b:0x0, c:0x91, d:0x71
	s:0x0, i:0x3, f:0x0
	stm Stack[c], d (*c = d)
[0x3] 	a:0x0, b:0x0, c:0x91, d:0x71
	s:0x0, i:0x4, f:0x0
	mov d, 0x4f
[0x4] 	a:0x0, b:0x0, c:0x91, d:0x4f
	s:0x0, i:0x5, f:0x0
	mov c, 0x96
[0x5] 	a:0x0, b:0x0, c:0x96, d:0x4f
	s:0x0, i:0x6, f:0x0
	stm Stack[c], d (*c = d)

You can then go through and statically analyze the Disassembled <REDACTED>
code at your leisure.

# Debugging <REDACTED> Code
While the static analysis features of this project are handy, I wanted to make
the challenges even more easier for myself, so I wrote a my own interpreter and
a gdb analog for this architecture, which I call YDB (see if you can find the
redacted name with that).

To load up a YDB session, make sure the INSTRUCTION_FILE and optionally
MEMORY_FILE variables contain the paths of your sourced instruction and
memory initialization files.  Then, simply run the Python script from the
commandline and you will be dropped into a YDB session with the instructions
you provided.  This will look like this:

[0x0] 	mov d, 0x71
YDB> 

The interface of the debugger shows you the next instruction that will be
executed if you step, and the instruction number for reference (0-indexed).

Now, there are a bunch of rich features here to explore.  I'll list them all
here at the top so you can get an idea.

	Stepping and Continuing Execution

	Inspecting Registers
	Manipulating / Setting Registers
	Watching / Recording Registers

	Setting Instruction Breakpoints
	Setting Operation Breakpoints
	Deleting Old Breakpoints

	Inspecting the Stack
	Setting Stack Values

	Inspecting Memory Values
	Setting Memory Values

	Inspecting the Current and Next Few Instructions

	Inspecting Open File Descriptors


Now we'll step thorugh one at a time, since, as you'll notice, the one feature
I neglected to add was a "help" feature.

## Stepping and Continuing Execution
As this architecture only supports 1-byte registers, there are only a
maximum of 256 possible instructions in the largest possible <REDACTED> program.
So then, while you're debugging, stepping through instructions one at a time is
not too tedious of a process, and will end up being the most common operation
you perform.

As such, if you enter no command at the prompt, the default behavior is to
step to the next instruction.

As each new instruction is reached, the debugger will print the current
assembled instruction as well as the register values if you have enabled that
toggle.

To run the program until either it hits a breakpoint or it exits, enter the
command "c".  This will run execution until a blocking input is executed (it
will wait for you to enter a line, you will need to press enter twice to clear
the stdin buffer) or until the program exits.

While the program is running, it will do the same instruction and register
reporting as if you had been stepping manually, so if you made some smart
breakpoints this can save you a lot of time doing these challenges.

## Working with Registers
This debugger lets you inspect, modify, and watch the various <REDACTED>
registers in the interpretter I wrote as the program is being debugged live.

To inspect the registers at a standard debuggin prompt, use the "reg" command.
If that gets too tedious for you and you want the register values reported
after every instruction is executed, use the "tr" (for toggle register) to
toggle register reporting after every instruction.  You can see in the below
example that the 4 data registers are separated from the 3 control-flow
registers by a newline.

	[0x0] 	mov d, 0x71
	YDB> reg
		a:0x0, b:0x0, c:0x0, d:0x0
		s:0x0, i:0x1, f:0x0
	YDB>

### Watching Registers
If this is still too tedious for you, you can set a watch for the specific
register you want to monitor, and then continue until your next breakpoint to
view all of the values it took on during that time period.

To view the registers that are currently being watched, use the "watch" command.

	YDB> watch
	Watching registers:
	a :  False
	b :  False
	c :  False
	d :  False
	s :  False
	i :  False
	f :  False

To add a register to the watchlist, use the watch command again, but name the
register.

	YDB> watch a
	Watching reg a

Now if you get the watch report again, you'll notice that a new entry has been
added for register a down at the bottom.

	YDB> watch
	Watching registers:
	a :  True
	b :  False
	c :  False
	d :  False
	s :  False
	i :  False
	f :  False
	a recorded values: ['0x0']

If you step through execution or run the program, as any of the watched
registers take on new values, they will be added to the list of values in
chronological order as such...

	YDB> watch
	Watching registers:
	a :  True
	b :  False
	c :  False
	d :  False
	s :  False
	i :  False
	f :  False
	a recorded values: ['0x0', '0x1', '0x59', '0x0', '0x59']

This also applies to any values that you manually change the registers to
with the "set" command.

	YDB> set a 0x77
	YDB> watch
	Watching registers:
	a :  True
	b :  False
	c :  False
	d :  False
	s :  False
	i :  False
	f :  False
	a recorded values: ['0x0', '0x1', '0x59', '0x0', '0x59', '0x77']

I will touch on setting values in its own section

## Setting Values
Now that I have shown you how to inspect the registers, memory, and stack,
I will show you how to take an active hand in the debugging process and
modifying these values on the fly to be able to affect the control flow of
the interpreter as the program is being run.

You can modify values in the registers, stack, and in interpreter memory. This
is all accomplished via the "set" command.  The set command operates on 3-part
input. All set commands consist of `set <location> <value>`, 3 space-separated
values.

`set` is just the word "set"

`<locaion>` is either `m[x]`, `s[x]`, or `<reg_name>`, where the x in s[] or m[]
is the offset (in decimal or hex) of the stack or memory location you want to
change, and `<reg_name>` is the name of one of the registers a-f

`<value>` is the decimal or hex value that you want to insert at the given
location.

You can enter in a set command at any time program execution is paused and you
have a debugger prompt, allowing you to go down different execution paths at
will.

A special case here is setting the value of the `i` register, which will
directly change the current instruction, which you can view by issuing an `inst`
command.


# Sourcing the <REDACTED> Code to decompile yourself
To disassemble a pre-assembled <REDACTED> program (such as the one given in the
pre-initialized memory of the earlier levels), simply identify the loaded
instructions of the program in the ghidra disassembly of the C interpreter
(this is generally contained in the "vm_mem" section), and copy
(as special... -> byte string) and paste that array into a file
(I called mine "inst"). This should look like this, all one line:

71 04 08 91 02 08 04 02 02 4f 04 08 96

You can choose to copy with or without spaces, this script strips them anyway

Now that you have isolated the <REDACTED> program from the interpreter, you
simply need to step through the ghidra disassembly of the interpreter and follow
the comments that tell you where to find the values of all random identifiers
for this new level, and plug them into the dictionaries at the top of the 
REDACTED_decoder.py file.

Now that you have the <REDACTED> program isolated and the script is set up to
handle this level's dialect of <REDACTED>, all you have to do is to either
invoke the instruction_dump() function for a static text dump of the high-level
instructions contained in the bytecode you copied out earlier, OR invoke the
decoder script with no arguments and INSTRUCTION_FILE pointing to your

## Note for the Reader
As the challenges in their original form are still up (for prestige, not for
credit), I have opted to redact all potentially identifiable information from
this repo until the architecture in question has been significantly changed or
removed, or a significant amount of time has passed.
