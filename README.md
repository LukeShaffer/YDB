# Welcome to YDB, the World's first ~REDACTED~ Custom Architecture Assembler, Disassembler and Debugger!

This project contains a set of scripts I wrote to help complete a series of
binary reverse engineering challenges (and more) that I faced during a
cybersecurity course I took. This custom architecture also recently featured
prominently in a recent DEF CON CTF Qualifier, and you can find a good writeup
about it here: ~REDACTED~.

The challenges were presented as such:

1) You are given a compiled linux binary that implements this custom
architecture in an interpreter written in C.  The trick with each level is that
all of the values of everything in the interpreter (register ID's,
syscall opcodes, instruction opcodes) are randomized between each level, so
these will need to be frequently changed out and replaced between levels.

2) You craft an input in the form of binary assembled ~REDACTED~ that implements
features of the architecture, such as opening and reading and writing files to
and from memory, and feed that to the original executable to have it be
interpreted and executed.

3) You identify a security vulnerability in each challenge's implementation
of the ~REDACTED~ architecture (in either the architecture itself or the C
interpreter) and exploit that with your input to pass the challenge and get the
flag.

As everyone knows, hand-crafting and decoding an assembled program is EXTREMELY
tedious work, no good programmer could imagine doing that much manual repetitive
labor.

So I wrote a set of scripts to do the work for me.

And here I present this project that will assemble, disassemble, and even let
you debug programs written in assembled ~REDACTED~.

If you want to jump right in now and read the documentation later, navigate to
this directory in the terminal and just run `python3 decoder.py` to be dropped
into a debugger session with an actual challenge copied straight from the
course.

---

## Note on the Redacted
As the challenges in their original form are still up (for prestige, not for
credit), I have opted to redact all potentially identifiable information from
this repo until the architecture in question has been significantly changed or
removed, or a significant amount of time has passed.

---

Before we begin, it would be helpful for the user to obtain 
1) The challenge binary that will be running the ~REDACTED~ interpreter.

2) ghidra to be able to copy and paste the pre-loaded ~REDACTED~ instructions
into a text-form that this assembler/debugger is capable of reading.


# Assembling Code
A note before we get started, I found myself switching back and forth between
describing the process of processing ~REDACTED~ into binary as both "assembling"
and "compiling," so I may slip up and use one or the other, but for the rest of
this section they both refer to the same process of transforming high level
~REDACTED~ into binary bytecode that can be fed to the challenge C interpreter.

This project allows you to translate "high-level" instructions in the form

    imm i, 25
    add a, b
    stk c, 0
    ldm a, s

... from either a multiline string snippet in a larger Python script, or a
separate .y85 script file. I tried to make this as similar to an existing
language compiler as possible, and you can even make inline comments with
the "#" sign both in the inline and separate file scripts.  Finally, there is
no indentation requirement for parsing ~REDACTED~, the only requirement is that
each instruction and comment sits on its own line.

For those familiar with pwntools, I tried to emulate their inline assembly
style while developing my assembler for this architecture so you might see some
similarities.  

Examples:

```
binary = compiler.compile('imm a, 0')

binary = compiler.compile('''
    # You can even include comments in your inline assembly
    imm a, 0
    imm b, 0
    imm c, 0xff
    sys read_memory, d

    # How cool is that?
    imm a, 0
    imm b, 0xa0
    imm c, {}
    sys read_memory, d

    imm a, 0
    imm b, 0xff
    imm c, 0xff
    sys read_memory, d

    '''.format(len(shellcode))
)

# Compiles script to "<filename>.yb" for ~REDACTED~ binary
compiler.compile_script('external_script.y85')
```

To utilize this project's assembly capabilities, direct your attention to the
`compiler.py` file.  There are routines in place for both the regular and
extended 64-bit version of the architecture present in this file. You can use
the `compile()`, `compile_64()`, or `compile_script()` functions to either
create ~REDACTED~ bytecode dynamically in Python (perhaps to solve a blind
reversing challenge) or statically assemble your instructions from an outside
file into another file containing the bytecode for you to feed to the
~REDACTED~ interpreter later.

As each challenge of the reverse engineering section was "randomized", the
system I developed is extremely modular so that all someone needs to do between
levels is to plug in their new identifiers into the nicely labeled dictionaries
at the top, and the same sequence of high level ~REDACTED~ instructions will be
assembled to a new binary sequence.

# Decompiling ~REDACTED~
This repo comes pre-loaded with the ~REDACTED~ instructions taken from an
example interpreter challenge so that you can try it out right away.  See the
`inst` file.

To get a static list of the decoded instructions, just import the `decoder.py`
file, load the instructions (and optional preloaded memory if that level
contains it) via the `load_instructions()` and `load_memory()` functions, and
then invoke the `instruction_dump()` function. You will get a list of all
instructions contained in the program in a format like this:

    [0x1]   mov c, 0x91
    [0x2]   stm Stack[c], d (*c = d)
    [0x3]   mov d, 0x4f
    [0x4]   mov c, 0x96
    [0x5]   stm Stack[c], d (*c = d)


If you toggle register display before getting the list, it will look like this:
```
[0x1]   a:0x0, b:0x0, c:0x0, d:0x71
        s:0x0, i:0x2, f:0x0
        mov c, 0x91
[0x2]   a:0x0, b:0x0, c:0x91, d:0x71
        s:0x0, i:0x3, f:0x0
        stm Stack[c], d (*c = d)
[0x3]   a:0x0, b:0x0, c:0x91, d:0x71
        s:0x0, i:0x4, f:0x0
        mov d, 0x4f
[0x4]   a:0x0, b:0x0, c:0x91, d:0x4f
        s:0x0, i:0x5, f:0x0
        mov c, 0x96
[0x5]   a:0x0, b:0x0, c:0x96, d:0x4f
        s:0x0, i:0x6, f:0x0
        stm Stack[c], d (*c = d)
```

You can then go through and statically analyze the disassembled ~REDACTED~
code at your leisure.

# Debugging ~REDACTED~ Code
While the static analysis features of this project are handy, I wanted to make
the challenges even more easier for myself, so I wrote a my own interpreter and
a gdb analog for this architecture, which I call YDB (see if you can find the
redacted name with that).

To load up a YDB session, make sure the `INSTRUCTION_FILE` and optionally
`MEMORY_FILE` variables contain the paths of your sourced instruction and
memory initialization files.  Then, simply run the Python script from the
commandline and you will be dropped into a YDB session with the instructions
you provided.  This will look like this:

    [0x0]   mov d, 0x71
    YDB> 

The interface of the debugger shows you the next instruction that will be
executed if you step, and the instruction number for reference (0-indexed).

Now, there are a bunch of rich features here to explore.  I'll list them all
here at the top so you can get an idea.

* Control Flow
    * Stepping and Continuing Execution

    * Setting Instruction Breakpoints
    * Setting Operation Breakpoints
    * Deleting Old Breakpoints

* Working with Registers
    * Manipulating / Setting Registers
    * Watching / Recording Registers

* Working with the Stack
    * Inspecting the Stack
    * Setting Stack Values

* Working with Memory
    * Inspecting Memory Values
    * Setting Memory Values

* General Purpose
    * Inspecting the Current and Next Few Instructions
    * Inspecting Open File Descriptors


Now we'll step through one at a time, since, as you'll notice, the one feature
I neglected to add was a `help` command.

## Control Flow
### Stepping and Continuing Execution
As this architecture only supports 1-byte registers, there are only a
maximum of 256 possible instructions in the largest possible ~REDACTED~ program.
So then, while you're debugging, stepping through instructions one at a time is
not too tedious of a process, and will end up being the most common operation
you perform.

As such, if you enter no command (just press enter) at the prompt, the default
behavior is to step to the next instruction.

As each new instruction is reached, the debugger will print the current
assembled instruction as well as the register values if you have enabled that
toggle.

To run the program until either it hits a breakpoint or it exits, enter the
command `c` (for "continue").  This will run execution until a blocking input
is executed - like a read syscall (it will wait for you to enter a line, you
will need to press enter twice to clear the stdin buffer) or until the program
exits.

While the program is running, it will do the same instruction and register
reporting as if you had been stepping manually, so if you made some smart
breakpoints this can save you a lot of time doing these challenges.

## Breakpoints
To get a quick look at your current breakpoint situation, use the `break`
command.  This will give you a nice little menu that looks like this

    YDB> break
    Breakpoints:
    []

    Memory breakpoints:
    []

    Break on syscalls? False
    Break on jumps? False
    Break on compare? False


As you can see, there is support for regular instruction-number breakpoints,
memory breakpoints, as well as instruction-type breakpoints.

### Setting Breakpoints
To set an instruction breakpoint, use `break <inst #>` where the instruction
number can be in decimal (default) or hex ("0x" prefix).  This will show up in
the following way:

    YDB> break 8 
    Added breakpoint to instruction 8
    YDB> break
    Breakpoints:
    ['0x9', '0x8']

    Memory breakpoints:
    []

    Break on syscalls? False
    Break on jumps? False
    Break on compare? False

As you can see, the instruction number breakpoints are reported in chronological
order, and not numerical order to make it easier to let you follow your train
of thought if you get lost and find yourself thinking, "wait, what am I even
doing in this function again?".

---

To set a memory breakpoint, the process is exactly the same except you must
add the `mem` keyword between the `break` and `<index #>` keywords.  A memory
breakpoint will trigger any time the memory address in question is accessed for
either reading or writing, and will drop you into debugger command mode
immediately before the instruction is executed and will let you know that a
`Memory breakpoint at location x` has been triggered.

    YDB> break mem 0x8f
    Added breakpoint to memory address 0x8f
    YDB> break mem 19
    Added breakpoint to memory address 0x13
    YDB> break
    Breakpoints:
    ['0x9', '0x8']

    Memory breakpoints:
    ['0x8f', '0x13']

    Break on syscalls? False
    Break on jumps? False
    Break on compare? False

---

Finally, to toggle breaking on certain instruction types, use `break` with
any supported instruction type, which is currently only `sys, jmp, and cmp`.

These are a one-size-fits-all breakpoint that will simply break anytime an
instruction of the type you specified is about to be executed.  As such they
operate an a slightly different toggle system, where you issue the same command
to turn them on or off again.


### Deleting Old Breakpoints
The `del` command is used to remove unneeded breakpoints from a debugging
session. Since instruction-type breakpoints are toggles they have no concept of
deletion. and are simply toggled off by repeting the `break sys` or similar
command.

To delete an instruction number breakpoint, you actually have 2 options. You can
delete a breakpoint by either specifying its address in hex, or its breakpoint
number in decimal (0-indexed). Let's use this situation as an example:

    YDB> break 8 
    Added breakpoint to instruction 8
    YDB> break
    Breakpoints:
    ['0x9', '0x8']

    Memory breakpoints:
    ['0x9', 0x8]

    Break on syscalls? False
    Break on jumps? False
    Break on compare? False

To delete the breakpoint on instruction 8, you can issue either of the following
commands:

    del 0x8
    del 1

And use any of these to delete the breakpoint on instruction 9

    del 0x9
    del 0


Deleting memory breakpoints functions exactly the same, except that you have to
specify the `mem` keyword before the breakpoint identifier.

## Working with Registers
This debugger lets you inspect, modify, and watch the various ~REDACTED~
registers in the interpretter as the program is being debugged live.


### Getting and Setting Registers
To inspect the registers at a standard debugging prompt, use the `reg` command.
If that gets too tedious for you and you want the register values reported
after every instruction is executed, use the `tr` (for toggle register) to
toggle register reporting after every instruction step.  You can see in the
below example that the 4 data registers are separated from the 3 control-flow
registers by a newline.

    [0x0]   mov d, 0x71
    YDB> reg
        a:0x0, b:0x0, c:0x0, d:0x0
        s:0x0, i:0x1, f:0x0
    YDB>

To set the value of a register, use the `set` command.  All set commands
consist of `set <location> <value>`, 3 space-separated values.

    `set` is just the word "set"

    `<locaion>` is either `m[x]`, `s[x]`, or `<reg_name>`, where the x in s[] or m[]
    is the offset (in decimal or hex) of the stack or memory location you want to
    change, and `<reg_name>` is the name of one of the registers a-f

    `<value>` is the decimal or hex value that you want to insert at the given
    location.


You can enter in a `set` command at any time program execution is paused and you
have a debugger prompt, allowing you to go down different execution paths at
will.

A special case here is setting the value of the `i` register, which will
directly change the current instruction, which you can view by issuing an `inst`
command.

Here are some examples setting the registers:

    YDB> set a 9
    YDB> reg
        a:0x9, b:0x0, c:0x0, d:0x0
        s:0x0, i:0x1, f:0x0
    YDB> set a 0xf3
    YDB> reg
        a:0xf3, b:0x0, c:0x0, d:0x0
        s:0x0, i:0x1, f:0x0


    YDB> set i 0x50
    YDB> inst 5
        current + 0: add a, d (a += d)
        current + 1: add b, d (b += d)
        current + 2: push a
        current + 3: push b
        current + 4: ldm a, Stack[a] (a = *a)
    YDB> set i 0x53
    YDB> inst 5
        current + 0: push b
        current + 1: ldm a, Stack[a] (a = *a)
        current + 2: ldm b, Stack[b] (b = *b)
        current + 3: cmp a, b
        current + 4: pop b



### Watching Registers
If this is still too tedious for you, you can set a watch for the specific
register you want to monitor, and then continue until your next breakpoint to
view all of the values it took on during that time period.

To view the registers that are currently being watched, use the `watch` command.

    YDB> watch
    Watching registers:
    a :  False
    b :  False
    c :  False
    d :  False
    s :  False
    i :  False
    f :  False

To add a register to the watchlist, use the `watch` command again, but name the
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
... note that duplicate values are not combined so that you can get the full
picture of the path the register has traveled.

This also applies to any values that you manually change the registers to
with the `set` command.

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

## Working with the Stack
Here is a map of the address space layout of the ~REDACTED~ architecture.

    0x000 - 0x2fc:   Instruction Space
    0x2fd - 0x3fb:   Stack Space
    0x3fc - 0x402:   Registers

The stack is kept track of during program execution via the stack register `s`.
The value of the register simply represents how many items have been pushed
onto the stack at the current moment.  There is no base pointer register
present. Although the architecture does make use of the stack to store return
addresses after simple function invocations, it trusts the programmer to
remember their own stack variables.

The stack pointer starts initialized to 0, and increments every time something
is pushed to it, and decrements every time something is popped from it.

You'll notice that the only section of memory that would be considered
writable for user data is the stack. In this effect, the stack is really just
another name for the memory to be used to store miscellaneous data from the
user.

### Inspecting the Stack
To view the current entire stack (determined by the current value of the `s`
register), simply use the `s` command.

    
    YDB> reg
    a:0x59, b:0x40, c:0x20, d:0xb
    s:0xe, i:0x38, f:0x0
    YDB> s
    Current stack dump
        [0x0] -> 0x0    ('\x00')
        [0x1] -> 0xf3   ()
        [0x2] -> 0x0    ('\x00')
        [0x3] -> 0x98   ()
        [0x4] -> 0x45   ('E')
        [0x5] -> 0x4e   ('N')
        [0x6] -> 0x54   ('T')
        [0x7] -> 0x45   ('E')
        [0x8] -> 0x52   ('R')
        [0x9] -> 0x20   (' ')
        [0xa] -> 0x4b   ('K')
        [0xb] -> 0x45   ('E')
        [0xc] -> 0x59   ('Y')
        [0xd] -> 0x3a   (':')
        [0xe] -> 0x20   (' ')

As you can see, I have made the job of the reverse engineer extremely easy
here by adding in a built-in string detector that will report the ASCII
translation of whatever data is currently on the stack, which comes in handy in
situations like this where you can clearly see some I/O data.


You can also only get a slice of the stack by specifying it in Python slicing
syntax:

```
    YDB> s[2:6]
        [0x2] -> 0x0    ('\x00')
        [0x3] -> 0x98   ()
        [0x4] -> 0x45   ('E')
        [0x5] -> 0x4e   ('N')

        YDB> s[-1]
            [0xe] -> 0x20   (' ')

    YDB> s[-5:-2]
        [0xa] -> 0x4b   ('K')
        [0xb] -> 0x45   ('E')
        [0xc] -> 0x59   ('Y')

    YDB> s[-0x5:-0x2]
        [0xa] -> 0x4b   ('K')
        [0xb] -> 0x45   ('E')
        [0xc] -> 0x59   ('Y')

    YDB> s[5:]
        [0x5] -> 0x4e   ('N')
        [0x6] -> 0x54   ('T')
        [0x7] -> 0x45   ('E')
        [0x8] -> 0x52   ('R')
        [0x9] -> 0x20   (' ')
        [0xa] -> 0x4b   ('K')
        [0xb] -> 0x45   ('E')
        [0xc] -> 0x59   ('Y')
        [0xd] -> 0x3a   (':')

    YDB> s[:-3]
        [0x0] -> 0x0    ('\x00')
        [0x1] -> 0x0    ('\x00')
        [0x2] -> 0x0    ('\x00')
        [0x3] -> 0x98   ()
        [0x4] -> 0x45   ('E')
        [0x5] -> 0x4e   ('N')
        [0x6] -> 0x54   ('T')
        [0x7] -> 0x45   ('E')
        [0x8] -> 0x52   ('R')
        [0x9] -> 0x20   (' ')
        [0xa] -> 0x4b   ('K')
        [0xb] -> 0x45   ('E')
```

* Currently, the third slice argument is not supported.


### Setting Stack Values
Sometimes, you mess up your input to a read syscall or you would like to insert
some non-printable characters to the stack to simulate a malicious input.  Stack
writes can be performed any time with the `set` command and the `s[x]` location.

Example:

    YDB> set s[0] 0x20
    YDB> set s[1] 30
    YDB> s[0:3]
    Current stack dump
        [0x0] -> 0x20   (' ')
        [0x1] -> 0x1e   ('\x1e')
        [0x2] -> 0x0    ('\x00')

Currently, you can only set one location at a time using this method, so if you
want to insert an entire string on the stack, you will have to do it character
by character.  But at least you can copy and paste the commands into the
terminal so you don't have to do it over in case you mess up.


## Working with Memory
The concept of "Memory" in the ~REDACTED~ architecture is a bit weird, since it
it can either refer to the entire program's address space, or to the stack in
particular, but not to its own dedicated location.

Here is the address space layout of this architecture again for you to see:

    0x000 - 0x2fc:   Instruction Space
    0x2fd - 0x3fb:   Stack Space
    0x3fc - 0x402:   Registers


Data is stored in a big-endian style, with strings being read from lower
addresses to higher ones.

Since the registers (in the base version of the architecture at least) are all
only 1-byte, addressing is simplified in the sense that there are no alignment
concerns.

In the context of this section, "memory" will refer to the entire program's
address space.

### Inspecting Memory Values
Inspecting memory values is identical to inspecting stack values, except the
keyword is m and not s.

To view the contents of a single cell of memory, use the `m[x]` command, where
x is the location of the memory location you want to view, ranging from 0 to
0x402 inclusive.  This address range includes both the code section as well as
the registers at the end of the memory space.

You can also view slices of memory via the same Python slicing syntax from the
stack section.

### Setting Memory Values
Again, just like the stack section, you can change an arbitrary section of
memory by using the `set` command, with the `m[x]` location.

Just like the stack section, only one address is able to be set at a time.


## General Purpose
### Inspecting the Current and Next Few Instructions
To print the current instruction you are on, use the `inst` command

    YDB> inst
        instruction: mov c, 0xb
        opcode:0x8, arg1:0x2, arg2:0xb
        Raw Bytes: 0x0B0208

As you can see, this reports the disassembled instruction, as well as a chopped
up and raw version of the bytes of the current instruction under examination.

To view multiple instructions ahead in an abbreviated form, add a number after
the `inst` command

    YDB> inst 10
        current + 0: mov d, 0x6b
        current + 1: mov c, 0x94
        current + 2: stm Stack[c], d (*c = d)
        current + 3: mov d, 0xac
        current + 4: mov c, 0x92
        current + 5: stm Stack[c], d (*c = d)
        current + 6: mov d, 0xa4
        current + 7: mov c, 0x98
        current + 8: stm Stack[c], d (*c = d)
        current + 9: push a

This shows the disassembled instruction as well as the raw bytes of each
instruction.

You can also view previous (contiguous) instructions by giving a negative
number.

    YDB> inst -5
    current + -5: mov d, 0x6b
    current + -4: mov c, 0x94
    current + -3: stm Stack[c], d (*c = d)
    current + -2: mov d, 0xac
    current + -1: mov c, 0x92

Finally, it will also predict if future branches captured by your lookup will
be taken or not based on the current value of the registers.

    YDB> inst 5
        current + 0: pop b =>
        current + 1: pop a =>
        current + 2: mov d, 0x61
        current + 3: jmp 0xff if arg1 != arg2
    ..Not Taken
        current + 4: mov d, 0xff


### Inspecting Open File Descriptors
To inspect the open file descriptors during the interpreter run, use the `fd`
command.

    YDB> fd
    File Descriptors
         0  ->  STDIN
         1  ->  STDOUT
         2  ->  STDERR

Since the ~REDACTED~ architecture only has the capability to open file
descriptors and not to close them, this list will only grow as the program runs,
and none of the entries will ever switch their numbers once created.

Whenever a file descriptor is opened in the debugger, there is a message
that will print to let you know all about it.


    [0xd1]  syscall: open(filename: stack[reg_a], flags: reg_b, mode: reg_c) => d
    YDB> 
    File "/flag" opened to fd 3 with flags 0 and mode 133

It will also then be available from the file descriptor list

    YDB> fd
    File Descriptors
         0  ->  STDIN
         1  ->  STDOUT
         2  ->  STDERR
         3  ->  /flag




# Sourcing the ~REDACTED~ Code to decompile yourself
To disassemble a pre-assembled ~REDACTED~ program (such as the one given in the
pre-initialized memory of the earlier levels), simply identify the loaded
instructions of the program in the ghidra disassembly of the C interpreter
(this is generally contained in the "vm_mem" section), and copy
(as special... -> byte string) and paste that array into a file
(I called mine "inst"). This should look like this, all one line:

71 04 08 91 02 08 04 02 02 4f 04 08 96

You can choose to copy with or without spaces, this script strips them anyway.

Now that you have isolated the ~REDACTED~ program from the interpreter, you
simply need to step through the ghidra disassembly of the interpreter and follow
the comments  in the decoder.py file that tell you where to find the values of
all the random identifiers for this new level, and plug them into the
dictionaries at the top of the decoder.py file.

Now that you have the ~REDACTED~ program isolated and the script is set up to
handle this level's dialect of ~REDACTED~, all you have to do is to either
invoke the `instruction_dump()` function for a static text dump of the
high-level instructions contained in the bytecode you copied out earlier, OR
invoke the decoder script with no arguments and INSTRUCTION_FILE pointing to
your copied text bytes to launch up a live YDB session to begin exploring.


