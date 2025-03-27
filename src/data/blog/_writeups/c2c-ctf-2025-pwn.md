---
title: C2C 2025 Qualifiers - pwn'ed
author: Abhishek Satpathy
pubDatetime: 2025-03-21T23:35:23Z
slug: c2c-ctf-quals-pwned
featured: false
draft: false
tags:
  - pwn
  - c2c-quals
  - rev

description: A writeup on all the challenges in the pwn category for C2C 2025 qualifier.
---

## Table of contents

## Introduction

Although the challenges were a little simplistic, I thought it might be fun to walk through my process solving some of them.

Prerequisites

- A basic understanding of C and x86-64 ASM.
- Some familiarity with Ghidra

## Husky Sniff

There was no description, just a download link, so I started by just running the program.

```shell
root@ubuntu-droplet:/home/ctf/c2c/pwn/HuskySniff# ./huskysniff
Word on campus is the Northeastern Husky sniffed out the hidden flag—apparently it's tucked away in the executable. Woof you waiting for? Happy hacking!
```

Because it said it was tucked away in the executable, my first instinct was just to run strings on it and `grep` for the flag format "c2c_ctf{(.\*)}" which gave me the flag.

```shell
root@ubuntu-droplet:/home/ctf/c2c/pwn/HuskySniff# strings huskysniff | grep c2c_ctf{
c2c_ctf{crwzotngdyqfqbjc}
```

+100!

## Husky Hungry

The challenge description was as follows:

> Need to feed husky the right food to get the flag.

I started by running the executable to see what was going on:

```shell
root@ubuntu-droplet:/home/ctf/c2c/pwn/Husky_Hungry# ./huskyhungry
Arooo! Hey there, human friend-I'm feeling rumbly in my tummy again. If you bring me that tasty salmon I love so much, I'll let you in on a little secret...and by secret, I mean a very special flag! So don't keep a hungry Husky waiting-fetch that feast, and the flag is yours! Woof!
sdkfjsdkfj
I sniff the bowl, wrinkle my nose, and whine softly—this meal just isn't doing it for me.
```

Clearly we have to put in a specific input, so I took a look at the Ghidra decompilation. Uh-oh... it's complete nonsense. Running `file huskyhungry` reveals the executable is UPX packed, so after unpacking and taking a look in Ghidra I saw this in the `main` function.

```cpp
FUN_00401e90(s_n2n_neq{MfTjlbkFZysblJfG}_004c5100,0xb)
```

Looking at the function it seems to be a simple Caesar cipher. I attached my labelled code (binary was stripped) below.

```cpp
void decrypt_flag(char *encrypted_flag, int shift)
{
  char character;
  int iVar2;
  int char_code;

  character = *param_1;
  if (character == '\0') {
    return;
  }
  do {
    char_code = (int) character;
    is_alphabetical = FUN_004031c0(char_code);
    if (is_alphabetical != 0) {
      is_alphabetical = FUN_004032c0(char_code);
      char_code = ((char_code - ((-(uint)(iVar2 == 0) & 0x20) + 0x41)) - shift) + 26;
      *encrypted_flag = (-(is_alphabetical == 0) & 0x20U) + 0x41 + (char)char_code + (char)(char_code / 26) * 26;
    }
    character = encrypted_flag[1];
    encrypted_flag = encrypted_flag + 1;
  } while (char != '\0');
  return;
}
```

The shift is `-shift` so after running the string `n2n_neq{MfTjlbkFZysblJfG}` through a simple -11 cipher script I got the flag.

```python
if __name__ == "__main__":
    flag = "n2n_neq{MfTjlbkFZysblJfG}"
    decrypted = []
    for char in flag:
        if char.isalpha():
            # Shift character by -11
            code = ord(char) - 11

            # Handle wrap-around for letters
            if char.isupper():
                if code < ord('A'):
                    code += 26
            else:
                if code < ord('a'):
                    code += 26

            decrypted.append(chr(code))
        else:
            # Keep non-alphabetic characters unchanged
            decrypted.append(char)

    print("Decrypted flag:", ''.join(decrypted))
# Decrypted flag: c2c_ctf{BuIyaqzUOnhqaYuV}
```

## Husky Walk

Funny challenge description:

> Bring huksy to the right park.

The first thing I did was run `strings` on the file and `grep` for the flag. Much to my disappointment it was in there. I'm not sure how this challenge was meant to be solved, but it almost feels like I'm cheating.

```shell
root@ubuntu-droplet:/home/ctf/c2c/pwn/HuskyWalk# strings huskywalk | grep c2c_ctf
c2c_ctf{Qv7T8bWcY3nR1oJ}
```

## Husky Play

Husky Play challenge description:

> Need to give husky the right toy.

Another UPX-packed executable, after unpacking I ran another grep command and found the following encrypted flag.

```shell
root@ubuntu-droplet:/home/ctf/c2c/pwn/HuskyWalk# strings huskyplay | grep {
y2y_ypb{mtkLrrReqfswcJNh}
```

Assuming this is another Caesar cipher I used the same decryption routine with a slight change to account for the new shift.

```python
if __name__ == "__main__":
    flag = "y2y_ypb{mtkLrrReqfswcJNh}"
    decrypted = []
    for char in flag:
        if char.isalpha():
            # Shift character
            code = ord(char) - (ord('y') - ord('c'))

            # Handle wrap-around for letters
            if char.isupper():
                if code < ord('A'):
                    code += 26
            else:
                if code < ord('a'):
                    code += 26

            decrypted.append(chr(code))
        else:
            # Keep non-alphabetic characters unchanged
            decrypted.append(char)

    print("Decrypted flag:", ''.join(decrypted))
# Decrypted flag: c2c_ctf{qxoPvvViujwagNRl}
```

Unfortunately cheesed :(

## Husky Maze

Definitely my favorite challenge! Also the only one where I think I used the intended route, so let's get into the challenge description!

> Need to solve a maze.

```shell
root@ubuntu-droplet:/home/ctf/c2c/pwn/HuskyWalk# file huskyrescue
huskyrescue: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cf0b1406c19957c495f9e2e28199d5cfa8331353, for GNU/Linux 3.2.0, not stripped
```

I started by running the executable.

```shell
root@ubuntu-droplet:/home/ctf/c2c/pwn/HuskyWalk# ./huskyrescue
Woof woof! It's me, Husky! I'm stuck in this big, confusing maze, and I really need your help to find my way out. I can move up (1), down (2), left (3), or right (4), but some paths are blocked, and I don't want to get lost! Please tell me the right sequence of moves all at once so I can make it to the exit safely. I promise I'll be the best boy and listen carefully! I know you won't let me down! Enter movement sequence (1=Up, 2=Down, 3=Left, 4=Right): 1
Wait... this isn't right... I think I'm lost!
```

Looking at the decompiled code we get a better picture of what's going on.

```cpp
undefined8 main(void)
{
  char cVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  long in_FS_OFFSET;
  undefined local_48 [16];
  undefined local_38 [16];
  long local_20;

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = (undefined  [16])0x0;
  local_48 = (undefined  [16])0x0;
  __printf_chk(1,
               "Woof woof! It\'s me, Husky! I\'m stuck in this big, confusing maze, and I really nee d your help to find my way out. I can move up (1), down (2), left (3), or right (4), but some paths are blocked, and I don\'t want to get lost! Please tell me the right s equence of moves all at once so I can make it to the exit safely. I promise I\'ll be the best boy and listen carefully! I know you won\'t let me down! Enter movement sequ ence (1=Up, 2=Down, 3=Left, 4=Right): "
              );
  iVar2 = __isoc99_scanf(&DAT_00102320,local_38);
  if (iVar2 == 1) {
    uVar4 = 1;
    iVar2 = move_husky(local_38);
    lVar3 = 0;
    if (iVar2 == 0) {
      puts("Wait... this isn\'t right... I think I\'m lost!");
    }
    else {
      do {
        cVar1 = local_38[lVar3];
        iVar2 = 0x30303030;
        if (cVar1 != '\0') {
          iVar2 = cVar1 * 0x1010101;
        }
        *(int *)(local_48 + lVar3 * 4) = iVar2;
        lVar3 = lVar3 + 1;
      } while (lVar3 != 4);
      uVar4 = 0;
      tea_decrypt(encrypted_flag,local_48);
      tea_decrypt(0x104030,local_48);
      __printf_chk(1,
                   "Yay! You did it! I made it out of the maze, all thanks to you! You\'re the best!  As a reward for rescuing me, here\'s something special. Take it and wear it prou dly! %s\n"
                   ,encrypted_flag);
    }
  }
  else {
    uVar4 = 1;
    puts(
        "Uh-oh! That doesn\'t look right... I don\'t understand this! Can you give me the moves in t he correct format?"
        );
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar4;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

We could probably reverse engineer the `tea_decrypt` function, but let's take a look at the `move_husky` function first.

```cpp
bool move_husky(char *param_1)

{
  char cVar1;
  size_t sVar2;
  char *pcVar3;
  uint uVar4;
  uint uVar5;

  sVar2 = strlen(param_1);
  uVar5 = 0;
  uVar4 = 0;
  pcVar3 = param_1 + sVar2;
  do {
    if (pcVar3 == param_1) {
      return uVar5 == 3 && uVar4 == 3;
    }
    cVar1 = *param_1;
    if (cVar1 == '3') {
      uVar5 = uVar5 - 1;
    }
    else if (cVar1 < '4') {
      if (cVar1 == '1') {
        uVar4 = uVar4 - 1;
      }
      else {
        if (cVar1 != '2') {
          return false;
        }
        uVar4 = uVar4 + 1;
      }
    }
    else {
      if (cVar1 != '4') {
        return false;
      }
      uVar5 = uVar5 + 1;
    }
    if (3 < uVar4) {
      return false;
    }
    if (3 < uVar5) {
      return false;
    }
    param_1 = param_1 + 1;
  } while (*(int *)(maze + ((long)(int)uVar5 + (long)(int)uVar4 * 4) * 4) == 0);
  return false;
```

The general set-up seems to be we need to enter the full maze sequence in one input, and the maze is hard-coded in memory. Taking a look at the maze in memory after retyping the variable in Ghidra as `int[4][4]` gives us the following image.

![ghidradecompilation](@/assets/images/ctf/c2cctf-ghidra.png)

From there it's clear the instruction set is `242424`. Using that we get the flag.

```shell
root@ubuntu-droplet:/home/ctf/c2c/pwn/HuskyWalk# ./huskyrescue
Woof woof! It's me, Husky! I'm stuck in this big, confusing maze, and I really need your help to find my way out. I can move up (1), down (2), left (3), or right (4), but some paths are blocked, and I don't want to get lost! Please tell me the right sequence of moves all at once so I can make it to the exit safely. I promise I'll be the best boy and listen carefully! I know you won't let me down! Enter movement sequence (1=Up, 2=Down, 3=Left, 4=Right): 242424
Yay! You did it! I made it out of the maze, all thanks to you! You're the best! As a reward for rescuing me, here's something special. Take it and wear it proudly! c2c_ctf{lzrtrdtEDFuxmvaD5Uguva}
```

## Reflection

Overall, although some of the challenges were a little trivial, I very much enjoyed the maze challenge and reverse engineering the encryption function. Looking forward to meeting the other C2C'ers at Northwestern this summer!
