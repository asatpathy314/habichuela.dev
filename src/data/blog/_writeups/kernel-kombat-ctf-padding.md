---
title: Kernel Kombat CTF - Padding
author: Abhishek Satpathy
pubDatetime: 2025-03-21T23:35:23Z
modDatetime: 2025-03-27T05:24:55Z
slug: kernel-kombat-ctf-padding
featured: false
draft: false
tags:
  - rev
  - crypto
  - kernel kombat

description: A writeup on a simple rev/crypto challenge at Kernel Kombat CTF
---

## Table of contents

## Introduction

This problem was placed in the `rev` category, although arguably it might've fit better
in `crypto`. The challenge description was the following:

![description](@/assets/images/ctf/kkctf-padding.png))

The `chall.c` file that came with the challenge had the following content:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* Encryption(char* text, char* key) {
    int textLen = strlen(text);
    int keyLen = strlen(key);
    char* cipherText = (char*)malloc((textLen + 1) * sizeof(char));
    int* cipher = (int*)malloc(keyLen * sizeof(int));

    for (int i = 0; i < keyLen; i++) {
        cipher[i] = (int)(text[i]) - (int)('A') + (int)(key[i]) - (int)('A');
    }

    for (int i = 0; i < keyLen; i++) {
        if (cipher[i] > 25) {
            cipher[i] -= 26;
        }
    }

    for (int i = 0; i < keyLen; i++) {
        cipherText[i] = (char)(cipher[i] + (int)('A'));
    }
    cipherText[keyLen] = '\0';

    free(cipher);
    return cipherText;
}

int main() {
    char plainText[100];
    char key[100];

    printf("text to encrypt :");
    scanf("%s", plainText);

    printf("tell me the key :");
    scanf("%s", key);

    char* encryptedText = Encryption(plainText, key);
    printf("Cipher Text - %s\n", encryptedText);

    free(encryptedText);
    return 0;
}
```

## Reversing the Encryption Function

Before we try and crack the cipher, I figured the next step was to reverse the encryption mechanism considering that this was a `rev` challenge. Taking a look at the encryption mechanism, it seems to take in a plaintext `char *text` and a key called `char *key`. Then it iterates through the length of key and performs the following.

1. For each character in the key it adds the raw character value of the plaintext (i.e. for A its 1, for D its 4) to the raw character value of the key. Then it stores the value in `char* cipherText` sequentially.

2. It subtracts 26 from each character in cipherText if the current value of the character is > 26.

3. Then it adds the value of char 'A' to each character in the ciphertext to bring it back to human-readable range.

After reading the encryption mechanism we can make one assumption that will make our life much easier.

1. The length of the plaintext = length of the key = length of the ciphertext because the `Encryption` function goes sequentially and is limited by the length of the key.

Now that we understand what the `Encryption` function does we can reverse it, first in C.

In order to reverse it we can perform the following operations.

1. Subtract the value of char 'A' from each character in the ciphertext.
2. Subtract the raw value of the key (i.e. key[i] - 'A') at index i from the char at index i where i < length of key.
3. If the ciphertext is now < 0 at any index i we add 26 at that index.

In order to perform the decryption I wrote the following function in C:

```c
char* Decryption(char* cipherText, char* key) {
    int cipherLen = strlen(cipherText);
    int keyLen = strlen(key);
    char* plainText = (char*)malloc((cipherLen + 1) * sizeof(char));

    for (int i = 0; i < keyLen; i++) {
        plainText[i] = (int)(cipherText[i]) - (int)('A');
    }

    for (int i=0; i < keyLen; i++) {
        plainText[i] = (int)(plainText[i]) - ((int)(key[i])-(int)('A'));
    }

    for (int i=0; i < keyLen; i++) {
        if (plainText[i] < 0) {
            plainText[i] += 26;
        }
        plainText[i] = (int)plainText[i] + (int)('A');
    }
    return plainText;
}
```

Not the most exciting C code ever, but I tried to do my best to stay true to the original function's logic. Now comes the next part.

## Finding the Key

The challenge description was a little on the nose about they used their "password as the secret key," so my first thought was to try `rockyou.txt`. For the sake of convenience I also translated `Decrypt` into python so I'll attach the solve script below.

```python
def Decryption(cipherText, key):
    keyLen = len(key)
    plainText = []

    for i in range (keyLen):
        newChar = ord(cipherText[i]) - ord('A')
        plainText.append(newChar)

    for i in range (keyLen):
        plainText[i] = plainText[i] - ((ord(key[i]) - ord('A')))

    for i in range (keyLen):
        if (plainText[i] < 0):
            plainText[i] += 26

    plainText = [chr(x + ord('A')) for x in plainText]
    return ''.join(plainText)

cipher = "VHEXDCLVSA"

with open("rockyou.txt", "r") as f:
    passwords = f.readlines()

for password in passwords:
    password = password.strip()
    if len(password) == len(cipher) and password.isupper():
        try:
            print(Decryption(cipher, password))
        except:
            print("unable to decode")

```

After piping the output of the program into a file, after opening the file the fourth result was the flag.

Original Text : `FLAGKERNEL`

Flag : `kernelkombat{FLAGKERNEL}`
