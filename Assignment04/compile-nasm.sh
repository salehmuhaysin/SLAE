#!/bin/bash

echo "[+] Compiling with NASM..."
nasm -f elf32 -o $1.o $1.nasm

echo "[+] Linking ..."
ld -o $1 $1.o

echo "[+] Removing .o ..."
rm $1.o

echo "[+] Done!"
./$1
