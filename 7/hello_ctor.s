BITS 64 ; nasm 어셈블러의 64비트 모드

SECTION .text
global main

main:
	push rax ; save all clobbered registers
	push rcx
	push rdx
	push rsi
	push rdi
	push r11
	
	mov rax, 1 ; sys_write
	mov rdi, 1 ; stdout
	lea rsi, [rel $+hello-$] ; hello
	mov rdx, [rel $+len-$]   ; len
	syscall
	
	pop r11
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rax

	push 0x404a70;jump to original constructor
	ret

hello: db "hello world", 33, 10
len  : dd 13

