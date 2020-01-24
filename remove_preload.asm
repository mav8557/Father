global _start

section .data:
	fname db "/etc/ld.so.preload", 0

section .text:
_start:
	mov eax, 10
	mov ebx, fname
	int 0x80

	mov eax, 1
	mov ebx, 0
	int 0x80
