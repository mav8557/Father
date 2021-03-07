global _start

section .data:
	fname db "/etc/ld.so.preload", 0

section .text:
_start:
	mov eax, 10
	mov ebx, fname
	int 0x80

	mov ebx, eax
	mov eax, 1
	int 0x80
