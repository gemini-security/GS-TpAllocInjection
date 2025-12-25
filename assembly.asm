[section .data]
id: dd 0
jmptofake: dq 0

[section .text]

BITS 64
DEFAULT REL

global setup
global executioner

setup:
	mov dword [id], 000h
	mov dword [id], ecx
	mov qword [jmptofake], 00000000h
	mov qword [jmptofake], rdx
	ret

executioner:
	mov r10, rcx
	mov eax, dword [id]
	jmp qword [jmptofake]
	ret
