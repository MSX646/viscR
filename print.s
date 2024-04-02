BITS 64;
global main

main:
	jmp get_string ; jmp-call-pop tips

print:
	mov rax, 0x1 ; sysscall write
	mov rdi, 0x1 ; stdout
	pop rsi 
	mov rdx, 0xe ; 13 length 
	syscall
	jmp end

get_string:
	call print
	db `at0m1c_JunK1e\n`
end:
	xor rax, rax
	xor rdi, rdi
	xor rdx, rdx
	xor rsi, rsi
