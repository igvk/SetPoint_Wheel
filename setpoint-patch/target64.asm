
public iexplore_exe

_wcsicmp proto; :qword,:qword,:qword

.data

iexplore_exe db "iexplore.exe", 0

.code

target_handler_ASM proc
    sub rsp, 28h
    jmp code_start

; This is the exact code from target, but it can not be executed here due to different call/jump addresses
orig_start:
    lea rcx, [rsp+0EE8h]
    call qword ptr [$+6+55C52h]
orig_patch:
    lea rdx, [$+7+8EA7Bh]
    mov rcx, rax
    call qword ptr [$+6+561B2h]
    cmp eax, edi
    jnz $+6+1F2h
    cmp qword ptr [rsp+40h], 2
    jnz $+2+5Bh
    lea rdx, [$+7+89113h]
    lea rcx, [rsp+78h]
    call $+5-0C5FA7h
    nop

code_start:
    mov rax, rcx
    xor rdi, rdi
code_patch:
    lea rdx, [iexplore_exe]
    mov rcx, rax
    call _wcsicmp
    cmp eax, edi
    jnz notfound
    mov edx, 9
code_success:
    mov rcx, rdi
    jmp return
notfound:
    mov edx, 0
return:
    movsxd rax, edx
    add rsp, 28h
    ret

    db 12 dup(0cch)
target_handler_ASM endp

end
