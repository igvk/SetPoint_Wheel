
public original_jump_address
public original_branch_jump_address
extern patched_switch_foreground_process_handler : proc

.data

iexplore_exe db "iexplore.exe", 0

original_jump_address dq 0
original_branch_jump_address dq 0

.code

; Injected procedure must be called by jmp from the patched code
; original_jump_address & original_branch_jump_address should be set beforehand to the return code address

injected_handler_V690 proc
    ; Stack is kept unchanged in this procedure
    ; Space in stack belonging to the 5th function parameter as seen from the caller is used
    ; Shadow space of the target function may be used in the callee
    mov [rsp+20h], rax ; the only value that should be kept
    mov rcx, rax ; name
    call patched_switch_foreground_process_handler
    test eax, eax
    jl no
    mov edx, eax
    mov rax, [rsp+20h]
    jmp [original_branch_jump_address]
no:
    lea rdx, [iexplore_exe]
    ; rcx should point to the name that was originally passed in rax
    mov rcx, [rsp+20h]
    jmp [original_jump_address]
injected_handler_V690 endp

end
